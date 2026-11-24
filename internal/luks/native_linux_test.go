// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-blockstore.
//
// go-blockstore is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build linux

package luks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/internal/luks/luktest"
)

// These tests format real LUKS2 containers in sparse files without root; unlocking stays in the integration suite.

// luksTestPassphrase seals a passphrase for these tests. It clears go-luks2's
// 8-byte floor, which the fake-backed tests never exercise because the fake does
// not enforce one. Every call seals a fresh enclave, destroyed with the test.
func luksTestPassphrase(t *testing.T) *enclave.MemoryEnclave {
	t.Helper()
	return sealTestPassphrase(t, "correct-horse-battery-staple")
}

// sealTestPassphrase seals the given passphrase into an enclave destroyed with
// the test. NewMemoryEnclave takes ownership of its argument and wipes it, so
// the conversion from a string hands it a copy nobody else holds.
func sealTestPassphrase(t *testing.T, passphrase string) *enclave.MemoryEnclave {
	t.Helper()
	sealed, err := enclave.NewMemoryEnclave([]byte(passphrase))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	t.Cleanup(func() {
		if destroyErr := sealed.Destroy(); destroyErr != nil {
			t.Errorf("Destroy: %v", destroyErr)
		}
	})
	return sealed
}

// newContainerFile writes a LUKS2 container onto a sparse file of the given size
// with exactly the parameters this provider pins, and returns its path.
func newContainerFile(t *testing.T, size int64) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "container.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating the backing file: %v", err)
	}
	if truncErr := f.Truncate(size); truncErr != nil {
		t.Fatalf("sizing the backing file: %v", truncErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		t.Fatalf("closing the backing file: %v", closeErr)
	}

	if err := (Native{}).Format(context.Background(), path, luksTestPassphrase(t)); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return path
}

// TestNativeFormatPinsFIPSParameters asserts the written header's parameters; go-luks2's defaults are not FIPS-approved.
func TestNativeFormatPinsFIPSParameters(t *testing.T) {
	device := newContainerFile(t, 32<<20)
	metadata := luktest.Read(t, device)

	keyslot, ok := metadata.Keyslots["0"]
	if !ok {
		t.Fatal("the header has no keyslot 0")
	}
	if keyslot.KDF.Type != pbkdf {
		t.Errorf("KDF = %q, want %q; argon2 is not FIPS-approved and is the library default",
			keyslot.KDF.Type, pbkdf)
	}
	if keyslot.KDF.Hash != hashAlgo {
		t.Errorf("KDF hash = %q, want %q", keyslot.KDF.Hash, hashAlgo)
	}
	if keyslot.AF.Hash != hashAlgo {
		t.Errorf("anti-forensic hash = %q, want %q; one hash across the header", keyslot.AF.Hash, hashAlgo)
	}
	// The header stores the key size in bytes; 64 bytes is AES-256-XTS.
	if want := keySizeBits / 8; keyslot.KeySize != want {
		t.Errorf("key size = %d bytes, want %d (AES-256-XTS)", keyslot.KeySize, want)
	}

	wantCipher := cipher + "-" + cipherMode
	if keyslot.Area.Encryption != wantCipher {
		t.Errorf("keyslot area encryption = %q, want %q", keyslot.Area.Encryption, wantCipher)
	}
	segment, ok := metadata.Segments["0"]
	if !ok {
		t.Fatal("the header has no data segment 0")
	}
	if segment.Encryption != wantCipher {
		t.Errorf("segment encryption = %q, want %q", segment.Encryption, wantCipher)
	}
	if segment.SectorSize != sectorSize {
		t.Errorf("sector size = %d, want %d", segment.SectorSize, sectorSize)
	}

	// argon2 must appear nowhere: it is the library's default and is not
	// FIPS-approved, so a header mentioning it means a parameter stopped being
	// stated somewhere.
	if strings.Contains(strings.ToLower(keyslot.KDF.Type), "argon2") {
		t.Errorf("the header names %q; argon2 is not FIPS-approved", keyslot.KDF.Type)
	}
	for id, digest := range metadata.Digests {
		if strings.Contains(strings.ToLower(digest.Type), "argon2") {
			t.Errorf("digest %s uses %q; argon2 is not FIPS-approved", id, digest.Type)
		}
	}
}

// TestNativeFormatProducesTheHeaderTheSizingConstantAssumes checks the data offset HeaderBytes sizes every encrypted volume by.
func TestNativeFormatProducesTheHeaderTheSizingConstantAssumes(t *testing.T) {
	sizes := map[string]int64{
		"32 MiB":   32 << 20,
		"64 MiB":   64 << 20,
		"128 MiB":  128 << 20,
		"300 MiB":  300 << 20,
		"1200 MiB": 1200 << 20,
	}

	for name, size := range sizes {
		t.Run(name, func(t *testing.T) {
			device := newContainerFile(t, size)

			offset, err := (Native{}).DataOffset(context.Background(), device)
			if err != nil {
				t.Fatalf("DataOffset: %v", err)
			}
			if offset != HeaderBytes {
				t.Errorf("this container's header cost %d bytes; HeaderBytes says %d. "+
					"The constant sizes every encrypted volume this provider creates — re-measure it "+
					"against go-luks2's layout rather than adjusting the volumes",
					offset, HeaderBytes)
			}
		})
	}
}

// TestNativeFormatClearsTheIterationFloor requires at least the NIST SP 800-132 minimum of 1000 PBKDF2 iterations.
func TestNativeFormatClearsTheIterationFloor(t *testing.T) {
	device := newContainerFile(t, 32<<20)

	keyslot, ok := luktest.Read(t, device).Keyslots["0"]
	if !ok {
		t.Fatal("the header has no keyslot 0")
	}
	if keyslot.KDF.Iterations == nil {
		t.Fatal("the keyslot records no iteration count")
	}
	if got := *keyslot.KDF.Iterations; got < 1000 {
		t.Errorf("PBKDF2 iterations = %d, below the 1000 NIST SP 800-132 asks for", got)
	}
}

// TestNativeFormatRefusesAShortPassphrase documents the bound go-luks2 enforces
// and cryptsetup did not. A KeyProvider returning fewer than 8 bytes now fails
// at the operation, which is worth a test because nothing in this package's own
// validation catches it.
func TestNativeFormatRefusesAShortPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "container.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating the backing file: %v", err)
	}
	if truncErr := f.Truncate(32 << 20); truncErr != nil {
		t.Fatalf("sizing the backing file: %v", truncErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		t.Fatalf("closing the backing file: %v", closeErr)
	}

	if err := (Native{}).Format(context.Background(), path, sealTestPassphrase(t, "short")); err == nil {
		t.Fatal("Format accepted a passphrase below go-luks2's 8-byte floor")
	}
}

// TestNativeTestKeyVerifiesWithoutUnlocking is what a restore leans on: the key
// is checked against the header the restored volume is about to receive, before
// anything is created, and checking it exposes no plaintext device.
func TestNativeTestKeyVerifiesWithoutUnlocking(t *testing.T) {
	device := newContainerFile(t, 32<<20)
	backend := Native{}

	if err := backend.TestKey(context.Background(), device, luksTestPassphrase(t)); err != nil {
		t.Fatalf("TestKey refused the passphrase the container was formatted with: %v", err)
	}
	if err := backend.TestKey(context.Background(), device, sealTestPassphrase(t, "not-the-passphrase")); err == nil {
		t.Fatal("TestKey accepted a passphrase that opens no keyslot")
	}
}

// TestNativeDataOffsetRefusesWhatIsNotAContainer covers the read that Status and
// Resize depend on. A device with no header, and a path that is not there at
// all, both have to be errors: a zero offset silently reported would overstate
// every encrypted volume's usable capacity by a whole header.
func TestNativeDataOffsetRefusesWhatIsNotAContainer(t *testing.T) {
	dir := t.TempDir()
	backend := Native{}

	plain := filepath.Join(dir, "plain.img")
	if err := os.WriteFile(plain, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if offset, err := backend.DataOffset(context.Background(), plain); err == nil {
		t.Errorf("DataOffset = %d for a device with no LUKS header, want an error", offset)
	}

	if offset, err := backend.DataOffset(context.Background(), filepath.Join(dir, "absent.img")); err == nil {
		t.Errorf("DataOffset = %d for a device that does not exist, want an error", offset)
	}
}

// TestNativeDataOffsetRefusesAnUnusableSegmentTable covers rewritten headers with segment tables that have no single usable capacity.
func TestNativeDataOffsetRefusesAnUnusableSegmentTable(t *testing.T) {
	rewrites := map[string]func(map[string]any) error{
		"two segments": func(m map[string]any) error {
			segments := m["segments"].(map[string]any)
			second := maps.Clone(segments["0"].(map[string]any))
			second["offset"] = strconv.FormatInt(32<<20, 10)
			segments["1"] = second
			return nil
		},
		"no segments": func(m map[string]any) error {
			m["segments"] = map[string]any{}
			return nil
		},
		"offset not a number": func(m map[string]any) error { return luktest.SetSegmentOffset(m, "sixteen") },
		"offset zero":         func(m map[string]any) error { return luktest.SetSegmentOffset(m, "0") },
		"offset negative":     func(m map[string]any) error { return luktest.SetSegmentOffset(m, "-4096") },
	}

	for name, rewrite := range rewrites {
		t.Run(name, func(t *testing.T) {
			device := newContainerFile(t, 32<<20)
			luktest.Rewrite(t, device, rewrite)

			if offset, err := (Native{}).DataOffset(context.Background(), device); err == nil {
				t.Fatalf("DataOffset = %d, want a refusal", offset)
			}
		})
	}
}

// TestNativeDataOffsetReadsAForeignHeader is the other half of the same read:
// a container whose data does NOT start where this package would have put it is
// reported at its own offset, not at HeaderBytes. A volume restored from an
// outside snapshot carries exactly such a header, and assuming the constant
// there would misstate its capacity by the difference.
func TestNativeDataOffsetReadsAForeignHeader(t *testing.T) {
	const foreign = 4 << 20
	device := newContainerFile(t, 32<<20)

	luktest.Rewrite(t, device, func(m map[string]any) error {
		if err := luktest.SetSegmentOffset(m, strconv.FormatInt(foreign, 10)); err != nil {
			return err
		}
		// go-luks2 refuses a header whose keyslot area overruns the data, so
		// the area is shrunk to end where the data starts: the two 16 KiB
		// header copies sit in front of it.
		return luktest.SetKeyslotsSize(m, strconv.FormatInt(foreign-2*16384, 10))
	})

	offset, err := (Native{}).DataOffset(context.Background(), device)
	if err != nil {
		t.Fatalf("DataOffset: %v", err)
	}
	if offset != foreign {
		t.Errorf("DataOffset = %d, want the header's own %d", offset, foreign)
	}
	if offset == HeaderBytes {
		t.Error("DataOffset returned the constant instead of reading the header")
	}
}

// TestNativeMappingOperationsFailRatherThanSucceedQuietly issues mapping operations on absent devices and requires errors.
func TestNativeMappingOperationsFailRatherThanSucceedQuietly(t *testing.T) {
	backend := Native{}
	ctx := context.Background()
	absentDevice := filepath.Join(t.TempDir(), "absent.img")
	absentMapping := "bs-vg0_no-such-volume-" + strconv.Itoa(os.Getpid())

	ops := map[string]func() error{
		"Open":  func() error { return backend.Open(ctx, absentDevice, absentMapping, luksTestPassphrase(t)) },
		"Close": func() error { return backend.Close(ctx, absentMapping) },
	}

	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			if err := op(); err == nil {
				t.Errorf("%s succeeded against a device and mapping that do not exist", name)
			}
		})
	}
}

// TestNativeOperationsHonorACancelledContext checks the one thing a context can
// mean here. go-luks2 takes none, so cancellation is observed at the call
// boundary: an operation that has not started does not start. See Backend
// for why an operation that HAS started is run to completion.
func TestNativeOperationsHonorACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	backend := Native{}
	device := filepath.Join(t.TempDir(), "container.img")

	ops := map[string]func() error{
		"Format":     func() error { return backend.Format(ctx, device, luksTestPassphrase(t)) },
		"Open":       func() error { return backend.Open(ctx, device, "bs-vg0_data", luksTestPassphrase(t)) },
		"Close":      func() error { return backend.Close(ctx, "bs-vg0_data") },
		"TestKey":    func() error { return backend.TestKey(ctx, device, luksTestPassphrase(t)) },
		"DataOffset": func() error { _, err := backend.DataOffset(ctx, device); return err },
		"Mapping":    func() error { _, _, err := backend.Mapping(ctx, "bs-vg0_data"); return err },
		"Identity":   func() error { _, err := backend.Identity(ctx, device); return err },
	}

	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			if err := op(); !errors.Is(err, context.Canceled) {
				t.Errorf("%s = %v, want context.Canceled", name, err)
			}
		})
	}
}

// TestBackingDeviceRequiresExactlyOneSlave requires a dm-crypt mapping to have exactly one backing device.
func TestBackingDeviceRequiresExactlyOneSlave(t *testing.T) {
	// One arbitrary device number, used for every case; the directory it names
	// is what varies.
	const major, minor = 253, 7
	rdev := uint64(major<<8 | minor)

	// newRoot builds a fake sysfs whose slaves directory holds these entries,
	// and gives each named dm device a dm/name file.
	newRoot := func(t *testing.T, slaves []string, dmNames map[string]string) string {
		t.Helper()
		root := t.TempDir()
		slaveDir := filepath.Join(root, "dev", "block",
			strconv.Itoa(major)+":"+strconv.Itoa(minor), "slaves")
		if err := os.MkdirAll(slaveDir, 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		for _, name := range slaves {
			if err := os.Mkdir(filepath.Join(slaveDir, name), 0o750); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
		}
		for kname, dmName := range dmNames {
			dir := filepath.Join(root, "class", "block", kname, "dm")
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "name"), []byte(dmName+"\n"), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
		}
		return root
	}

	t.Run("one device-mapper slave is reported dm-canonically", func(t *testing.T) {
		root := newRoot(t, []string{"dm-3"}, map[string]string{"dm-3": "vg0-data"})
		backing, err := backingDevice(root, rdev)
		if err != nil {
			t.Fatalf("backingDevice: %v", err)
		}
		if want := "/dev/mapper/vg0-data"; backing != want {
			t.Errorf("backingDevice = %q, want %q — the spelling an operator recognizes", backing, want)
		}
	})

	t.Run("one ordinary slave is reported by kernel name", func(t *testing.T) {
		root := newRoot(t, []string{"sdb1"}, nil)
		backing, err := backingDevice(root, rdev)
		if err != nil {
			t.Fatalf("backingDevice: %v", err)
		}
		if want := "/dev/sdb1"; backing != want {
			t.Errorf("backingDevice = %q, want %q", backing, want)
		}
	})

	refusals := map[string][]string{
		"no slaves":  {},
		"two slaves": {"dm-3", "dm-4"},
	}
	for name, slaves := range refusals {
		t.Run(name, func(t *testing.T) {
			root := newRoot(t, slaves, nil)
			backing, err := backingDevice(root, rdev)
			if err == nil {
				t.Fatalf("backingDevice = %q, want a refusal", backing)
			}
			if !errors.Is(err, ErrNoBackingDevice) {
				t.Errorf("backingDevice = %v, want ErrNoBackingDevice", err)
			}
		})
	}

	t.Run("no slaves directory at all", func(t *testing.T) {
		if backing, err := backingDevice(t.TempDir(), rdev); err == nil {
			t.Fatalf("backingDevice = %q for a device sysfs does not describe, want a refusal", backing)
		}
	})
}

// TestDeviceSizeReadsSysfsSectorsAndRefusesWhatItCannotParse reads sysfs size in 512-byte sectors and refuses unparseable values.
func TestDeviceSizeReadsSysfsSectorsAndRefusesWhatItCannotParse(t *testing.T) {
	const major, minor = 253, 7
	rdev := uint64(major<<8 | minor)

	withSize := func(t *testing.T, content string) string {
		t.Helper()
		root := t.TempDir()
		dir := filepath.Join(root, "dev", "block", strconv.Itoa(major)+":"+strconv.Itoa(minor))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "size"), []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return root
	}

	t.Run("sectors are scaled to bytes", func(t *testing.T) {
		// 2129920 sectors is what a 1 GiB + 16 MiB device reports, and the
		// literal on the right is that in bytes: the test fails if the unit
		// is ever taken as bytes or as 4 KiB blocks.
		got, err := deviceSize(withSize(t, "2129920\n"), rdev)
		if err != nil {
			t.Fatalf("deviceSize: %v", err)
		}
		if want := int64(1090519040); got != want {
			t.Errorf("deviceSize = %d, want %d", got, want)
		}
	})

	refusals := map[string]string{
		"empty":         "",
		"not a number":  "lots\n",
		"negative":      "-8\n",
		"zero sectors":  "0\n",
		"overflows int": "99999999999999999999\n",
	}
	for name, content := range refusals {
		t.Run(name, func(t *testing.T) {
			if got, err := deviceSize(withSize(t, content), rdev); err == nil {
				t.Fatalf("deviceSize = %d for %q, want a refusal", got, content)
			}
		})
	}

	t.Run("no size file at all", func(t *testing.T) {
		if got, err := deviceSize(t.TempDir(), rdev); err == nil {
			t.Fatalf("deviceSize = %d for a device sysfs does not describe, want a refusal", got)
		}
	})
}

// TestIdentityFollowsSymlinksAndRefusesNonDevices covers the comparison
// luksIsOpen decides ownership on. The same device answers to several paths, so
// the identity has to survive a symlink; anything that is not a device has no
// identity to report and must fail rather than answer 0:0.
func TestIdentityFollowsSymlinksAndRefusesNonDevices(t *testing.T) {
	backend := Native{}
	ctx := context.Background()

	direct, err := backend.Identity(ctx, "/dev/null")
	if err != nil {
		t.Fatalf("Identity(/dev/null): %v", err)
	}
	if direct == "" {
		t.Fatal("Identity(/dev/null) reported no device number")
	}

	link := filepath.Join(t.TempDir(), "link-to-null")
	if linkErr := os.Symlink("/dev/null", link); linkErr != nil {
		t.Fatalf("Symlink: %v", linkErr)
	}
	viaLink, err := backend.Identity(ctx, link)
	if err != nil {
		t.Fatalf("Identity(symlink): %v", err)
	}
	if viaLink != direct {
		t.Errorf("Identity through a symlink = %q, direct = %q; the same device must answer alike",
			viaLink, direct)
	}

	regular := filepath.Join(t.TempDir(), "not-a-device")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if id, err := backend.Identity(ctx, regular); err == nil {
		t.Errorf("Identity(regular file) = %q, want a refusal", id)
	}
	if id, err := backend.Identity(ctx, filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Errorf("Identity(absent path) = %q, want a refusal", id)
	}
}

// Upstream conformance: these tests pin on-disk properties go-luks2 must hold; do not change their assertions to make them pass.

// hashOutputBytes is the digest size of each hash a LUKS2 header may declare.
var hashOutputBytes = map[string]int{
	"sha1":   20,
	"sha256": 32,
	"sha384": 48,
	"sha512": 64,
}

// TestNativeFormatWritesASpecLengthDigest requires a pbkdf2 digest of the declared hash's length (64 bytes for sha512); keep hashAlgo sha512.
func TestNativeFormatWritesASpecLengthDigest(t *testing.T) {
	device := newContainerFile(t, 32<<20)

	metadata := luktest.Read(t, device)
	if len(metadata.Digests) == 0 {
		t.Fatal("the header carries no digest")
	}

	for id, digest := range metadata.Digests {
		want, known := hashOutputBytes[strings.ToLower(digest.Hash)]
		if !known {
			t.Errorf("digest %s declares hash %q, which is not one this package knows a length for", id, digest.Hash)
			continue
		}
		raw, decodeErr := base64.StdEncoding.DecodeString(digest.Digest)
		if decodeErr != nil {
			t.Errorf("digest %s is not decodable: %v", id, decodeErr)
			continue
		}
		if len(raw) != want {
			t.Errorf("digest %s declares hash %q and stores %d bytes, but %s produces %d. "+
				"A container written this way is not what cryptsetup wrote, and a container "+
				"cryptsetup wrote will not verify here: every encrypted volume provisioned "+
				"before this package moved to go-luks2 becomes unopenable, reporting "+
				"\"incorrect passphrase\" for the correct passphrase. Upstream: go-luks2 #73 "+
				"(format.go:243, unlock.go:485 both hardcode 32)",
				id, digest.Hash, len(raw), digest.Hash, want)
		}
	}
}

// TestNativeFormatWritesACryptsetupReadableHeader requires a header cryptsetup accepts, so volumes stay recoverable.
func TestNativeFormatWritesACryptsetupReadableHeader(t *testing.T) {
	device := newContainerFile(t, 32<<20)

	raw, err := os.ReadFile(device)
	if err != nil {
		t.Fatalf("reading the container back: %v", err)
	}

	// "tokens" must be present as an empty object; cryptsetup rejects a header without it.
	t.Run("json area declares tokens", func(t *testing.T) {
		jsonArea, jsonErr := luktest.JSONArea(raw, 0)
		if jsonErr != nil {
			t.Fatalf("reading the JSON area: %v", jsonErr)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(jsonArea, &fields); err != nil {
			t.Fatalf("parsing the JSON area: %v", err)
		}
		if _, ok := fields["tokens"]; !ok {
			t.Error(`the JSON area omits "tokens"; LUKS2 requires it present as an object, ` +
				`empty when there are none. cryptsetup fails validation on its absence and ` +
				`refuses the whole device`)
		}
	})

	// keyslots_size is the keyslots area size; cryptsetup requires keyslots_offset + keyslots_size <= data_offset.
	t.Run("keyslots area fits in front of the data", func(t *testing.T) {
		metadata := luktest.Read(t, device)
		keyslotsSize, err := strconv.ParseInt(metadata.Config.KeyslotsSize, 10, 64)
		if err != nil {
			t.Fatalf("keyslots_size %q: %v", metadata.Config.KeyslotsSize, err)
		}
		keyslotsOffset, err := strconv.ParseInt(metadata.Keyslots["0"].Area.Offset, 10, 64)
		if err != nil {
			t.Fatalf("keyslot area offset %q: %v", metadata.Keyslots["0"].Area.Offset, err)
		}
		dataOffset, err := strconv.ParseInt(metadata.Segments["0"].Offset, 10, 64)
		if err != nil {
			t.Fatalf("segment offset %q: %v", metadata.Segments["0"].Offset, err)
		}
		if end := keyslotsOffset + keyslotsSize; end > dataOffset {
			t.Errorf("keyslots_size %d at offset %d ends at %d, past the data offset %d. "+
				"cryptsetup reads keyslots_size as the AREA size and refuses a header where "+
				"the area overruns the data; go-luks2 stores offset+area instead",
				keyslotsSize, keyslotsOffset, end, dataOffset)
		}
	})

	// The secondary header at 0x4000 carries LUKS2_MAGIC_2ND, "SKUL\xba\xbe".
	t.Run("secondary header carries the secondary magic", func(t *testing.T) {
		const secondaryOffset = 0x4000
		if len(raw) < secondaryOffset+6 {
			t.Fatalf("the container is %d bytes, too small to hold a secondary header", len(raw))
		}
		got := raw[secondaryOffset : secondaryOffset+6]
		if want := []byte("SKUL\xba\xbe"); !bytes.Equal(got, want) {
			t.Errorf("the secondary header magic is %q, want %q. cryptsetup cannot read the "+
				"backup header, so a damaged primary header is unrecoverable", got, want)
		}
	})
}

// TestNativeRoundTripIsNotEvidenceOfConformance passes because Format and Unlock share one assumption; it proves no interoperability.
func TestNativeRoundTripIsNotEvidenceOfConformance(t *testing.T) {
	device := newContainerFile(t, 32<<20)

	if err := (Native{}).TestKey(context.Background(), device, luksTestPassphrase(t)); err != nil {
		t.Fatalf("go-luks2 cannot open a container go-luks2 formatted: %v", err)
	}

	// The round trip succeeded. State plainly what it did not establish.
	t.Log("a go-luks2 round trip passes; it is self-consistency, not conformance. " +
		"The gates are TestNativeFormatWritesASpecLengthDigest (can a volume written " +
		"by the previous cryptsetup implementation still be opened?) and " +
		"TestNativeFormatWritesACryptsetupReadableHeader (can an operator recover a " +
		"volume written by this one?).")
}
