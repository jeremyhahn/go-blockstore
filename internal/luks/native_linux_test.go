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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// These tests format REAL LUKS2 containers and read the headers back, and they
// need neither root nor a block device to do it: go-luks2 formats a regular
// file, so a sparse file in t.TempDir() carries a container this package would
// otherwise only see on a logical volume.
//
// That is the whole reason they exist. Everything about the container this
// provider creates — the FIPS parameters, and the 16 MiB data offset the sizing
// contract is built on — used to be checkable only by reading a cryptsetup
// command line, which asserted what was ASKED FOR rather than what was written,
// or by the integration suite, which needs root and does not run on every
// change. Formatting in-process asserts the header itself, on every `go test`.
//
// What they cannot cover is unlocking: a plaintext mapping is a device-mapper
// device, which needs root and /dev/mapper/control. Those paths stay in the
// integration suite.

// luksTestPassphraseBytes is a passphrase for these tests. It clears go-luks2's
// 8-byte floor, which the fake-backed tests never exercise because the fake does
// not enforce one.
var luksTestPassphraseBytes = []byte("correct-horse-battery-staple")

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

	if err := (Native{}).Format(context.Background(), path, luksTestPassphraseBytes); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return path
}

// TestNativeFormatPinsFIPSParameters asserts the parameters of the header that
// is actually WRITTEN, which is the assertion the old argv check was standing in
// for.
//
// go-luks2's defaults are not FIPS-approved — an empty KDFType formats with
// argon2id and an empty HashAlgo derives with SHA-256 — so a container formatted
// by this provider must state every parameter rather than inherit one. Dropping
// any of these silently produces a container that is weaker, or non-compliant,
// or both, and nothing about the resulting volume says so.
func TestNativeFormatPinsFIPSParameters(t *testing.T) {
	device := newContainerFile(t, 32<<20)

	_, metadata, err := luks2.ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

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
	// The header carries the master key size in BYTES; the option is in bits,
	// and XTS splits it in two — so 64 bytes here is AES-256-XTS.
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
	for _, kdf := range []*luks2.KDF{keyslot.KDF} {
		if strings.Contains(strings.ToLower(kdf.Type), "argon2") {
			t.Errorf("the header names %q; argon2 is not FIPS-approved", kdf.Type)
		}
	}
	for id, digest := range metadata.Digests {
		if strings.Contains(strings.ToLower(digest.Type), "argon2") {
			t.Errorf("digest %s uses %q; argon2 is not FIPS-approved", id, digest.Type)
		}
	}
}

// TestNativeFormatProducesTheHeaderTheSizingConstantAssumes is the assertion the
// whole #11 sizing contract rests on, checked against the formatter that
// actually writes the header rather than against the one it was measured on.
//
// HeaderBytes was measured on cryptsetup 2.7.0 in 2026-08-27 and is used to
// size every encrypted volume this provider creates: the logical volume is made
// that much larger than the requested usable capacity. If go-luks2 laid the
// header out differently, every encrypted volume would come out the wrong size
// and Status would report a usable capacity the caller cannot use.
//
// It does not, and the sizes are the same five the cryptsetup measurement used,
// so the two are directly comparable. The offset does not scale with the device.
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

// TestNativeFormatClearsTheIterationFloor records the one parameter deliberately
// left to the library, and the floor it must not fall below.
//
// NIST SP 800-132 asks for at least 1000 PBKDF2 iterations. Measured on
// go-luks2 v0.1.7-alpha (2026-08-29) the answer was 100000 every time: its
// benchmark timed 1000 iterations at millisecond resolution, PBKDF2-SHA-512
// finishes that in under a millisecond, and it fell through to a hard-coded
// figure — so it did not adapt to hardware the way cryptsetup's did, where the
// same parameters produced 3,344,740.
//
// The improvement arrived: go-luks2 v0.2.0-alpha calibrates, and on 2026-09-03
// the same parameters produced 3,988,449. This test did not have to change,
// which is the point of it — the floor is what compliance needs, the count is
// not load-bearing for the high-entropy material this provider stretches, and
// pinning the measured value would have turned that improvement into a test
// failure. It is left unpinned for the next one.
func TestNativeFormatClearsTheIterationFloor(t *testing.T) {
	device := newContainerFile(t, 32<<20)

	_, metadata, err := luks2.ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	keyslot, ok := metadata.Keyslots["0"]
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

	if err := (Native{}).Format(context.Background(), path, []byte("short")); err == nil {
		t.Fatal("Format accepted a passphrase below go-luks2's 8-byte floor")
	}
}

// TestNativeTestKeyVerifiesWithoutUnlocking is what a restore leans on: the key
// is checked against the header the restored volume is about to receive, before
// anything is created, and checking it exposes no plaintext device.
func TestNativeTestKeyVerifiesWithoutUnlocking(t *testing.T) {
	device := newContainerFile(t, 32<<20)
	backend := Native{}

	if err := backend.TestKey(context.Background(), device, luksTestPassphraseBytes); err != nil {
		t.Fatalf("TestKey refused the passphrase the container was formatted with: %v", err)
	}
	if err := backend.TestKey(context.Background(), device, []byte("not-the-passphrase")); err == nil {
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

// TestNativeDataOffsetRefusesAnUnusableSegmentTable covers the fail-closed
// branches of the read that every capacity answer is built on.
//
// None of these shapes can be produced by formatting: they are what a container
// that is MID-REENCRYPTION, or one whose header has been corrupted or written by
// something else, looks like. Each is built by rewriting the header of a real
// container — go-luks2 re-checksums both copies on write, so what comes back is
// a header this package genuinely has to cope with rather than a mangled file.
//
// Guessing at any of them would be worse than failing. Two segments have no
// single usable capacity; a zero offset would say the container costs nothing
// and hand the caller its own header as usable space.
func TestNativeDataOffsetRefusesAnUnusableSegmentTable(t *testing.T) {
	rewrites := map[string]func(*luks2.LUKS2Metadata){
		"two segments": func(m *luks2.LUKS2Metadata) {
			second := *m.Segments["0"]
			second.Offset = strconv.FormatInt(32<<20, 10)
			m.Segments["1"] = &second
		},
		"no segments":         func(m *luks2.LUKS2Metadata) { m.Segments = map[string]*luks2.Segment{} },
		"offset not a number": func(m *luks2.LUKS2Metadata) { m.Segments["0"].Offset = "sixteen" },
		"offset zero":         func(m *luks2.LUKS2Metadata) { m.Segments["0"].Offset = "0" },
		"offset negative":     func(m *luks2.LUKS2Metadata) { m.Segments["0"].Offset = "-4096" },
	}

	for name, rewrite := range rewrites {
		t.Run(name, func(t *testing.T) {
			device := newContainerFile(t, 32<<20)

			hdr, metadata, err := luks2.ReadHeader(device)
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			rewrite(metadata)
			if err := luks2.WriteHeader(device, hdr, metadata); err != nil {
				t.Fatalf("WriteHeader: %v", err)
			}

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

	hdr, metadata, err := luks2.ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	metadata.Segments["0"].Offset = strconv.FormatInt(foreign, 10)
	metadata.Config.KeyslotsSize = strconv.FormatInt(foreign, 10)
	if writeErr := luks2.WriteHeader(device, hdr, metadata); writeErr != nil {
		t.Fatalf("WriteHeader: %v", writeErr)
	}

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

// TestNativeMappingReportsAnAbsentNameAsAbsent is the negative answer luksIsOpen
// is allowed to act on, and the only one. A name nothing has ever opened is not
// an error.
func TestNativeMappingReportsAnAbsentNameAsAbsent(t *testing.T) {
	info, exists, err := (Native{}).Mapping(context.Background(), "bs-vg0_no-such-volume-"+strconv.Itoa(os.Getpid()))
	if err != nil {
		t.Fatalf("Mapping: %v", err)
	}
	if exists {
		t.Fatalf("Mapping reported %+v for a name nothing has opened", info)
	}
}

// TestNativeMappingOperationsFailRatherThanSucceedQuietly covers the paths that
// need device-mapper, without needing it: the operations are issued against a
// device and a mapping that do not exist, and every one of them has to come back
// with an error. The success paths are the integration suite's — see
// TestIntegrationEncryptedVolumeRoundTrip — but a silent success here would mean
// Attach reporting a plaintext device that was never created.
func TestNativeMappingOperationsFailRatherThanSucceedQuietly(t *testing.T) {
	backend := Native{}
	ctx := context.Background()
	absentDevice := filepath.Join(t.TempDir(), "absent.img")
	absentMapping := "bs-vg0_no-such-volume-" + strconv.Itoa(os.Getpid())

	ops := map[string]func() error{
		"Open":  func() error { return backend.Open(ctx, absentDevice, absentMapping, luksTestPassphraseBytes) },
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
		"Format":     func() error { return backend.Format(ctx, device, luksTestPassphraseBytes) },
		"Open":       func() error { return backend.Open(ctx, device, "bs-vg0_data", luksTestPassphraseBytes) },
		"Close":      func() error { return backend.Close(ctx, "bs-vg0_data") },
		"TestKey":    func() error { return backend.TestKey(ctx, device, luksTestPassphraseBytes) },
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

// TestBackingDeviceRequiresExactlyOneSlave covers the fail-closed rule on the
// lookup that decides whether a mapping is ours.
//
// A dm-crypt target is stacked on exactly one device, so none and several are
// both "this is not the mapping we are looking for" rather than something to
// pick a winner out of. Neither shape can be produced on a real /sys on demand,
// which is why sysfsRoot is a parameter.
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

// TestDeviceSizeReadsSysfsSectorsAndRefusesWhatItCannotParse covers the
// number a stale-mapping check is decided on. sysfs publishes a block device's
// size in 512-byte sectors regardless of its logical sector size — that unit
// is the kernel's, fixed in the block layer, not a property of the device — so
// the reading is scaled once here and nowhere else. Every unreadable shape is
// a refusal: the whole point of measuring is to refuse a mapping whose size
// cannot be established, and a 0 read as "zero bytes" would make every
// mapping look stale, while one read as "unknown, assume fine" would make none
// of them.
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

// --- Upstream conformance ---------------------------------------------------
//
// THE TESTS BELOW FAIL AGAINST go-luks2 v0.1.7-alpha, AND THAT FAILURE IS THE
// POINT. They are not aspirational and they are not to be made green by
// changing what they assert; each one pins a property of the on-disk container
// that a storage product cannot ship without, and each one is red because
// go-luks2 does not hold it yet. They go green when the upstream defects they
// name are fixed, and that is the signal this repo needs.
//
// None of them can be caught by round-tripping through go-luks2. Its Format and
// its Unlock make the SAME wrong assumption, so they agree with each other
// perfectly: format-then-unlock passes while a container written by anything
// else — including every volume this package provisioned before 2026-08-29 —
// does not open, and a container written here cannot be read by the tools an
// operator recovers with. Self-consistency is exactly what these tests refuse
// to accept as evidence. See TestNativeRoundTripIsNotEvidenceOfConformance.

// hashOutputBytes is the digest size of each hash a LUKS2 header may declare.
var hashOutputBytes = map[string]int{
	"sha1":   20,
	"sha256": 32,
	"sha384": 48,
	"sha512": 64,
}

// TestNativeFormatWritesASpecLengthDigest is the migration gate, expressed as
// the invariant that makes migration possible.
//
// A LUKS2 pbkdf2 digest is the master key run through PBKDF2 to the output
// length of the hash the digest DECLARES. Declare sha512 and the stored digest
// is 64 bytes. go-luks2 hardcodes 32 (format.go:243 and unlock.go:485, both
// `DeriveKey(..., 32)`), so it writes a 32-byte digest under a sha512 label and
// verifies by deriving 32 bytes and comparing.
//
// This package pins hashAlgo = "sha512". The consequence, measured 2026-08-29
// on this host against cryptsetup 2.7.0 rather than reasoned about:
//
//   - A container formatted by cryptsetup with this package's exact parameters
//     stores a 64-byte digest. `luks2.TestKey` on it, WITH THE CORRECT
//     PASSPHRASE, returns "incorrect passphrase" — subtle.ConstantTimeCompare
//     of a 32-byte derivation against a 64-byte stored value can only be 0.
//     Every encrypted volume this package provisioned before the go-luks2
//     migration is therefore unopenable. That is a data-availability incident,
//     not a test failure.
//   - The reverse direction is NOT broken: cryptsetup derives its comparison to
//     the length actually stored, so it accepts a 32-byte digest. That is worth
//     knowing because it means fixing this defect alone does not restore
//     cryptsetup interop — see TestNativeFormatWritesACryptsetupReadableHeader,
//     which covers the separate defects that do.
//
// Upstream: go-luks2 #73. Do not work around it here by moving hashAlgo to
// sha256: that would silently downgrade a deliberate FIPS 180-4 choice and
// still would not open a single existing sha512 volume.
func TestNativeFormatWritesASpecLengthDigest(t *testing.T) {
	device := newContainerFile(t, 32<<20)

	_, metadata, err := luks2.ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
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

// TestNativeFormatWritesACryptsetupReadableHeader is the disaster-recovery gate.
//
// An encrypted volume outlives the program that made it. When a host will not
// boot, or this library has a bug, or a volume has to be opened from a rescue
// image, the operator reaches for cryptsetup — luksDump, luksHeaderBackup,
// luksChangeKey, luksOpen. A container only this library can read has no
// recovery path at all, which is not a property a storage product may ship.
//
// Measured 2026-08-29 against cryptsetup 2.7.0: it rejects a go-luks2 container
// outright — `cryptsetup isLuks` exits 1 and luksDump answers "is not a valid
// LUKS device", so not one of those commands is available. This is NOT the
// digest defect above; the digest length is something cryptsetup tolerates.
// Three separate header-conformance defects cause it, and each subtest below
// pins one. Patching all three into a go-luks2 container by hand and re-asking
// cryptsetup: isLuks exits 0, luksDump renders it, and `luksOpen
// --test-passphrase` accepts the passphrase. So these three are the whole gap.
//
// Upstream: not yet filed as of 2026-08-29; report them alongside #73.
func TestNativeFormatWritesACryptsetupReadableHeader(t *testing.T) {
	device := newContainerFile(t, 32<<20)

	raw, err := os.ReadFile(device)
	if err != nil {
		t.Fatalf("reading the container back: %v", err)
	}

	// "tokens" must be PRESENT, as an empty object, not omitted. go-luks2 tags
	// it `json:"tokens,omitempty"` (types.go:67), so a container with no tokens
	// — which is every container this package formats — omits the key. Measured:
	// cryptsetup answers `JSON area "" is missing "tokens" (object)
	// specification` and fails validation before it looks at anything else.
	t.Run("json area declares tokens", func(t *testing.T) {
		jsonArea, jsonErr := luksJSONArea(raw, 0)
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

	// keyslots_size is the size of the keyslots AREA, and cryptsetup requires
	// keyslots_offset + keyslots_size <= data_offset. go-luks2 stores the offset
	// PLUS the area (format.go:207), which overshoots by the 32768 the two
	// metadata copies occupy. Measured: `keyslots_size is too large 16777216
	// (bytes). Data offset: 16777216, keyslots offset: 32768`.
	t.Run("keyslots area fits in front of the data", func(t *testing.T) {
		_, metadata, readErr := luks2.ReadHeader(device)
		if readErr != nil {
			t.Fatalf("ReadHeader: %v", readErr)
		}
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

	// The secondary header at 0x4000 carries its own magic, "SKUL\xba\xbe" —
	// LUKS2_MAGIC_2ND. go-luks2 writes the PRIMARY magic there
	// (header.go:writeHeaderInternal copies the header and changes only
	// HeaderOffset). Measured: cryptsetup reports `LUKS2 header read failed
	// (-22)` for the backup copy, so a container whose primary header is damaged
	// cannot be repaired from its own backup — which is the entire reason LUKS2
	// writes two.
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

// TestNativeRoundTripIsNotEvidenceOfConformance is here to stop the wrong
// conclusion being drawn from a green suite.
//
// go-luks2's Format and its Unlock share the digest-length assumption, so they
// agree with each other exactly. This test PASSES, and it passes for a reason
// that says nothing about whether a volume written elsewhere can be opened or a
// volume written here can be recovered. It exists so that the next person to
// see a passing round-trip reads this instead of concluding the container is
// interoperable.
func TestNativeRoundTripIsNotEvidenceOfConformance(t *testing.T) {
	device := newContainerFile(t, 32<<20)

	if err := (Native{}).TestKey(context.Background(), device, luksTestPassphraseBytes); err != nil {
		t.Fatalf("go-luks2 cannot open a container go-luks2 formatted: %v", err)
	}

	// The round trip succeeded. State plainly what it did not establish.
	t.Log("a go-luks2 round trip passes; it is self-consistency, not conformance. " +
		"The gates are TestNativeFormatWritesASpecLengthDigest (can a volume written " +
		"by the previous cryptsetup implementation still be opened?) and " +
		"TestNativeFormatWritesACryptsetupReadableHeader (can an operator recover a " +
		"volume written by this one?).")
}

// luksJSONArea returns the JSON metadata that follows a LUKS2 binary header,
// trimmed at its NUL padding.
func luksJSONArea(raw []byte, headerOffset int) ([]byte, error) {
	const binaryHeaderLen = 4096
	// hdr_size is a big-endian u64 at byte 8 of the binary header, and covers
	// the binary header plus the JSON area.
	if len(raw) < headerOffset+binaryHeaderLen {
		return nil, fmt.Errorf("the container is %d bytes, too small to hold a header", len(raw))
	}
	headerSize := binary.BigEndian.Uint64(raw[headerOffset+8 : headerOffset+16])
	end := headerOffset + int(headerSize) // #nosec G115 -- bounded by the length check below
	if headerSize > uint64(len(raw)) || end > len(raw) {
		return nil, fmt.Errorf("the header declares %d bytes, past the end of a %d-byte container",
			headerSize, len(raw))
	}
	area := raw[headerOffset+binaryHeaderLen : end]
	if nul := bytes.IndexByte(area, 0); nul >= 0 {
		area = area[:nul]
	}
	return area, nil
}
