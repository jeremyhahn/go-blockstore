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

package local

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// openKey reads an enclave's contents for assertion purposes. Test-only: it
// copies locked material onto the heap, which is exactly what production code
// must never do.
func openKey(t *testing.T, enc *enclave.MemoryEnclave) string {
	t.Helper()
	var out string
	if err := enc.WithBytes(func(b []byte) error {
		out = string(b)
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	return out
}

func TestStaticKeyProviderHandsOutFreshEnclaves(t *testing.T) {
	original := []byte("secret")
	stored, err := enclave.NewMemoryEnclave(original)
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}

	// go-enclave takes ownership of the slice at the boundary where the caller
	// still knows it is sensitive, so it comes back wiped and this package never
	// sees a heap copy at all.
	for i, c := range original {
		if c != 0 {
			t.Fatalf("byte %d of the caller's slice = %d, want it wiped to 0", i, c)
		}
	}

	provider, err := StaticKeyProvider(stored)
	if err != nil {
		t.Fatalf("StaticKeyProvider: %v", err)
	}

	first, err := provider(context.Background(), "data")
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	if got := openKey(t, first); got != "secret" {
		t.Fatalf("key = %q, want the passphrase given at construction", got)
	}

	// The provider destroys what it is handed, so a second call has to produce
	// a distinct live enclave rather than the same one again.
	second, err := provider(context.Background(), "data")
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	if first == second {
		t.Fatal("the provider handed out the same enclave twice; destroying one would break the other")
	}

	first.Destroy()
	if !second.IsAlive() {
		t.Fatal("destroying one enclave killed another the provider handed out")
	}
	if got := openKey(t, second); got != "secret" {
		t.Fatalf("second key = %q, want the same passphrase", got)
	}
	second.Destroy()
}

// TestDestroyedEnclaveCannotBeBorrowed is the property the whole design rests
// on: once the provider is done with a passphrase, the material is gone and a
// later borrow fails rather than returning stale bytes.
func TestDestroyedEnclaveCannotBeBorrowed(t *testing.T) {
	stored, err := enclave.NewMemoryEnclave([]byte("secret"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	provider, err := StaticKeyProvider(stored)
	if err != nil {
		t.Fatalf("StaticKeyProvider: %v", err)
	}
	enc, err := provider(context.Background(), "data")
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	enc.Destroy()

	if enc.IsAlive() {
		t.Error("IsAlive() = true after Destroy")
	}
	if enc.Size() != 0 {
		t.Errorf("Size() = %d after Destroy, want 0", enc.Size())
	}
	borrowErr := enc.WithBytes(func([]byte) error {
		t.Error("the callback ran on a destroyed enclave")
		return nil
	})
	if borrowErr == nil {
		t.Fatal("WithBytes succeeded on a destroyed enclave, want an error")
	}
	if !errors.Is(borrowErr, enclave.ErrEnclaveDestroyed) {
		t.Errorf("WithBytes = %v, want ErrEnclaveDestroyed", borrowErr)
	}
}

// TestProviderDestroysTheKeyAfterUse pins the ownership half of the contract:
// the provider takes what the KeyProvider hands over and destroys it once
// cryptsetup has consumed it, so locked pages are not left holding a passphrase
// after the operation that needed it.
func TestProviderDestroysTheKeyAfterUse(t *testing.T) {
	var handedOut []*enclave.MemoryEnclave

	runner := newFakeRunner()
	p := newTestProvider(t, runner, func(o *Options) {
		o.Encrypted = true
		o.KeyProvider = func(context.Context, string) (*enclave.MemoryEnclave, error) {
			enc, err := enclave.NewMemoryEnclave([]byte(testKey))
			if err != nil {
				return nil, err
			}
			handedOut = append(handedOut, enc)
			return enc, nil
		}
	})

	if _, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if len(handedOut) == 0 {
		t.Fatal("the KeyProvider was never called")
	}
	for i, enc := range handedOut {
		if enc.IsAlive() {
			t.Errorf("enclave %d is still alive after the operation that borrowed it", i)
		}
	}
}

// TestKeyIsBorrowedOnlyForTheCommand checks the narrowness of the window: the
// passphrase is a []byte while cryptsetup is being fed and at no other time.
func TestKeyIsBorrowedOnlyForTheCommand(t *testing.T) {
	var aliveDuringRun bool
	var enc *enclave.MemoryEnclave

	runner := newFakeRunner()
	runner.on("cryptsetup", func(_ []string, stdin []byte) ([]byte, error) {
		// Only the commands actually fed a passphrase say anything here; the
		// closing `cryptsetup close` carries no stdin at all.
		if stdin != nil {
			aliveDuringRun = aliveDuringRun || (enc != nil && enc.IsAlive() && string(stdin) == testKey)
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, func(o *Options) {
		o.Encrypted = true
		o.KeyProvider = func(context.Context, string) (*enclave.MemoryEnclave, error) {
			created, err := enclave.NewMemoryEnclave([]byte(testKey))
			enc = created
			return created, err
		}
	})

	if _, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !aliveDuringRun {
		t.Error("the passphrase was not available to the command that needed it")
	}
	if enc.IsAlive() {
		t.Error("the enclave outlived the command it was borrowed for")
	}
}

// TestLUKSFormatPinsFIPSParameters asserts the exact argv. cryptsetup's
// defaults are not FIPS-approved and have moved between versions, so a volume
// formatted by this provider must state every parameter rather than inherit
// one: dropping any of these silently produces a container that is weaker, or
// non-compliant, or both, and nothing about the resulting volume says so.
func TestLUKSFormatPinsFIPSParameters(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner, encrypted)

	if err := p.luksFormat(context.Background(), "data", "/dev/vg0/data"); err != nil {
		t.Fatalf("luksFormat: %v", err)
	}

	call := runner.mustFind(t, "cryptsetup")
	want := "cryptsetup luksFormat --type luks2 --batch-mode " +
		"--pbkdf pbkdf2 --hash sha512 --cipher aes-xts-plain64 --key-size 512 " +
		"--key-file - /dev/vg0/data"
	if call.line() != want {
		t.Errorf("luksFormat ran:\n  %s\nwant:\n  %s", call.line(), want)
	}

	// The passphrase still goes in on stdin, never argv.
	if !bytes.Equal(call.Stdin, []byte(testKey)) {
		t.Errorf("stdin = %q, want the passphrase", call.Stdin)
	}
	assertKeyNeverOnArgv(t, runner)
}

// TestLUKSFormatDoesNotPinIterations records the one parameter deliberately
// left to cryptsetup. Measured on 2.7.0, it enforces a hard PBKDF2 minimum of
// 1000 — the floor NIST SP 800-132 asks for — and refuses to go below it, so
// benchmarking cannot undershoot compliance. A fixed count could not rise on
// faster hardware and would undershoot the benchmark everywhere it mattered.
func TestLUKSFormatDoesNotPinIterations(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner, encrypted)

	if err := p.luksFormat(context.Background(), "data", "/dev/vg0/data"); err != nil {
		t.Fatalf("luksFormat: %v", err)
	}

	call := runner.mustFind(t, "cryptsetup")
	for _, unwanted := range []string{"--pbkdf-force-iterations", "--iter-time"} {
		if contains(call.Args, unwanted) {
			t.Errorf("luksFormat pinned %s; the benchmark adapts to hardware and cannot go below cryptsetup's floor", unwanted)
		}
	}
}

func TestFileKeyProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "luks.key")
	if err := os.WriteFile(path, []byte("from-a-file"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	enc, err := FileKeyProvider(path)(context.Background(), "data")
	if err != nil {
		t.Fatalf("FileKeyProvider: %v", err)
	}
	defer enc.Destroy()

	if got := openKey(t, enc); got != "from-a-file" {
		t.Fatalf("key = %q, want the file's bytes verbatim", got)
	}
}

// TestFileKeyProviderRereadsOnEachCall is what makes key rotation take effect
// without restarting the process.
func TestFileKeyProviderRereadsOnEachCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "luks.key")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	provider := FileKeyProvider(path)

	first, err := provider(context.Background(), "data")
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	first.Destroy()

	if writeErr := os.WriteFile(path, []byte("new"), 0o600); writeErr != nil {
		t.Fatalf("WriteFile: %v", writeErr)
	}

	second, err := provider(context.Background(), "data")
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	defer second.Destroy()

	if got := openKey(t, second); got != "new" {
		t.Fatalf("key = %q, want the rotated value", got)
	}
}

func TestFileKeyProviderRejectsUnusableFiles(t *testing.T) {
	dir := t.TempDir()

	if _, err := FileKeyProvider(filepath.Join(dir, "absent"))(context.Background(), "data"); err == nil {
		t.Error("FileKeyProvider succeeded for a file that does not exist")
	}

	empty := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := FileKeyProvider(empty)(context.Background(), "data"); err == nil {
		t.Error("FileKeyProvider succeeded for an empty key file")
	}

	// An oversized file is refused rather than mlock'd: locked memory is
	// rationed, and a path pointing at something enormous is a misconfiguration.
	big := filepath.Join(dir, "big.key")
	if err := os.WriteFile(big, make([]byte, maxKeyFileBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := FileKeyProvider(big)(context.Background(), "data"); err == nil {
		t.Error("FileKeyProvider locked a file over the size limit")
	}
}

// TestLockedMemoryErrorIsLegible covers the refusal path an operator actually
// hits. The provider does not fall back to unprotected memory when the kernel
// will not lock pages, so the error has to say what to change.
func TestLockedMemoryErrorIsLegible(t *testing.T) {
	err := lockedMemoryError(&enclave.LockedMemoryError{Cause: errors.New("cannot allocate memory")})

	if !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
		t.Fatalf("lockedMemoryError dropped the sentinel: %v", err)
	}
	for _, want := range []string{"RLIMIT_MEMLOCK", "LimitMEMLOCK", "ulimit -l"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}

	// An unrelated error passes through untouched rather than being dressed up
	// as a memlock problem.
	other := errors.New("some other failure")
	if got := lockedMemoryError(other); !errors.Is(got, other) {
		t.Errorf("lockedMemoryError(%v) = %v, want it passed through", other, got)
	}
}

// TestLUKSIsOpenRefusesAForeignMapping is the fail-open this check exists for.
// The mapping name is deterministic, which makes it findable and also makes it
// claimable — a stale mapping from an earlier run, or one opened by hand, sits
// under exactly the name this provider looks for. Trusting the name would have
// Attach return that mapping as this volume's plaintext device, handing the
// caller another volume's decrypted contents to mount.
func TestLUKSIsOpenRefusesAForeignMapping(t *testing.T) {
	runner := newFakeRunner().withMappingsBackedBy(map[string]string{
		// Our name, someone else's volume.
		"bs-vg0_data": "/dev/mapper/vg0-somebodyelse",
	})
	p := newTestProvider(t, runner, withKey)

	open, err := p.luksIsOpen(context.Background(), "data")
	if err == nil {
		t.Fatal("luksIsOpen adopted a mapping over a different device")
	}
	if open {
		t.Error("luksIsOpen reported a foreign mapping as ours")
	}
	if !strings.Contains(err.Error(), "somebodyelse") {
		t.Errorf("error = %q, want it to name the device actually behind the mapping", err)
	}
}

// TestLUKSIsOpenAcceptsOurOwnMapping checks the identity comparison is by
// device rather than by path text: cryptsetup reports the dm-canonical
// /dev/mapper/<vg>-<lv>, which is a different string from the /dev/<vg>/<lv>
// this provider opened, and the same device.
func TestLUKSIsOpenAcceptsOurOwnMapping(t *testing.T) {
	runner := newFakeRunner().withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey)

	open, err := p.luksIsOpen(context.Background(), "data")
	if err != nil {
		t.Fatalf("luksIsOpen: %v", err)
	}
	if !open {
		t.Error("luksIsOpen did not recognize the provider's own mapping")
	}
}

// TestLUKSIsOpenFailsClosedOnUnreadableIdentity covers a status that cannot be
// tied to a device at all. The point of reading it is to refuse what cannot be
// established, so a missing or repeated device line is a failure, not a pass.
func TestLUKSIsOpenFailsClosedOnUnreadableIdentity(t *testing.T) {
	cases := map[string]string{
		"no device line":   "/dev/mapper/bs-vg0_data is active.\n  type:    LUKS2\n",
		"empty device":     "/dev/mapper/bs-vg0_data is active.\n  device:  \n",
		"two device lines": "/dev/mapper/bs-vg0_data is active.\n  device:  /dev/mapper/vg0-data\n  device:  /dev/mapper/vg0-other\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			out := body
			runner := newFakeRunner().on("cryptsetup", func(args []string, _ []byte) ([]byte, error) {
				if len(args) > 0 && args[0] == "status" {
					return []byte(out), nil
				}
				return nil, nil
			})
			p := newTestProvider(t, runner, withKey)

			if open, err := p.luksIsOpen(context.Background(), "data"); err == nil {
				t.Fatalf("luksIsOpen returned %v and no error for %s", open, name)
			}
		})
	}
}

// TestAttachRefusesToAdoptAForeignMapping is the same rule seen from the API:
// the caller must not be handed another volume's plaintext device.
func TestAttachRefusesToAdoptAForeignMapping(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withMappingsBackedBy(map[string]string{"bs-vg0_data": "/dev/mapper/vg0-somebodyelse"})
	p := newTestProvider(t, runner, withKey)

	if _, err := p.Attach(context.Background(), "data", "node-a"); err == nil {
		t.Fatal("Attach returned a mapping over a different volume as this volume's device")
	}
}

func TestMappingNamesAreNamespacedByVolumeGroup(t *testing.T) {
	first := newTestProvider(t, newFakeRunner(), func(o *Options) { o.VolumeGroup = "vg0" })
	second := newTestProvider(t, newFakeRunner(), func(o *Options) { o.VolumeGroup = "vg1" })

	if first.mappingName("data") == second.mappingName("data") {
		t.Fatalf("both volume groups claim the mapping %q", first.mappingName("data"))
	}
	if first.cryptPath("data") == second.cryptPath("data") {
		t.Fatalf("both volume groups resolve to the device %q", first.cryptPath("data"))
	}

	// The separator has to be a character validateName rejects, or a
	// group/volume pair could still collide with another by moving a hyphen.
	a := newTestProvider(t, newFakeRunner(), func(o *Options) { o.VolumeGroup = "vg-a" })
	b := newTestProvider(t, newFakeRunner(), func(o *Options) { o.VolumeGroup = "vg" })
	if a.mappingName("data") == b.mappingName("a-data") {
		t.Fatalf("hyphen rearrangement collides on %q", a.mappingName("data"))
	}
}

// TestKeyProviderFailurePropagates covers a TPM-backed provider that cannot
// unseal: the operation must fail rather than fall through to an unlock attempt
// with no key.
func TestKeyProviderFailurePropagates(t *testing.T) {
	sentinel := errors.New("TPM policy not satisfied")
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	p := newTestProvider(t, runner, func(o *Options) {
		o.KeyProvider = func(context.Context, string) (*enclave.MemoryEnclave, error) { return nil, sentinel }
	})

	_, err := p.Attach(context.Background(), "data", "node-a")
	if !errors.Is(err, sentinel) {
		t.Fatalf("Attach = %v, want the KeyProvider error", err)
	}
	assertNoLine(t, runner, "cryptsetup open --type luks2 --key-file - /dev/vg0/data bs-vg0_data")
}

func TestEmptyKeyIsRejected(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	p := newTestProvider(t, runner, func(o *Options) {
		o.KeyProvider = func(context.Context, string) (*enclave.MemoryEnclave, error) { return nil, nil }
	})

	if _, err := p.Attach(context.Background(), "data", "node-a"); err == nil {
		t.Fatal("Attach succeeded with an empty key")
	}
}

// TestKeyProviderReceivesTheVolumeID lets an implementation hold a distinct key
// per volume.
func TestKeyProviderReceivesTheVolumeID(t *testing.T) {
	var seen []string
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	p := newTestProvider(t, runner, func(o *Options) {
		o.KeyProvider = func(_ context.Context, volID string) (*enclave.MemoryEnclave, error) {
			seen = append(seen, volID)
			return enclave.NewMemoryEnclave([]byte(testKey))
		}
	})

	if _, err := p.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if len(seen) != 1 || seen[0] != "data" {
		t.Fatalf("KeyProvider saw %v, want [data]", seen)
	}
}

// TestCryptsetupFailuresPropagate walks the LUKS commands the provider issues
// and checks each one's failure reaches the caller instead of being swallowed.
func TestCryptsetupFailuresPropagate(t *testing.T) {
	ctx := context.Background()

	cases := map[string]struct {
		setup func() *fakeRunner
		call  func(*Provider) error
	}{
		"luksFormat": {
			setup: func() *fakeRunner {
				r := newFakeRunner()
				r.fail("cryptsetup", 1, "not a valid device")
				return r
			},
			call: func(p *Provider) error {
				_, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: gib})
				return err
			},
		},
		"luksOpen": {
			setup: func() *fakeRunner {
				r := newFakeRunner().
					withLVs(lvFixture{Name: "data", SizeBytes: gib}).
					withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
				r.on("cryptsetup", func(args []string, _ []byte) ([]byte, error) {
					if len(args) > 0 && args[0] == "open" {
						return nil, &ExitError{Name: "cryptsetup", Args: args, Code: 2, Stderr: "no key available"}
					}
					return nil, &ExitError{Name: "cryptsetup", Args: args, Code: 4}
				})
				return r
			},
			call: func(p *Provider) error {
				_, err := p.Attach(ctx, "data", "node-a")
				return err
			},
		},
		"luksClose": {
			setup: func() *fakeRunner {
				r := newFakeRunner().
					withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
					withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
				r.on("cryptsetup", func(args []string, _ []byte) ([]byte, error) {
					if len(args) > 0 && args[0] == "status" {
						return []byte("active"), nil
					}
					return nil, &ExitError{Name: "cryptsetup", Args: args, Code: 5, Stderr: "device busy"}
				})
				return r
			},
			call: func(p *Provider) error { return p.Detach(ctx, "data", "node-a") },
		},
		"status": {
			setup: func() *fakeRunner {
				r := newFakeRunner().
					withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
					withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
				// A cryptsetup that is not installed at all: not an *ExitError,
				// so it must not be read as "the mapping is not open".
				r.on("cryptsetup", func([]string, []byte) ([]byte, error) {
					return nil, errors.New("exec: cryptsetup: executable file not found in $PATH")
				})
				return r
			},
			call: func(p *Provider) error {
				_, err := p.Status(ctx, "data")
				return err
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := newTestProvider(t, tc.setup(), encrypted)
			if err := tc.call(p); err == nil {
				t.Fatal("the operation succeeded despite a cryptsetup failure")
			}
		})
	}
}
