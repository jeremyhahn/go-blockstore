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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jeremyhahn/go-enclave"
)

// fsTypeLUKS is what blkid reports for a LUKS container.
const fsTypeLUKS = "crypto_LUKS"

// The LUKS2 parameters every container this provider creates is formatted with.
// They are pinned rather than left to cryptsetup because cryptsetup's defaults
// are not FIPS-approved and its compiled-in defaults vary by host and version:
// on cryptsetup 2.7.0 the default LUKS2 PBKDF is argon2id.
const (
	// luksPBKDF is PBKDF2, the only key-derivation function among cryptsetup's
	// choices that is FIPS-approved. Argon2id, cryptsetup's default, is not.
	//
	// Its memory-hardness is what argon2 is chosen for, and it is not
	// load-bearing here: the KDF is stretching KeyProvider material, which is a
	// machine-generated high-entropy key out of a file or an enclave and never
	// an interactive human passphrase. There is no low-entropy secret for a
	// GPU-parallel attacker to grind at. A caller feeding a human-chosen
	// passphrase into KeyProvider has picked the wrong layer for it — stretch it
	// where it is entered, and hand this one the result.
	luksPBKDF = "pbkdf2"

	// luksHash is SHA-512: FIPS 180-4 approved, and faster per byte than
	// SHA-256 on 64-bit hardware, so the same wall-clock benchmark buys more
	// iterations of real work. It also matches the 256-bit security level of
	// the cipher below, and is what cryptsetup then uses for the anti-forensic
	// stripes and the keyslot digest, keeping one hash across the header.
	luksHash = "sha512"

	// luksCipher is AES in XTS mode, the block-device standard and FIPS-approved.
	luksCipher = "aes-xts-plain64"

	// luksKeySize is in bits, and XTS splits it into two internal keys — so 512
	// here is AES-256-XTS, not AES-512. cryptsetup's default is 256, which XTS
	// halves to AES-128; pinning 512 is what makes the strength explicit rather
	// than a consequence of a default that has moved before.
	luksKeySize = "512"
)

// mappingPrefix namespaces this provider's device-mapper names so an unlocked
// volume is recognizable on a host that also runs other cryptsetup consumers.
const mappingPrefix = "bs-"

// KeyProvider supplies the passphrase that unlocks a volume's LUKS container,
// as a locked enclave rather than as bytes.
//
// It is called each time the provider formats, unlocks or resizes an encrypted
// volume, always with the volume's ID, so an implementation can hold a distinct
// key per volume.
//
// THE PROVIDER TAKES OWNERSHIP of what it is handed and destroys the enclave as
// soon as cryptsetup has consumed the passphrase, so every call returns a fresh
// enclave rather than one the implementation intends to reuse. Between those two
// points the passphrase is borrowed for exactly one command: it exists as a
// []byte only inside a MemoryEnclave.WithBytes callback that does nothing but
// write it to that process's standard input.
//
// The type is an enclave and not a []byte because a []byte cannot be taken back.
// Go's garbage collector may copy a heap slice while it lives, and zeroing the
// slice a caller still holds reaches neither those copies nor anything the
// scheduler moved; the bytes are also swappable and would land in a core dump.
// An enclave's pages are mlock'd, guarded, kept out of core dumps and wiped on
// release, which is the guarantee this package needs and the reason go-enclave
// is a portfolio-wide primitive rather than something restated here.
//
// This is the whole of the provider's involvement with key management. Where
// the key comes from — a file, an operator prompt, a TPM-sealed blob unsealed
// by go-trusted-platform — is the caller's business, and deliberately so: a
// provider that knew how to talk to a TPM would drag hardware-specific
// dependencies into a library whose other backends have no use for them. The
// caller unseals into an enclave; this provider borrows it and destroys it.
type KeyProvider func(ctx context.Context, volID string) (*enclave.MemoryEnclave, error)

// FileKeyProvider returns a KeyProvider that reads the passphrase from a file,
// re-reading it on each call so a rotated key file takes effect without
// restarting the process. Trailing newlines are not stripped: the file's bytes
// are the passphrase, which is what `cryptsetup --key-file` does with a file of
// its own.
//
// The bytes go from the file descriptor into the enclave's locked pages
// directly. There is no intermediate slice to wipe, and therefore none for the
// garbage collector to have copied first — which is what os.ReadFile would have
// left behind.
func FileKeyProvider(path string) KeyProvider {
	return func(_ context.Context, _ string) (*enclave.MemoryEnclave, error) {
		f, err := os.Open(path) // #nosec G304 -- path is operator configuration, not caller input
		if err != nil {
			return nil, fmt.Errorf("go-blockstore/local: reading LUKS key file: %w", err)
		}
		defer func() { _ = f.Close() }()

		info, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("go-blockstore/local: sizing LUKS key file: %w", err)
		}
		size := info.Size()
		if size <= 0 {
			return nil, errors.New("go-blockstore/local: LUKS key file is empty")
		}
		if size > maxKeyFileBytes {
			return nil, fmt.Errorf("go-blockstore/local: LUKS key file is %d bytes, over the %d-byte limit", size, maxKeyFileBytes)
		}

		enc, err := enclave.NewMemoryEnclaveSized(int(size))
		if err != nil {
			return nil, lockedMemoryError(err)
		}

		// The read happens inside the borrow, straight into the locked pages.
		if err := enc.WithBytes(func(buf []byte) error {
			if _, readErr := io.ReadFull(f, buf); readErr != nil {
				return fmt.Errorf("go-blockstore/local: reading LUKS key file: %w", readErr)
			}
			return nil
		}); err != nil {
			enc.Destroy()
			return nil, err
		}
		return enc, nil
	}
}

// maxKeyFileBytes bounds what FileKeyProvider will lock. A passphrase is not
// large, locked memory is a rationed resource under RLIMIT_MEMLOCK, and a
// misconfigured path pointing at something enormous should be refused rather
// than have the provider try to mlock it.
const maxKeyFileBytes = 1 << 20

// StaticKeyProvider returns a KeyProvider backed by a fixed passphrase, held in
// the enclave it is given for the returned provider's lifetime.
//
// It TAKES OWNERSHIP of stored: the caller keeps no reference and does not
// destroy it. Each call hands out a fresh enclave, because the provider destroys
// what it is given, and those copies are made from locked pages into locked
// pages and never exist on the heap.
//
// The parameter is an enclave and not a []byte on purpose. A []byte would put
// the passphrase on the ordinary heap before this function could do anything
// about it, and no amount of wiping afterwards reaches the copies the garbage
// collector or the caller may already have made — the entry point itself was the
// leak, not what happened after it. A caller with raw bytes moves them across
// with enclave.NewMemoryEnclave, which wipes the slice as it takes it, and does
// so at the point where it still knows the bytes are sensitive.
//
// It suits tests and single-key deployments. The passphrase stays in memory for
// as long as the provider lives, which a TPM-backed or prompt-backed
// implementation does not — locked memory is still memory. enclave.WipeAll
// reclaims it at an orderly exit.
func StaticKeyProvider(stored *enclave.MemoryEnclave) (KeyProvider, error) {
	if stored == nil || !stored.IsAlive() {
		return nil, errors.New("go-blockstore/local: StaticKeyProvider needs a live enclave")
	}
	return func(_ context.Context, _ string) (*enclave.MemoryEnclave, error) {
		var fresh *enclave.MemoryEnclave
		err := stored.WithBytes(func(src []byte) error {
			created, createErr := enclave.NewMemoryEnclaveSized(len(src))
			if createErr != nil {
				return lockedMemoryError(createErr)
			}
			if fillErr := created.WithBytes(func(dst []byte) error {
				copy(dst, src)
				return nil
			}); fillErr != nil {
				created.Destroy()
				return fillErr
			}
			fresh = created
			return nil
		})
		if err != nil {
			return nil, err
		}
		return fresh, nil
	}, nil
}

// lockedMemoryError turns go-enclave's refusal into something an operator can
// act on.
//
// The provider does not fall back to unprotected memory when the kernel will
// not lock pages — that would quietly hand back the exact guarantee this design
// exists to provide — so the refusal has to say what to change. It is almost
// always RLIMIT_MEMLOCK, which is small by default and easy to miss because
// nothing else in the process needs it.
func lockedMemoryError(err error) error {
	if errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
		return fmt.Errorf("go-blockstore/local: cannot lock memory for the LUKS passphrase, "+
			"so it will not be held at all: raise RLIMIT_MEMLOCK for this process "+
			"(LimitMEMLOCK= under systemd, ulimit -l in a shell): %w", err)
	}
	return err
}

// mappingName is the device-mapper name an unlocked volume appears under.
//
// The volume group is part of the name because device-mapper names are a single
// flat namespace for the whole host, while a volume ID is only unique within its
// group. Two providers over different groups, each holding an encrypted volume
// called "data", would otherwise both claim "bs-data" — and the second Attach
// would find the first one's mapping already open, return it, and quietly hand
// the caller another group's decrypted device to mount.
//
// The underscore separator is what keeps that fix from having a smaller version
// of the same hole: validateName rejects underscores, so no group/volume pair
// can collide with another by rearranging where a hyphen falls.
func (p *Provider) mappingName(volID string) string {
	return mappingPrefix + p.volumeGroup + "_" + volID
}

// cryptPath is the device path of an unlocked volume's plaintext mapping.
func (p *Provider) cryptPath(volID string) string {
	return "/dev/mapper/" + p.mappingName(volID)
}

// key fetches the passphrase for a volume as an enclave the caller must
// destroy, failing clearly when the provider was configured for encryption
// without a way to obtain keys.
func (p *Provider) key(ctx context.Context, volID string) (*enclave.MemoryEnclave, error) {
	if p.keyProvider == nil {
		return nil, fmt.Errorf("go-blockstore/local: volume %q is encrypted but no KeyProvider is configured", volID)
	}
	enc, err := p.keyProvider(ctx, volID)
	if err != nil {
		return nil, fmt.Errorf("go-blockstore/local: obtaining key for %q: %w", volID, lockedMemoryError(err))
	}
	if enc == nil || !enc.IsAlive() || enc.Size() == 0 {
		if enc != nil {
			enc.Destroy()
		}
		return nil, fmt.Errorf("go-blockstore/local: KeyProvider returned no usable key for %q", volID)
	}
	return enc, nil
}

// runWithKey borrows the volume's passphrase for exactly one command.
//
// The borrow window is this function and nothing else: the passphrase becomes a
// []byte when WithBytes hands one over, is written to the command's standard
// input, and stops being one when the callback returns. The enclave is
// destroyed on the way out whatever happened, so a failed command does not
// leave locked pages holding a key behind.
func (p *Provider) runWithKey(ctx context.Context, volID, name string, args ...string) error {
	enc, err := p.key(ctx, volID)
	if err != nil {
		return err
	}
	defer enc.Destroy()

	return enc.WithBytes(func(key []byte) error {
		_, runErr := p.runner.Run(ctx, key, name, args...)
		return runErr
	})
}

// luksFormat writes a LUKS2 header onto the device.
//
// Every cryptographic parameter is stated rather than defaulted. A container
// formatted by this provider is the same on every host, whatever cryptsetup was
// compiled to prefer there — which matters because the defaults are neither
// stable nor FIPS-approved: cryptsetup 2.7.0 picks argon2id for LUKS2 and a
// 256-bit key that XTS halves to AES-128.
//
// The iteration count is left to cryptsetup's benchmark on purpose. Measured on
// cryptsetup 2.7.0, it enforces a hard PBKDF2 minimum of 1000 — it refuses
// --pbkdf-force-iterations 999 outright — which is also the floor NIST SP
// 800-132 asks for, so the compliance floor holds without this provider pinning
// anything. Even --iter-time 1, the most degenerate benchmark available, came
// back with 1688 iterations, and the default produced 3,344,740 on this
// hardware. A fixed count would be strictly worse: it cannot rise on faster
// hardware, so it would undershoot the benchmark everywhere it mattered.
//
// The passphrase goes to cryptsetup on standard input via "--key-file -", never
// as an argument: an argument would be readable from /proc/<pid>/cmdline by any
// process on the host while the format runs. --batch-mode suppresses the
// interactive "this will overwrite data" confirmation, which has no answer in a
// library call.
func (p *Provider) luksFormat(ctx context.Context, volID, device string) error {
	err := p.runWithKey(ctx, volID, "cryptsetup", "luksFormat",
		"--type", "luks2",
		"--batch-mode",
		"--pbkdf", luksPBKDF,
		"--hash", luksHash,
		"--cipher", luksCipher,
		"--key-size", luksKeySize,
		"--key-file", "-",
		device,
	)
	if err != nil {
		return fmt.Errorf("go-blockstore/local: formatting LUKS container on %s: %w", device, err)
	}
	return nil
}

// luksOpen unlocks the container and exposes its plaintext mapping.
func (p *Provider) luksOpen(ctx context.Context, volID, device string) error {
	err := p.runWithKey(ctx, volID, "cryptsetup", "open",
		"--type", "luks2",
		"--key-file", "-",
		device,
		p.mappingName(volID),
	)
	if err != nil {
		return fmt.Errorf("go-blockstore/local: unlocking %s: %w", device, err)
	}
	return nil
}

// luksClose tears down the plaintext mapping.
func (p *Provider) luksClose(ctx context.Context, volID string) error {
	if _, err := p.runner.Run(ctx, nil, "cryptsetup", "close", p.mappingName(volID)); err != nil {
		return fmt.Errorf("go-blockstore/local: locking %s: %w", p.mappingName(volID), err)
	}
	return nil
}

// luksResize grows the plaintext mapping to match a grown container.
func (p *Provider) luksResize(ctx context.Context, volID string) error {
	err := p.runWithKey(ctx, volID, "cryptsetup", "resize", "--key-file", "-", p.mappingName(volID))
	if err != nil {
		return fmt.Errorf("go-blockstore/local: resizing %s: %w", p.mappingName(volID), err)
	}
	return nil
}

// cryptsetupWrongDevice is the status cryptsetup returns from `status` when the
// named mapping does not exist. Its other statuses cover wrong parameters, no
// permission and out of memory, none of which mean "not open".
const cryptsetupWrongDevice = 4

// luksIsOpen reports whether the volume's plaintext mapping exists AND is the
// one this provider would have made.
//
// The mapping name is deterministic, which makes it findable and also makes it
// claimable: a stale mapping left by an earlier run, or one an operator opened
// by hand, sits under exactly the name this provider looks for. Treating the
// name as proof would have Attach return that mapping as this volume's
// plaintext device — handing the caller some other volume's decrypted contents
// to mount — and Detach close it, and Resize grow it.
//
// So the backing device is checked. cryptsetup names it on a "device:" line,
// and the comparison is by major:minor rather than by path, because the same
// device answers to several paths — measured, cryptsetup reports the
// dm-canonical /dev/mapper/<vg>-<lv> whatever the mapping was opened against.
// A mapping under our name over some other device is an error, not something to
// adopt: it is a conflict a human has to resolve, and continuing would act on
// the wrong volume.
//
// Only cryptsetup's "no such device" status is the negative answer. Anything
// else is reported, because guessing "not open" would make Attach try to unlock
// a volume that is already unlocked, or Detach skip a mapping it should have
// closed.
func (p *Provider) luksIsOpen(ctx context.Context, volID string) (bool, error) {
	name := p.mappingName(volID)

	out, err := p.runner.Run(ctx, nil, "cryptsetup", "status", name)
	if err != nil {
		if exitErr, ok := asExitError(err); ok && exitErr.Code == cryptsetupWrongDevice {
			return false, nil
		}
		return false, fmt.Errorf("go-blockstore/local: checking %s: %w", name, err)
	}

	backing, err := parseCryptsetupBackingDevice(out)
	if err != nil {
		return false, fmt.Errorf("go-blockstore/local: reading what %s is backed by: %w", name, err)
	}

	same, err := p.sameDevice(ctx, backing, p.lvPath(volID))
	if err != nil {
		return false, err
	}
	if !same {
		return false, fmt.Errorf("go-blockstore/local: the device-mapper name %q is in use by a mapping over %s, "+
			"not over this volume's %s; close it or rename it before operating on this volume",
			name, backing, p.lvPath(volID))
	}
	return true, nil
}

// parseCryptsetupBackingDevice pulls the "device:" line out of cryptsetup
// status. Absent or repeated, it fails closed rather than guessing — the whole
// point of reading it is to refuse a mapping whose identity is not established.
func parseCryptsetupBackingDevice(out []byte) (string, error) {
	var devices []string
	for _, line := range strings.Split(string(out), "\n") {
		rest, found := strings.CutPrefix(strings.TrimSpace(line), "device:")
		if !found {
			continue
		}
		if device := strings.TrimSpace(rest); device != "" {
			devices = append(devices, device)
		}
	}
	switch len(devices) {
	case 1:
		return devices[0], nil
	case 0:
		return "", errors.New("cryptsetup status reported no backing device")
	default:
		return "", fmt.Errorf("cryptsetup status reported %d backing devices: %s", len(devices), strings.Join(devices, ", "))
	}
}
