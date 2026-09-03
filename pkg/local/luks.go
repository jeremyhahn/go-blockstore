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
	"strconv"

	"github.com/jeremyhahn/go-enclave"
)

// fsTypeLUKS is what blkid reports for a LUKS container.
const fsTypeLUKS = "crypto_LUKS"

// The LUKS2 parameters every container this provider creates is formatted with.
// They are pinned rather than left to the library because go-luks2's defaults
// are not FIPS-approved: FormatOptions with an empty KDFType formats with
// argon2id, and an empty HashAlgo derives with SHA-256.
const (
	// luksPBKDF is PBKDF2, the only key-derivation function among go-luks2's
	// choices that is FIPS-approved. Argon2id, its default, is not — and cannot
	// become so by accident, because argon2 is implemented in pure Go by
	// golang.org/x/crypto and never enters the Go Cryptographic Module at all.
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
	// SHA-256 on 64-bit hardware. It also matches the 256-bit security level of
	// the cipher below, and is what go-luks2 then uses for the anti-forensic
	// stripes and the keyslot digest, keeping one hash across the header.
	luksHash = "sha512"

	// luksCipher and luksCipherMode are AES in XTS mode, the block-device
	// standard and FIPS-approved. They are two constants because go-luks2 takes
	// them separately and joins them for the header, where they appear as the
	// familiar "aes-xts-plain64".
	luksCipher     = "aes"
	luksCipherMode = "xts-plain64"

	// luksKeySizeBits is in bits, and XTS splits it into two internal keys — so
	// 512 here is AES-256-XTS, not AES-512. go-luks2's default is also 512, and
	// stating it is what makes the strength a property of this package rather
	// than a consequence of a default that has moved before: cryptsetup, which
	// wrote every container this package created before 2026-08-29, defaults to
	// 256, which XTS halves to AES-128.
	luksKeySizeBits = 512
)

// luksHeaderBytes is the space a LUKS2 container this provider formats reserves
// in front of the caller's data: 16 MiB, of which two 16 KiB metadata copies
// and a 16744448-byte keyslots area account for every byte.
//
// It is a constant rather than something read back per volume because the
// provider PINS every parameter that determines it — see luksFormat — so the
// figure is a property of this package and of go-luks2's layout, not of
// whatever a host happens to ship. It is measured rather than taken from
// folklore, and it has now been measured against two independent formatters
// that agree to the byte:
//
//   - cryptsetup 2.7.0 (measured 2026-08-27 on a loopback volume group).
//     Formatting with exactly these parameters at 32 MiB, 64 MiB, 128 MiB,
//     300 MiB and 1200 MiB put the data segment at offset 16777216 every time,
//     and the plaintext mapping came back exactly that much smaller than the
//     logical volume under it.
//   - go-luks2 v0.1.7-alpha (measured 2026-08-29, formatting sparse files at
//     the same five sizes and reading the segment offset back out of the header
//     it wrote). Offset 16777216 at every size, keyslot area at 32768 with
//     258048 bytes used.
//
// It does not scale with the device, and the arithmetic behind it is not a
// coincidence of two implementations: go-luks2 computes the offset as the
// keyslots area start plus the keyslots area size (pkg/luks2/format.go), the
// area starts at 0x8000 = 32768 because two 16 KiB metadata copies precede it,
// and the area is the cryptsetup-compatible LUKS2DefaultKeyslotsSize of
// 16 MiB - 2*16 KiB = 16744448, which is larger than the 258048 bytes a single
// 512-bit keyslot needs. 32768 + 16744448 = 16777216.
//
// Where go-luks2 and cryptsetup DIVERGE is a device too small to hold a header
// and any data at all. cryptsetup shrinks the keyslots area to fit; go-luks2
// does not, and writes a segment offset past the end of the device, which then
// fails to open. Sizing here always adds this figure to a capacity that is
// already positive, so no backing device this provider creates lands in that
// range either way.
//
// It sizes containers this provider CREATES. What an existing container's
// header actually costs is read from that header — see luksDataOffset — because
// a volume restored from a snapshot carries whatever header its source had.
const luksHeaderBytes = 16 << 20

// encryptedTagPrefix names the LVM tag this provider sets on a volume once it
// holds a LUKS container, and the tag CARRIES THE HEADER'S SIZE rather than
// just the fact that there is one: "blockstore.luks-header=16777216".
//
// It exists for one question: what is a DETACHED volume's usable capacity?
// Answering it means knowing what the volume's header costs, and an inactive
// logical volume has no device node to read one from — measured, blkid answers
// a path that does not exist with the same "nothing here" status it uses for a
// device carrying no signature, so probing one reports every encrypted volume
// as plain. Status holds no lock and must not activate a volume to look.
//
// The SIZE is in the tag, and not merely a boolean, because the size is known
// at every point one is written and is not recoverable later. A volume restored
// verbatim from an outside snapshot carries THAT snapshot's header, which need
// not be the 16 MiB this package formats — the restore measured it to size the
// volume, so recording only "encrypted" would throw away a number already in
// hand and leave Status subtracting the wrong one. That error does not stay
// small or stay safe: against a 32 MiB header it OVER-states usable capacity by
// 16 MiB, and a caller sizing data to the answer would overrun the volume.
//
// The name is dot-namespaced and spelled out. A volume group is a shared place
// — the same reasoning that makes this provider check a device-mapper name's
// backing device rather than trust the name — so the tag has to be one no
// operator or neighboring tool would pick by accident, and it has to mean
// something to a human reading `lvs -o lv_tags` on a group they did not set up.
// Measured on LVM 2.03.16: every character here is in the set LVM accepts, "="
// included; the tag round-trips through the JSON report verbatim; --addtag and
// --deltag are both idempotent; and --deltag and --addtag can be given to one
// lvchange, which is what lets the value be corrected atomically.
//
// Tags are NOT inherited by snapshots — measured: a snapshot of a tagged origin
// comes back with no tags at all — so nothing here decides anything about a
// snapshot. A restore reads the source's header off the snapshot device
// instead, which it has activated anyway.
const encryptedTagPrefix = "blockstore.luks-header="

// encryptedTagFor renders the tag recording a container's header size.
func encryptedTagFor(headerBytes int64) string {
	return encryptedTagPrefix + strconv.FormatInt(headerBytes, 10)
}

// ErrResizeWhileAttached is returned by Resize for an encrypted volume whose
// plaintext mapping is open on this node. Detach it and resize again.
//
// It exists because growing a dm-crypt mapping in place means reloading the
// device-mapper table underneath the live device, and that needs the
// container's master key. go-luks2 v0.1.8-alpha exposes neither a resize nor
// any way to obtain that key (getMasterKey and unlockKeyslot are unexported),
// so the only mechanism available through it is to REMOVE the mapping and
// unlock again. That is a destructive shape wearing a resize's name: the
// teardown is unconditional and the rebuild can fail — a KeyProvider rotated
// since the volume was attached, a damaged header, any device-mapper refusal —
// and what the caller is left with is not an unresized volume but no plaintext
// device at all. Validating the key first narrows the window and does not close
// it, so the operation is refused rather than attempted.
//
// It is NOT wrapped around common.ErrUnsupported, and the difference is the
// whole value of the sentinel. ErrUnsupported tells a caller this backend
// cannot serve the request and that retrying or reconfiguring is pointless;
// this request is served perfectly well one Detach later, which is the opposite
// advice. A caller holding the attachment acts on that distinction — it is the
// same shape as common.ErrNotPrimary, "the request is fine, the volume is in
// the wrong state at the moment" — so the sentinel says so in its own right.
//
// The detached path has no such hazard and is not restricted: Resize over a
// detached volume unlocks the container itself, grows the filesystem and locks
// it again, and a failure anywhere in that leaves the volume exactly as
// detached as it started. See growDetachedEncryptedFilesystem.
var ErrResizeWhileAttached = errors.New("cannot resize an encrypted volume while it is attached")

// mappingPrefix namespaces this provider's device-mapper names so an unlocked
// volume is recognizable on a host that also runs other LUKS consumers.
const mappingPrefix = "bs-"

// KeyProvider supplies the passphrase that unlocks a volume's LUKS container,
// as a locked enclave rather than as bytes.
//
// It is called each time the provider formats, unlocks or resizes an encrypted
// volume, always with the volume's ID, so an implementation can hold a distinct
// key per volume.
//
// THE PROVIDER TAKES OWNERSHIP of what it is handed and destroys the enclave as
// soon as the LUKS operation has consumed the passphrase, so every call returns
// a fresh enclave rather than one the implementation intends to reuse. Between
// those two points the passphrase is borrowed for exactly one operation: it
// exists as a []byte only inside a MemoryEnclave.WithBytes callback, which hands
// it to go-luks2 for the length of one call and nothing longer. That borrow is
// narrower than it used to be — the bytes no longer leave the process at all,
// where they were once written to a cryptsetup child's standard input.
//
// The type is an enclave and not a []byte because a []byte cannot be taken back.
// Go's garbage collector may copy a heap slice while it lives, and zeroing the
// slice a caller still holds reaches neither those copies nor anything the
// scheduler moved; the bytes are also swappable and would land in a core dump.
// An enclave's pages are mlock'd, guarded, kept out of core dumps and wiped on
// release, which is the guarantee this package needs and the reason go-enclave
// is a portfolio-wide primitive rather than something restated here.
//
// THE PASSPHRASE MUST BE AT LEAST 8 BYTES AND AT MOST 512. That is go-luks2's
// bound, checked on every format and every unlock, and it is stated here because
// a KeyProvider that returns something shorter fails at the operation rather
// than at configuration time. It is not a constraint on real key material —
// anything a TPM unseals or a key file holds is far longer — but it does reject
// a toy passphrase that a cryptsetup-backed build would have accepted.
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
// are the passphrase, which is what `cryptsetup --key-file` did with a file of
// its own and what any container already formatted that way expects.
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

// withKey borrows the volume's passphrase for exactly one LUKS operation.
//
// The borrow window is this function and nothing else: the passphrase becomes a
// []byte when WithBytes hands one over, is passed to op, and stops being one
// when the callback returns. The enclave is destroyed on the way out whatever
// happened, so a failed operation does not leave locked pages holding a key
// behind.
//
// op MUST NOT retain the slice. Every implementation of luksBackend is bound by
// the same rule, and the native one keeps to it by handing the bytes straight
// to go-luks2, which derives from them and holds nothing.
func (p *Provider) withKey(ctx context.Context, volID string, op func(key []byte) error) error {
	enc, err := p.key(ctx, volID)
	if err != nil {
		return err
	}
	defer enc.Destroy()

	return enc.WithBytes(op)
}

// luksFormat writes a LUKS2 header onto the device.
//
// Every cryptographic parameter is stated rather than defaulted. A container
// formatted by this provider is the same on every host and in every build,
// which matters because the library's defaults are not FIPS-approved:
// go-luks2 formats with argon2id and derives with SHA-256 when it is not told
// otherwise. Nothing here depends on a cryptsetup binary being installed, being
// a particular version, or being compiled with a particular set of defaults —
// there is no cryptsetup involved at all.
//
// The iteration count is left to go-luks2's benchmark rather than pinned, for
// the reason a pinned count is worse: a fixed number cannot rise on faster
// hardware. That reasoning did not hold until go-luks2 v0.2.0-alpha, and the
// history is kept because it is what makes the current number credible: the
// benchmark timed 1000 PBKDF2-SHA-512 iterations at millisecond resolution, a
// derivation that finishes in well under a millisecond, so the elapsed time
// rounded to zero and every container came out with a hard-coded 100000 —
// against the 3,344,740 cryptsetup 2.7.0 chose on the same hardware. go-luks2
// #102 fixed the calibration and this provider adopted it in #45.
//
// Measured after the adoption, with the parameters below: 3,988,449 iterations,
// 2.42s of derivation, against 100000 and 363ms before it. So the count now
// tracks the hardware, and luksPBKDFIterTime is consulted rather than ignored.
// The cost is real and is paid on every Provision — roughly two seconds per
// container that used to be a third of one — and it is the cost of the work
// actually being done.
//
// The floor was never the concern for the material this provider stretches:
// KeyProvider returns machine-generated high-entropy key material, not a human
// passphrase, so there is no low-entropy secret for the iteration count to be
// defending, and 100000 already cleared the 1000 NIST SP 800-132 asks for. What
// changed is that a parameter this code states is now the parameter that takes
// effect.
//
// The passphrase never leaves the process. It was written to a cryptsetup
// child's standard input before 2026-08-29 — never as an argument, which any
// process on the host could have read out of /proc/<pid>/cmdline — and now it
// is borrowed out of locked memory for one function call and no file descriptor
// at all.
func (p *Provider) luksFormat(ctx context.Context, volID, device string) error {
	err := p.withKey(ctx, volID, func(key []byte) error {
		return p.luks.Format(ctx, device, key)
	})
	if err != nil {
		return fmt.Errorf("go-blockstore/local: formatting LUKS container on %s: %w", device, err)
	}
	return nil
}

// luksOpen unlocks the container and exposes its plaintext mapping.
func (p *Provider) luksOpen(ctx context.Context, volID, device string) error {
	err := p.withKey(ctx, volID, func(key []byte) error {
		return p.luks.Open(ctx, device, p.mappingName(volID), key)
	})
	if err != nil {
		return fmt.Errorf("go-blockstore/local: unlocking %s: %w", device, err)
	}
	return nil
}

// luksClose tears down the plaintext mapping.
func (p *Provider) luksClose(ctx context.Context, volID string) error {
	if err := p.luks.Close(ctx, p.mappingName(volID)); err != nil {
		return fmt.Errorf("go-blockstore/local: locking %s: %w", p.mappingName(volID), err)
	}
	return nil
}

// luksTestPassphrase checks that the key this provider holds for volID opens
// the container on device, WITHOUT unlocking it.
//
// The check derives the keyslot's key and verifies it against the header's
// digest, and creates no device-mapper mapping at all. So a restore can
// establish that the volume it is about to produce will be openable before it
// creates anything, rather than after it has copied the image.
func (p *Provider) luksTestPassphrase(ctx context.Context, volID, device string) error {
	return p.withKey(ctx, volID, func(key []byte) error {
		return p.luks.TestKey(ctx, device, key)
	})
}

// luksDataOffset reports where a container's data starts — the space its header
// occupies, and so the difference between the logical volume's size and the
// usable capacity of the mapping over it.
//
// See luksBackend.DataOffset for why it is read from the header rather than
// assumed to be luksHeaderBytes, and for what an unreadable answer means.
func (p *Provider) luksDataOffset(ctx context.Context, device string) (int64, error) {
	offset, err := p.luks.DataOffset(ctx, device)
	if err != nil {
		return 0, fmt.Errorf("go-blockstore/local: reading the LUKS header on %s: %w", device, err)
	}
	return offset, nil
}

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
// So the backing device is checked, and the comparison is by major:minor rather
// than by path, because the same device answers to several paths: the kernel
// names the mapping's backing device in sysfs as a dm-canonical
// /dev/mapper/<vg>-<lv>, whatever path the mapping was opened against. A
// mapping under our name over some other device is an error, not something to
// adopt: it is a conflict a human has to resolve, and continuing would act on
// the wrong volume.
//
// Only "there is no mapping under that name" is the negative answer. Anything
// else is reported, because guessing "not open" would make Attach try to unlock
// a volume that is already unlocked, or Detach skip a mapping it should have
// closed.
func (p *Provider) luksIsOpen(ctx context.Context, volID string) (bool, error) {
	name := p.mappingName(volID)

	info, exists, err := p.luks.Mapping(ctx, name)
	if err != nil {
		return false, fmt.Errorf("go-blockstore/local: checking %s: %w", name, err)
	}
	if !exists {
		return false, nil
	}

	want, err := p.luks.Identity(ctx, p.lvPath(volID))
	if err != nil {
		return false, fmt.Errorf("go-blockstore/local: identifying %s: %w", p.lvPath(volID), err)
	}
	if info.BackingID != want {
		return false, fmt.Errorf("go-blockstore/local: the device-mapper name %q is in use by a mapping over %s, "+
			"not over this volume's %s; close it or rename it before operating on this volume",
			name, info.Backing, p.lvPath(volID))
	}
	return true, nil
}
