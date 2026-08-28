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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
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

// luksHeaderBytes is the space a LUKS2 container this provider formats reserves
// in front of the caller's data: 16 MiB, of which two 16 KiB metadata copies
// and a 16744448-byte keyslots area account for every byte.
//
// It is a constant rather than something read back per volume because the
// provider PINS every parameter that determines it — see luksFormat — so the
// figure is a property of this package and not of whichever cryptsetup the host
// happens to ship. It is measured rather than taken from folklore. On
// cryptsetup 2.7.0 (measured 2026-08-27 on a loopback volume group),
// formatting with exactly those parameters at 32 MiB, 64 MiB, 128 MiB, 300 MiB
// and 1200 MiB put the data segment at offset 16777216 every time, and the
// plaintext mapping came back exactly that much smaller than the logical volume
// under it. It does not scale with the device.
//
// Where cryptsetup DOES depart from it is a device too small to hold a header
// and any data at all: at 16 MiB and below it shrinks the keyslots area to fit
// the device and the container ends up with zero usable bytes, so cryptsetup
// open fails. Sizing here always adds this figure to a capacity that is already
// positive, so no backing device this provider creates lands in that range.
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

// luksTestPassphrase checks that the key this provider holds for volID opens
// the container on device, WITHOUT unlocking it.
//
// --test-passphrase is what makes that possible: measured on cryptsetup 2.7.0,
// it verifies the passphrase against the keyslots and creates no device-mapper
// mapping at all — exit 0 for a key that opens the container, 2 for one that
// does not, 1 for a device that is not a LUKS container. So a restore can
// establish that the volume it is about to produce will be openable before it
// creates anything, rather than after it has copied the image.
func (p *Provider) luksTestPassphrase(ctx context.Context, volID, device string) error {
	return p.runWithKey(ctx, volID, "cryptsetup", "open",
		"--test-passphrase",
		"--type", "luks2",
		"--key-file", "-",
		device,
	)
}

// luksSegments is the shape of `cryptsetup luksDump --dump-json-metadata`, cut
// down to the one thing this provider reads. LUKS2 renders the offset as a
// decimal STRING, not a JSON number.
type luksSegments struct {
	Segments map[string]struct {
		Offset string `json:"offset"`
	} `json:"segments"`
}

// luksDataOffset reports where a container's data starts — the space its header
// occupies, and so the difference between the logical volume's size and the
// usable capacity of the mapping over it.
//
// It is read from the header rather than assumed to be luksHeaderBytes because
// not every container this provider handles was formatted by this provider. A
// volume restored from an encrypted snapshot carries its SOURCE's header
// verbatim, and that source may have been made by an older version of this
// package or by an operator's own cryptsetup with different parameters.
// Assuming the constant there would misreport such a volume's capacity by
// however much the two headers differ.
//
// No passphrase is involved: measured on cryptsetup 2.7.0, luksDump reads the
// unencrypted metadata and exits 0 without one. The device has to be active —
// an inactive logical volume has no device node at all.
//
// A container with anything other than exactly one data segment is refused
// rather than guessed at. More than one means a reencryption is in progress,
// and picking a segment out of that state would produce a capacity that is true
// of neither the old layout nor the new one.
func (p *Provider) luksDataOffset(ctx context.Context, device string) (int64, error) {
	out, err := p.runner.Run(ctx, nil, "cryptsetup", "luksDump", "--dump-json-metadata", device)
	if err != nil {
		return 0, fmt.Errorf("go-blockstore/local: reading the LUKS header on %s: %w", device, err)
	}

	var meta luksSegments
	if err := json.Unmarshal(out, &meta); err != nil {
		return 0, fmt.Errorf("go-blockstore/local: parsing the LUKS header on %s: %w", device, err)
	}
	if len(meta.Segments) != 1 {
		return 0, fmt.Errorf("go-blockstore/local: the LUKS header on %s reports %d data segments, not one; "+
			"a container mid-reencryption has no single usable capacity", device, len(meta.Segments))
	}

	for _, segment := range meta.Segments {
		offset, parseErr := strconv.ParseInt(strings.TrimSpace(segment.Offset), 10, 64)
		if parseErr != nil {
			return 0, fmt.Errorf("go-blockstore/local: the LUKS header on %s reports data offset %q: not a number",
				device, segment.Offset)
		}
		if offset <= 0 {
			return 0, fmt.Errorf("go-blockstore/local: the LUKS header on %s reports data offset %d, which leaves no room for a header",
				device, offset)
		}
		return offset, nil
	}
	// Unreachable: the length was checked above.
	return 0, fmt.Errorf("go-blockstore/local: the LUKS header on %s reports no data segment", device)
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
