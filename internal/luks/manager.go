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

// Package luks holds the LUKS2 machinery the storage providers share.
//
// It exists because there are now two providers that put a dm-crypt layer over
// a block device — pkg/local over a logical volume, pkg/drbd over a replicated
// device — and the parts that are the same for both are all the parts that are
// easy to get subtly wrong: the pinned cryptographic parameters, the borrow
// window a passphrase is allowed to exist in, and the ownership check that
// refuses a mapping under this software's deterministic name which turns out to
// be over somebody else's device. Two copies of those would be two chances to
// diverge, and the divergence would be silent.
//
// What is NOT here is anything about how a provider finds its backing device or
// what it does with the plaintext one. The mapping name's scope, the device
// path, and where in a volume's lifecycle the container is opened and closed are
// each provider's own: pkg/local opens on Attach because that is where its
// device becomes usable, and pkg/drbd opens on Promote because that is where
// DRBD lets the device be opened at all.
package luks

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-enclave"
)

// FSType is what blkid reports for a LUKS container.
const FSType = "crypto_LUKS"

// The LUKS2 parameters every container created through this package is
// formatted with. They are pinned rather than left to the library because
// go-luks2's defaults are not FIPS-approved: FormatOptions with an empty KDFType
// formats with argon2id, and an empty HashAlgo derives with SHA-256.
const (
	// pbkdf is PBKDF2, the only key-derivation function among go-luks2's
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
	pbkdf = "pbkdf2"

	// hashAlgo is SHA-512: FIPS 180-4 approved, and faster per byte than
	// SHA-256 on 64-bit hardware. It also matches the 256-bit security level of
	// the cipher below, and is what go-luks2 then uses for the anti-forensic
	// stripes and the keyslot digest, keeping one hash across the header.
	hashAlgo = "sha512"

	// cipher and cipherMode are AES in XTS mode, the block-device standard and
	// FIPS-approved. They are two constants because go-luks2 takes them
	// separately and joins them for the header, where they appear as the
	// familiar "aes-xts-plain64".
	cipher     = "aes"
	cipherMode = "xts-plain64"

	// keySizeBits is in bits, and XTS splits it into two internal keys — so 512
	// here is AES-256-XTS, not AES-512. go-luks2's default is also 512, and
	// stating it is what makes the strength a property of this package rather
	// than a consequence of a default that has moved before: cryptsetup, which
	// wrote every container this software created before 2026-08-29, defaults to
	// 256, which XTS halves to AES-128.
	keySizeBits = 512
)

// HeaderBytes is the space a LUKS2 container formatted here reserves in front
// of the caller's data: 16 MiB, of which two 16 KiB metadata copies and a
// 16744448-byte keyslots area account for every byte.
//
// It is a constant rather than something read back per volume because every
// parameter that determines it is PINNED above, so the figure is a property of
// this package and of go-luks2's layout, not of whatever a host happens to ship.
// It is measured rather than taken from folklore, and it has now been measured
// against two independent formatters that agree to the byte:
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
// fails to open. Sizing always adds this figure to a capacity that is already
// positive, so no backing device this software creates lands in that range
// either way.
//
// It sizes containers this package CREATES. What an existing container's header
// actually costs is read from that header — see Manager.DataOffset — because a
// volume restored from a snapshot carries whatever header its source had.
const HeaderBytes = 16 << 20

// The device-mapper name prefixes the providers namespace their mappings with,
// so an unlocked volume is recognizable on a host that also runs other LUKS
// consumers.
//
// THEY MUST NOT BE PREFIXES OF ONE ANOTHER, and "bs-" and "bsr-" are not:
// they differ at index 2, so no scope/volume pair can spell a name belonging to
// the other provider by rearranging where a hyphen falls. Two providers over
// one host is not hypothetical — a node can run a local provider and a
// replicated one out of the same volume group — and the mapping namespace is
// flat for the whole host.
//
// A collision that got through anyway would still be refused rather than acted
// on: Manager.IsOpen compares the mapping's backing device by major:minor and
// reports a foreign one as an error. These constants are what keeps that
// refusal from being something an ordinary deployment ever sees.
const (
	// MappingPrefix is pkg/local's.
	MappingPrefix = "bs-"

	// ReplicatedMappingPrefix is pkg/drbd's.
	ReplicatedMappingPrefix = "bsr-"
)

// Manager binds a Backend, a KeyProvider and a mapping namespace into the
// per-volume operations a provider performs.
//
// The namespace is everything the mapping name carries in front of the volume
// ID: one of the prefixes above, whatever the provider scopes by — a volume
// group, say — and a separator. Device-mapper names are a single flat namespace
// for the whole host while a volume ID is only unique within its provider, so
// two providers each holding an encrypted volume called "data" would otherwise
// both claim one name and the second open would find the first one's mapping
// already there.
//
// THE NAMESPACE IS THE PROVIDER'S TO BUILD, and the separator is why. It has to
// be a character that provider's own name validation forbids in a scope and in
// a volume ID, or the concatenation is ambiguous: pkg/local rejects underscores
// in both and separates with one, while pkg/drbd ACCEPTS underscores in a
// resource name — DRBD does — and separates with a dot, which its name regexp
// rejects. A separator chosen here could only be right for one of them, and
// being wrong would mean two different volumes spelling one mapping name.
//
// The errScope is the package name errors are attributed to, so a refusal
// reaching an operator says which provider produced it.
type Manager struct {
	backend   Backend
	keys      KeyProvider
	namespace string
	errScope  string
}

// NewManager binds the seams. backend must not be nil; keys may be, for a
// provider that is not configured for encryption — every operation that needs a
// passphrase then refuses with a sentence saying so.
func NewManager(backend Backend, keys KeyProvider, namespace, errScope string) *Manager {
	return &Manager{backend: backend, keys: keys, namespace: namespace, errScope: errScope}
}

// HasKeys reports whether a KeyProvider was configured.
func (m *Manager) HasKeys() bool { return m != nil && m.keys != nil }

// MappingName is the device-mapper name an unlocked volume appears under.
func (m *Manager) MappingName(volID string) string {
	return m.namespace + volID
}

// CryptPath is the device path of an unlocked volume's plaintext mapping.
func (m *Manager) CryptPath(volID string) string {
	return "/dev/mapper/" + m.MappingName(volID)
}

// key fetches the passphrase for a volume as an enclave the caller must
// destroy, failing clearly when the provider was configured for encryption
// without a way to obtain keys.
func (m *Manager) key(ctx context.Context, volID string) (*enclave.MemoryEnclave, error) {
	if m.keys == nil {
		return nil, fmt.Errorf("%s: volume %q is encrypted but no KeyProvider is configured", m.errScope, volID)
	}
	enc, err := m.keys(ctx, volID)
	if err != nil {
		return nil, fmt.Errorf("%s: obtaining key for %q: %w", m.errScope, volID, LockedMemoryError(m.errScope, err))
	}
	if enc == nil || !enc.IsAlive() || enc.Size() == 0 {
		if enc != nil {
			enc.Destroy()
		}
		return nil, fmt.Errorf("%s: KeyProvider returned no usable key for %q", m.errScope, volID)
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
// op MUST NOT retain the slice. Every implementation of Backend is bound by the
// same rule, and the native one keeps to it by handing the bytes straight to
// go-luks2, which derives from them and holds nothing.
func (m *Manager) withKey(ctx context.Context, volID string, op func(key []byte) error) error {
	enc, err := m.key(ctx, volID)
	if err != nil {
		return err
	}
	defer enc.Destroy()

	return enc.WithBytes(op)
}

// Format writes a LUKS2 header onto the device.
//
// Every cryptographic parameter is stated rather than defaulted. A container
// formatted here is the same on every host and in every build, which matters
// because the library's defaults are not FIPS-approved: go-luks2 formats with
// argon2id and derives with SHA-256 when it is not told otherwise. Nothing here
// depends on a cryptsetup binary being installed, being a particular version, or
// being compiled with a particular set of defaults — there is no cryptsetup
// involved at all.
//
// The iteration count is left to go-luks2's benchmark rather than pinned, for
// the reason a pinned count is worse: a fixed number cannot rise on faster
// hardware. That reasoning did not hold until go-luks2 v0.2.0-alpha, and the
// history is kept because it is what makes the current number credible: the
// benchmark timed 1000 PBKDF2-SHA-512 iterations at millisecond resolution, a
// derivation that finishes in well under a millisecond, so the elapsed time
// rounded to zero and every container came out with a hard-coded 100000 —
// against the 3,344,740 cryptsetup 2.7.0 chose on the same hardware. go-luks2
// #102 fixed the calibration and go-blockstore adopted it in #45.
//
// Measured after the adoption, with the pinned parameters: 3,988,449 iterations,
// 2.42s of derivation, against 100000 and 363ms before it. So the count now
// tracks the hardware, and pbkdfIterTime is consulted rather than ignored. The
// cost is real and is paid on every container created — roughly two seconds
// where it used to be a third of one — and it is the cost of the work actually
// being done.
//
// The passphrase never leaves the process. It was written to a cryptsetup
// child's standard input before 2026-08-29 — never as an argument, which any
// process on the host could have read out of /proc/<pid>/cmdline — and now it
// is borrowed out of locked memory for one function call and no file descriptor
// at all.
func (m *Manager) Format(ctx context.Context, volID, device string) error {
	err := m.withKey(ctx, volID, func(key []byte) error {
		return m.backend.Format(ctx, device, key)
	})
	if err != nil {
		return fmt.Errorf("%s: formatting LUKS container on %s: %w", m.errScope, device, err)
	}
	return nil
}

// Open unlocks the container and exposes its plaintext mapping.
func (m *Manager) Open(ctx context.Context, volID, device string) error {
	err := m.withKey(ctx, volID, func(key []byte) error {
		return m.backend.Open(ctx, device, m.MappingName(volID), key)
	})
	if err != nil {
		return fmt.Errorf("%s: unlocking %s: %w", m.errScope, device, err)
	}
	return nil
}

// Close tears down the plaintext mapping.
func (m *Manager) Close(ctx context.Context, volID string) error {
	if err := m.backend.Close(ctx, m.MappingName(volID)); err != nil {
		return fmt.Errorf("%s: locking %s: %w", m.errScope, m.MappingName(volID), err)
	}
	return nil
}

// TestPassphrase checks that the key held for volID opens the container on
// device, WITHOUT unlocking it.
//
// The check derives the keyslot's key and verifies it against the header's
// digest, and creates no device-mapper mapping at all. So a restore can
// establish that the volume it is about to produce will be openable before it
// creates anything, rather than after it has copied the image.
func (m *Manager) TestPassphrase(ctx context.Context, volID, device string) error {
	return m.withKey(ctx, volID, func(key []byte) error {
		return m.backend.TestKey(ctx, device, key)
	})
}

// DataOffset reports where a container's data starts — the space its header
// occupies, and so the difference between the backing device's size and the
// usable capacity of the mapping over it.
//
// See Backend.DataOffset for why it is read from the header rather than assumed
// to be HeaderBytes, and for what an unreadable answer means.
func (m *Manager) DataOffset(ctx context.Context, device string) (int64, error) {
	offset, err := m.backend.DataOffset(ctx, device)
	if err != nil {
		return 0, fmt.Errorf("%s: reading the LUKS header on %s: %w", m.errScope, device, err)
	}
	return offset, nil
}

// IsOpen reports whether the volume's plaintext mapping exists AND is the one
// this provider would have made over backing.
//
// The mapping name is deterministic, which makes it findable and also makes it
// claimable: a stale mapping left by an earlier run, or one an operator opened
// by hand, sits under exactly the name a provider looks for. Treating the name
// as proof would have an unlock return that mapping as this volume's plaintext
// device — handing the caller some other volume's decrypted contents to mount —
// and a teardown close it, and a resize grow it.
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
// else is reported, because guessing "not open" would make an unlock try to
// open a volume that is already open, or a teardown skip a mapping it should
// have closed.
func (m *Manager) IsOpen(ctx context.Context, volID, backing string) (bool, error) {
	_, open, err := m.ownMapping(ctx, volID, backing)
	return open, err
}

// ownMapping is the lookup IsOpen and MeasureMapping share: the mapping under
// the volume's name, if there is one, refused unless it is over backing.
//
// It is one function so the two callers cannot disagree about what "our
// mapping" means. A measurement taken of a mapping the ownership check would
// have refused is a measurement of somebody else's device, and a resize that
// acted on it would grow — or refuse to grow — the wrong volume.
func (m *Manager) ownMapping(ctx context.Context, volID, backing string) (MappingInfo, bool, error) {
	name := m.MappingName(volID)

	info, exists, err := m.backend.Mapping(ctx, name)
	if err != nil {
		return MappingInfo{}, false, fmt.Errorf("%s: checking %s: %w", m.errScope, name, err)
	}
	if !exists {
		return MappingInfo{}, false, nil
	}

	want, err := m.backend.Identity(ctx, backing)
	if err != nil {
		return MappingInfo{}, false, fmt.Errorf("%s: identifying %s: %w", m.errScope, backing, err)
	}
	if info.BackingID != want {
		return MappingInfo{}, false, fmt.Errorf("%s: the device-mapper name %q is in use by a mapping over %s, "+
			"not over this volume's %s; close it or rename it before operating on this volume",
			m.errScope, name, info.Backing, backing)
	}
	return info, true, nil
}

// MappingSize is how an open mapping's length relates to the device it
// decrypts, measured at one instant.
type MappingSize struct {
	// MappingBytes is the plaintext device's length: what the kernel presents,
	// fixed when the mapping was loaded.
	MappingBytes int64

	// DataBytes is the backing device's current size less the container's
	// data offset — the length a mapping opened NOW would be given. It is what
	// MappingBytes was equal to at the moment the mapping was opened, and it
	// moves when the device does.
	DataBytes int64
}

// Stale reports whether the mapping has fallen behind its device: the device
// grew after the mapping was opened, and the plaintext capacity did not follow.
// A filesystem grown "to fit" a stale mapping grows to the OLD size.
func (s MappingSize) Stale() bool { return s.MappingBytes < s.DataBytes }

// MeasureMapping reports how the volume's open mapping relates to the device
// under it.
//
// It exists because this seam has no resize — see Backend — so the one thing a
// provider CAN do about a device that grew under an open mapping is notice.
// go-luks2 sizes a "dynamic" segment's mapping from the backing device at the
// moment it opens it and never again; after the device grows, the plaintext
// device is still the size it was, and a filesystem grown to fill it fills
// the old size while every layer above reports the new one. That is the silent
// wrong answer this measurement exists to turn into a refusal.
//
// The mapping must be open and must be this volume's; the same ownership check
// IsOpen makes is made here, and a name held by a mapping over some other
// device is an error rather than a measurement. Everything else that cannot
// be accounted for is an error too, fail-closed: a data offset the header does
// not state, a backing device no larger than its own header, or a mapping
// LONGER than the device's data area — which is a device that shrank under a
// live mapping, a state nothing here can size correctly and one whose writes
// past the end will fail.
func (m *Manager) MeasureMapping(ctx context.Context, volID, backing string) (MappingSize, error) {
	info, open, err := m.ownMapping(ctx, volID, backing)
	if err != nil {
		return MappingSize{}, err
	}
	if !open {
		return MappingSize{}, fmt.Errorf("%s: %s has no open mapping to measure", m.errScope, backing)
	}

	offset, err := m.DataOffset(ctx, backing)
	if err != nil {
		return MappingSize{}, err
	}
	if info.SizeBytes <= 0 {
		return MappingSize{}, fmt.Errorf("%s: the mapping over %s reports a length of %d bytes, which cannot be right",
			m.errScope, backing, info.SizeBytes)
	}
	if info.BackingSizeBytes <= offset {
		return MappingSize{}, fmt.Errorf("%s: %s is %d bytes, which is no larger than its own %d-byte LUKS header",
			m.errScope, backing, info.BackingSizeBytes, offset)
	}
	size := MappingSize{MappingBytes: info.SizeBytes, DataBytes: info.BackingSizeBytes - offset}
	if size.MappingBytes > size.DataBytes {
		return MappingSize{}, fmt.Errorf("%s: the mapping over %s is %d bytes but the device now holds only %d past its header; "+
			"the device shrank under a live mapping and no size can be established for it",
			m.errScope, backing, size.MappingBytes, size.DataBytes)
	}
	return size, nil
}
