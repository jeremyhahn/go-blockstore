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
	"context"
	"crypto"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"golang.org/x/sys/unix"
)

// Native is the Backend the providers run on a real host: every
// operation is performed in this process by go-luks2 rather than by forking
// cryptsetup.
//
// It is Linux-only, and the build tag is not a formality. go-luks2 reaches the
// kernel through device-mapper ioctls (github.com/anatol/devmapper.go), which
// exist nowhere else, and it carries no build constraints of its own — importing
// it from a file with no tag would stop the packages importing it compiling for darwin and
// windows, which it does today. See native_other.go for what the other
// platforms get.
//
// It holds no state. Everything it needs is on the device or in the kernel, in
// keeping with the rest of the provider.
type Native struct{}

// Ensure the backend satisfies the seam at compile time.
var _ Backend = Native{}

// sectorSize is the encryption sector size every container this package
// creates uses.
//
// It is pinned for the same reason the cipher and the KDF are: it is one of the
// inputs to the on-disk layout, and a library default that moved would move the
// layout with it. 512 is also what the data-offset measurement recorded in
// HeaderBytes was taken at.
const sectorSize = 512

// pbkdfIterTime is the wall-clock target go-luks2 calibrates PBKDF2 against when
// it picks an iteration count.
//
// It is stated rather than defaulted, like every other format parameter, and it
// happens to be go-luks2's own default. It BUYS nothing until go-luks2
// v0.2.0-alpha, and that is recorded here rather than discovered later: measured
// against v0.1.7-alpha on 2026-08-29, the benchmark timed 1000 iterations of
// PBKDF2-HMAC-SHA-512 with time.Since(...).Milliseconds(), that derivation takes
// well under a millisecond on this hardware, and the elapsed time therefore
// rounded to ZERO — so it fell through to a hard-coded 100000 and this figure
// was not consulted at all.
//
// go-luks2 #102 fixed the calibration. Measured on 2026-09-03 across the bump,
// with the parameters Format pins below: v0.1.10-alpha wrote 100000 iterations
// in 363ms, v0.2.0-alpha writes 3,988,449 in 2.42s — so this constant is now
// the target it always claimed to be, and the derivation lands where the 2000ms
// asks. See Manager.Format for why the old count was nonetheless acceptable for the
// high-entropy material it stretches.
const pbkdfIterTime = 2 * time.Second

// hashFunc is hashAlgo as go-luks2 v1 spells it. It is both the digest and
// anti-forensic hash (FormatParams.Hash) and the keyslot's PBKDF2 pseudo-random
// function (KDFParams.Hash): v1 takes the two separately, and this package
// states both so that one hash runs across the header.
const hashFunc = crypto.SHA512

// Format writes a LUKS2 header onto the device with every cryptographic
// parameter pinned. See Manager.Format for what each one is and why.
func (Native) Format(ctx context.Context, device string, key *enclave.MemoryEnclave) error {
	return withVolume(ctx, device, func(v *luks2.Volume) error {
		return v.Format(ctx, key, luks2.FormatParams{
			Cipher:     cipher + "-" + cipherMode,
			KeySize:    keySizeBits,
			Hash:       hashFunc,
			SectorSize: sectorSize,
			KDF: luks2.KDFParams{
				Type:     luks2.KDFType(pbkdf),
				Hash:     hashFunc,
				IterTime: pbkdfIterTime,
			},
		})
	})
}

// withVolume pins the device for one operation and releases the pin when it
// returns. A failure to release is reported alongside the operation's own error
// rather than instead of it.
func withVolume(ctx context.Context, device string, op func(v *luks2.Volume) error, opts ...luks2.Option) error {
	v, err := luks2.Open(ctx, device, opts...)
	if err != nil {
		return err
	}
	opErr := op(v)
	if closeErr := v.Close(); closeErr != nil {
		return errors.Join(opErr, closeErr)
	}
	return opErr
}

// Open unlocks the container and creates its plaintext mapping.
//
// The mapping's length is not passed in and is not this package's to choose:
// the data segment a Format here writes is "dynamic", so go-luks2 sizes the
// mapping from the backing device at the moment it opens it. That is what makes
// growing a container a matter of growing the logical volume and re-opening —
// see each provider's resize path.
func (Native) Open(ctx context.Context, device, name string, key *enclave.MemoryEnclave) error {
	return withVolume(ctx, device, func(v *luks2.Volume) error {
		volumeKey, err := v.Unlock(ctx, key)
		if err != nil {
			return err
		}
		defer volumeKey.Destroy()

		_, err = dmcrypt.Activate(ctx, v, volumeKey, name)
		return err
	})
}

// Close removes the plaintext mapping.
func (Native) Close(ctx context.Context, name string) error {
	return dmcrypt.Deactivate(ctx, name)
}

// TestKey checks a passphrase against the container's keyslots without
// unlocking it: go-luks2 derives the key and verifies it against the header's
// digest, and no device-mapper mapping is created. So a restore can establish
// that the volume it is about to produce will be openable before it creates
// anything, rather than after it has copied the image.
func (Native) TestKey(ctx context.Context, device string, key *enclave.MemoryEnclave) error {
	return withVolume(ctx, device, func(v *luks2.Volume) error {
		volumeKey, err := v.Unlock(ctx, key)
		if err != nil {
			return err
		}
		volumeKey.Destroy()
		return nil
	}, luks2.WithReadOnly())
}

// DataOffset reports where a container's data starts — the space its header
// occupies, and so the difference between the logical volume's size and the
// usable capacity of the mapping over it.
//
// It is read from the header rather than assumed to be HeaderBytes because
// not every container handled here was formatted here. A
// volume restored from an encrypted snapshot carries its SOURCE's header
// verbatim, and that source may have been made by an older version of this
// package or by an operator's own cryptsetup with different parameters.
// Assuming the constant there would misreport such a volume's capacity by
// however much the two headers differ.
//
// No passphrase is involved: the segment table is unencrypted metadata, and
// go-luks2 reads it with an ordinary open(2). The device does have to exist —
// an inactive logical volume has no device node at all.
//
// A container with anything other than exactly one data segment is refused
// rather than guessed at. More than one means a reencryption is in progress,
// and picking a segment out of that state would produce a capacity that is true
// of neither the old layout nor the new one.
func (Native) DataOffset(ctx context.Context, device string) (int64, error) {
	var offset int64
	err := withVolume(ctx, device, func(v *luks2.Volume) error {
		header, err := v.Header(ctx)
		if err != nil {
			return err
		}
		segments := header.Segments()
		if len(segments) != 1 {
			return fmt.Errorf("the LUKS header reports %d data segments, not one; "+
				"a container mid-reencryption has no single usable capacity", len(segments))
		}

		// go-luks2 parses the offset, which LUKS2 renders as a decimal STRING.
		offset = segments[0].Offset
		if offset <= 0 {
			return fmt.Errorf("the LUKS header reports data offset %d, which leaves no room for a header", offset)
		}
		return nil
	}, luks2.WithReadOnly())
	if err != nil {
		return 0, err
	}
	return offset, nil
}

// Mapping reports whether a plaintext mapping exists under name, what it is
// stacked on, and how large each of the two is.
//
// The backing device comes from sysfs rather than from device-mapper, because
// the dm ioctls go-luks2 uses expose the table only to whoever loaded it: there
// is no "what is this mapping over" call to make. The kernel publishes the
// stack in /sys/dev/block/<major>:<minor>/slaves, one symlink per device
// underneath, and reading it needs no privilege and no passphrase.
//
// The sizes come from the same tree, for the same reason and one more: the
// BLKGETSIZE64 ioctl needs the device opened, and DRBD refuses every open of a
// Secondary's device, so a measurement that opened would fail on exactly the
// node where the question "has this device outgrown its mapping" is asked
// after a resize. sysfs answers for any block device the kernel has, opened or
// not, and it answers with the kernel's own current capacity — the number
// set_capacity() published, which is the number a fresh Unlock would size the
// mapping from.
func (n Native) Mapping(ctx context.Context, name string) (MappingInfo, bool, error) {
	mapping, err := dmcrypt.Lookup(ctx, name)
	if errors.Is(err, dmcrypt.ErrNotActive) {
		return MappingInfo{}, false, nil
	}
	if err != nil {
		return MappingInfo{}, false, err
	}
	// The kernel's own answer for which device this is, rather than whatever
	// /dev/mapper/<name> currently points at.
	rdev := unix.Mkdev(mapping.Major, mapping.Minor)

	backing, err := backingDevice(sysfsRoot, rdev)
	if err != nil {
		return MappingInfo{}, false, err
	}
	backingRdev, err := blockDeviceNumber(backing)
	if err != nil {
		return MappingInfo{}, false, err
	}

	size, err := deviceSize(sysfsRoot, rdev)
	if err != nil {
		return MappingInfo{}, false, fmt.Errorf("measuring the mapping %s: %w", name, err)
	}
	backingSize, err := deviceSize(sysfsRoot, backingRdev)
	if err != nil {
		return MappingInfo{}, false, fmt.Errorf("measuring %s under the mapping %s: %w", backing, name, err)
	}

	return MappingInfo{
		Backing:          backing,
		BackingID:        formatDeviceID(backingRdev),
		SizeBytes:        size,
		BackingSizeBytes: backingSize,
	}, true, nil
}

// Identity returns a device's major:minor.
func (Native) Identity(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	rdev, err := blockDeviceNumber(path)
	if err != nil {
		return "", err
	}
	return formatDeviceID(rdev), nil
}

// blockDeviceNumber returns the device number a path leads to.
//
// os.Stat follows symlinks, which is the point: a device-mapper device is
// reachable as /dev/<vg>/<lv>, /dev/mapper/<vg>-<lv> and /dev/dm-N, the first
// two being symlinks to the third, so comparing the strings tools print says
// nothing about whether two paths are the same device. Lstat would describe the
// link and report no device number at all.
func blockDeviceNumber(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("identifying %s: %w", path, err)
	}
	if info.Mode()&os.ModeDevice == 0 {
		return 0, fmt.Errorf("%s has no device number; it is not a block device", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("identifying %s: the filesystem reported no device number", path)
	}
	return stat.Rdev, nil
}

// formatDeviceID renders a device number the way the rest of the provider
// compares them: major and minor in hex, which is the spelling `stat -c %t:%T`
// produced when this check ran through a command and the spelling every
// recorded fixture uses.
func formatDeviceID(rdev uint64) string {
	return fmt.Sprintf("%x:%x", unix.Major(rdev), unix.Minor(rdev))
}

// sysfsRoot is where the kernel publishes what a device is stacked on. It is a
// parameter of backingDevice rather than a literal inside it so the fail-closed
// cases can be tested against a directory a test owns — there is no way to make
// a real /sys list two slaves for one dm-crypt target on demand, and those are
// exactly the shapes that must not be read as success.
const sysfsRoot = "/sys"

// sysfsSectorBytes is the unit of /sys/dev/block/<major>:<minor>/size. It is
// the block layer's 512-byte sector whatever the device's own logical sector
// size — a 4Kn disk still reports its capacity in these — so the scaling is a
// constant and not a second lookup.
const sysfsSectorBytes = 512

// deviceSize returns a block device's current capacity in bytes, read from
// sysfs.
//
// Every unreadable shape is a refusal rather than a zero. This number decides
// whether a plaintext mapping still covers the device it decrypts, and the two
// wrong defaults are both silent: a 0 read as a size makes every mapping look
// stale, and an error read as "unknown, assume fine" makes none of them. A
// missing file is a device the kernel does not have — the same fail-closed
// answer backingDevice gives for a missing slaves directory.
func deviceSize(root string, rdev uint64) (int64, error) {
	path := filepath.Join(root, "dev", "block", fmt.Sprintf("%d:%d", unix.Major(rdev), unix.Minor(rdev)), "size")
	// #nosec G304 -- the path is built from a device number and a sysfs root
	// this package owns; nothing a caller supplies reaches it.
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", path, err)
	}
	sectors, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s reports %q: not a sector count", path, strings.TrimSpace(string(raw)))
	}
	if sectors <= 0 || sectors > math.MaxInt64/sysfsSectorBytes {
		return 0, fmt.Errorf("%s reports %d sectors, which is not a size this package can act on", path, sectors)
	}
	return sectors * sysfsSectorBytes, nil
}

// backingDevice returns the single device a device-mapper device is stacked on,
// as the most legible path that leads to it.
//
// Exactly one is required. A dm-crypt target has one backing device, so none or
// several is not the mapping being looked for, and the whole point
// of the lookup is to refuse what cannot be established — see ErrNoBackingDevice.
//
// The path is dm-canonical where it can be: a slave that is itself
// device-mapper publishes its name under <root>/class/block/<kname>/dm/name, and
// /dev/mapper/<that> is the spelling an operator recognizes and the one
// cryptsetup used to print. Anything else is reported as /dev/<kname>, which is
// what the kernel calls it.
func backingDevice(root string, rdev uint64) (string, error) {
	dir := filepath.Join(root, "dev", "block", fmt.Sprintf("%d:%d", unix.Major(rdev), unix.Minor(rdev)), "slaves")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 1 {
		return "", fmt.Errorf("%w: %s lists %d", ErrNoBackingDevice, dir, len(names))
	}

	kname := names[0]

	// #nosec G304 -- kname is a directory entry, not a caller-supplied path.
	//
	// G304 fires because the path is built from a variable. That variable is an
	// entry of a directory the KERNEL owns and populates: os.ReadDir returns one
	// path element per entry, never "." or "..", and never a name containing a
	// separator, so filepath.Join here cannot leave root however sysfs is
	// spelled. Nothing a caller of this package supplies reaches it — the volume
	// ID is not in the path, and neither is anything derived from one. The read
	// is also advisory: a failure just means the backing device is reported by
	// its kernel name instead of its device-mapper one.
	if dmName, err := os.ReadFile(filepath.Join(root, "class", "block", kname, "dm", "name")); err == nil {
		if trimmed := strings.TrimSpace(string(dmName)); trimmed != "" {
			return "/dev/mapper/" + trimmed, nil
		}
	}
	return "/dev/" + kname, nil
}
