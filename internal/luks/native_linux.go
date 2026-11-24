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

// sectorSize is the pinned encryption sector size.
const sectorSize = 512

// pbkdfIterTime is the wall-clock target go-luks2 calibrates PBKDF2 against.
const pbkdfIterTime = 2 * time.Second

// hashFunc is hashAlgo as go-luks2 v1 spells it, for both FormatParams.Hash and KDFParams.Hash.
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

		// LUKS2 renders the offset as a decimal string.
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

// blockDeviceNumber returns the device number a path leads to, following symlinks.
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

// formatDeviceID renders a device number as hex major:minor.
func formatDeviceID(rdev uint64) string {
	return fmt.Sprintf("%x:%x", unix.Major(rdev), unix.Minor(rdev))
}

// sysfsRoot is a parameter so tests can supply the fail-closed shapes.
const sysfsRoot = "/sys"

// sysfsSectorBytes is the unit of the sysfs size file, always 512.
const sysfsSectorBytes = 512

// deviceSize returns a block device's current capacity from sysfs; every unreadable shape is an error.
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

// backingDevice returns the single device a device-mapper device is stacked on, as /dev/mapper/<name> where possible, else /dev/<kname>.
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
	if dmName, err := os.ReadFile(filepath.Join(root, "class", "block", kname, "dm", "name")); err == nil {
		if trimmed := strings.TrimSpace(string(dmName)); trimmed != "" {
			return "/dev/mapper/" + trimmed, nil
		}
	}
	return "/dev/" + kname, nil
}
