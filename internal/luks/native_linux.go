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

// Native is the Backend on a real host: go-luks2 in process, Linux-only because it uses device-mapper ioctls; it holds no state.
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

// Open unlocks the container; go-luks2 sizes the dynamic segment's mapping from the backing device at open.
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

// TestKey checks a passphrase against the keyslots without creating a mapping.
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

// DataOffset reads where the data starts from the header, without a passphrase; anything but exactly one data segment is refused.
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

// Mapping reports whether a mapping exists under name, its backing device and both sizes, all from sysfs without opening either device.
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
