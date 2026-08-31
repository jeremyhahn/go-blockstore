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

package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"golang.org/x/sys/unix"
)

// nativeLUKS is the luksBackend this provider runs on a real host: every
// operation is performed in this process by go-luks2 rather than by forking
// cryptsetup.
//
// It is Linux-only, and the build tag is not a formality. go-luks2 reaches the
// kernel through device-mapper ioctls (github.com/anatol/devmapper.go), which
// exist nowhere else, and it carries no build constraints of its own — importing
// it from a file with no tag would stop package local compiling for darwin and
// windows, which it does today. See luksbackend_other.go for what the other
// platforms get.
//
// It holds no state. Everything it needs is on the device or in the kernel, in
// keeping with the rest of the provider.
type nativeLUKS struct{}

// Ensure the backend satisfies the seam at compile time.
var _ luksBackend = nativeLUKS{}

// luksSectorSize is the encryption sector size every container this provider
// creates uses.
//
// It is pinned for the same reason the cipher and the KDF are: it is one of the
// inputs to the on-disk layout, and a library default that moved would move the
// layout with it. 512 is also what the data-offset measurement recorded in
// luksHeaderBytes was taken at.
const luksSectorSize = 512

// luksPBKDFIterTime is the wall-clock target, in milliseconds, that go-luks2
// benchmarks PBKDF2 against when it picks an iteration count.
//
// It is stated rather than defaulted, like every other format parameter, and it
// happens to be go-luks2's own default. What it actually BUYS is smaller than
// it looks and the difference is recorded here rather than discovered later:
// measured against go-luks2 v0.1.7-alpha on 2026-08-29, the benchmark times
// 1000 iterations of PBKDF2-HMAC-SHA-512 with time.Since(...).Milliseconds(),
// that derivation takes well under a millisecond on this hardware, and the
// elapsed time therefore rounds to ZERO — so the benchmark falls through to a
// hard-coded 100000 and this figure is not consulted at all. Every container
// formatted here comes out with exactly 100000 iterations, whatever is set
// here. See luksFormat for why that is acceptable for the material this
// provider stretches, and it is filed against go-luks2 rather than worked
// around here.
const luksPBKDFIterTime = 2000

// Format writes a LUKS2 header onto the device with every cryptographic
// parameter pinned. See luksFormat for what each one is and why.
func (nativeLUKS) Format(ctx context.Context, device string, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return luks2.Format(luks2.FormatOptions{
		Device:        device,
		Passphrase:    key,
		Cipher:        luksCipher,
		CipherMode:    luksCipherMode,
		KeySize:       luksKeySizeBits,
		HashAlgo:      luksHash,
		SectorSize:    luksSectorSize,
		KDFType:       luksPBKDF,
		PBKDFIterTime: luksPBKDFIterTime,
	})
}

// Open unlocks the container and creates its plaintext mapping.
//
// The mapping's length is not passed in and is not this provider's to choose:
// the data segment a Format here writes is "dynamic", so go-luks2 sizes the
// mapping from the backing device at the moment it opens it. That is what makes
// growing a container a matter of growing the logical volume and re-opening —
// see Resize.
func (nativeLUKS) Open(ctx context.Context, device, name string, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return luks2.Unlock(device, key, name)
}

// Close removes the plaintext mapping.
func (nativeLUKS) Close(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return luks2.Lock(name)
}

// TestKey checks a passphrase against the container's keyslots without
// unlocking it: go-luks2 derives the key and verifies it against the header's
// digest, and no device-mapper mapping is created. So a restore can establish
// that the volume it is about to produce will be openable before it creates
// anything, rather than after it has copied the image.
func (nativeLUKS) TestKey(ctx context.Context, device string, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return luks2.TestKey(device, key)
}

// DataOffset reports where a container's data starts — the space its header
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
// No passphrase is involved: the segment table is unencrypted metadata, and
// go-luks2 reads it with an ordinary open(2). The device does have to exist —
// an inactive logical volume has no device node at all.
//
// A container with anything other than exactly one data segment is refused
// rather than guessed at. More than one means a reencryption is in progress,
// and picking a segment out of that state would produce a capacity that is true
// of neither the old layout nor the new one.
func (nativeLUKS) DataOffset(ctx context.Context, device string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	_, metadata, err := luks2.ReadHeader(device)
	if err != nil {
		return 0, err
	}
	if len(metadata.Segments) != 1 {
		return 0, fmt.Errorf("the LUKS header reports %d data segments, not one; "+
			"a container mid-reencryption has no single usable capacity", len(metadata.Segments))
	}

	for _, segment := range metadata.Segments {
		// LUKS2 renders the offset as a decimal STRING, not a JSON number, and
		// go-luks2 carries it across unparsed.
		offset, parseErr := strconv.ParseInt(strings.TrimSpace(segment.Offset), 10, 64)
		if parseErr != nil {
			return 0, fmt.Errorf("the LUKS header reports data offset %q: not a number", segment.Offset)
		}
		if offset <= 0 {
			return 0, fmt.Errorf("the LUKS header reports data offset %d, which leaves no room for a header", offset)
		}
		return offset, nil
	}
	// Unreachable: the length was checked above.
	return 0, errors.New("the LUKS header reports no data segment")
}

// Mapping reports whether a plaintext mapping exists under name, and what it is
// stacked on.
//
// The backing device comes from sysfs rather than from device-mapper, because
// the dm ioctls go-luks2 uses expose the table only to whoever loaded it: there
// is no "what is this mapping over" call to make. The kernel publishes the
// stack in /sys/dev/block/<major>:<minor>/slaves, one symlink per device
// underneath, and reading it needs no privilege and no passphrase.
func (n nativeLUKS) Mapping(ctx context.Context, name string) (mappingInfo, bool, error) {
	if err := ctx.Err(); err != nil {
		return mappingInfo{}, false, err
	}
	if !luks2.IsUnlocked(name) {
		return mappingInfo{}, false, nil
	}

	path, err := luks2.GetMappedDevicePath(name)
	if err != nil {
		return mappingInfo{}, false, err
	}
	rdev, err := blockDeviceNumber(path)
	if err != nil {
		return mappingInfo{}, false, err
	}

	backing, err := backingDevice(sysfsRoot, rdev)
	if err != nil {
		return mappingInfo{}, false, err
	}
	backingRdev, err := blockDeviceNumber(backing)
	if err != nil {
		return mappingInfo{}, false, err
	}

	return mappingInfo{Backing: backing, BackingID: formatDeviceID(backingRdev)}, true, nil
}

// Identity returns a device's major:minor.
func (nativeLUKS) Identity(ctx context.Context, path string) (string, error) {
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

// backingDevice returns the single device a device-mapper device is stacked on,
// as the most legible path that leads to it.
//
// Exactly one is required. A dm-crypt target has one backing device, so none or
// several is not the mapping this provider is looking for, and the whole point
// of the lookup is to refuse what cannot be established — see errNoBackingDevice.
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
		return "", fmt.Errorf("%w: %s lists %d", errNoBackingDevice, dir, len(names))
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
