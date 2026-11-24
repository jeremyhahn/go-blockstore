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

package blkdev

import (
	"errors"
	"math"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// deviceSize reads a block device's size with BLKGETSIZE64 into a uint64, which the kernel writes on every architecture.
func deviceSize(f *os.File) (int64, error) {
	var size uint64

	// The pointer is passed to a syscall that completes before this returns, so
	// the variable cannot move underneath it.
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		uintptr(unix.BLKGETSIZE64),
		uintptr(unsafe.Pointer(&size)), // #nosec G103 -- ioctl argument, valid for the duration of the call
	)
	if errno != 0 {
		return 0, translateIoctlError(errno)
	}
	if size > math.MaxInt64 {
		// No device is this large; a driver that says so is reporting something
		// other than a size, and every offset computed from it would be wrong.
		return 0, ErrSizeOutOfRange
	}
	return int64(size), nil
}

// zeroRange runs BLKZEROOUT over [start, start+length) through the raw ioctl.
func zeroRange(f *os.File, start, length uint64) error {
	rng := [2]uint64{start, length}

	// The pointer is passed to a syscall that completes before this returns, so
	// the array cannot move underneath it.
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		uintptr(unix.BLKZEROOUT),
		uintptr(unsafe.Pointer(&rng)), // #nosec G103 -- ioctl argument, valid for the duration of the call
	)
	if errno != 0 {
		return translateIoctlError(errno)
	}
	return nil
}

// translateIoctlError maps a bare errno to a message that says what it means for a block device.
func translateIoctlError(err error) error {
	for errno, mapped := range ioctlErrors {
		if errors.Is(err, errno) {
			return mapped
		}
	}
	return err
}

// ioctlErrors maps the errnos these ioctls actually return to errors that name
// the condition in this package's terms.
var ioctlErrors = map[error]error{
	// The file is not a block device, so the driver has no such ioctl. The
	// kernel's name for that is "inappropriate ioctl for device".
	unix.ENOTTY: ErrNotBlockDevice,

	// The device is a block device whose driver does not implement zeroing.
	unix.EOPNOTSUPP: ErrZeroOutUnsupported,
}
