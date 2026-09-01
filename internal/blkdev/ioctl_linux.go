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

// deviceSize reads a block device's size with BLKGETSIZE64.
//
// Seeking to the end would appear to do the same thing and does not: on a block
// device the seek reports the size the kernel has cached for the partition,
// which is stale after an LVM resize until the device is reopened. The ioctl
// asks the driver.
// The buffer is a uint64 and the call is the raw ioctl, which matters on 32-bit
// Linux: BLKGETSIZE64 writes eight bytes whatever the architecture, while a Go
// int is four bytes there — so the obvious unix.IoctlGetInt hands the kernel a
// pointer to a buffer half the size of what it is about to write.
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

// zeroRange runs BLKZEROOUT over [start, start+length).
//
// The argument is a two-element array of unsigned 64-bit values, which is why
// this goes through the raw ioctl rather than one of the typed helpers: there is
// no helper for a struct-shaped argument.
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

// translateIoctlError turns a bare errno into something that says what it means
// here.
//
// This is the whole reason the conversion needs care. A binary printed a
// diagnosed message and exited; a syscall returns ENOTTY or EOPNOTSUPP, which on
// their own send a reader looking for a terminal or a filesystem. The mapping is
// a table rather than a chain of ifs so that adding a case is adding a row.
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
