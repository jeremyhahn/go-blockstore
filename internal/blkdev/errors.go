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

package blkdev

import "errors"

var (
	// ErrNegativeOffset reports an offset below zero.
	ErrNegativeOffset = errors.New("blkdev: offset is negative")

	// ErrOffsetPastEnd reports an offset beyond the device.
	ErrOffsetPastEnd = errors.New("blkdev: offset is past the end of the device")

	// ErrNotBlockDevice reports an ioctl attempted on something that is not a
	// block device. The kernel says ENOTTY, which on its own reads as a
	// terminal problem and sends a reader somewhere unhelpful.
	ErrNotBlockDevice = errors.New("blkdev: not a block device")

	// ErrSizeOutOfRange reports a device size the kernel gave as a 64-bit
	// unsigned value that does not fit the signed one every caller uses. No
	// device is that large; a driver reporting it is reporting something other
	// than a size, and an offset computed against it would be meaningless.
	ErrSizeOutOfRange = errors.New("blkdev: the device reports a size larger than can be represented")

	// ErrZeroOutUnsupported reports a device whose driver does not implement
	// BLKZEROOUT. It is distinct from a failure: the request was well formed
	// and this device cannot serve it, so the caller needs another way to
	// destroy the data rather than a retry.
	ErrZeroOutUnsupported = errors.New("blkdev: the device does not support zeroing a range")
)

// CopyError reports a failed device copy, naming both ends and the step that
// failed — which is what an exit status from dd could not.
type CopyError struct {
	// Source and Destination are the devices.
	Source      string
	Destination string

	// Op is the step that failed, in the words of what it was doing.
	Op string

	// Err is the underlying failure.
	Err error
}

func (e *CopyError) Error() string {
	return "blkdev: " + e.Op + " while copying " + e.Source + " to " + e.Destination + ": " + e.Err.Error()
}

func (e *CopyError) Unwrap() error { return e.Err }

// ZeroOutError reports a failed zeroing, with the range it was asked for.
//
// The size travels with it because the most likely mistakes are about the
// range: an offset past the end, or a device smaller than the caller believed.
// An errno alone cannot distinguish those.
type ZeroOutError struct {
	// Device is the block device.
	Device string

	// Offset is where the zeroing was to start.
	Offset int64

	// Size is the device's size, when it was determined. Zero when the failure
	// came before that.
	Size int64

	// Err is the underlying failure or one of the sentinels above.
	Err error
}

func (e *ZeroOutError) Error() string {
	msg := "blkdev: zeroing " + e.Device + " from offset " + itoa(e.Offset)
	if e.Size > 0 {
		msg += " of " + itoa(e.Size) + " bytes"
	}
	return msg + ": " + e.Err.Error()
}

func (e *ZeroOutError) Unwrap() error { return e.Err }

// SizeError reports that a device's size could not be read.
type SizeError struct {
	// Device is the block device.
	Device string

	// Err is the underlying failure.
	Err error
}

func (e *SizeError) Error() string {
	return "blkdev: reading the size of " + e.Device + ": " + e.Err.Error()
}

func (e *SizeError) Unwrap() error { return e.Err }

// itoa formats without fmt, so these errors carry no formatting dependency.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var digits [24]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		digits[i] = '-'
	}
	return string(digits[i:])
}
