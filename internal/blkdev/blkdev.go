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

// Package blkdev copies, flushes and zeroes block devices directly, without dd or blkdiscard.
package blkdev

import (
	"context"
	"io"
	"os"
)

// CopyBufferSize is the transfer size, matching the bs=4M the dd invocations
// used. Large enough that the per-call overhead disappears against the I/O, and
// small enough to stay off the large-object heap path.
const CopyBufferSize = 4 << 20

// Copy writes the whole of src onto dst (never created) and syncs it; it stops early if ctx is canceled.
func Copy(ctx context.Context, src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- caller-supplied device path, validated by the provider
	if err != nil {
		return &CopyError{Source: src, Destination: dst, Op: "opening the source", Err: err}
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY, 0) // #nosec G304 -- caller-supplied device path, validated by the provider
	if err != nil {
		return &CopyError{Source: src, Destination: dst, Op: "opening the destination", Err: err}
	}
	defer func() { _ = out.Close() }()

	if _, err := io.CopyBuffer(out, &contextReader{ctx: ctx, r: in}, make([]byte, CopyBufferSize)); err != nil {
		return &CopyError{Source: src, Destination: dst, Op: "copying", Err: err}
	}

	if err := out.Sync(); err != nil {
		return &CopyError{Source: src, Destination: dst, Op: "flushing the destination", Err: err}
	}
	// Close is deferred as well, but its error is the one that reports a failed
	// writeback, and a deferred close discards it.
	if err := out.Close(); err != nil {
		return &CopyError{Source: src, Destination: dst, Op: "closing the destination", Err: err}
	}

	// The flush and close are uninterruptible writeback, so the context is checked again after them.
	if err := ctx.Err(); err != nil {
		return &CopyError{Source: src, Destination: dst, Op: "copying", Err: err}
	}
	return nil
}

// contextReader stops a copy within one buffer once its context is done.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// ZeroOut zeroes a block device from offset to the end with BLKZEROOUT, which guarantees zeroes where a discard does not.
func ZeroOut(ctx context.Context, device string, offset int64) error {
	if offset < 0 {
		return &ZeroOutError{Device: device, Offset: offset, Err: ErrNegativeOffset}
	}
	if err := ctx.Err(); err != nil {
		return &ZeroOutError{Device: device, Offset: offset, Err: err}
	}

	f, err := os.OpenFile(device, os.O_WRONLY, 0) // #nosec G304 -- caller-supplied device path, validated by the provider
	if err != nil {
		return &ZeroOutError{Device: device, Offset: offset, Err: err}
	}
	defer func() { _ = f.Close() }()

	size, err := deviceSize(f)
	if err != nil {
		return &ZeroOutError{Device: device, Offset: offset, Err: err}
	}

	length, zero, err := rangeToZero(offset, size)
	if err != nil {
		return &ZeroOutError{Device: device, Offset: offset, Size: size, Err: err}
	}
	if !zero {
		return nil
	}

	if err := zeroRange(f, uint64(offset), length); err != nil {
		return &ZeroOutError{Device: device, Offset: offset, Size: size, Err: err}
	}

	// The ioctl is uninterruptible; report a caller that gave up meanwhile, even though the range is zeroed.
	if err := ctx.Err(); err != nil {
		return &ZeroOutError{Device: device, Offset: offset, Size: size, Err: err}
	}
	return nil
}

// rangeToZero decides the zeroing range for a device size, so the decisions are unit-testable.
func rangeToZero(offset, size int64) (length uint64, zero bool, err error) {
	// Checked by ZeroOut before the device is opened; repeated here so this
	// function's own contract makes the conversion below provably in range.
	if offset < 0 {
		return 0, false, ErrNegativeOffset
	}
	if offset > size {
		return 0, false, ErrOffsetPastEnd
	}
	if offset == size {
		// Nothing beyond the offset. Asking the kernel to zero an empty range
		// is not obviously harmless on every device, and there is nothing to do.
		return 0, false, nil
	}
	return uint64(size - offset), true, nil // #nosec G115 -- 0 <= offset < size, checked above
}

// Size reports a block device's size in bytes.
func Size(device string) (int64, error) {
	f, err := os.Open(device) // #nosec G304 -- caller-supplied device path, validated by the provider
	if err != nil {
		return 0, &SizeError{Device: device, Err: err}
	}
	defer func() { _ = f.Close() }()

	size, err := deviceSize(f)
	if err != nil {
		return 0, &SizeError{Device: device, Err: err}
	}
	return size, nil
}

// Operator is the seam through which a provider reaches these operations, so tests need no real device.
type Operator interface {
	// Copy writes the whole of src onto dst and flushes it.
	Copy(ctx context.Context, src, dst string) error

	// ZeroOut writes zeroes over the device from offset to its end.
	ZeroOut(ctx context.Context, device string, offset int64) error
}

// System is the Operator backed by real devices.
type System struct{}

// Copy writes the whole of src onto dst and flushes it.
func (System) Copy(ctx context.Context, src, dst string) error { return Copy(ctx, src, dst) }

// ZeroOut writes zeroes over the device from offset to its end.
func (System) ZeroOut(ctx context.Context, device string, offset int64) error {
	return ZeroOut(ctx, device, offset)
}
