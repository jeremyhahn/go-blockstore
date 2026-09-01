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

// Package blkdev performs the block-device operations this repository used to
// reach for dd and blkdiscard to do.
//
// Neither binary was doing anything the process cannot do itself: dd is a read
// loop with a flush, and blkdiscard --zeroout is one ioctl. What they added was
// a fork, a PATH lookup, and an error surface consisting of an exit status.
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

// Copy writes the whole of src onto dst and flushes it to stable storage.
//
// This is what `dd if=src of=dst bs=4M conv=fsync,nocreat` did. nocreat is
// structural here rather than a flag: dst is opened without O_CREATE, so a
// destination that does not exist is an error instead of a new empty file
// appearing where a device was expected. conv=fsync is the Sync at the end —
// without it the copy is complete only as far as the page cache, and a caller
// that goes on to detach the volume can lose the tail.
//
// The copy stops early if ctx is canceled. dd had no such property; a canceled
// context simply left it running to completion.
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

	// The transfer honors the context per buffer, but the flush and close after
	// it do not: on a block device they are the writeback, and they can take
	// substantial time with no way to interrupt them. A caller whose deadline
	// expired in there would otherwise be told the copy succeeded and go on to
	// the next step — for a restore, tagging the volume and reporting it ready
	// — under a context that has been dead since before the copy finished.
	//
	// Same reasoning and same treatment as ZeroOut: what this reports is that
	// the caller gave up, not that nothing was written.
	if err := ctx.Err(); err != nil {
		return &CopyError{Source: src, Destination: dst, Op: "copying", Err: err}
	}
	return nil
}

// contextReader stops a copy when its context is done.
//
// io.Copy takes no context, so cancellation has to enter through the reader. The
// check is per buffer rather than per byte, which for a 4 MiB buffer means a
// canceled copy stops within one transfer.
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

// ZeroOut writes zeroes over a range of a block device, from offset to the end.
//
// This is `blkdiscard --zeroout --offset N`, which despite the command's name
// is the BLKZEROOUT ioctl and not BLKDISCARD. The distinction is the whole
// reason the callers use it: a discard tells the device it may forget a range,
// and what a later read returns is up to the device — for some, the old
// contents. BLKZEROOUT guarantees zeroes. Every caller here is destroying a
// former tenant's data, so a guarantee is the point and the weaker ioctl would
// quietly not provide it.
//
// The range runs to the end of the device, which is what the callers mean and
// what blkdiscard did with no --length.
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

	// The ioctl cannot be interrupted, and on a large device it is the step that
	// takes minutes: a caller that gave up did so while it was running, and the
	// check before it was made long ago. So the context is checked again here.
	//
	// What this reports is that the CALLER gave up, not that the device is
	// untouched — the zeroing above completed, and the volume is zeroed whatever
	// this returns. Reporting it is still the right way round: every caller uses
	// a failed wipe to stop short of the deletion that follows, and stopping
	// leaves a zeroed volume to try again on. Reporting success would hand a
	// dead context to the next step instead.
	if err := ctx.Err(); err != nil {
		return &ZeroOutError{Device: device, Offset: offset, Size: size, Err: err}
	}
	return nil
}

// rangeToZero decides what ZeroOut asks the kernel for, given where the caller
// wants zeroing to start and how large the device turned out to be.
//
// It is separate from ZeroOut because it is the part with the decisions in it —
// an offset past the end is a caller error, an offset exactly at the end is
// nothing to do, and everything else runs to the end of the device — while the
// rest of ZeroOut is an open and an ioctl that need a real block device and
// root to reach. Deciding here means the decisions are checked by the unit
// tests rather than only by the integration suite.
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

// Operator is the seam through which a provider reaches these operations.
//
// Same reason as the other seams in this repository: the work happens on a real
// block device, and a test that cannot substitute it can only run as root
// against hardware it had to build first.
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
