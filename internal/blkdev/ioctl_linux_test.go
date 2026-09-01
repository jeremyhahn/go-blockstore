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
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestTranslateIoctlError covers the table the conversion exists for. A bare
// errno is what the syscall gives back and what dd and blkdiscard used to spare
// the caller: ENOTTY reads as "inappropriate ioctl for device", which sends
// somebody looking for a terminal.
func TestTranslateIoctlError(t *testing.T) {
	cases := map[string]struct {
		in   error
		want error
	}{
		"not a block device":      {in: unix.ENOTTY, want: ErrNotBlockDevice},
		"zeroing unsupported":     {in: unix.EOPNOTSUPP, want: ErrZeroOutUnsupported},
		"anything else is kept":   {in: unix.EIO, want: unix.EIO},
		"a non-errno is kept too": {in: os.ErrClosed, want: os.ErrClosed},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := translateIoctlError(tc.in); !errors.Is(got, tc.want) {
				t.Errorf("translateIoctlError(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestCopyReportsAFailedFlush covers conv=fsync's failure, which is the branch
// that decides whether a copy that reached the page cache and no further is
// reported as done. A FIFO accepts the write and refuses the fsync, so the
// branch is reachable without a block device.
func TestCopyReportsAFailedFlush(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	writeFile(t, src, []byte("go-blockstore"))

	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	// Both ends of a FIFO block until the other arrives, so the reader is
	// started and then joined rather than waited for first — waiting would
	// deadlock, since the open for reading does not return until Copy opens the
	// write end. The reader drains what is written, so the copy itself cannot
	// be what fails.
	done := make(chan struct{})
	go func() {
		defer close(done)
		r, err := os.OpenFile(fifo, os.O_RDONLY, 0)
		if err != nil {
			return
		}
		defer func() { _ = r.Close() }()
		_, _ = io.Copy(io.Discard, r)
	}()

	err := Copy(t.Context(), src, fifo)
	<-done

	if err == nil {
		t.Fatal("Copy reported success over a destination that cannot be flushed")
	}
	var copyErr *CopyError
	if !errors.As(err, &copyErr) {
		t.Fatalf("error is not a *CopyError: %v", err)
	}
	if copyErr.Op != "flushing the destination" {
		t.Errorf("failed at %q, want the flush", copyErr.Op)
	}
}

// TestCopyReportsACancellationOnceTheTransferIsUnderWay covers giving up on a
// copy that has already moved bytes, which is the case the callers actually
// meet: a restore of a large volume runs for minutes.
//
// The copy stops and reports it. What it must NOT do is finish quietly and let
// a restore go on to tag the volume and report it ready under a context whose
// caller gave up — which is also why the flush and close at the end are
// followed by a second check of the context, since on a block device those are
// the writeback and can block for a long time with no way to interrupt them.
// Which of the two checks catches a cancellation depends on where the copy had
// got to; both return the same thing to the caller, and only a device slow
// enough to block in the writeback can be made to take the second one.
func TestCopyReportsACancellationOnceTheTransferIsUnderWay(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "fifo")
	dst := filepath.Join(dir, "dst")
	writeFile(t, dst, make([]byte, 64))

	if err := unix.Mkfifo(src, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w, err := os.OpenFile(src, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		// The write completes before the caller gives up, so the copy is under
		// way rather than refused at the door.
		_, _ = w.WriteString("go-blockstore")
		cancel()
		_ = w.Close()
	}()

	err := Copy(ctx, src, dst)
	<-done

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Copy = %v, want it to wrap context.Canceled", err)
	}
	var copyErr *CopyError
	if !errors.As(err, &copyErr) || copyErr.Source != src || copyErr.Destination != dst {
		t.Errorf("error does not carry the copy's ends: %v", err)
	}
}
