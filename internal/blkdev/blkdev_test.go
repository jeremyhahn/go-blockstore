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

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Copy works on ordinary files, so its behavior is testable without root or a
// block device. ZeroOut and Size need a real device for their success paths and
// are covered there by the providers' integration suites; their refusals are
// reachable here.

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

func TestCopyTransfersTheWholeSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	// Larger than one buffer, so the loop runs more than once.
	content := bytes.Repeat([]byte("go-blockstore"), (CopyBufferSize/13)+1024)
	writeFile(t, src, content)
	writeFile(t, dst, make([]byte, len(content)))

	if err := Copy(context.Background(), src, dst); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("destination holds %d bytes, want the source's %d and identical", len(got), len(content))
	}
}

// TestCopyDoesNotCreateTheDestination is dd's conv=nocreat, which is structural
// here rather than a flag: a missing destination means the device the caller
// meant to write is absent, and creating an empty regular file in its place
// turns that into a copy that appears to succeed.
func TestCopyDoesNotCreateTheDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "absent")
	writeFile(t, src, []byte("payload"))

	err := Copy(context.Background(), src, dst)
	if err == nil {
		t.Fatal("Copy created a destination that did not exist")
	}
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Error("Copy left a file where the destination should have been missing")
	}

	var copyErr *CopyError
	if !errors.As(err, &copyErr) {
		t.Fatalf("error is not a *CopyError: %v", err)
	}
	if copyErr.Destination != dst || copyErr.Source != src {
		t.Errorf("error names %q -> %q, want the paths it was given", copyErr.Source, copyErr.Destination)
	}
	if !strings.Contains(copyErr.Error(), "destination") {
		t.Errorf("error %q does not say which end failed", copyErr)
	}
}

func TestCopyReportsAMissingSource(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")
	writeFile(t, dst, []byte("x"))

	err := Copy(context.Background(), filepath.Join(dir, "absent"), dst)
	if err == nil {
		t.Fatal("Copy succeeded with no source")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Copy = %v, want it to wrap os.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), "source") {
		t.Errorf("error %q does not say which end failed", err)
	}
}

// TestCopyStopsOnACancelledContext is a property dd never had: a canceled
// context left it running to completion.
func TestCopyStopsOnACancelledContext(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	content := bytes.Repeat([]byte("a"), 8*CopyBufferSize)
	writeFile(t, src, content)
	writeFile(t, dst, make([]byte, len(content)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Copy(ctx, src, dst)
	if err == nil {
		t.Fatal("Copy ran to completion under a canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Copy = %v, want it to wrap context.Canceled", err)
	}
}

func TestZeroOutRefusesANegativeOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev")
	writeFile(t, path, make([]byte, 4096))

	err := ZeroOut(context.Background(), path, -1)
	if !errors.Is(err, ErrNegativeOffset) {
		t.Fatalf("ZeroOut = %v, want ErrNegativeOffset", err)
	}

	var zeroErr *ZeroOutError
	if !errors.As(err, &zeroErr) {
		t.Fatalf("error is not a *ZeroOutError: %v", err)
	}
	if zeroErr.Offset != -1 || zeroErr.Device != path {
		t.Errorf("error carries %s@%d, want the arguments it was given", zeroErr.Device, zeroErr.Offset)
	}
}

// TestZeroOutRefusesANonBlockDevice covers the translation the conversion
// exists to provide. The kernel answers ENOTTY — "inappropriate ioctl for
// device" — which on its own sends a reader looking for a terminal.
func TestZeroOutRefusesANonBlockDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regular")
	writeFile(t, path, make([]byte, 4096))

	err := ZeroOut(context.Background(), path, 0)
	if !errors.Is(err, ErrNotBlockDevice) {
		t.Fatalf("ZeroOut = %v, want ErrNotBlockDevice", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the device", err)
	}
}

func TestZeroOutReportsAMissingDevice(t *testing.T) {
	err := ZeroOut(context.Background(), filepath.Join(t.TempDir(), "absent"), 0)
	if err == nil {
		t.Fatal("ZeroOut succeeded on a device that does not exist")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ZeroOut = %v, want it to wrap os.ErrNotExist", err)
	}
}

func TestZeroOutHonoursACancelledContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev")
	writeFile(t, path, make([]byte, 4096))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ZeroOut(ctx, path, 0)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ZeroOut = %v, want it to wrap context.Canceled", err)
	}
}

func TestSizeRefusesANonBlockDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regular")
	writeFile(t, path, make([]byte, 4096))

	_, err := Size(path)
	if !errors.Is(err, ErrNotBlockDevice) {
		t.Fatalf("Size = %v, want ErrNotBlockDevice", err)
	}

	var sizeErr *SizeError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("error is not a *SizeError: %v", err)
	}
	if sizeErr.Device != path {
		t.Errorf("error names %q, want %q", sizeErr.Device, path)
	}
}

func TestSizeReportsAMissingDevice(t *testing.T) {
	_, err := Size(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("Size succeeded on a device that does not exist")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Size = %v, want it to wrap os.ErrNotExist", err)
	}
}

// TestErrorsCarryTheirContext checks what these types exist for. An exit status
// from dd or blkdiscard said nothing about what was being operated on; these
// have to say it in the message, or the conversion has traded a bad error for a
// worse one.
func TestErrorsCarryTheirContext(t *testing.T) {
	underlying := errors.New("boom")

	copyErr := &CopyError{Source: "/dev/a", Destination: "/dev/b", Op: "copying", Err: underlying}
	for _, want := range []string{"/dev/a", "/dev/b", "copying", "boom"} {
		if !strings.Contains(copyErr.Error(), want) {
			t.Errorf("CopyError = %q, want it to mention %q", copyErr, want)
		}
	}
	if !errors.Is(copyErr, underlying) {
		t.Error("CopyError does not unwrap")
	}

	zeroErr := &ZeroOutError{Device: "/dev/a", Offset: 1024, Size: 4096, Err: underlying}
	for _, want := range []string{"/dev/a", "1024", "4096", "boom"} {
		if !strings.Contains(zeroErr.Error(), want) {
			t.Errorf("ZeroOutError = %q, want it to mention %q", zeroErr, want)
		}
	}
	if !errors.Is(zeroErr, underlying) {
		t.Error("ZeroOutError does not unwrap")
	}

	// A size that was never determined is left out rather than printed as 0,
	// which would read as a zero-length device.
	early := &ZeroOutError{Device: "/dev/a", Offset: 1024, Err: underlying}
	if strings.Contains(early.Error(), "of 0 bytes") {
		t.Errorf("ZeroOutError = %q, want no size when none was read", early)
	}

	sizeErr := &SizeError{Device: "/dev/a", Err: underlying}
	if !strings.Contains(sizeErr.Error(), "/dev/a") || !errors.Is(sizeErr, underlying) {
		t.Errorf("SizeError = %q, want it to name the device and unwrap", sizeErr)
	}
}

func TestItoa(t *testing.T) {
	cases := map[int64]string{
		0: "0", 1: "1", 9: "9", 10: "10", 4096: "4096",
		-1: "-1", -4096: "-4096",
		9223372036854775807: "9223372036854775807",
	}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestRangeToZero covers the decisions ZeroOut makes once it knows the device's
// size. The surrounding open and ioctl need root and a real block device, which
// is exactly why the decisions do not live inside them.
func TestRangeToZero(t *testing.T) {
	const size = int64(4096)

	cases := map[string]struct {
		offset     int64
		wantLength uint64
		wantZero   bool
		wantErr    error
	}{
		"from the start":     {offset: 0, wantLength: 4096, wantZero: true},
		"from the middle":    {offset: 1024, wantLength: 3072, wantZero: true},
		"one byte short":     {offset: 4095, wantLength: 1, wantZero: true},
		"exactly at the end": {offset: size, wantLength: 0, wantZero: false},
		"past the end":       {offset: size + 1, wantErr: ErrOffsetPastEnd},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			length, zero, err := rangeToZero(tc.offset, size)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("rangeToZero(%d, %d) = %v, want %v", tc.offset, size, err, tc.wantErr)
			}
			if zero != tc.wantZero {
				t.Errorf("zero = %v, want %v", zero, tc.wantZero)
			}
			if length != tc.wantLength {
				t.Errorf("length = %d, want %d", length, tc.wantLength)
			}
		})
	}
}

// TestRangeToZeroRunsToTheEnd is the property the callers depend on: they are
// destroying a former tenant's data, so a range that stops short leaves some of
// it behind while the call reports success.
func TestRangeToZeroRunsToTheEnd(t *testing.T) {
	for _, size := range []int64{512, 4096, 1 << 30, 1 << 40} {
		for _, offset := range []int64{0, 1, size / 2, size - 1} {
			length, zero, err := rangeToZero(offset, size)
			if err != nil || !zero {
				t.Fatalf("rangeToZero(%d, %d) = (%d, %v, %v), want a range", offset, size, length, zero, err)
			}
			if int64(length)+offset != size {
				t.Errorf("rangeToZero(%d, %d) stops at %d, want the end of the device",
					offset, size, offset+int64(length))
			}
		}
	}
}
