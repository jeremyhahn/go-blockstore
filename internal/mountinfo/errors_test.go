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

package mountinfo

import (
	"errors"
	"strings"
	"testing"
)

// TestReadErrorIsDistinctFromParseError pins the separation this package was
// built around. "The table could not be read" and "the table was read and holds
// no such device" must never collapse into one answer, because a teardown acts
// on the second immediately before destroying a volume. Asking findmnt made
// them the same exit status; here they are different types.
func TestReadErrorIsDistinctFromParseError(t *testing.T) {
	underlying := errors.New("permission denied")

	readErr := &ReadError{Path: ProcPath, Err: underlying}
	if !strings.Contains(readErr.Error(), ProcPath) || !strings.Contains(readErr.Error(), "permission denied") {
		t.Errorf("ReadError = %q, want the path and the cause", readErr)
	}
	if !errors.Is(readErr, underlying) {
		t.Error("ReadError does not unwrap")
	}

	parseErr := &ParseError{Line: 7, Text: "bad record", Err: ErrNoSeparator}
	if !errors.Is(parseErr, ErrNoSeparator) {
		t.Error("ParseError does not unwrap to its sentinel")
	}

	// Neither is the other, which is the point.
	var asRead *ReadError
	if errors.As(parseErr, &asRead) {
		t.Error("a ParseError matched *ReadError")
	}
	var asParse *ParseError
	if errors.As(readErr, &asParse) {
		t.Error("a ReadError matched *ParseError")
	}
}

func TestParseErrorNamesTheRecord(t *testing.T) {
	err := &ParseError{Line: 42, Text: "1 2 badness", Err: ErrTooFewFields}
	for _, want := range []string{"42", "1 2 badness", "too few fields"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ParseError = %q, want it to mention %q", err, want)
		}
	}
}

func TestDeviceErrorNamesThePath(t *testing.T) {
	underlying := errors.New("no such file")
	err := &DeviceError{Path: "/dev/absent", Err: underlying}

	if !strings.Contains(err.Error(), "/dev/absent") || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("DeviceError = %q, want the path and the cause", err)
	}
	if !errors.Is(err, underlying) {
		t.Error("DeviceError does not unwrap")
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{
		0: "0", 1: "1", 9: "9", 10: "10", 12345: "12345",
		-1: "-1", -12345: "-12345",
	}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestLoadReportsAnUnreadableTable covers the ReadError path without needing
// /proc to be broken: Parse is where a read failure surfaces, and a reader that
// fails partway is the same condition.
func TestLoadReportsAnUnreadableTable(t *testing.T) {
	_, err := Parse(failingReader{})
	if err == nil {
		t.Fatal("Parse succeeded over a reader that fails")
	}
	var readErr *ReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("error is not a *ReadError: %v", err)
	}
}

// failingReader fails on the first read, standing in for a table that cannot be
// read to the end.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("I/O error") }
