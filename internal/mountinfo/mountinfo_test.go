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

// realLine is a record copied verbatim from this host's /proc/self/mountinfo
// for an LVM volume, so the parser is tested against the shape the kernel
// actually emits rather than one invented to suit it.
const realLine = `580 30 252:3 / /tmp/scratch/mi2 rw,relatime shared:500 - ext4 /dev/mapper/bsmi-vol rw`

func TestParseReadsARealRecord(t *testing.T) {
	entries, err := Parse(strings.NewReader(realLine))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("parsed %d entries, want 1", len(entries))
	}

	got := entries[0]
	want := Entry{
		Major:      252,
		Minor:      3,
		Root:       "/",
		MountPoint: "/tmp/scratch/mi2",
		FSType:     "ext4",
		Source:     "/dev/mapper/bsmi-vol",
	}
	if got != want {
		t.Errorf("parsed %+v, want %+v", got, want)
	}
}

// TestParseUnescapesPaths is the trap this package exists to avoid. The kernel
// escapes space, tab, newline and backslash as three-digit octal because the
// format is whitespace-separated. A caller comparing a mount point against the
// path it asked for gets no match for "/mnt/my data" unless that is undone —
// and concludes the volume is not mounted.
func TestParseUnescapesPaths(t *testing.T) {
	cases := map[string]struct {
		field string
		want  string
	}{
		"space":               {`/mnt/sp\040ace`, "/mnt/sp ace"},
		"tab":                 {`/mnt/ta\011b`, "/mnt/ta\tb"},
		"newline":             {`/mnt/new\012line`, "/mnt/new\nline"},
		"backslash":           {`/mnt/back\134slash`, `/mnt/back\slash`},
		"several":             {`/mnt/a\040b\040c`, "/mnt/a b c"},
		"nothing to unescape": {"/mnt/plain", "/mnt/plain"},
		"trailing backslash":  {`/mnt/odd\`, `/mnt/odd\`},
		"not an octal escape": {`/mnt/od\d`, `/mnt/od\d`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			line := `1 2 8:1 / ` + tc.field + ` rw - ext4 /dev/sda1 rw`
			entries, err := Parse(strings.NewReader(line))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if entries[0].MountPoint != tc.want {
				t.Errorf("MountPoint = %q, want %q", entries[0].MountPoint, tc.want)
			}
		})
	}
}

// TestParseFindsTheSeparatorRatherThanAssumingIt covers the variable-length
// optional fields. Their number changes with the mount — a shared mount has a
// peer group, a private one has nothing — so the fields after the separator
// cannot be found by counting from the left.
func TestParseFindsTheSeparatorRatherThanAssumingIt(t *testing.T) {
	cases := map[string]string{
		"no optional fields": `1 2 8:1 / /mnt rw - ext4 /dev/sda1 rw`,
		"one optional field": `1 2 8:1 / /mnt rw shared:1 - ext4 /dev/sda1 rw`,
		"several optional":   `1 2 8:1 / /mnt rw shared:1 master:2 propagate_from:3 - ext4 /dev/sda1 rw`,
	}

	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			entries, err := Parse(strings.NewReader(line))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if entries[0].FSType != "ext4" || entries[0].Source != "/dev/sda1" {
				t.Errorf("parsed %+v, want the fields after the separator", entries[0])
			}
		})
	}
}

func TestParseRejectsMalformedRecords(t *testing.T) {
	cases := map[string]struct {
		line string
		want error
	}{
		"too few fields":      {"1 2 8:1 /", ErrTooFewFields},
		"no separator":        {`1 2 8:1 / /mnt rw ext4 /dev/sda1 rw`, ErrNoSeparator},
		"truncated after sep": {`1 2 8:1 / /mnt rw - ext4`, ErrTruncatedAfterSeparator},
		// Filesystem type and source present, super options missing. The parser
		// reads neither, so this is the record it would happily half-read — and
		// a table that is not the format it claims to be must be refused, since
		// what a caller does with the answer is destroy a volume.
		"no super options":          {`1 2 8:1 / /mnt rw - ext4 /dev/sda1`, ErrTruncatedAfterSeparator},
		"device number no colon":    {`1 2 81 / /mnt rw - ext4 /dev/sda1 rw`, ErrMalformedDeviceNumber},
		"device major not a number": {`1 2 x:1 / /mnt rw - ext4 /dev/sda1 rw`, ErrMalformedDeviceNumber},
		"device minor not a number": {`1 2 8:x / /mnt rw - ext4 /dev/sda1 rw`, ErrMalformedDeviceNumber},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.line))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse = %v, want %v", err, tc.want)
			}

			// The record and its line number travel with it, so a report is
			// actionable without going back to the file.
			var parseErr *ParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("error is not a *ParseError: %v", err)
			}
			if parseErr.Line != 1 {
				t.Errorf("Line = %d, want 1", parseErr.Line)
			}
			if !strings.Contains(parseErr.Error(), strings.Fields(tc.line)[0]) {
				t.Errorf("error %q does not quote the record", parseErr)
			}
		})
	}
}

// TestParseDeviceNumbersAreDecimal pins the detail that silently matches the
// wrong device: mountinfo prints major:minor in DECIMAL, while stat's %t:%T —
// the obvious way to get the same pair for comparison — prints hex.
func TestParseDeviceNumbersAreDecimal(t *testing.T) {
	entries, err := Parse(strings.NewReader(`1 2 252:16 / /mnt rw - ext4 /dev/dm-16 rw`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if entries[0].Major != 252 || entries[0].Minor != 16 {
		t.Fatalf("device = %d:%d, want 252:16 read as decimal", entries[0].Major, entries[0].Minor)
	}
}

func TestParseSkipsBlankLinesAndHandlesEmptyInput(t *testing.T) {
	entries, err := Parse(strings.NewReader("\n\n   \n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("parsed %d entries from blank input, want 0", len(entries))
	}

	entries, err = Parse(strings.NewReader(""))
	if err != nil || len(entries) != 0 {
		t.Fatalf("Parse of empty input = (%v, %v), want no entries and no error", entries, err)
	}
}

// TestParseHandlesALongTable covers the scanner's buffer: a deep mount point
// would otherwise turn a healthy table into a parse failure.
func TestParseHandlesALongTable(t *testing.T) {
	deep := "/mnt/" + strings.Repeat("a/", 20000)
	line := `1 2 8:1 / ` + deep + ` rw - ext4 /dev/sda1 rw`

	entries, err := Parse(strings.NewReader(line))
	if err != nil {
		t.Fatalf("Parse of a deep mount point: %v", err)
	}
	if entries[0].MountPoint != deep {
		t.Error("the deep mount point did not survive parsing")
	}
}

func TestMountPointsFor(t *testing.T) {
	entries := []Entry{
		{Major: 252, Minor: 3, MountPoint: "/mnt/a"},
		{Major: 8, Minor: 1, MountPoint: "/"},
		{Major: 252, Minor: 3, MountPoint: "/mnt/b"},
	}

	got := MountPointsFor(entries, 252, 3)
	if len(got) != 2 || got[0] != "/mnt/a" || got[1] != "/mnt/b" {
		t.Fatalf("MountPointsFor = %v, want both mounts of 252:3 in order", got)
	}

	if got := MountPointsFor(entries, 99, 99); len(got) != 0 {
		t.Errorf("MountPointsFor of an unmounted device = %v, want none", got)
	}
}

// TestEntryAtPrefersTheLastMatch encodes what the kernel means by two records
// on one path: mounting over an occupied directory leaves both, and the later
// one is what is visible there.
func TestEntryAtPrefersTheLastMatch(t *testing.T) {
	entries := []Entry{
		{Major: 8, Minor: 1, MountPoint: "/mnt", FSType: "ext4"},
		{Major: 0, Minor: 84, MountPoint: "/mnt", FSType: "tmpfs"},
	}

	got, ok := EntryAt(entries, "/mnt")
	if !ok {
		t.Fatal("EntryAt found nothing")
	}
	if got.FSType != "tmpfs" {
		t.Errorf("EntryAt = %q, want the mount that is visible there now", got.FSType)
	}

	if _, ok := EntryAt(entries, "/nowhere"); ok {
		t.Error("EntryAt found a mount at a path with none")
	}
}

// TestVisibleMountPointsForSkipsShadowedMounts is the distinction that decides
// who gets unmounted. A directory mounted over keeps both records, the later
// one is what a process reaching the path gets, and umount(2) detaches what is
// visible — so acting on a path where this device has been covered unmounts
// somebody else's filesystem and leaves this one exactly where it was.
func TestVisibleMountPointsForSkipsShadowedMounts(t *testing.T) {
	entries := []Entry{
		{Major: 252, Minor: 3, MountPoint: "/mnt/data"},  // ours, then covered
		{Major: 0, Minor: 84, MountPoint: "/mnt/data"},   // tmpfs on top
		{Major: 252, Minor: 3, MountPoint: "/mnt/other"}, // ours, visible
	}

	if got := MountPointsFor(entries, 252, 3); len(got) != 2 {
		t.Fatalf("MountPointsFor = %v, want both mounts: a hidden mount is still a mount", got)
	}

	got := VisibleMountPointsFor(entries, 252, 3)
	if len(got) != 1 || got[0] != "/mnt/other" {
		t.Fatalf("VisibleMountPointsFor = %v, want only /mnt/other", got)
	}
}

// TestVisibleMountPointsForKeepsTheTopOfAStack covers the other direction: a
// device mounted OVER something else is what is visible there, and it is this
// provider's to unmount.
func TestVisibleMountPointsForKeepsTheTopOfAStack(t *testing.T) {
	entries := []Entry{
		{Major: 8, Minor: 1, MountPoint: "/mnt/data"},
		{Major: 252, Minor: 3, MountPoint: "/mnt/data"},
	}

	got := VisibleMountPointsFor(entries, 252, 3)
	if len(got) != 1 || got[0] != "/mnt/data" {
		t.Fatalf("VisibleMountPointsFor = %v, want /mnt/data", got)
	}
	if got := VisibleMountPointsFor(entries, 8, 1); len(got) != 0 {
		t.Errorf("the covered device is visible at %v", got)
	}
}

// TestVisibleMountPointsForKeepsKernelOrder matters because Delete unmounts
// deepest-first over what this returns, and an order that drifted from the
// table's would put a parent before the child mounted inside it.
func TestVisibleMountPointsForKeepsKernelOrder(t *testing.T) {
	entries := []Entry{
		{Major: 252, Minor: 3, MountPoint: "/mnt/a"},
		{Major: 252, Minor: 3, MountPoint: "/mnt/b"},
		{Major: 252, Minor: 3, MountPoint: "/mnt/c"},
	}

	got := VisibleMountPointsFor(entries, 252, 3)
	if len(got) != 3 || got[0] != "/mnt/a" || got[1] != "/mnt/b" || got[2] != "/mnt/c" {
		t.Errorf("VisibleMountPointsFor = %v, want the kernel's order", got)
	}
}

func TestVisibleMountPointsForAnUnmountedDevice(t *testing.T) {
	entries := []Entry{{Major: 8, Minor: 1, MountPoint: "/"}}
	if got := VisibleMountPointsFor(entries, 252, 3); len(got) != 0 {
		t.Errorf("VisibleMountPointsFor of an unmounted device = %v, want none", got)
	}
}
