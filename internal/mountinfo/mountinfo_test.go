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
		// The kernel's identity for this MOUNT, which is what distinguishes it
		// from a second mount of the same device at the same path.
		ID: 580,
		// The mount this one is mounted ON. It is the edge that makes the table
		// a tree, and the tree is what decides whether a path reaches this
		// mount at all.
		ParentID:   30,
		Major:      252,
		Minor:      3,
		Root:       "/",
		MountPoint: "/tmp/scratch/mi2",
		FSType:     "ext4",
		Source:     "/dev/mapper/bsmi-vol",
		// The record carries shared:500, so the propagation comes with it. This
		// is the field that decides whether a mount is visible in another
		// namespace at all.
		Propagation: Propagation{Shared: true, PeerGroup: 500},
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

// TestParsePropagation covers the optional fields, which are what decide
// whether a mount made here can be seen anywhere else.
//
// A mount under a private parent exists only in the namespace that made it: a
// workload in another namespace walks to the path and finds the directory as it
// was before anything was mounted on it, with no error at any layer. These
// fields are the only evidence of that, and they are the ones a parser is most
// tempted to skip over on the way to the fields after the separator.
func TestParsePropagation(t *testing.T) {
	cases := map[string]struct {
		optional string
		want     Propagation
		render   string
	}{
		"private": {
			optional: "",
			want:     Propagation{},
			render:   "private",
		},
		"shared": {
			optional: "shared:2",
			want:     Propagation{Shared: true, PeerGroup: 2},
			render:   "shared:2",
		},
		"slave": {
			optional: "master:3",
			want:     Propagation{Slave: true, MasterGroup: 3},
			render:   "master:3",
		},
		"shared and slave": {
			optional: "shared:2 master:3",
			want:     Propagation{Shared: true, PeerGroup: 2, Slave: true, MasterGroup: 3},
			render:   "shared:2 master:3",
		},
		"unbindable": {
			optional: "unbindable",
			want:     Propagation{Unbindable: true},
			render:   "unbindable",
		},
		// propagate_from accompanies master: on a slave whose peer group is not
		// reachable from this namespace. It says nothing this cares about, and
		// the point is that an unrecognized tag does not disturb the rest.
		"slave with propagate_from": {
			optional: "master:3 propagate_from:5",
			want:     Propagation{Slave: true, MasterGroup: 3},
			render:   "master:3",
		},
		"a tag this kernel version invented": {
			optional: "shared:2 something_new:9",
			want:     Propagation{Shared: true, PeerGroup: 2},
			render:   "shared:2",
		},
		// A malformed value is not a propagation claim, so it is not honored.
		// Fail-closed here means NOT reporting a mount as shared on a field the
		// parser could not read.
		"shared with an unreadable peer group": {
			optional: "shared:notanumber",
			want:     Propagation{},
			render:   "private",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			line := "1 2 8:1 / /mnt rw"
			if tc.optional != "" {
				line += " " + tc.optional
			}
			line += " - ext4 /dev/sda1 rw"

			entries, err := Parse(strings.NewReader(line))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if entries[0].Propagation != tc.want {
				t.Errorf("Propagation = %+v, want %+v", entries[0].Propagation, tc.want)
			}
			if got := entries[0].Propagation.String(); got != tc.render {
				t.Errorf("String() = %q, want %q", got, tc.render)
			}
		})
	}
}

// TestPropagationPrivate names the state that fails silently, so a caller can
// ask for it directly rather than spelling out the absence of the others.
func TestPropagationPrivate(t *testing.T) {
	cases := map[string]struct {
		p    Propagation
		want bool
	}{
		"nothing set":  {Propagation{}, true},
		"shared":       {Propagation{Shared: true, PeerGroup: 1}, false},
		"slave":        {Propagation{Slave: true, MasterGroup: 1}, false},
		"unbindable":   {Propagation{Unbindable: true}, false},
		"shared+slave": {Propagation{Shared: true, Slave: true}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.p.Private(); got != tc.want {
				t.Errorf("Private() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPropagationSurvivesAVariableNumberOfOptionalFields is the interaction
// between this and the separator search: the optional fields are where the
// record's length varies, so reading them wrongly is also how the fields AFTER
// the separator get misread.
func TestPropagationSurvivesAVariableNumberOfOptionalFields(t *testing.T) {
	line := `1 2 8:1 / /mnt rw shared:1 master:2 propagate_from:3 unbindable - ext4 /dev/sda1 rw`

	entries, err := Parse(strings.NewReader(line))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := entries[0]
	if got.FSType != "ext4" || got.Source != "/dev/sda1" {
		t.Errorf("the fields after the separator were misread: %+v", got)
	}
	if !got.Propagation.Shared || got.Propagation.PeerGroup != 1 {
		t.Errorf("Propagation = %+v, want shared:1 among the rest", got.Propagation)
	}
	if !got.Propagation.Unbindable {
		t.Error("unbindable was not read")
	}
}

// TestParseRejectsAMalformedMountID keeps the identity honest. The mount id is
// what a caller compares to decide whether the mount it is about to act on is
// still its own, so a record whose id cannot be read is not a record with a
// missing field — it is one no such decision can be made from.
func TestParseRejectsAMalformedMountID(t *testing.T) {
	_, err := Parse(strings.NewReader(`x 2 8:1 / /mnt rw - ext4 /dev/sda1 rw`))
	if !errors.Is(err, ErrMalformedMountID) {
		t.Fatalf("Parse = %v, want ErrMalformedMountID", err)
	}
}

// TestParseReadsDistinctMountIDsForStackedMounts is the case the id exists for:
// one device, one path, two mounts. Nothing else in a record tells them apart.
func TestParseReadsDistinctMountIDsForStackedMounts(t *testing.T) {
	table := "31 1 252:3 / /mnt/data rw shared:1 - ext4 /dev/vg0/data rw\n" +
		"87 1 252:3 / /mnt/data rw shared:2 - ext4 /dev/vg0/data rw\n"

	entries, err := Parse(strings.NewReader(table))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("parsed %d entries, want 2", len(entries))
	}
	if entries[0].ID == entries[1].ID {
		t.Fatal("two stacked mounts of one device share an id, so nothing distinguishes them")
	}

	// And the visible one is the later record, which is the one umount(2) would
	// detach — so it is the id a caller has to compare against.
	visible, ok := EntryAt(entries, "/mnt/data")
	if !ok {
		t.Fatal("EntryAt found nothing")
	}
	if visible.ID != entries[1].ID {
		t.Errorf("the visible mount is id %d, want the later record %d", visible.ID, entries[1].ID)
	}
}
