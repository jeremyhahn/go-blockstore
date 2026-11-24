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
	"sort"
	"strings"
	"testing"
)

// The tables below were captured from /proc/self/mountinfo on a Linux 6.8 host, root record included.

// ancestorOvermountTable: tmpBASE at base, tmpVOL at base/vol, then tmpOVER over base, covering the volume's ancestor.
const ancestorOvermountTable = `562 438 252:1 / / rw,relatime - ext4 /dev/mapper/vgmint-root rw,errors=remount-ro
624 562 0:76 / /tmp/bs33/base rw,relatime - tmpfs tmpBASE rw,size=1024k,uid=1000,gid=1000,inode64
625 624 0:87 / /tmp/bs33/base/vol rw,relatime - tmpfs tmpVOL rw,size=1024k,uid=1000,gid=1000,inode64
626 624 0:88 / /tmp/bs33/base rw,relatime - tmpfs tmpOVER rw,size=1024k,uid=1000,gid=1000,inode64
`

// ancestorBeforeOvermountTable is the same three mounts one step earlier, with
// nothing covering the base. It is here so the ancestor test can show that the
// volume's own record is byte-for-byte identical in both tables: record 625 is
// the same line, and only the arrival of 626 changes the answer.
const ancestorBeforeOvermountTable = `562 438 252:1 / / rw,relatime - ext4 /dev/mapper/vgmint-root rw,errors=remount-ro
624 562 0:76 / /tmp/bs33/base rw,relatime - tmpfs tmpBASE rw,size=1024k,uid=1000,gid=1000,inode64
625 624 0:87 / /tmp/bs33/base/vol rw,relatime - tmpfs tmpVOL rw,size=1024k,uid=1000,gid=1000,inode64
`

// equalPathTable: two tmpfs mounts on one path; record 625's parent is 624, the mount it covers.
const equalPathTable = `562 438 252:1 / / rw,relatime - ext4 /dev/mapper/vgmint-root rw,errors=remount-ro
624 562 0:76 / /tmp/bs33/x rw,relatime - tmpfs tmpLOWER rw,size=1024k,uid=1000,gid=1000,inode64
625 624 0:87 / /tmp/bs33/x rw,relatime - tmpfs tmpUPPER rw,size=1024k,uid=1000,gid=1000,inode64
`

// movedOnTopTable: after mount --move, the mount on top (624) is listed first.
const movedOnTopTable = `562 438 252:1 / / rw,relatime - ext4 /dev/mapper/vgmint-root rw,errors=remount-ro
624 625 0:76 / /tmp/bs33/y rw,relatime - tmpfs tmpEARLY rw,size=1024k,uid=1000,gid=1000,inode64
625 562 0:87 / /tmp/bs33/y rw,relatime - tmpfs tmpLATE rw,size=1024k,uid=1000,gid=1000,inode64
`

// compositeOvermountTable: 625 and 684 share a path, separated only by their ancestor chain; 684 sits inside the covering mount.
const compositeOvermountTable = `562 438 252:1 / / rw,relatime - ext4 /dev/mapper/vgmint-root rw,errors=remount-ro
624 562 0:76 / /tmp/bs33c/base rw,relatime - tmpfs tmpBASE rw,uid=1000,gid=1000,inode64
625 624 0:87 / /tmp/bs33c/base/vol rw,relatime - tmpfs tmpVOL rw,uid=1000,gid=1000,inode64
626 624 0:88 / /tmp/bs33c/base rw,relatime - tmpfs tmpOVER rw,uid=1000,gid=1000,inode64
684 626 0:89 / /tmp/bs33c/base/vol rw,relatime - tmpfs tmpVOL2 rw,uid=1000,gid=1000,inode64
720 562 0:89 / /tmp/bs33c/bindtarget rw,relatime - tmpfs tmpVOL2 rw,uid=1000,gid=1000,inode64
`

// ordinaryHostTable is an untouched workstation table; root record 30 follows its children and its parent id 1 names no record.
const ordinaryHostTable = `25 30 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
26 30 0:24 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw
27 30 0:5 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=32497924k,nr_inodes=8124481,mode=755,inode64
28 27 0:25 / /dev/pts rw,nosuid,noexec,relatime shared:3 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
29 30 0:26 / /run rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,size=6521976k,mode=755,inode64
30 1 252:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vgmint-root rw,errors=remount-ro
31 25 0:6 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:8 - securityfs securityfs rw
32 27 0:27 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw,inode64
33 29 0:28 / /run/lock rw,nosuid,nodev,noexec,relatime shared:6 - tmpfs tmpfs rw,size=5120k,inode64
34 25 0:29 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
35 25 0:30 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:10 - pstore pstore rw
36 25 0:31 / /sys/firmware/efi/efivars rw,nosuid,nodev,noexec,relatime shared:11 - efivarfs efivarfs rw
37 25 0:32 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:12 - bpf bpf rw,mode=700
38 26 0:33 / /proc/sys/fs/binfmt_misc rw,relatime shared:14 - autofs systemd-1 rw,fd=32,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=8292
39 27 0:20 / /dev/mqueue rw,nosuid,nodev,noexec,relatime shared:15 - mqueue mqueue rw
40 27 0:34 / /dev/hugepages rw,nosuid,nodev,relatime shared:16 - hugetlbfs hugetlbfs rw,pagesize=2M
41 25 0:7 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime shared:17 - debugfs debugfs rw
42 25 0:12 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime shared:18 - tracefs tracefs rw
43 25 0:35 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec,relatime shared:19 - fusectl fusectl rw
44 25 0:21 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime shared:20 - configfs configfs rw
46 29 0:36 / /run/qemu rw,nosuid,nodev,relatime shared:30 - tmpfs tmpfs rw,mode=755,inode64
48 30 259:2 / /boot rw,relatime shared:46 - ext4 /dev/nvme0n1p2 rw
50 48 259:1 / /boot/efi rw,relatime shared:48 - vfat /dev/nvme0n1p1 rw,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro
53 38 0:38 / /proc/sys/fs/binfmt_misc rw,nosuid,nodev,noexec,relatime shared:50 - binfmt_misc binfmt_misc rw
737 29 0:66 / /run/user/1000 rw,nosuid,nodev,relatime shared:709 - tmpfs tmpfs rw,size=6521972k,nr_inodes=1630493,mode=700,uid=1000,gid=1000,inode64
785 737 0:67 / /run/user/1000/gvfs rw,nosuid,nodev,relatime shared:760 - fuse.gvfsd-fuse gvfsd-fuse rw,user_id=1000,group_id=1000
842 737 0:68 / /run/user/1000/doc rw,nosuid,nodev,relatime shared:781 - fuse.portal portal rw,user_id=1000,group_id=1000
61 30 0:55 / /tmp/pin2180246903/mnt rw,nosuid,nodev,relatime shared:413 - tmpfs tmpfs rw,size=1024k,inode64
`

// mustParse fails the test rather than returning an error, because every table
// in this file is real kernel output and a parse failure means the test itself
// is broken, not the code under it.
func mustParse(t *testing.T, table string) []Entry {
	t.Helper()
	entries, err := Parse(strings.NewReader(table))
	if err != nil {
		t.Fatalf("parsing a real mount table: %v", err)
	}
	return entries
}

// hiddenMountIDs is the inverse of what the package reports: the mount ids a
// walk to their own mount point does NOT reach. Naming what is hidden makes a
// false positive — a mount wrongly refused — show up as a named id rather than
// as a shorter list.
func hiddenMountIDs(entries []Entry) []uint32 {
	visible := visibility(entries)
	var hidden []uint32
	for i, e := range entries {
		if !visible[i] {
			hidden = append(hidden, e.ID)
		}
	}
	sort.Slice(hidden, func(a, b int) bool { return hidden[a] < hidden[b] })
	return hidden
}

func sameIDs(got, want []uint32) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestVisibleMountPointsForSeesAnAncestorOvermount requires a mount covering the base to hide the volume.
func TestVisibleMountPointsForSeesAnAncestorOvermount(t *testing.T) {
	const volDevice = "0:87"

	before := mustParse(t, ancestorBeforeOvermountTable)
	if got := VisibleMountPointsFor(before, 0, 87); len(got) != 1 || got[0] != "/tmp/bs33/base/vol" {
		t.Fatalf("with nothing covering the base, VisibleMountPointsFor(%s) = %v, want /tmp/bs33/base/vol", volDevice, got)
	}

	after := mustParse(t, ancestorOvermountTable)
	if got := VisibleMountPointsFor(after, 0, 87); len(got) != 0 {
		t.Errorf("with tmpOVER on the ancestor /tmp/bs33/base, VisibleMountPointsFor(%s) = %v, want none: a walk to that path lands inside tmpOVER", volDevice, got)
	}

	// The mount did not go anywhere, and a teardown asking whether the volume
	// is busy must still be told about it.
	if got := MountPointsFor(after, 0, 87); len(got) != 1 || got[0] != "/tmp/bs33/base/vol" {
		t.Errorf("MountPointsFor(%s) = %v, want the mount to still be reported: hidden is not unmounted", volDevice, got)
	}

	// The covering mount is reachable, and the covered ancestor is not.
	if got := VisibleMountPointsFor(after, 0, 88); len(got) != 1 || got[0] != "/tmp/bs33/base" {
		t.Errorf("VisibleMountPointsFor(0:88 tmpOVER) = %v, want /tmp/bs33/base", got)
	}
	if got := VisibleMountPointsFor(after, 0, 76); len(got) != 0 {
		t.Errorf("VisibleMountPointsFor(0:76 tmpBASE) = %v, want none: it was mounted over", got)
	}

	if got := hiddenMountIDs(after); !sameIDs(got, []uint32{624, 625}) {
		t.Errorf("hidden mounts = %v, want exactly the covered base 624 and the volume 625 beneath it", got)
	}
}

// TestVisibleMountPointsForOnEqualPaths: the covering mount's parent is the mount it covers.
func TestVisibleMountPointsForOnEqualPaths(t *testing.T) {
	entries := mustParse(t, equalPathTable)

	if entries[2].ParentID != entries[1].ID {
		t.Fatalf("the fixture is not the stack it claims to be: %d's parent is %d, want %d",
			entries[2].ID, entries[2].ParentID, entries[1].ID)
	}

	if got := VisibleMountPointsFor(entries, 0, 87); len(got) != 1 || got[0] != "/tmp/bs33/x" {
		t.Errorf("VisibleMountPointsFor(0:87 tmpUPPER) = %v, want /tmp/bs33/x", got)
	}
	if got := VisibleMountPointsFor(entries, 0, 76); len(got) != 0 {
		t.Errorf("VisibleMountPointsFor(0:76 tmpLOWER) = %v, want none: it is underneath", got)
	}
	if got := hiddenMountIDs(entries); !sameIDs(got, []uint32{624}) {
		t.Errorf("hidden mounts = %v, want exactly the covered lower mount 624", got)
	}
}

// TestVisibleMountPointsForFollowsTheTreeWhenFileOrderDisagrees is the second
// answer the old rule got wrong, and it got it wrong in both directions at
// once: it reported the covered mount as visible AND the covering mount as
// hidden. mount --move leaves a record where it was in the file, so the record
// listed first is the one on top.
func TestVisibleMountPointsForFollowsTheTreeWhenFileOrderDisagrees(t *testing.T) {
	entries := mustParse(t, movedOnTopTable)

	if entries[1].ParentID != entries[2].ID {
		t.Fatalf("the fixture is not the inversion it claims to be: record %d's parent is %d, want the LATER record %d",
			entries[1].ID, entries[1].ParentID, entries[2].ID)
	}

	if got := VisibleMountPointsFor(entries, 0, 76); len(got) != 1 || got[0] != "/tmp/bs33/y" {
		t.Errorf("VisibleMountPointsFor(0:76 tmpEARLY) = %v, want /tmp/bs33/y: it is the child mounted on 625, so it is on top", got)
	}
	if got := VisibleMountPointsFor(entries, 0, 87); len(got) != 0 {
		t.Errorf("VisibleMountPointsFor(0:87 tmpLATE) = %v, want none: the moved mount landed on it", got)
	}
	if got := hiddenMountIDs(entries); !sameIDs(got, []uint32{625}) {
		t.Errorf("hidden mounts = %v, want exactly 625", got)
	}
}

// TestVisibleMountPointsForDoesNotInventCoveringOnAnOrdinaryHost allows exactly one hidden mount, binfmt_misc over autofs.
func TestVisibleMountPointsForDoesNotInventCoveringOnAnOrdinaryHost(t *testing.T) {
	entries := mustParse(t, ordinaryHostTable)
	if len(entries) != 28 {
		t.Fatalf("the host table is %d records, want 28", len(entries))
	}

	if got := hiddenMountIDs(entries); !sameIDs(got, []uint32{38}) {
		t.Errorf("hidden mounts = %v, want exactly 38 — the autofs that binfmt_misc is mounted over", got)
	}

	// The root filesystem is reachable, which is the assertion that fails first
	// if a parent listed after its children or a parent id naming no record is
	// mishandled. Record 30 is both.
	if got := VisibleMountPointsFor(entries, 252, 1); len(got) != 1 || got[0] != "/" {
		t.Errorf("VisibleMountPointsFor(252:1, the root filesystem) = %v, want /", got)
	}
}

// TestVisibilityTreatsADanglingParentAsTheTopOfTheTable covers the shape every
// namespace's root record has: a parent id naming no record in the file,
// because the file shows one namespace and its root hangs off a mount outside
// it. Read as "unknown, therefore suspect" it would hide the entire table.
func TestVisibilityTreatsADanglingParentAsTheTopOfTheTable(t *testing.T) {
	entries := mustParse(t, ancestorBeforeOvermountTable)
	if _, found := indexByID(entries)[entries[0].ParentID]; found {
		t.Fatalf("the fixture's root record %d has parent %d, which this table apparently does contain",
			entries[0].ID, entries[0].ParentID)
	}
	if got := hiddenMountIDs(entries); len(got) != 0 {
		t.Errorf("hidden mounts = %v, want none: nothing in this table is covered", got)
	}
}

// TestVisibilityFailsOpenOnATableThatLoops: a parent loop reports the mounts rather than refusing them.
func TestVisibilityFailsOpenOnATableThatLoops(t *testing.T) {
	const loop = `10 11 0:76 / /a rw,relatime - tmpfs a rw
11 10 0:87 / /b rw,relatime - tmpfs b rw
`
	entries := mustParse(t, loop)
	if got := hiddenMountIDs(entries); len(got) != 0 {
		t.Errorf("hidden mounts = %v, want none: a cyclic table decides nothing and must not refuse everything", got)
	}
}

// TestVisibilityTreatsASelfParentedRecordAsTheTopOfTheTable, as a zero-valued Entry would be.
func TestVisibilityTreatsASelfParentedRecordAsTheTopOfTheTable(t *testing.T) {
	const selfParented = `10 10 0:76 / / rw,relatime - tmpfs root rw
20 10 0:87 / /vol rw,relatime - tmpfs vol rw
`
	entries := mustParse(t, selfParented)
	if entries[0].ID != entries[0].ParentID {
		t.Fatalf("record %d's parent is %d; this test is built on a record that is its own parent", entries[0].ID, entries[0].ParentID)
	}

	if got := hiddenMountIDs(entries); len(got) != 0 {
		t.Errorf("hidden mounts = %v, want none: a self-edge is not a tree edge, so neither the record nor the mount beneath it is covered", got)
	}
	if got := VisibleMountPointsFor(entries, 0, 87); len(got) != 1 || got[0] != "/vol" {
		t.Errorf("VisibleMountPointsFor(0:87) = %v, want /vol", got)
	}

	// The same shape reached the other way: one entry built in code, never
	// parsed, whose ID and ParentID are both the zero value.
	built := []Entry{{Major: 252, Minor: 3, MountPoint: "/mnt/only"}}
	if got := VisibleMountPointsFor(built, 252, 3); len(got) != 1 || got[0] != "/mnt/only" {
		t.Errorf("VisibleMountPointsFor of a single hand-built entry = %v, want /mnt/only: a zero-valued Entry must not be its own parent", got)
	}
}

// TestVisibilityFailsOpenOnADuplicatedMountID covers the other malformed shape:
// two records claiming one id, so a parent edge pointing at that id identifies
// no single record. The edge is not followed, which leaves the child looking
// parentless and therefore reachable — the same recoverable direction.
func TestVisibilityFailsOpenOnADuplicatedMountID(t *testing.T) {
	const duplicated = `10 1 0:76 / /a rw,relatime - tmpfs a rw
10 1 0:88 / /b rw,relatime - tmpfs b rw
20 10 0:87 / /a/vol rw,relatime - tmpfs vol rw
`
	entries := mustParse(t, duplicated)
	if got := indexByID(entries)[10]; got != ambiguousID {
		t.Fatalf("id 10 indexed as record %d, want it recorded as ambiguous", got)
	}
	if got := VisibleMountPointsFor(entries, 0, 87); len(got) != 1 || got[0] != "/a/vol" {
		t.Errorf("VisibleMountPointsFor(0:87) = %v, want /a/vol: an edge into an ambiguous id is followed nowhere", got)
	}
}

// TestParseRejectsAMalformedParentID pins the refusal rather than a zero.
func TestParseRejectsAMalformedParentID(t *testing.T) {
	const bad = `580 notanumber 252:3 / /tmp/scratch/mi2 rw,relatime - ext4 /dev/mapper/bsmi-vol rw`

	_, err := Parse(strings.NewReader(bad))
	if !errors.Is(err, ErrMalformedParentID) {
		t.Fatalf("Parse of a record with a non-numeric parent id = %v, want ErrMalformedParentID", err)
	}

	var parseErr *ParseError
	if !errors.As(err, &parseErr) || parseErr.Line != 1 {
		t.Errorf("error = %v, want a ParseError naming line 1 so the report is actionable", err)
	}
}

// TestEntryAtReportsNothingBehindAnOvermountedAncestor is the same correction
// applied to the lookup PropagationOf uses. A walk to /tmp/bs33/base/vol lands
// inside tmpOVER, so no record in this table is what that path resolves to —
// and reporting the hidden volume would tell a propagation guard that the
// device is visible at a path nothing can reach it by.
func TestEntryAtReportsNothingBehindAnOvermountedAncestor(t *testing.T) {
	before := mustParse(t, ancestorBeforeOvermountTable)
	if got, ok := EntryAt(before, "/tmp/bs33/base/vol"); !ok || got.ID != 625 {
		t.Fatalf("before the overmount, EntryAt(/tmp/bs33/base/vol) = %d,%v, want mount 625", got.ID, ok)
	}

	after := mustParse(t, ancestorOvermountTable)
	if got, ok := EntryAt(after, "/tmp/bs33/base/vol"); ok {
		t.Errorf("EntryAt(/tmp/bs33/base/vol) = mount %d (%s), want nothing found: the path resolves inside tmpOVER",
			got.ID, got.Source)
	}

	// The covered ancestor's own path still resolves — to the mount on top of it.
	got, ok := EntryAt(after, "/tmp/bs33/base")
	if !ok || got.ID != 626 {
		t.Errorf("EntryAt(/tmp/bs33/base) = %d,%v, want the covering mount 626", got.ID, ok)
	}
}

// TestEntryAtFollowsTheTreeWhenFileOrderDisagrees: the last record naming /tmp/bs33/y is underneath.
func TestEntryAtFollowsTheTreeWhenFileOrderDisagrees(t *testing.T) {
	entries := mustParse(t, movedOnTopTable)
	got, ok := EntryAt(entries, "/tmp/bs33/y")
	if !ok {
		t.Fatal("EntryAt found nothing at /tmp/bs33/y")
	}
	if got.ID != 624 {
		t.Errorf("EntryAt(/tmp/bs33/y) = mount %d (%s), want 624 (tmpEARLY) — the record listed FIRST is the one on top",
			got.ID, got.Source)
	}
}

// TestVisibleMountPointsForReportsABindOfACoveredMountUnderTheCoveringDevice: a bind of a covered path binds the covering device.
func TestVisibleMountPointsForReportsABindOfACoveredMountUnderTheCoveringDevice(t *testing.T) {
	const boundTable = `562 438 252:1 / / rw,relatime - ext4 /dev/mapper/vgmint-root rw,errors=remount-ro
624 562 0:76 / /tmp/bs33/base rw,relatime - tmpfs tmpBASE rw,size=1024k,uid=1000,gid=1000,inode64
625 624 0:87 / /tmp/bs33/base/vol rw,relatime - tmpfs tmpVOL rw,size=1024k,uid=1000,gid=1000,inode64
626 625 0:88 / /tmp/bs33/base/vol rw,relatime - tmpfs tmpVOL2 rw,size=1024k,uid=1000,gid=1000,inode64
684 562 0:88 / /tmp/bs33/other rw,relatime - tmpfs tmpVOL2 rw,size=1024k,uid=1000,gid=1000,inode64
`
	entries := mustParse(t, boundTable)

	got := VisibleMountPointsFor(entries, 0, 88)
	if len(got) != 2 || got[0] != "/tmp/bs33/base/vol" || got[1] != "/tmp/bs33/other" {
		t.Errorf("VisibleMountPointsFor(0:88 tmpVOL2) = %v, want both its own mount point and the bind, in kernel order", got)
	}
	if got := VisibleMountPointsFor(entries, 0, 87); len(got) != 0 {
		t.Errorf("VisibleMountPointsFor(0:87 tmpVOL) = %v, want none: binding its path bound what covers it, not it", got)
	}
}

// TestVisibilitySeparatesTwoRecordsOnOnePathByTheirAncestorChain: the kernel placed the file in tmpVOL2, the mount this reports.
func TestVisibilitySeparatesTwoRecordsOnOnePathByTheirAncestorChain(t *testing.T) {
	entries := mustParse(t, compositeOvermountTable)

	// The fixture is only interesting while the two records on that path are
	// unrelated in the tree; a future edit that made one the other's parent
	// would turn this into the equal-path case, which is tested elsewhere.
	vol, vol2 := entries[2], entries[4]
	if vol.MountPoint != vol2.MountPoint {
		t.Fatalf("records %d and %d name %q and %q, want one path", vol.ID, vol2.ID, vol.MountPoint, vol2.MountPoint)
	}
	if vol.ParentID == vol2.ID || vol2.ParentID == vol.ID {
		t.Fatalf("records %d and %d are parent and child, so the tree separates them directly and this test is not the case it claims", vol.ID, vol2.ID)
	}

	if got := hiddenMountIDs(entries); !sameIDs(got, []uint32{624, 625}) {
		t.Errorf("hidden mounts = %v, want the covered base 624 and the tmpVOL 625 beneath it — and NOT 684, which is reached through the covering mount", got)
	}
	if got := VisibleMountPointsFor(entries, 0, 87); len(got) != 0 {
		t.Errorf("VisibleMountPointsFor(0:87 tmpVOL) = %v, want none: its ancestor /tmp/bs33c/base was mounted over", got)
	}
	if got := VisibleMountPointsFor(entries, 0, 89); len(got) != 2 || got[0] != "/tmp/bs33c/base/vol" || got[1] != "/tmp/bs33c/bindtarget" {
		t.Errorf("VisibleMountPointsFor(0:89 tmpVOL2) = %v, want its own mount point and the bind of it, in kernel order", got)
	}
	if got := VisibleMountPointsFor(entries, 0, 88); len(got) != 1 || got[0] != "/tmp/bs33c/base" {
		t.Errorf("VisibleMountPointsFor(0:88 tmpOVER) = %v, want /tmp/bs33c/base", got)
	}

	got, ok := EntryAt(entries, "/tmp/bs33c/base/vol")
	if !ok || got.ID != 684 {
		t.Errorf("EntryAt(/tmp/bs33c/base/vol) = %d,%v, want 684 (tmpVOL2) — the one reached through the covering mount", got.ID, ok)
	}
}

// mountPointStringRule is the previous last-record-wins rule, kept to show the tree rule gives a different answer.
func mountPointStringRule(entries []Entry, major, minor uint32) []string {
	top := make(map[string]Entry, len(entries))
	var order []string
	for _, e := range entries {
		if _, seen := top[e.MountPoint]; !seen {
			order = append(order, e.MountPoint)
		}
		top[e.MountPoint] = e
	}

	var targets []string
	for _, mountPoint := range order {
		if e := top[mountPoint]; e.Major == major && e.Minor == minor {
			targets = append(targets, mountPoint)
		}
	}
	return targets
}

// TestTheStringRuleCallsAnAncestorOvermountVisible shows the string rule wrongly reports the covered volume visible.
func TestTheStringRuleCallsAnAncestorOvermountVisible(t *testing.T) {
	entries := mustParse(t, ancestorOvermountTable)

	old := mountPointStringRule(entries, 0, 87)
	if len(old) != 1 || old[0] != "/tmp/bs33/base/vol" {
		t.Fatalf("the replaced rule reported %v; this test is built on it reporting /tmp/bs33/base/vol, so it no longer demonstrates the defect", old)
	}

	now := VisibleMountPointsFor(entries, 0, 87)
	if len(now) != 0 {
		t.Errorf("VisibleMountPointsFor = %v, want none — the old rule already returns %v, so this test passes either way unless the answers differ", now, old)
	}
}

// TestTheStringRuleInvertsBothAnswersAfterAMountMove is the second difference,
// and the worse one: on the moved-on-top table the old rule does not merely
// miss a covered mount, it names the covered mount as visible and the covering
// mount as hidden. Unmounting on that answer detaches the wrong filesystem
// rather than failing.
func TestTheStringRuleInvertsBothAnswersAfterAMountMove(t *testing.T) {
	entries := mustParse(t, movedOnTopTable)

	if old := mountPointStringRule(entries, 0, 76); len(old) != 0 {
		t.Fatalf("the replaced rule reported tmpEARLY at %v; this test is built on it reporting none", old)
	}
	if old := mountPointStringRule(entries, 0, 87); len(old) != 1 || old[0] != "/tmp/bs33/y" {
		t.Fatalf("the replaced rule reported tmpLATE at %v; this test is built on it reporting /tmp/bs33/y", old)
	}

	if now := VisibleMountPointsFor(entries, 0, 76); len(now) != 1 || now[0] != "/tmp/bs33/y" {
		t.Errorf("VisibleMountPointsFor(0:76 tmpEARLY) = %v, want /tmp/bs33/y — the old rule says none, so agreeing with it is the bug", now)
	}
	if now := VisibleMountPointsFor(entries, 0, 87); len(now) != 0 {
		t.Errorf("VisibleMountPointsFor(0:87 tmpLATE) = %v, want none — the old rule says /tmp/bs33/y, so agreeing with it is the bug", now)
	}
}

// TestTheStringRuleAndTheTreeRuleAgreeOnAnOrdinaryHost is the other half of the
// comparison, and the one that says the change is a correction rather than a
// different set of wrong answers. On a table with no ancestor overmount and no
// moved mount, the two rules must return the same thing for every device in it.
func TestTheStringRuleAndTheTreeRuleAgreeOnAnOrdinaryHost(t *testing.T) {
	entries := mustParse(t, ordinaryHostTable)

	seen := make(map[[2]uint32]bool, len(entries))
	for _, e := range entries {
		device := [2]uint32{e.Major, e.Minor}
		if seen[device] {
			continue
		}
		seen[device] = true

		old := mountPointStringRule(entries, e.Major, e.Minor)
		now := VisibleMountPointsFor(entries, e.Major, e.Minor)
		if strings.Join(old, "\x00") != strings.Join(now, "\x00") {
			t.Errorf("device %d:%d: tree rule = %v, string rule = %v; they must agree on a table with nothing overmounted above anything",
				e.Major, e.Minor, now, old)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("compared %d devices, so the comparison proved nothing", len(seen))
	}
}
