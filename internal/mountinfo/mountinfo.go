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

// Package mountinfo reads the kernel's mount table from /proc/self/mountinfo.
//
// It replaces asking findmnt. findmnt is a formatter over this same file, so
// going to the file directly removes a process, a JSON round trip, and a
// dependency on which util-linux is installed — the last of which mattered:
// findmnt's escaping of a path varies by flag and version, and a mount point
// that came back spelled differently than it went in silently failed to match.
//
// It also removes a worse ambiguity. findmnt has exactly one non-zero exit and
// its manual gives that status to "nothing matched" and "any other error"
// alike, so a findmnt that could not read the mount table at all was
// indistinguishable from a device that is not mounted — and "not mounted" is
// the answer a teardown acts on immediately before destroying a volume. Reading
// the file has no such gap: it opens and parses, or it fails and says why.
//
// Identity here is the device number rather than a path. Field 3 of each record
// is the mounted device's major:minor, which is the same whichever of a
// device's several names was used to mount it — /dev/<vg>/<lv>,
// /dev/mapper/<vg>-<lv>, or the /dev/dm-N underneath. Comparing those strings
// was the source of the spelling problem; comparing device numbers does not
// have one.
//
// The table is a TREE, not a list. Each record names its own mount id and its
// parent's, and which mounts a walk to a path crosses is a fact about that tree
// — not about the mount-point strings, and not about the order of the records.
// Both of those shortcuts were measured against a running kernel and both give
// wrong answers; see VisibleMountPointsFor.
package mountinfo

import (
	"bufio"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
)

// ProcPath is the kernel file this package reads.
//
// self rather than a pid: the table is per mount namespace, and the one this
// process sees is the one its mounts land in.
const ProcPath = "/proc/self/mountinfo"

// Entry is one mounted filesystem.
type Entry struct {
	// ID is the kernel's identity for this MOUNT — not for the filesystem and
	// not for the device, both of which several mounts can share.
	//
	// It is what distinguishes one mount of a device at a path from a SECOND
	// mount of the same device at the same path, which (device, path) cannot.
	// A mount that has been unmounted and remade has a different ID, so an ID
	// that still matches is evidence the mount is the same one and not a
	// replacement made in the meantime.
	ID uint32

	// ParentID is the ID of the mount this one is mounted ON — the mount owning
	// the directory it covers. It is the edge that makes the table a tree, and
	// the tree is the only thing that says which mounts a walk to a path
	// crosses.
	//
	// It is not recoverable from the mount points. A parent's mount point is a
	// path prefix of its child's, but so are the mount points of many records
	// that are not the parent, and prefix matching cannot tell them apart —
	// measured on an ordinary 28-record host, a prefix rule flags 6 pairs as
	// covered with nothing overmounted at all. Reading the edge the kernel
	// wrote has no such failure mode.
	//
	// A record whose ParentID names no record in the table is the root of what
	// this table can see: the file shows one mount namespace, and that
	// namespace's root mount hangs off a mount outside it. That is normal, not
	// an error — an ordinary host's root record reads "562 438 ..." with no
	// record 438 anywhere in the file.
	ParentID uint32

	// Major and Minor identify the mounted device. They are the stable identity
	// of a mount, unlike Source, which is whatever name it was mounted under.
	Major uint32
	Minor uint32

	// Root is the subtree of the filesystem that is mounted, "/" for a whole
	// filesystem and something deeper for a bind mount.
	Root string

	// MountPoint is where it is mounted, with the kernel's escaping undone.
	MountPoint string

	// FSType is the filesystem type, as the kernel names it.
	FSType string

	// Source is the mount source field — a device path for a block-backed
	// filesystem, and something arbitrary otherwise. Present for diagnostics;
	// match on Major and Minor instead.
	Source string

	// Propagation is how mount and unmount events cross this mount into other
	// namespaces, read from the optional fields.
	Propagation Propagation
}

// Propagation is a mount's propagation state — the optional fields between the
// mount options and the "-" separator.
//
// It decides whether a mount made here is VISIBLE anywhere else. A mount under
// a private parent exists only in the namespace that made it: a workload in
// another mount namespace walks to the path and finds the directory it was
// before anything was mounted on it, with no error at any layer. That is why
// the fields are parsed rather than skipped — they are the difference between
// a working handoff and an empty directory nobody is told about.
type Propagation struct {
	// Shared reports the "shared:N" field: this mount belongs to a peer group
	// and propagates its events to the rest of it. This is what a handoff to
	// another namespace requires.
	Shared bool

	// PeerGroup is the N of "shared:N", meaningful only when Shared is set.
	PeerGroup uint32

	// Slave reports the "master:N" field: this mount RECEIVES events from peer
	// group N. A mount can be both shared and a slave.
	Slave bool

	// MasterGroup is the N of "master:N", meaningful only when Slave is set.
	MasterGroup uint32

	// Unbindable reports the "unbindable" field: this mount cannot be bind
	// mounted at all, which makes it unusable for a handoff by construction.
	Unbindable bool
}

// Private reports a mount that propagates nothing: no peer group, no master.
//
// It is the default state of a mount in most namespaces and the one that fails
// silently, so it is named rather than left as the absence of the others.
func (p Propagation) Private() bool { return !p.Shared && !p.Slave && !p.Unbindable }

// String renders the propagation the way /proc/self/mountinfo spells it, which
// is what an operator will compare against when they go and look.
func (p Propagation) String() string {
	if p.Unbindable {
		return "unbindable"
	}
	var parts []string
	if p.Shared {
		parts = append(parts, "shared:"+utoa(p.PeerGroup))
	}
	if p.Slave {
		parts = append(parts, "master:"+utoa(p.MasterGroup))
	}
	if len(parts) == 0 {
		return "private"
	}
	return strings.Join(parts, " ")
}

// Load reads and parses the kernel's mount table.
func Load() ([]Entry, error) {
	f, err := os.Open(ProcPath)
	if err != nil {
		return nil, &ReadError{Path: ProcPath, Err: err}
	}
	defer func() { _ = f.Close() }()

	return Parse(f)
}

// Parse reads a mount table in /proc/self/mountinfo format.
//
// The format is positional up to a "-" separator whose position varies, because
// the optional fields between the mount options and the separator are a
// variable-length list. Everything before the separator is counted from the
// left, everything after it from the separator — which is why this cannot be a
// fixed field split.
func Parse(r io.Reader) ([]Entry, error) {
	var entries []Entry

	scanner := bufio.NewScanner(r)
	// Mount points can be long, and the default 64KiB token limit would turn a
	// deep path into a parse failure on an otherwise healthy table.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}

		entry, err := parseLine(text)
		if err != nil {
			return nil, &ParseError{Line: line, Text: text, Err: err}
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, &ReadError{Path: ProcPath, Err: err}
	}
	return entries, nil
}

// minFieldsBeforeSeparator is how many fixed fields precede the optional ones:
// mount id, parent id, major:minor, root, mount point, mount options.
const minFieldsBeforeSeparator = 6

// separator divides the fixed fields from the ones counted from the right.
const separator = "-"

// parseLine reads one record.
func parseLine(text string) (Entry, error) {
	fields := strings.Fields(text)
	if len(fields) < minFieldsBeforeSeparator {
		return Entry{}, errTooFewFields
	}

	// The optional fields are variable in number, so the separator is found
	// rather than assumed. Everything after it is positional again.
	sep := -1
	for i := minFieldsBeforeSeparator; i < len(fields); i++ {
		if fields[i] == separator {
			sep = i
			break
		}
	}
	if sep < 0 {
		return Entry{}, errNoSeparator
	}
	// After the separator: filesystem type, mount source, super options — three
	// fields, so the last of them is at sep+3 and the record needs sep+4 in
	// total. Counting to sep+3 accepted a record with the super options missing,
	// which is a table this parser cannot vouch for; a mount table that is not
	// the format it claims to be must be refused rather than half-read, because
	// what a caller does with a partial answer is destroy a volume.
	if len(fields) < sep+4 {
		return Entry{}, errTruncatedAfterSeparator
	}

	major, minor, err := parseDeviceNumber(fields[2])
	if err != nil {
		return Entry{}, err
	}
	id, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return Entry{}, errMalformedMountID
	}
	// The parent id is refused rather than defaulted, for the reason the super
	// options are: a record whose tree edge could not be read is a record whose
	// visibility cannot be decided, and a zero substituted here would make it
	// look like a record with no parent — the one shape that is treated as the
	// top of the table and therefore always reachable. Failing open on a field
	// the format guarantees is how a wrong answer gets a confident one.
	parentID, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return Entry{}, errMalformedParentID
	}

	return Entry{
		ID:          uint32(id),
		ParentID:    uint32(parentID),
		Major:       major,
		Minor:       minor,
		Root:        unescape(fields[3]),
		MountPoint:  unescape(fields[4]),
		FSType:      unescape(fields[sep+1]),
		Source:      unescape(fields[sep+2]),
		Propagation: parsePropagation(fields[minFieldsBeforeSeparator:sep]),
	}, nil
}

// parsePropagation reads the optional fields.
//
// They are a variable-length list of tags, which is why the separator has to be
// found rather than counted to, and an unrecognized tag is IGNORED rather than
// rejected: the kernel is free to add one, and a parser that refused a record
// over a tag it did not know would fail closed on a mount table that is
// perfectly valid. The fields this reads are fixed by the format and the ones
// it does not recognize say nothing about propagation.
func parsePropagation(optional []string) Propagation {
	var p Propagation
	for _, field := range optional {
		tag, value, hasValue := strings.Cut(field, ":")
		switch {
		case tag == "unbindable":
			p.Unbindable = true
		case tag == "shared" && hasValue:
			if n, err := strconv.ParseUint(value, 10, 32); err == nil {
				p.Shared, p.PeerGroup = true, uint32(n)
			}
		case tag == "master" && hasValue:
			if n, err := strconv.ParseUint(value, 10, 32); err == nil {
				p.Slave, p.MasterGroup = true, uint32(n)
			}
		}
	}
	return p
}

// utoa keeps Propagation.String free of a fmt dependency, for the reason the
// errors in this package are free of one.
func utoa(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

// parseDeviceNumber reads the "major:minor" field.
//
// The numbers are DECIMAL here, which is worth stating because the obvious way
// to obtain the same pair for comparison — stat's %t:%T — prints them in hex.
// Reading one as the other silently matches the wrong device.
func parseDeviceNumber(field string) (uint32, uint32, error) {
	majorText, minorText, found := strings.Cut(field, ":")
	if !found {
		return 0, 0, errMalformedDeviceNumber
	}

	major, err := strconv.ParseUint(majorText, 10, 32)
	if err != nil {
		return 0, 0, errMalformedDeviceNumber
	}
	minor, err := strconv.ParseUint(minorText, 10, 32)
	if err != nil {
		return 0, 0, errMalformedDeviceNumber
	}
	return uint32(major), uint32(minor), nil
}

// unescape undoes the octal escaping the kernel applies to the path-like
// fields.
//
// The kernel escapes exactly four characters — space, tab, newline and
// backslash — as three-digit octal, because the format is whitespace-separated
// and a raw space would end the field early. Leaving them escaped is not a
// cosmetic problem: a caller comparing a mount point against the path it asked
// for gets no match for "/mnt/my data", and concludes the volume is not
// mounted.
func unescape(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}

	var out strings.Builder
	out.Grow(len(field))

	for i := 0; i < len(field); i++ {
		if field[i] != '\\' || i+3 >= len(field) {
			out.WriteByte(field[i])
			continue
		}
		value, err := strconv.ParseUint(field[i+1:i+4], 8, 8)
		if err != nil {
			// Not an escape this format produces; the backslash is literal.
			out.WriteByte(field[i])
			continue
		}
		out.WriteByte(byte(value))
		i += 3
	}
	return out.String()
}

// MountPointsFor returns every path the given device is mounted at, in the
// order the kernel lists them.
func MountPointsFor(entries []Entry, major, minor uint32) []string {
	var targets []string
	for _, e := range entries {
		if e.Major == major && e.Minor == minor {
			targets = append(targets, e.MountPoint)
		}
	}
	return targets
}

// ambiguousID marks a mount id claimed by more than one record, which no
// kernel-produced table contains and which therefore identifies nothing.
const ambiguousID = -1

// indexByID maps each mount id to its record.
//
// An id that appears twice is recorded as ambiguous rather than resolved to
// either claimant. A tree edge into an ambiguous id is followed nowhere, which
// makes the record look parentless and so REACHABLE — the fail-open direction,
// chosen because the cost of the two errors is not symmetric: a mount wrongly
// called hidden is a volume Delete refuses with no way past it, while a mount
// wrongly called reachable is the behavior callers already have today.
func indexByID(entries []Entry) map[uint32]int {
	byID := make(map[uint32]int, len(entries))
	for i, e := range entries {
		if _, seen := byID[e.ID]; seen {
			byID[e.ID] = ambiguousID
			continue
		}
		byID[e.ID] = i
	}
	return byID
}

// parentOf returns the index of a record's parent, and whether there is one to
// follow.
//
// Three shapes are not edges, and all three end the chain the same way — as the
// top of what this table describes, which leaves the record reachable:
//
//   - A parent id naming NO record. Every mount namespace's root has it; the
//     file shows one namespace and its root hangs off a mount outside it.
//   - A parent id claimed by more than one record, which identifies nothing.
//   - A record that is its OWN parent. Not a shape a kernel writes, but Parse
//     is fed text; it is also what an Entry built in code rather than parsed
//     looks like, since a zero-valued Entry has ID and ParentID both zero.
//     Following that edge would make such a record its own ancestor, and
//     covering its own mount point, so a table assembled by a caller would
//     report every one of its mounts hidden.
func parentOf(entries []Entry, byID map[uint32]int, i int) (int, bool) {
	p, ok := byID[entries[i].ParentID]
	if !ok || p == ambiguousID || p == i {
		return 0, false
	}
	return p, true
}

// topAtOwnMountPoint marks, for each record, whether it is the mount that a
// walk arriving at its mount point lands on — assuming the walk gets there at
// all, which is the separate question reachableAt answers.
//
// Two rules, in this order.
//
// The TREE rule: a record is covered when another record is its CHILD mounted
// at its own mount point. That is what the kernel writes when a directory that
// already has a mount on it is mounted over — path lookup follows into the
// mount that is there, so the new mount's parent is the mount it covers and its
// mount point renders as the same string. Measured, mounting tmpfs over an
// existing tmpfs at /tmp/bs33/x gives "624 562 ... /tmp/bs33/x" followed by
// "625 624 ... /tmp/bs33/x": parent 624, same path. This rule states the
// covering relation the kernel itself recorded, so it neither invents one nor
// misses one.
//
// The ORDER rule, applied only to records the tree rule left standing: among
// records naming one mount point, the last in the table wins. This is the rule
// this function used to apply alone. It is kept because a table can be built in
// code rather than parsed — an Entry with no ids has no tree to consult — and
// because two records on one path with no edge between them would otherwise
// both be called visible, which is the dangerous direction: it would hand
// umount(2) a path where this device is not on top.
//
// The order rule is second rather than first because file order is not mount
// order. mount --move re-parents a mount and leaves its record where it was:
// moving the first-created of two mounts on top of the second produces
// "624 625 ... /y" BEFORE "625 562 ... /y", where the record listed first is
// the one on top. Reading order alone there names the wrong filesystem, in both
// directions at once.
//
// The order rule cannot then wrongly hide the survivor of an ancestor
// overmount. Two records can share a mount point with no edge between them —
// one under a mount that was covered, the other under the mount that covered it
// — and there the earlier record is always the covered one: the later mount
// exists only because the cover was already in place, and a mount made at that
// path after the cover lands INSIDE the covering filesystem and takes it for a
// parent. Measured on a live kernel; the table is compositeOvermountTable.
func topAtOwnMountPoint(entries []Entry, byID map[uint32]int) []bool {
	top := make([]bool, len(entries))
	for i := range top {
		top[i] = true
	}

	for i := range entries {
		p, ok := parentOf(entries, byID, i)
		if ok && entries[p].MountPoint == entries[i].MountPoint {
			top[p] = false
		}
	}

	lastAtPath := make(map[string]int, len(entries))
	for i, e := range entries {
		if top[i] {
			lastAtPath[e.MountPoint] = i
		}
	}
	for i, e := range entries {
		if top[i] && lastAtPath[e.MountPoint] != i {
			top[i] = false
		}
	}
	return top
}

// The states a record passes through while its reachability is resolved.
const (
	unresolved uint8 = iota
	resolving
	isReachable
	isHidden
)

// stackBase climbs from a record to the BOTTOM of the stack sharing its mount
// point, and is the distinction between "an ancestor" and "an ancestor in the
// way".
//
// Mounting over a mount point that already has a mount on it makes the new
// mount a CHILD of the one it covers, at the same mount point — measured, not
// assumed. So the covering mount's own parent is a mount that is, correctly,
// not top at its mount point. A walk to that path does not traverse the covered
// mount and then the covering one; it arrives at the path once and lands on the
// top of the stack. Treating the stack below as ancestors to check would hide
// every mount that is on top of anything, which is the opposite of the truth.
//
// The climb is bounded by the size of the table because a cycle cannot come
// from a kernel but can come from text.
func stackBase(entries []Entry, byID map[uint32]int, i int) int {
	for steps := 0; steps <= len(entries); steps++ {
		p, ok := parentOf(entries, byID, i)
		if !ok || entries[p].MountPoint != entries[i].MountPoint {
			return i
		}
		i = p
	}
	return i
}

// reachableAt marks, for each record, whether its mount point PATH resolves to
// it — which is the question umount(2) turns on, since it detaches whatever the
// path it is handed resolves to.
//
// A record is reachable when it is top at its own mount point AND the mount its
// stack hangs off is itself reachable, applied all the way up. The chain of
// parents is exactly the set of mounts a walk down the path crosses, which is
// why it is the right chain and a path-prefix scan is not: the kernel renders
// each mount point as a full path from the process root by walking that same
// chain, so a parent's mount point is always a prefix of its child's — but the
// converse does not hold, and prefix matching flags unrelated mounts.
//
// This is what catches the case a comparison of mount points cannot: a volume
// at /mnt/base/vol with another filesystem later mounted at /mnt/base. No
// second record names /mnt/base/vol, so nothing about that path has changed —
// but /mnt/base now has a child mounted at /mnt/base, so the volume's parent is
// not top at its own mount point, and the volume is not reachable.
//
// A chain ends at a record with no parent in the table, which is normal: the
// file describes one mount namespace and its root mount hangs off a mount
// outside it. A chain that loops — impossible from a kernel, reachable from
// hand-written text — ends there too, and is treated as reachable rather than
// left to recurse: refusing to unmount a volume over a malformed table would
// leave an operator with no way forward.
func reachableAt(entries []Entry, byID map[uint32]int, top []bool) []bool {
	state := make([]uint8, len(entries))
	chain := make([]int, 0, len(entries))

	for start := range entries {
		if state[start] != unresolved {
			continue
		}

		chain = chain[:0]
		verdict := isReachable
		for i := start; ; {
			if s := state[i]; s != unresolved {
				// Either an answer computed on an earlier walk, which the whole
				// chain below it inherits, or the walk meeting itself.
				verdict = s
				if s == resolving {
					verdict = isReachable
				}
				break
			}
			state[i] = resolving
			chain = append(chain, i)

			if !top[i] {
				verdict = isHidden
				break
			}
			p, ok := parentOf(entries, byID, stackBase(entries, byID, i))
			if !ok {
				break
			}
			i = p
		}

		// Everything walked shares the verdict: each was top at its own mount
		// point, so a hidden ancestor hides all of them and a reachable one
		// leaves all of them reachable.
		for _, i := range chain {
			state[i] = verdict
		}
	}

	reachable := make([]bool, len(entries))
	for i, s := range state {
		reachable[i] = s == isReachable
	}
	return reachable
}

// visibility reports, per record, whether that mount is what its mount point
// resolves to.
func visibility(entries []Entry) []bool {
	byID := indexByID(entries)
	return reachableAt(entries, byID, topAtOwnMountPoint(entries, byID))
}

// VisibleMountPointsFor returns the paths where the device is the filesystem
// that is CURRENTLY VISIBLE, which is a smaller set than MountPointsFor.
//
// A mount can stop being what a path resolves to without going anywhere. Mount
// over an occupied directory and both records stay in the table; the one a
// process walking there reaches is the new one. The earlier mount is still
// mounted and still this device's — MountPointsFor is right to report it — but
// it is hidden, and that distinction decides who gets unmounted: umount(2)
// takes a path and detaches whatever is visible at it. Handing it a path where
// this device has been covered unmounts SOMEBODY ELSE'S filesystem while
// leaving this one exactly where it was.
//
// So anything that unmounts by path asks this, and anything asking "is it
// mounted at all" — a teardown deciding whether the volume is busy, a status —
// asks MountPointsFor, where a hidden mount still counts.
//
// Visibility is decided from the mount TREE, which catches two cases that
// comparing mount points cannot:
//
//   - An ANCESTOR overmount. This volume at /mnt/base/vol, another filesystem
//     later mounted at /mnt/base. The volume is no longer reachable by that
//     path and no second record names it, so no comparison of mount-point
//     strings can see it.
//   - A mount re-parented by mount --move, which leaves the record where it was
//     in the file. The covering mount can then be listed FIRST, and "the last
//     record on a path wins" names the wrong filesystem.
//
// The shortcut this deliberately does not take is treating a later record whose
// mount point is a path PREFIX of this one as covering it. That was measured
// against an ordinary host's 28-record table: it flags 6 pairs with nothing
// overmounted at all, and 4 of the host's records list their parent after
// themselves, so order does not rescue it either. Every one of those is a
// volume Delete would refuse to remove with no way for an operator past it. The
// tree rule flags exactly one pair on that same host — a real double mount of
// /proc/sys/fs/binfmt_misc, which the old string rule found too.
//
// A bind mount is a separate record with its own place in the tree, so it gets
// its own answer; binding a path reaches whatever is visible there, so a bind
// of a covered mount is a mount of the COVERING device, and this reports it
// under that device rather than this one. A mount that was moved is reported
// where it is now, because the table describes the tree as it stands.
//
// The paths returned are the kernel's, in the kernel's order.
func VisibleMountPointsFor(entries []Entry, major, minor uint32) []string {
	visible := visibility(entries)

	var targets []string
	for i, e := range entries {
		if visible[i] && e.Major == major && e.Minor == minor {
			targets = append(targets, e.MountPoint)
		}
	}
	return targets
}

// EntryAt returns the mount that a path resolves to.
//
// It answers from the mount tree, for the reasons VisibleMountPointsFor does:
// the record a path reaches is the one that is top at that mount point with an
// unbroken chain of top mounts above it, which is neither "the last record
// naming the path" nor "the last record whose path is a prefix".
//
// A path whose every record is hidden behind an overmounted ancestor reports
// NOTHING found, which is the honest answer: a walk to that path does not reach
// any of them. It lands inside the covering filesystem, where either something
// else is mounted — with its own record, which this would find — or nothing is.
func EntryAt(entries []Entry, mountPoint string) (Entry, bool) {
	visible := visibility(entries)

	found := false
	var match Entry
	for i, e := range entries {
		if visible[i] && e.MountPoint == mountPoint {
			match, found = e, true
		}
	}
	return match, found
}

// Table is the seam through which a provider asks what is mounted.
//
// It exists for the same reason the mount and command seams do: the answers
// come from the running kernel, and a test that cannot substitute them can only
// run on a host that happens to have the right things mounted. Behind it,
// System reads /proc/self/mountinfo.
// Every method takes and returns universal types on purpose. The providers
// alias this interface into their public API (local.MountTable,
// drbd.MountTable), and an interface whose signatures name a type from an
// internal package is one no caller outside this module can implement — the
// seam would be exported and unusable.
type Table interface {
	// MountPointsFor returns every path the block device is mounted at, in the
	// order the kernel lists them, INCLUDING paths where it has since been
	// over-mounted and is no longer what is visible there. A device that is not
	// mounted yields no paths and no error; only a table that could not be read
	// is an error.
	//
	// This is the question "is it mounted at all", which is what a teardown
	// deciding whether a volume is busy has to ask.
	MountPointsFor(ctx context.Context, device string) ([]string, error)

	// VisibleMountPointsFor returns the paths where the device is the
	// filesystem currently visible, which is the question anything unmounting
	// by path has to ask: umount(2) detaches what is visible at the path it is
	// given, so a path where this device has been over-mounted would unmount
	// somebody else's filesystem.
	//
	// Covered means covered by anything on the way: a mount over the path
	// itself, or a mount over any DIRECTORY ABOVE it, which takes the path out
	// of reach without leaving a second record naming it.
	VisibleMountPointsFor(ctx context.Context, device string) ([]string, error)
}

// PropagationReader is the OPTIONAL half of the mount-table seam: it answers
// whether a mount can be seen outside the namespace that made it.
//
// It is separate from Table rather than another method on it because a caller
// that injects its own mount table should not have to implement a method for a
// guard it never turns on. Adding it to Table would stop such a caller
// compiling over a feature left at its default. A provider that needs it asks
// for it with a type assertion, and REFUSES when the table it was given cannot
// answer — an optional interface that silently degraded would be the
// guard-that-passes-when-it-cannot-check, which is the failure the guard exists
// to remove.
type PropagationReader interface {
	// PropagationOf reports the propagation of the mount that DEVICE has
	// visible at mountPoint, and the kernel's identity for that mount instance.
	//
	// It asks about a specific device at a specific path rather than about
	// whatever is at the path, because those are different questions in exactly
	// the case that matters. Another process can mount over the path in the
	// window after mount(2) returns, and a guard that read "the propagation at
	// this path" would then read the INTERLOPER's propagation — so a private
	// mount passes because something shared landed on top of it. Naming the
	// device makes that a refusal instead: ErrNotVisibleThere.
	//
	// The returned id identifies the mount instance. A caller that will act on
	// this mount later — to unmount it — compares the id it saw then against
	// the id it sees now, which is the only way to tell its own mount from a
	// SECOND mount of the same device stacked on the same path.
	//
	// A path with nothing mounted at it is ErrNotMounted rather than a false:
	// absence is not an answer about propagation, and a guard that read it as
	// one would pass the case where the mount is missing entirely. A path whose
	// mounts are all behind an overmounted ancestor reports ErrNotMounted too,
	// because a walk to that path reaches none of them.
	//
	// The DECISION about what counts as propagating is made here rather than by
	// the caller, because two call sites deciding it separately is how they end
	// up with two answers to one question.
	PropagationOf(ctx context.Context, device, mountPoint string) (id uint32, propagates bool, spelling string, err error)
}

// System is the Table backed by the running kernel.
type System struct{}

// MountPointsFor reads the mount table and returns this device's mount points.
//
// The device is resolved to its major:minor first, so a mount made under any of
// the device's names is found: /dev/<vg>/<lv>, /dev/mapper/<vg>-<lv> and the
// /dev/dm-N beneath them are one device and the kernel records the number.
func (System) MountPointsFor(ctx context.Context, device string) ([]string, error) {
	entries, major, minor, err := readFor(ctx, device)
	if err != nil {
		return nil, err
	}
	return MountPointsFor(entries, major, minor), nil
}

// VisibleMountPointsFor reads the mount table and returns the paths where this
// device is the filesystem visible there.
func (System) VisibleMountPointsFor(ctx context.Context, device string) ([]string, error) {
	entries, major, minor, err := readFor(ctx, device)
	if err != nil {
		return nil, err
	}
	return VisibleMountPointsFor(entries, major, minor), nil
}

// PropagationOf reads the mount table and reports how this device's mount at
// mountPoint propagates, and which mount instance it is.
//
// "Propagates" means shared: the mount belongs to a peer group and its events
// reach the other members. A private mount is invisible outside the namespace
// that made it, and an unbindable one cannot be handed over at all. A mount
// that is only a slave RECEIVES events and does not send them, so it does not
// carry a handoff either — which is why the answer is not "has any optional
// field".
//
// The VISIBLE mount at the path is the one asked about, and it must be this
// device's. A path where something else is on top is ErrNotVisibleThere rather
// than an answer about that other thing.
func (System) PropagationOf(ctx context.Context, device, mountPoint string) (uint32, bool, string, error) {
	entries, major, minor, err := readFor(ctx, device)
	if err != nil {
		return 0, false, "", err
	}

	entry, ok := EntryAt(entries, mountPoint)
	if !ok {
		return 0, false, "", &MountPointError{MountPoint: mountPoint, Err: ErrNotMounted}
	}
	if entry.Major != major || entry.Minor != minor {
		return 0, false, "", &MountPointError{MountPoint: mountPoint, Err: ErrNotVisibleThere}
	}
	return entry.ID, entry.Propagation.Shared, entry.Propagation.String(), nil
}

// readFor resolves a device to its number and reads the table, which is what
// both lookups do before they differ.
func readFor(ctx context.Context, device string) ([]Entry, uint32, uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, 0, &ReadError{Path: ProcPath, Err: err}
	}

	major, minor, err := DeviceNumber(device)
	if err != nil {
		return nil, 0, 0, err
	}
	entries, err := Load()
	if err != nil {
		return nil, 0, 0, err
	}
	return entries, major, minor, nil
}
