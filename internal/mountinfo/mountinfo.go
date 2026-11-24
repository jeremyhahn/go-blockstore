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

// Package mountinfo reads the mount table from /proc/self/mountinfo, identifying devices by number and visibility by the mount tree.
package mountinfo

import (
	"bufio"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
)

// ProcPath is the kernel file this package reads, for this process's mount namespace.
const ProcPath = "/proc/self/mountinfo"

// Entry is one mounted filesystem.
type Entry struct {
	// ID is the kernel's identity for this mount, distinct for a second mount of the same device at the same path.
	ID uint32

	// ParentID is the ID of the mount this one is mounted on; a ParentID naming no record is the namespace root.
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

// Propagation is a mount's propagation state, from the optional fields before the "-" separator.
type Propagation struct {
	// Shared reports the "shared:N" field: this mount belongs to a peer group
	// and propagates its events to the rest of it. This is what a handoff to
	// another namespace requires.
	Shared bool

	// PeerGroup is the N of "shared:N", meaningful only when Shared is set.
	PeerGroup uint32

	// Slave reports the "master:N" field: this mount receives events from peer group N.
	Slave bool

	// MasterGroup is the N of "master:N", meaningful only when Slave is set.
	MasterGroup uint32

	// Unbindable reports the "unbindable" field: this mount cannot be bind
	// mounted at all, which makes it unusable for a handoff by construction.
	Unbindable bool
}

// Private reports a mount that propagates nothing: no peer group, no master.
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

// Parse reads a mount table in /proc/self/mountinfo format; fields after the variable-position separator are counted from it.
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
	// After the separator: filesystem type, source and super options; a record missing any is refused.
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
	// An unreadable parent ID is refused, never defaulted to zero.
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

// parsePropagation reads the optional fields, ignoring unknown tags.
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

// parseDeviceNumber reads the "major:minor" field, which is decimal (stat's %t:%T is hex).
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

// unescape undoes the kernel's three-digit octal escaping of space, tab, newline and backslash.
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

// indexByID maps each mount ID to its record; a duplicated ID is ambiguous and treated as parentless.
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

// parentOf returns a record's parent index; a missing, ambiguous or self parent ends the chain.
func parentOf(entries []Entry, byID map[uint32]int, i int) (int, bool) {
	p, ok := byID[entries[i].ParentID]
	if !ok || p == ambiguousID || p == i {
		return 0, false
	}
	return p, true
}

// topAtOwnMountPoint marks records on top at their mount point: a child mounted at the same point covers its parent; otherwise the last record wins.
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

// stackBase climbs to the bottom of the stack sharing a record's mount point, bounded by the table size.
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

// reachableAt marks records whose mount point path resolves to them: top at their point with every stack above reachable; a loop counts as reachable.
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

// VisibleMountPointsFor returns the paths where the device is currently visible, decided from the mount tree; use it before unmounting by path.
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

// EntryAt returns the mount a path resolves to, or nothing when every record there is hidden.
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

// Table is the seam through which a provider asks what is mounted; System reads /proc/self/mountinfo. Signatures use only universal types.
type Table interface {
	// MountPointsFor returns every path the device is mounted at, hidden ones included; only an unreadable table is an error.
	MountPointsFor(ctx context.Context, device string) ([]string, error)

	// VisibleMountPointsFor returns the paths where the device is visible, excluding paths covered at or above them.
	VisibleMountPointsFor(ctx context.Context, device string) ([]string, error)
}

// PropagationReader is the optional half of the seam: whether a mount is visible outside its namespace.
type PropagationReader interface {
	// PropagationOf reports whether the device's visible mount at mountPoint is shared, and its mount ID; nothing mounted is ErrNotMounted.
	PropagationOf(ctx context.Context, device, mountPoint string) (id uint32, propagates bool, spelling string, err error)
}

// System is the Table backed by the running kernel.
type System struct{}

// MountPointsFor reads the mount table and returns this device's mount points, matched by major:minor.
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

// PropagationOf reports whether this device's visible mount at mountPoint is shared; something else on top is ErrNotVisibleThere.
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
