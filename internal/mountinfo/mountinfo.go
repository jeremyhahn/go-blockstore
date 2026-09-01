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

	return Entry{
		Major:      major,
		Minor:      minor,
		Root:       unescape(fields[3]),
		MountPoint: unescape(fields[4]),
		FSType:     unescape(fields[sep+1]),
		Source:     unescape(fields[sep+2]),
	}, nil
}

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

// VisibleMountPointsFor returns the paths where the device is the filesystem
// that is CURRENTLY VISIBLE, which is a smaller set than MountPointsFor.
//
// Mounting over an occupied directory leaves both records in the table, and the
// later one is what a process walking to that path reaches. The earlier mount
// is still there and still this device's — MountPointsFor is right to report it
// — but it is hidden, and that distinction decides who gets unmounted:
// umount(2) takes the path and detaches whatever is visible at it. Handing it a
// path where this device has been over-mounted unmounts SOMEBODY ELSE'S
// filesystem while leaving this one exactly where it was.
//
// So anything that unmounts by path asks this, and anything asking "is it
// mounted at all" — a teardown deciding whether the volume is busy, a status —
// asks MountPointsFor, where a hidden mount still counts.
//
// WHAT THIS DOES NOT CATCH: a mount hidden by an overmount of one of its
// ANCESTOR directories — this volume at /mnt/base/vol, another filesystem later
// mounted at /mnt/base. The volume stops being reachable by that path without
// any second record naming it, so no comparison of mount points can see it.
//
// Deciding that properly means reconstructing the mount tree from the mount and
// parent IDs and asking which mount is visible at each ancestor, which is a
// different piece of work from this one; the tempting shortcut — treat a later
// record whose mount point is an ancestor as hiding this one — was MEASURED
// against an ordinary host's table and is wrong: 4 of that host's 28 records
// list their parent AFTER themselves, and 5 pairs would be called hidden with
// nothing overmounted at all. Refusing to delete a volume that is perfectly
// deletable is not an improvement over the rare case it would catch, and where
// that case does happen the path simply does not resolve, so the unmount fails
// loudly rather than taking the wrong filesystem down. Tracked in #33.
func VisibleMountPointsFor(entries []Entry, major, minor uint32) []string {
	// The last record for a path is the visible one, so the table is read
	// through once to find each path's last record, keeping the kernel's order
	// for the answer.
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

// EntryAt returns the entry mounted at a path.
//
// The LAST match wins, which is what the kernel means: mounting over an
// occupied directory leaves both records in the table, and the later one is
// what is visible there now.
func EntryAt(entries []Entry, mountPoint string) (Entry, bool) {
	found := false
	var match Entry
	for _, e := range entries {
		if e.MountPoint == mountPoint {
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
	VisibleMountPointsFor(ctx context.Context, device string) ([]string, error)
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
