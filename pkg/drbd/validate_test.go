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

//go:build drbd

package drbd

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"simple", "vol1", true},
		{"hyphens and underscores", "tenant-a_vol-02", true},
		{"single character", "a", true},
		{"48 characters", strings.Repeat("a", 48), true},

		{"empty", "", false},
		{"49 characters", strings.Repeat("a", 49), false},
		{"uppercase", "Vol1", false},
		{"leading hyphen would read as an option", "-rf", false},
		{"leading underscore", "_vol", false},
		{"dot is the snapshot separator", "vol.1", false},
		{"slash would escape the volume group", "vg0/vol1", false},
		{"space", "vol 1", false},
		{"semicolon would close a drbd statement", "vol1;", false},
		{"brace would close a drbd block", "vol1}", false},
		{"newline", "vol1\nresource evil {", false},
		{"quote", `vol1"`, false},
		{"backtick", "vol1`id`", false},
		{"dollar", "vol1$(id)", false},
		{"NUL byte", "vol1\x00", false},
		{"drbdadm keyword all", "all", false},
		{"all digits reads as a minor", "12", false},
		{"minor- prefix", "minor-3", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateName("volume name", tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("validateName(%q) = %v, want nil", tc.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateName(%q) = nil, want an error", tc.in)
			}
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Errorf("validateName(%q) error is not common.ErrInvalidArgument: %v", tc.in, err)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{"node-a", true},
		{"node-a.storage.example", true},
		{"NODE-A", true},
		{"n", true},
		{"", false},
		{"-node", false},
		{"node-", false},
		{"node a", false},
		{"node;evil", false},
		{"node\"}", false},
		{strings.Repeat("a", 254), false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			err := validateHostname(SettingNodeName, tc.in)
			if tc.ok != (err == nil) {
				t.Fatalf("validateHostname(%q) = %v, want ok=%v", tc.in, err, tc.ok)
			}
			if err != nil && !errors.Is(err, common.ErrInvalidArgument) {
				t.Errorf("error is not common.ErrInvalidArgument: %v", err)
			}
		})
	}
}

func TestValidateFSType(t *testing.T) {
	for _, in := range []string{"", "ext4", "xfs"} {
		if err := validateFSType(in); err != nil {
			t.Errorf("validateFSType(%q) = %v, want nil", in, err)
		}
	}
	// A rejected type is one this provider would otherwise turn into a
	// "mkfs.<type>" binary name.
	for _, in := range []string{"btrfs", "EXT4", "ext4 ", "../../bin/sh", "ext4;id"} {
		err := validateFSType(in)
		if err == nil {
			t.Errorf("validateFSType(%q) = nil, want an error", in)
			continue
		}
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("validateFSType(%q) error is not common.ErrInvalidArgument: %v", in, err)
		}
	}
}

func TestValidateMountFlags(t *testing.T) {
	if err := validateMountFlags([]string{"noatime", "nodev", "nosuid"}); err != nil {
		t.Fatalf("allowed flags rejected: %v", err)
	}
	if err := validateMountFlags(nil); err != nil {
		t.Fatalf("no flags rejected: %v", err)
	}
	for _, f := range []string{"ro", "rw", "loop", "bind", "noatime,ro", "-o", "remount"} {
		err := validateMountFlags([]string{"noatime", f})
		if err == nil {
			t.Errorf("validateMountFlags(%q) = nil, want an error", f)
			continue
		}
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("validateMountFlags(%q) error is not common.ErrInvalidArgument: %v", f, err)
		}
	}
}

func TestValidateMountTarget(t *testing.T) {
	// A space inside a component is legal and stays legal: mount points with
	// spaces exist, and every path this provider passes is its own argv
	// element, so nothing has to quote or escape one.
	for _, in := range []string{"/mnt/vol1", "/srv/data", "/mnt/my volume", "/mnt/a b/c d"} {
		if err := validateMountTarget(in); err != nil {
			t.Errorf("validateMountTarget(%q) = %v, want nil", in, err)
		}
	}

	// Whitespace at the edge of a component is the shape that goes wrong
	// quietly: it reads as the same path to a human, is a different path to the
	// kernel, and anything that trims it turns "mounted elsewhere" into "not
	// mounted" and a teardown into a silent no-op. A control character is
	// worse — a newline makes one path look like two in every line-oriented
	// tool an operator will reach for.
	for _, in := range []string{
		"", "mnt/vol1", "/mnt/../etc", "/mnt/vol1/", "/mnt//vol1", "/",
		"/mnt/vol1 ", "/mnt/ vol1", "/mnt/vol1\t", "/mnt/a /b", "/mnt/a/ b",
		"/mnt/vol\x00 1", "/mnt/vol\n1", "/mnt/vol\r1", "/mnt/vol\t1", "/mnt/vol\x7f1",
	} {
		err := validateMountTarget(in)
		if err == nil {
			t.Errorf("validateMountTarget(%q) = nil, want an error", in)
			continue
		}
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("validateMountTarget(%q) error is not common.ErrInvalidArgument: %v", in, err)
		}
	}
}

func TestSnapshotNameRoundTrip(t *testing.T) {
	lv := snapshotLV("vol1", "nightly")
	if lv != "vol1.snap.nightly" {
		t.Fatalf("snapshotLV = %q", lv)
	}
	vol, snap, ok := splitSnapshotLV(lv)
	if !ok || vol != "vol1" || snap != "nightly" {
		t.Fatalf("splitSnapshotLV(%q) = (%q, %q, %v)", lv, vol, snap, ok)
	}

	// Names the allowlist forbids cannot be produced, but an LV in the volume
	// group that somebody else created can look like anything.
	for _, in := range []string{"vol1", "vol1.snap.", ".snap.nightly", "vol1.snap.a.snap.b", ""} {
		if _, _, ok := splitSnapshotLV(in); ok {
			t.Errorf("splitSnapshotLV(%q) claimed the name", in)
		}
	}
}

// TestAllowedMountFlagsAreClassified holds the relationship between this
// provider's allowlist and internal/mount's table: a subset, never a superset.
//
// An option outside the shared table has no classification, so mount(2) would
// get it as neither a kernel flag nor a data string — silently dropped rather
// than applied, which for something like nosuid means a security option the
// caller asked for and did not get.
func TestAllowedMountFlagsAreClassified(t *testing.T) {
	if flag, ok := mountFlagsAreClassified(); !ok {
		t.Errorf("this provider allows %q, which internal/mount does not classify; "+
			"it would be dropped rather than applied", flag)
	}
}

// TestNoUUIDIsAllowedForRestoredXFS covers a combination the API has to
// support because it supports both halves. A restore is a byte-for-byte copy,
// so a restored XFS volume carries its source's UUID, and XFS refuses to mount
// a filesystem whose UUID matches one already mounted. Rejecting nouuid would
// mean supporting XFS, supporting restores, and being unable to mount the
// result beside its source.
func TestNoUUIDIsAllowedForRestoredXFS(t *testing.T) {
	if err := validateMountFlags([]string{"nouuid"}); err != nil {
		t.Fatalf("validateMountFlags(nouuid) = %v, want nil", err)
	}
	// And it reaches mount(2) as a data option, not as a kernel flag: the
	// kernel has no bit for it and XFS parses it itself.
	flags, data := mount.Arguments(false, []string{"nouuid"})
	if flags != 0 {
		t.Errorf("nouuid set kernel flags %#x, want none", flags)
	}
	if data != "nouuid" {
		t.Errorf("nouuid reached mount(2) as data %q, want %q", data, "nouuid")
	}
}

// TestValidateNameRejectsLVMReservedNames covers names this provider's own
// character set permits and LVM will not take.
//
// A volume's name IS its logical volume's name, handed straight to lvcreate.
// Without this the request fails partway through provisioning — after the state
// record, after allocation, into the rollback path — for a reason the caller
// could have been told at the API boundary.
//
// Measured against LVM 2.03.16 on a loopback volume group rather than read out
// of documentation: every name below was refused by a real lvcreate, and the
// accepted ones were created and removed.
func TestValidateNameRejectsLVMReservedNames(t *testing.T) {
	rejected := []string{
		// "Names starting ... are reserved"
		"snapshot", "snapshotfoo", "pvmove", "pvmovefoo",
		// "Names including ... are reserved". These are reachable here and not
		// in pkg/local, whose names cannot contain an underscore at all.
		"foo_cdata", "foo_cmeta", "foo_corig", "foo_mimage", "foo_mlog",
		"foo_pmspare", "foo_rimage", "foo_rmeta", "foo_tdata", "foo_tmeta",
		"foo_vorigin", "a_tmeta_b",
	}
	for _, name := range rejected {
		t.Run(name, func(t *testing.T) {
			err := validateName("volume name", name)
			if err == nil {
				t.Fatalf("validateName(%q) = nil; lvcreate would refuse it", name)
			}
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Errorf("error is not ErrInvalidArgument: %v", err)
			}
		})
	}

	// Names that merely resemble the reserved ones are still fine, and so is
	// the underscore in general — narrowing further would cost callers names
	// LVM accepts for no benefit.
	for _, name := range []string{
		"snap-ok", "snaps", "pvmov", "a_b-c", "tmeta", "cdata", "vol_1",
	} {
		if err := validateName("volume name", name); err != nil {
			t.Errorf("validateName(%q) = %v, want nil", name, err)
		}
	}
}

// TestSnapshotLVNamesAvoidReservedSubstrings checks the constructed name, not
// just its halves. A snapshot's logical volume is "<volume>.snap.<name>", and
// the separator carries no underscore, so a reserved substring can only come
// from one half — both of which are validated. This pins that reasoning.
func TestSnapshotLVNamesAvoidReservedSubstrings(t *testing.T) {
	for _, pair := range [][2]string{
		{"vol1", "nightly"}, {"a_b", "c_d"}, {"t", "meta"},
		// The case that would matter if the separator carried an underscore:
		// "a_t" + "meta" is "_t" beside "meta", and only the ".snap." between
		// them keeps it from spelling "_tmeta".
		{"a_t", "meta"}, {"x_c", "data"}, {"vol", "v1"},
	} {
		vol, snap := pair[0], pair[1]
		if err := validateName("volume name", vol); err != nil {
			t.Fatalf("fixture %q is not a valid volume name: %v", vol, err)
		}
		if err := validateName("snapshot name", snap); err != nil {
			t.Fatalf("fixture %q is not a valid snapshot name: %v", snap, err)
		}
		lv := snapshotLV(vol, snap)
		for _, sub := range reservedLVMSubstrings {
			if strings.Contains(lv, sub) {
				t.Errorf("snapshot LV %q contains the reserved %q even though both halves are valid", lv, sub)
			}
		}
		for _, prefix := range reservedLVMPrefixes {
			if strings.HasPrefix(lv, prefix) {
				t.Errorf("snapshot LV %q starts with the reserved %q", lv, prefix)
			}
		}
	}
}
