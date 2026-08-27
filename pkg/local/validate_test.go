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

package local

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

func TestValidateNameRejects(t *testing.T) {
	cases := map[string]string{
		"empty":                "",
		"shell metacharacter":  "data;rm -rf /",
		"command substitution": "$(id)",
		"backtick":             "`id`",
		"pipe":                 "a|b",
		"space":                "my volume",
		"newline":              "data\nlvremove",
		"path traversal":       "../../etc/shadow",
		"slash":                "vg0/data",
		"leading hyphen":       "-wipesignatures",
		"underscore":           "data_snap_x",
		"dot":                  "data.1",
		"nul byte":             "data\x00",
		"reserved snapshot":    "snapshotdata",
		"reserved pvmove":      "pvmove0",
		"too long":             strings.Repeat("a", maxNameLen+1),
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateName("volume", value)
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Fatalf("validateName(%q) = %v, want common.ErrInvalidArgument", value, err)
			}
		})
	}
}

func TestValidateNameAccepts(t *testing.T) {
	for _, value := range []string{"a", "data", "data-1", "Data", "0", "vol-2026-08-26", strings.Repeat("a", maxNameLen)} {
		if err := validateName("volume", value); err != nil {
			t.Errorf("validateName(%q) = %v, want nil", value, err)
		}
	}
}

func TestValidateFSType(t *testing.T) {
	for _, ok := range []string{"", "ext2", "ext3", "ext4", "xfs"} {
		if err := validateFSType(ok); err != nil {
			t.Errorf("validateFSType(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"vfat", "ext4 -F /dev/sda", "ext4;id", "EXT4", "../../bin/sh", "btrfs"} {
		if err := validateFSType(bad); !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("validateFSType(%q) = %v, want common.ErrInvalidArgument", bad, err)
		}
	}
}

// TestValidateMountFlagsRejectsCompoundTokens is the case the whole-token
// allowlist exists for: the flags are joined into one comma-separated -o
// argument, so a token that already contains a comma would carry options past
// the allowlist.
func TestValidateMountFlagsRejectsCompoundTokens(t *testing.T) {
	for _, bad := range []string{
		"noatime,exec",
		"ro,suid",
		"noatime,",
		",noatime",
		"-o",
		"--bind",
		"bind",
		"loop",
		"remount",
		"uid=0",
		"noatime ",
		"NOATIME",
		"",
	} {
		if err := validateMountFlags(false, []string{bad}); !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("validateMountFlags([%q]) = %v, want common.ErrInvalidArgument", bad, err)
		}
	}
}

func TestValidateMountFlagsAccepts(t *testing.T) {
	good := []string{"noatime", "nodev", "nosuid", "noexec", "ro", "data=ordered", "errors=remount-ro"}
	if err := validateMountFlags(false, good); err != nil {
		t.Fatalf("validateMountFlags(%v) = %v, want nil", good, err)
	}
	if err := validateMountFlags(false, nil); err != nil {
		t.Fatalf("validateMountFlags(false, nil) = %v, want nil", err)
	}
}

func TestValidateTarget(t *testing.T) {
	bad := []string{
		"",
		"mnt/data",
		"./data",
		"/mnt/data/",
		"/mnt/../etc",
		"/mnt//data",
		"/",
		"/mnt/data\x00",
		"/mnt/data\nmore",
		"/mnt/data\ttab",
		"/mnt/data\x7f",
		"/mnt/data ",
		"\t/mnt/data",
	}
	for _, target := range bad {
		if err := validateTarget(target); !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("validateTarget(%q) = %v, want common.ErrInvalidArgument", target, err)
		}
	}
	// A space is valid: findmnt's default output prints it literally, so such a
	// target round-trips and Unmount converges on it.
	for _, target := range []string{"/mnt/data", "/var/lib/thing", "/mnt", "/mnt/my data"} {
		if err := validateTarget(target); err != nil {
			t.Errorf("validateTarget(%q) = %v, want nil", target, err)
		}
	}
}

func TestSplitSnapshotID(t *testing.T) {
	volID, name, ok := splitSnapshotID("data" + snapSeparator + "nightly")
	if !ok || volID != "data" || name != "nightly" {
		t.Fatalf("splitSnapshotID = (%q, %q, %v), want (data, nightly, true)", volID, name, ok)
	}

	// A hyphenated volume name and a hyphenated snapshot name still split at
	// the one separator, because neither half can contain an underscore.
	volID, name, ok = splitSnapshotID("vol-a-b" + snapSeparator + "snap-1-2")
	if !ok || volID != "vol-a-b" || name != "snap-1-2" {
		t.Fatalf("splitSnapshotID = (%q, %q, %v), want (vol-a-b, snap-1-2, true)", volID, name, ok)
	}

	for _, bad := range []string{"", "data", "data_snap_", "_snap_nightly", "datasnapnightly"} {
		if _, _, ok := splitSnapshotID(bad); ok {
			t.Errorf("splitSnapshotID(%q) reported ok, want not ok", bad)
		}
	}
}

// TestHostileInputRejectedBeforeExec is the load-bearing assertion behind the
// provider-owns-validation rule: a rejected value must never have reached a
// command line, so the fake must have recorded no calls at all.
func TestHostileInputRejectedBeforeExec(t *testing.T) {
	ctx := context.Background()
	const hostile = "data; lvremove -f vg0"

	cases := map[string]func(*Provider) error{
		"Provision name": func(p *Provider) error {
			_, err := p.Provision(ctx, common.VolumeSpec{Name: hostile, SizeBytes: 1024})
			return err
		},
		"Provision fstype": func(p *Provider) error {
			_, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 1024, FSType: "ext4 --bogus"})
			return err
		},
		"Provision size": func(p *Provider) error {
			_, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 0})
			return err
		},
		"Provision snapshot id": func(p *Provider) error {
			_, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 1024, SourceSnapshotID: common.SnapshotID(hostile)})
			return err
		},
		"Attach": func(p *Provider) error {
			_, err := p.Attach(ctx, hostile, "node-a")
			return err
		},
		"Detach": func(p *Provider) error { return p.Detach(ctx, hostile, "node-a") },
		"Mount volume": func(p *Provider) error {
			return p.Mount(ctx, hostile, "/mnt/data", common.MountOptions{})
		},
		"Mount target": func(p *Provider) error {
			return p.Mount(ctx, "data", "/mnt/../etc", common.MountOptions{})
		},
		"Mount flags": func(p *Provider) error {
			return p.Mount(ctx, "data", "/mnt/data", common.MountOptions{Flags: []string{"noatime,exec"}})
		},
		"Mount fstype": func(p *Provider) error {
			return p.Mount(ctx, "data", "/mnt/data", common.MountOptions{FSType: "vfat"})
		},
		"Unmount volume": func(p *Provider) error { return p.Unmount(ctx, hostile, "/mnt/data") },
		"Unmount target": func(p *Provider) error { return p.Unmount(ctx, "data", "relative/path") },
		"Resize volume":  func(p *Provider) error { return p.Resize(ctx, hostile, 2048) },
		"Resize size":    func(p *Provider) error { return p.Resize(ctx, "data", -1) },
		"Snapshot volume": func(p *Provider) error {
			_, err := p.Snapshot(ctx, hostile, "nightly")
			return err
		},
		"Snapshot name": func(p *Provider) error {
			_, err := p.Snapshot(ctx, "data", hostile)
			return err
		},
		"ListSnapshots": func(p *Provider) error {
			_, err := p.ListSnapshots(ctx, hostile)
			return err
		},
		"DeleteSnapshot": func(p *Provider) error {
			return p.DeleteSnapshot(ctx, common.SnapshotID(hostile))
		},
		"Delete": func(p *Provider) error { return p.Delete(ctx, hostile) },
		"Status": func(p *Provider) error {
			_, err := p.Status(ctx, hostile)
			return err
		},
	}

	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner()
			p := newTestProvider(t, runner)

			err := call(p)
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Fatalf("got %v, want common.ErrInvalidArgument", err)
			}
			if calls := runner.lines(); len(calls) != 0 {
				t.Fatalf("rejected input still reached the system: %v", calls)
			}
		})
	}
}

// TestNewRejectsHostileVolumeGroup covers the one caller-supplied name that is
// not a method argument: it reaches every lvm invocation the provider makes.
func TestNewRejectsHostileVolumeGroup(t *testing.T) {
	for _, bad := range []string{"", "vg0; id", "../vg0", "-vg0"} {
		if _, err := New(Options{VolumeGroup: bad, Runner: newFakeRunner()}); !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("New(VolumeGroup=%q) = %v, want common.ErrInvalidArgument", bad, err)
		}
	}
}
