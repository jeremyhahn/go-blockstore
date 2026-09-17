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
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"

	"github.com/jeremyhahn/go-blockstore/internal/luks"
)

func TestListLVsParsesTheReport(t *testing.T) {
	runner := newFakeRunner().on("lvs", func([]string, []byte) ([]byte, error) {
		return []byte(`{"report":[{"lv":[
			{"lv_name":"data","lv_size":"1073741824","lv_attr":"-wi-a-----","origin":"","lv_time":"2026-08-26 09:30:00 -0400","data_percent":""},
			{"lv_name":"data_snap_nightly","lv_size":"214748364","lv_attr":"swi-a-s---","origin":"data","lv_time":"2026-08-26 10:00:00 -0400","data_percent":"12.50","origin_size":"1073741824"}
		]}]}`), nil
	})
	p := newTestProvider(t, runner)

	lvs, err := p.listLVs(context.Background())
	if err != nil {
		t.Fatalf("listLVs: %v", err)
	}
	if len(lvs) != 2 {
		t.Fatalf("listLVs returned %d volumes, want 2", len(lvs))
	}

	data := lvs[0]
	if data.SizeBytes != gib {
		t.Errorf("SizeBytes = %d, want %d", data.SizeBytes, gib)
	}
	if !data.active() {
		t.Error("data should be active: lv_attr position 5 is 'a'")
	}
	if data.isSnapshot() {
		t.Error("data should not be a snapshot: it has no origin")
	}

	snap := lvs[1]
	if !snap.isSnapshot() || snap.Origin != "data" {
		t.Errorf("origin = %q, want data", snap.Origin)
	}
	if got, want := snap.usedBytes(), int64(26843545); got != want {
		t.Errorf("usedBytes = %d, want %d (12.5%% of the CoW area)", got, want)
	}
}

// TestActiveReadsTheStateFieldOnly checks the one lv_attr position the provider
// depends on, across the shapes LVM emits for different volume kinds.
func TestActiveReadsTheStateFieldOnly(t *testing.T) {
	cases := map[string]bool{
		"-wi-a-----": true,
		"-wi-------": false,
		"swi-a-s---": true,
		"swi---s---": false,
		"owi-aos---": true,
		"":           false,
		"-wi-":       false,
	}
	for attr, want := range cases {
		if got := (lvInfo{Attr: attr}).active(); got != want {
			t.Errorf("active(%q) = %v, want %v", attr, got, want)
		}
	}
}

func TestParseLVTime(t *testing.T) {
	for _, layout := range []string{
		"2026-08-26 09:30:00 -0400",
		"2026-08-26T09:30:00-0400",
		"2026-08-26T09:30:00-04:00",
	} {
		if parseLVTime(layout).IsZero() {
			t.Errorf("parseLVTime(%q) returned the zero time", layout)
		}
	}

	// An unparseable timestamp leaves CreatedAt zero rather than failing the
	// whole listing: a creation time is reporting detail.
	for _, unparseable := range []string{"", "  ", "yesterday", "26/08/2026"} {
		if !parseLVTime(unparseable).IsZero() {
			t.Errorf("parseLVTime(%q) produced a time", unparseable)
		}
	}
}

func TestListLVsRejectsMalformedOutput(t *testing.T) {
	runner := newFakeRunner().on("lvs", func([]string, []byte) ([]byte, error) {
		return []byte("not json at all"), nil
	})
	p := newTestProvider(t, runner)

	if _, err := p.listLVs(context.Background()); err == nil {
		t.Fatal("listLVs accepted output that is not a report")
	}
}

// TestListLVsRejectsUnreadableNumbers is the fail-closed rule for lvs's numeric
// columns. A parse failure used to leave the zero value, which is not a missing
// number but a plausible wrong one, and these feed decisions rather than
// reports: a zero lv_size makes Resize read every request as a grow and makes a
// restore's "is the target large enough" check pass for any size at all.
func TestListLVsRejectsUnreadableNumbers(t *testing.T) {
	cases := map[string]string{
		"suffixed size":    `{"report":[{"lv":[{"lv_name":"data","lv_size":"1.0g","lv_attr":"-wi-a-----","origin":"","lv_time":"","data_percent":""}]}]}`,
		"empty size":       `{"report":[{"lv":[{"lv_name":"data","lv_size":"","lv_attr":"-wi-a-----","origin":"","lv_time":"","data_percent":""}]}]}`,
		"garbage size":     `{"report":[{"lv":[{"lv_name":"data","lv_size":"n/a","lv_attr":"-wi-a-----","origin":"","lv_time":"","data_percent":""}]}]}`,
		"negative size":    `{"report":[{"lv":[{"lv_name":"data","lv_size":"-1024","lv_attr":"-wi-a-----","origin":"","lv_time":"","data_percent":""}]}]}`,
		"non-finite size":  `{"report":[{"lv":[{"lv_name":"data","lv_size":"NaN","lv_attr":"-wi-a-----","origin":"","lv_time":"","data_percent":""}]}]}`,
		"infinite size":    `{"report":[{"lv":[{"lv_name":"data","lv_size":"+Inf","lv_attr":"-wi-a-----","origin":"","lv_time":"","data_percent":""}]}]}`,
		"garbage percent":  `{"report":[{"lv":[{"lv_name":"s","lv_size":"1024","lv_attr":"swi-a-s---","origin":"data","lv_time":"","data_percent":"n/a"}]}]}`,
		"negative percent": `{"report":[{"lv":[{"lv_name":"s","lv_size":"1024","lv_attr":"swi-a-s---","origin":"data","lv_time":"","data_percent":"-5"}]}]}`,
		"percent over 100": `{"report":[{"lv":[{"lv_name":"s","lv_size":"1024","lv_attr":"swi-a-s---","origin":"data","lv_time":"","data_percent":"140"}]}]}`,
		"non-finite pct":   `{"report":[{"lv":[{"lv_name":"s","lv_size":"1024","lv_attr":"swi-a-s---","origin":"data","lv_time":"","data_percent":"NaN"}]}]}`,
		"snapshot no pct":  `{"report":[{"lv":[{"lv_name":"s","lv_size":"1024","lv_attr":"swi-a-s---","origin":"data","lv_time":"","data_percent":""}]}]}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			out := body
			runner := newFakeRunner().on("lvs", func([]string, []byte) ([]byte, error) {
				return []byte(out), nil
			})
			p := newTestProvider(t, runner)

			lvs, err := p.listLVs(context.Background())
			if err == nil {
				t.Fatalf("listLVs accepted %s and returned %v", name, lvs)
			}
			// The error names the volume group and the logical volume, so an
			// operator can find the row rather than being told a number was bad.
			if !strings.Contains(err.Error(), "vg0/") {
				t.Errorf("error = %q, want it to name the volume group and volume", err)
			}
		})
	}
}

// TestListLVsAcceptsAnEmptyPercentWhereLVMLeavesItEmpty is the other half, and
// it is measured rather than assumed: on LVM 2.03.16 data_percent is populated
// only while the kernel has the device mapped, so a plain volume reports empty
// always and so does an INACTIVE snapshot. Inactive is the ordinary state here —
// this provider leaves snapshots deactivated — so refusing an empty value for
// every snapshot would have failed every listing of a volume group holding one.
func TestListLVsAcceptsAnEmptyPercentWhereLVMLeavesItEmpty(t *testing.T) {
	cases := map[string]string{
		"plain volume":      `{"report":[{"lv":[{"lv_name":"data","lv_size":"1024","lv_attr":"-wi-a-----","origin":"","lv_time":"","data_percent":""}]}]}`,
		"inactive snapshot": `{"report":[{"lv":[{"lv_name":"s","lv_size":"1024","lv_attr":"swi---s---","origin":"data","lv_time":"","data_percent":"","origin_size":"4096"}]}]}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			out := body
			runner := newFakeRunner().on("lvs", func([]string, []byte) ([]byte, error) {
				return []byte(out), nil
			})
			p := newTestProvider(t, runner)

			lvs, err := p.listLVs(context.Background())
			if err != nil {
				t.Fatalf("listLVs: %v", err)
			}
			if len(lvs) != 1 || lvs[0].SizeBytes != 1024 || lvs[0].DataPercent != 0 {
				t.Fatalf("listLVs = %+v, want one row sized 1024 with no occupancy", lvs)
			}
		})
	}
}

// TestInactiveSnapshotReportsNoOccupancy records what a caller sees for the
// state snapshots are normally in: occupancy 0, because LVM does not measure an
// unmapped device and this provider will not activate one to find out —
// activating a snapshot activates its origin, moving a volume the caller may be
// using.
func TestInactiveSnapshotReportsNoOccupancy(t *testing.T) {
	runner := newFakeRunner().withLVs(
		lvFixture{Name: "data", SizeBytes: gib},
		lvFixture{Name: "data" + snapSeparator + "nightly", SizeBytes: gib / 5, Origin: "data", Active: false},
	)
	p := newTestProvider(t, runner)

	snaps, err := p.ListSnapshots(context.Background(), "data")
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("ListSnapshots = %v, want one", snaps)
	}
	if snaps[0].SizeBytes != 0 {
		t.Errorf("SizeBytes = %d, want 0 for an inactive snapshot", snaps[0].SizeBytes)
	}
}

func TestExtentSize(t *testing.T) {
	runner := newFakeRunner().withExtentSize(4 << 20)
	p := newTestProvider(t, runner)

	size, err := p.extentSize(context.Background())
	if err != nil {
		t.Fatalf("extentSize: %v", err)
	}
	if size != 4<<20 {
		t.Fatalf("extentSize = %d, want %d", size, 4<<20)
	}
}

func TestExtentSizeRejectsAnUnusableReport(t *testing.T) {
	for name, out := range map[string]string{
		"not json":   "vg_extent_size 4194304",
		"no vg rows": `{"report":[{"vg":[]}]}`,
		"empty size": `{"report":[{"vg":[{"vg_extent_size":""}]}]}`,
		"zero size":  `{"report":[{"vg":[{"vg_extent_size":"0"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			body := out
			runner := newFakeRunner().on("vgs", func([]string, []byte) ([]byte, error) {
				return []byte(body), nil
			})
			p := newTestProvider(t, runner)

			if _, err := p.extentSize(context.Background()); err == nil {
				t.Fatalf("extentSize accepted %q", body)
			}
		})
	}
}

func TestRoundUpToExtent(t *testing.T) {
	const extent = 4 << 20
	cases := map[int64]int64{
		1:          1 * extent,
		extent:     extent,
		extent + 1: 2 * extent,
		100000000:  100663296,
		100663296:  100663296,
		1 << 30:    1 << 30,
	}
	for in, want := range cases {
		if got := roundUpToExtent(in, extent); got != want {
			t.Errorf("roundUpToExtent(%d, %d) = %d, want %d", in, extent, got, want)
		}
	}

	// An unusable extent size leaves the value alone rather than dividing by
	// zero.
	if got := roundUpToExtent(1234, 0); got != 1234 {
		t.Errorf("roundUpToExtent(1234, 0) = %d, want 1234", got)
	}
}

// TestRoundUpToExtentAtTheBoundary walks the edge where the addition inside
// roundUpToExtent would overflow. Signed overflow in Go wraps rather than
// trapping, so an unguarded round of a near-maximal size comes back NEGATIVE —
// and a negative target reads as smaller than the volume already is, turning a
// request to grow enormously into an "unsupported shrink".
func TestRoundUpToExtentAtTheBoundary(t *testing.T) {
	const extent = 4 << 20
	limit := maxRoundableBytes(extent)

	cases := map[string]int64{
		"largest representable": limit,
		"one over":              limit + 1,
		"an extent below max":   math.MaxInt64 - extent,
		"max":                   math.MaxInt64,
	}

	for name, in := range cases {
		got := roundUpToExtent(in, extent)
		if got < 0 {
			t.Errorf("roundUpToExtent(%d) [%s] = %d, which is negative", in, name, got)
		}
		if got < in {
			t.Errorf("roundUpToExtent(%d) [%s] = %d, which is smaller than its input", in, name, got)
		}
	}

	// Below the limit it still rounds up as it always did.
	if got := roundUpToExtent(limit, extent); got%extent != 0 {
		t.Errorf("roundUpToExtent(%d) = %d, want a whole number of extents", limit, got)
	}
}

// TestParseLVNumberRefusesUnrepresentableSizes closes the same class at the
// other crossing: a float64 at or above 2^63 has no int64 to convert to, and Go
// leaves that conversion implementation-specific — on amd64 it yields a negative
// number, which would feed Resize and the restore size check as a real size.
func TestParseLVNumberRefusesUnrepresentableSizes(t *testing.T) {
	for _, raw := range []string{"9223372036854775808", "1e19", "1e300"} {
		if _, err := parseLVNumber(raw); err == nil {
			t.Errorf("parseLVNumber(%q) was accepted; it cannot be represented as an int64", raw)
		}
	}
	// Just under the boundary is still a number.
	if _, err := parseLVNumber("9223372036854775000"); err != nil {
		t.Errorf("parseLVNumber of a representable size = %v, want nil", err)
	}
}

func TestProbeFSTypeParsesBlkidExport(t *testing.T) {
	runner := newFakeRunner().on("blkid", func([]string, []byte) ([]byte, error) {
		return []byte("DEVNAME=/dev/vg0/data\nUUID=6a5b\nTYPE=xfs\nUSAGE=filesystem\n"), nil
	})
	p := newTestProvider(t, runner)

	fsType, err := p.probeFSType(context.Background(), "/dev/vg0/data")
	if err != nil {
		t.Fatalf("probeFSType: %v", err)
	}
	if fsType != "xfs" {
		t.Fatalf("probeFSType = %q, want xfs", fsType)
	}
}

// TestProbeFSTypeRequiresATypeOnSuccess closes a fail-open. A zero exit means
// blkid identified the device, so it owes a TYPE; returning "" for output that
// lacks one would hand callers the authoritative "this is a raw device" answer
// on the strength of truncated or unexpected output — and Attach acts on that
// answer by treating a LUKS container as a plain device.
func TestProbeFSTypeRequiresATypeOnSuccess(t *testing.T) {
	cases := map[string]string{
		"empty output":      "",
		"no TYPE field":     "DEVNAME=/dev/vg0/data\nUUID=6a5b\n",
		"garbage":           "not an export listing at all\n",
		"empty TYPE value":  "DEVNAME=/dev/vg0/data\nTYPE=\n",
		"conflicting TYPEs": "DEVNAME=/dev/vg0/data\nTYPE=ext4\nTYPE=crypto_LUKS\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			out := body
			runner := newFakeRunner().on("blkid", func([]string, []byte) ([]byte, error) {
				return []byte(out), nil
			})
			p := newTestProvider(t, runner)

			fsType, err := p.probeFSType(context.Background(), "/dev/vg0/data")
			if err == nil {
				t.Fatalf("probeFSType returned %q and no error for %s", fsType, name)
			}
		})
	}
}

// TestProbeFSTypeTreatsNoSignatureAsEmpty covers blkid's way of saying "nothing
// here", which is an exit status rather than empty output.
func TestProbeFSTypeTreatsNoSignatureAsEmpty(t *testing.T) {
	runner := newFakeRunner()
	runner.fail("blkid", 2, "")
	p := newTestProvider(t, runner)

	fsType, err := p.probeFSType(context.Background(), "/dev/vg0/data")
	if err != nil {
		t.Fatalf("probeFSType: %v", err)
	}
	if fsType != "" {
		t.Fatalf("probeFSType = %q, want the empty string for a raw device", fsType)
	}
}

// TestProbeFSTypeOnlyAcceptsTheNotFoundStatus checks that "no filesystem here"
// is read from blkid's one status that means it, not from any failure at all.
// Exit 8 is the dangerous one: it means low-level probing found an ambivalent
// result — two signatures on one device — and reporting that as a raw device
// would let Attach hand back an encrypted volume as though it were plain.
func TestProbeFSTypeOnlyAcceptsTheNotFoundStatus(t *testing.T) {
	for _, code := range []int{1, 4, 8} {
		runner := newFakeRunner()
		runner.fail("blkid", code, "blkid trouble")
		p := newTestProvider(t, runner)

		if _, err := p.probeFSType(context.Background(), "/dev/vg0/data"); err == nil {
			t.Errorf("probeFSType read blkid exit %d as an empty filesystem type", code)
		}
	}
}

// TestLUKSIsOpenOnlyAcceptsAnAbsentMapping keeps a lookup that could not answer
// from being read as "the mapping is not open".
//
// The negative answer is exactly one thing: the mapping lookup succeeded and
// found no mapping under the name. Everything else — a device-mapper that
// cannot be reached, a mapping whose backing device sysfs will not name, a
// permission problem — is reported, because guessing "not open" would make
// Attach try to unlock a volume that is already unlocked and Detach skip a
// mapping it should have closed.
func TestLUKSIsOpenOnlyAcceptsAnAbsentMapping(t *testing.T) {
	failures := map[string]error{
		"device-mapper unreachable": errors.New("open /dev/mapper/control: permission denied"),
		"backing device unnamed":    fmt.Errorf("%w: /sys/dev/block/253:3/slaves lists 0", luks.ErrNoBackingDevice),
	}
	for name, sentinel := range failures {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().on(luksBinary, func(args []string, _ []byte) ([]byte, error) {
				if len(args) > 0 && args[0] == "mapping" {
					return nil, sentinel
				}
				return nil, nil
			})
			p := newTestProvider(t, runner, withKey)

			open, err := p.luksIsOpen(context.Background(), "data")
			if err == nil {
				t.Fatalf("luksIsOpen = (%v, nil); an unanswerable lookup must not read as not open", open)
			}
			if !errors.Is(err, sentinel) {
				t.Errorf("luksIsOpen = %v, want it to carry %v", err, sentinel)
			}
		})
	}

	// The one negative answer: no mapping under the name.
	runner := newFakeRunner().withOpenMappings()
	p := newTestProvider(t, runner, withKey)
	open, err := p.luksIsOpen(context.Background(), "data")
	if err != nil || open {
		t.Errorf("luksIsOpen = (%v, %v), want (false, nil)", open, err)
	}
}

// TestProbeFSTypeSurfacesAMissingBlkid is the distinction that keeps an
// encrypted volume from being treated as plain on a host where blkid is not
// installed.
func TestProbeFSTypeSurfacesAMissingBlkid(t *testing.T) {
	runner := newFakeRunner().on("blkid", func([]string, []byte) ([]byte, error) {
		return nil, errors.New("exec: blkid: executable file not found in $PATH")
	})
	p := newTestProvider(t, runner)

	if _, err := p.probeFSType(context.Background(), "/dev/vg0/data"); err == nil {
		t.Fatal("probeFSType reported no filesystem when blkid could not run")
	}
}

// TestMountpointsForReturnsEveryTarget covers a device mounted more than once,
// which Delete has to unmount all of.
func TestMountpointsForReturnsEveryTarget(t *testing.T) {
	runner := newFakeRunner().withMounts(map[string][]string{
		"/dev/vg0/data":  {"/mnt/data", "/mnt/data-bind"},
		"/dev/vg0/other": {"/mnt/other"},
	})
	p := newTestProvider(t, runner)

	mounts, err := p.mountpointsFor(context.Background(), "/dev/vg0/data")
	if err != nil {
		t.Fatalf("mountpointsFor: %v", err)
	}
	if len(mounts) != 2 || mounts[0] != "/mnt/data" || mounts[1] != "/mnt/data-bind" {
		t.Fatalf("mountpointsFor = %v, want both of this device's mounts", mounts)
	}

	// Another device's mount is not this one's.
	if mounts, err := p.mountpointsFor(context.Background(), "/dev/vg0/absent"); err != nil || len(mounts) != 0 {
		t.Fatalf("mountpointsFor of an unmounted device = (%v, %v), want none and no error", mounts, err)
	}
}

// TestMountpointsForOnAnEmptyDevice keeps an unattached volume from reaching
// the mount table at all: there is no device to ask about.
func TestMountpointsForOnAnEmptyDevice(t *testing.T) {
	runner := newFakeRunner().withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})
	p := newTestProvider(t, runner)

	mounts, err := p.mountpointsFor(context.Background(), "")
	if err != nil {
		t.Fatalf("mountpointsFor: %v", err)
	}
	if len(mounts) != 0 {
		t.Fatalf("mountpointsFor = %v, want none", mounts)
	}
}

// TestMountpointsForFailsClosed is the distinction this conversion preserved
// and findmnt could not express. "The mount table could not be read" must never
// arrive as "nothing is mounted": that second answer is what Delete acts on
// immediately before a forced lvremove.
func TestMountpointsForFailsClosed(t *testing.T) {
	runner := newFakeRunner().failMountTable(errors.New("mount table unreadable"))
	p := newTestProvider(t, runner)

	mounts, err := p.mountpointsFor(context.Background(), "/dev/vg0/data")
	if err == nil {
		t.Fatalf("mountpointsFor returned %v and no error over an unreadable table", mounts)
	}
}

// TestLVMFailuresPropagate walks the lvm commands and checks each one's failure
// reaches the caller rather than being reported as success.
func TestLVMFailuresPropagate(t *testing.T) {
	ctx := context.Background()

	cases := map[string]struct {
		binary string
		// failCopy fails the block-device copy instead of a binary, for the one
		// operation whose failure no longer comes from an exec.
		failCopy bool
		lvs      []lvFixture
		call     func(*Provider) error
	}{
		"lvcreate": {
			binary: "lvcreate",
			call: func(p *Provider) error {
				_, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: gib})
				return err
			},
		},
		"lvchange on attach": {
			binary: "lvchange",
			lvs:    []lvFixture{{Name: "data", SizeBytes: gib}},
			call: func(p *Provider) error {
				_, err := p.Attach(ctx, "data", "node-a")
				return err
			},
		},
		"lvextend": {
			binary: "lvextend",
			lvs:    []lvFixture{{Name: "data", SizeBytes: gib}},
			call:   func(p *Provider) error { return p.Resize(ctx, "data", 2*gib) },
		},
		"lvcreate on snapshot": {
			binary: "lvcreate",
			lvs:    []lvFixture{{Name: "data", SizeBytes: gib}},
			call: func(p *Provider) error {
				_, err := p.Snapshot(ctx, "data", "nightly")
				return err
			},
		},
		"lvremove on delete": {
			binary: "lvremove",
			lvs:    []lvFixture{{Name: "data", SizeBytes: gib}},
			call:   func(p *Provider) error { return p.Delete(ctx, "data") },
		},
		"lvremove on delete snapshot": {
			binary: "lvremove",
			lvs: []lvFixture{
				{Name: "data", SizeBytes: gib},
				{Name: "data" + snapSeparator + "nightly", SizeBytes: gib / 5, Origin: "data"},
			},
			call: func(p *Provider) error {
				return p.DeleteSnapshot(ctx, common.SnapshotID("data"+snapSeparator+"nightly"))
			},
		},
		"copy on restore": {
			failCopy: true,
			lvs: []lvFixture{
				{Name: "data", SizeBytes: gib},
				{Name: "data" + snapSeparator + "nightly", SizeBytes: gib / 5, Origin: "data"},
			},
			call: func(p *Provider) error {
				_, err := p.Provision(ctx, common.VolumeSpec{
					Name:             "restored",
					SizeBytes:        gib,
					SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
				})
				return err
			},
		},
		"resize2fs": {
			binary: "resize2fs",
			lvs:    []lvFixture{{Name: "data", SizeBytes: gib, Active: true}},
			call:   func(p *Provider) error { return p.Resize(ctx, "data", 2*gib) },
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().withLVs(tc.lvs...)
			if tc.binary == "resize2fs" {
				runner.withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
			}
			what := tc.binary
			if tc.failCopy {
				what = "device copy"
				runner.failCopy(errors.New("copy said no"))
			} else {
				runner.fail(tc.binary, 5, "lvm said no")
			}
			p := newTestProvider(t, runner)

			if err := tc.call(p); err == nil {
				t.Fatalf("the operation succeeded despite a failing %s", what)
			}
		})
	}
}

// TestXFSGrowFailurePropagates covers the mounted-xfs branch of growFilesystem.
func TestXFSGrowFailurePropagates(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "xfs"}).
		withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})
	runner.fail("xfs_growfs", 1, "not a mounted XFS filesystem")
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err == nil {
		t.Fatal("Resize succeeded despite a failing xfs_growfs")
	}
}

// TestMountFailurePropagates keeps a failed mount from reading as success.
func TestMountFailurePropagates(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	runner.failMount(errors.New("mount point does not exist"))
	p := newTestProvider(t, runner)

	if err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{}); err == nil {
		t.Fatal("Mount succeeded despite a failing mount")
	}
}

// TestMountRefusesAVolumeWithNoFilesystem covers what mount(2) cannot do that
// mount(8) could: guess. The type has to be named, the probe supplies it for a
// formatted volume, and a raw one has nothing to mount.
func TestMountRefusesAVolumeWithNoFilesystem(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true})
	p := newTestProvider(t, runner)

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Mount = %v, want ErrInvalidArgument", err)
	}
	if len(runner.mountCalls()) != 0 {
		t.Error("a mount was attempted for a volume with no filesystem")
	}
}
