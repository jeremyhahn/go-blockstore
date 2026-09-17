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
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/internal/blkdev"
	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

const testSize = int64(1) << 30 // 1 GiB

// statusJSON renders a one-resource drbdsetup document in the shape of the
// testdata fixtures, for the provider tests that need a specific state.
func statusJSON(name string, minor int, role, conn, repl, disk string) string {
	return fmt.Sprintf(`[{
  "name": %q,
  "node-id": 0,
  "role": %q,
  "suspended": false,
  "write-ordering": "flush",
  "devices": [{"volume": 0, "minor": %d, "disk-state": %q, "client": false, "quorum": true, "size": 1052600}],
  "connections": [{
    "peer-node-id": 1,
    "name": %q,
    "connection": %q,
    "congested": false,
    "peer-role": "Secondary",
    "peer_devices": [{"volume": 0, "replication": %q, "peer-disk-state": "UpToDate", "out-of-sync": 0, "percent-in-sync": 100.0}]
  }]
}]`, name, role, minor, disk, testPeer, conn, repl)
}

// primaryStatus and secondaryStatus are the two states most tests need.
func primaryStatus(name string, minor int) string {
	return statusJSON(name, minor, "Primary", "Connected", "Established", "UpToDate")
}

func secondaryStatus(name string, minor int) string {
	return statusJSON(name, minor, "Secondary", "Connected", "Established", "UpToDate")
}

// scriptProvision scripts the three commands a Provision runs.
func (f *fakeRunner) scriptProvision(name string, size int64) {
	f.scriptProvisionAt(name, backingBytes(size, false))
}

// scriptProvisionAt is the same for a backing volume created at an explicit
// size, which a restore is: the destination is created at the SOURCE's size and
// grown afterwards, not at the size the caller asked for.
func (f *fakeRunner) scriptProvisionAt(name string, backingSize int64) {
	f.on(binLVCreate, "--yes", "--name", name, "--size", strconv.FormatInt(backingSize, 10)+"b", testVG).returns("")
	f.on(binDRBDAdm, "--", "--force", "create-md", name).returns("")
	f.on(binDRBDAdm, "up", name).returns("")
}

// originBacking is the backing size of a testSize volume as LVM would have
// created it — what a snapshot of one reports as its origin_size, and therefore
// the size a restore of it creates its destination at.
func originBacking() int64 {
	return roundUpTo(backingBytes(testSize, false), testExtentSize)
}

// provision runs a successful Provision, scripting it first.
func provision(t *testing.T, p *Provider, r *fakeRunner, spec *common.VolumeSpec) common.Volume {
	t.Helper()
	// The backing size is the provider's to decide — an encrypted one adds the
	// LUKS header on top — so the script follows its configuration.
	r.scriptProvisionAt(spec.Name, backingBytes(spec.SizeBytes, p.cfg.Encrypted))
	vol, err := p.Provision(context.Background(), *spec)
	if err != nil {
		t.Fatalf("Provision(%q): %v", spec.Name, err)
	}
	return vol
}

// defaultSpec carries Replicas: 2 because this provider requires it. Zero
// means "not replicated" in the common contract, which DRBD cannot serve.
func defaultSpec() *common.VolumeSpec {
	return &common.VolumeSpec{Name: testVolume, SizeBytes: testSize, FSType: "ext4", Replicas: 2}
}

// -----------------------------------------------------------------------------
// Provision
// -----------------------------------------------------------------------------

func TestProvision(t *testing.T) {
	p, r := newTestProvider(t)

	spec := defaultSpec()
	spec.Labels = map[string]string{"tenant": "acme"}
	vol := provision(t, p, r, spec)

	if vol.ID != testVolume {
		t.Errorf("Volume.ID = %q, want %q", vol.ID, testVolume)
	}
	if vol.Spec.SizeBytes != testSize {
		t.Errorf("Volume.Spec.SizeBytes = %d, want %d", vol.Spec.SizeBytes, testSize)
	}

	r.assertRan(t, fmt.Sprintf("lvcreate --yes --name vol1 --size %db vg0", backingBytes(testSize, false)))
	r.assertRan(t, "drbdadm -- --force create-md vol1")
	r.assertRan(t, "drbdadm up vol1")

	// Provisioning must not promote, force a promotion, or start an initial
	// sync: the first authoritative copy is the HA controller's decision.
	r.assertNotRan(t, "primary")
	r.assertNotRan(t, "new-current-uuid")
	// A raw device cannot be formatted from a Secondary, so no mkfs here.
	r.assertNotRan(t, "mkfs")

	res, err := os.ReadFile(p.resPath(testVolume))
	if err != nil {
		t.Fatalf("reading resource file: %v", err)
	}
	if !strings.Contains(string(res), `resource "vol1" {`) {
		t.Errorf("resource file does not define vol1:\n%s", res)
	}

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.FSType != "ext4" {
		t.Errorf("recorded FSType = %q, want ext4", meta.FSType)
	}
	if meta.Minor != 0 || meta.Port != defaultPortBase {
		t.Errorf("allocated minor/port = %d/%d, want 0/%d", meta.Minor, meta.Port, defaultPortBase)
	}
	if meta.Labels["tenant"] != "acme" {
		t.Errorf("labels not recorded: %v", meta.Labels)
	}
}

func TestProvisionAlreadyExists(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())

	_, err := p.Provision(context.Background(), *defaultSpec())
	if !errors.Is(err, common.ErrAlreadyExists) {
		t.Fatalf("second Provision = %v, want ErrAlreadyExists", err)
	}
}

func TestProvisionValidation(t *testing.T) {
	tests := []struct {
		name string
		spec common.VolumeSpec
		want error
	}{
		{"empty name", common.VolumeSpec{SizeBytes: testSize}, common.ErrInvalidArgument},
		{"hostile name", common.VolumeSpec{Name: "vol1; rm -rf /", SizeBytes: testSize}, common.ErrInvalidArgument},
		{"zero size", common.VolumeSpec{Name: testVolume}, common.ErrInvalidArgument},
		{"negative size", common.VolumeSpec{Name: testVolume, SizeBytes: -1}, common.ErrInvalidArgument},
		// A size whose backing (data plus DRBD metadata) does not fit in an
		// int64 is malformed input: unguarded it would reach lvcreate as a
		// wrapped-negative byte count. maxDataBytes(0, false) is the largest that fits
		// when lvcreate does the extent rounding, so one past it is the first
		// that does not.
		{"size at math.MaxInt64", common.VolumeSpec{Name: testVolume, SizeBytes: math.MaxInt64, Replicas: 2}, common.ErrInvalidArgument},
		{"size one past the representable backing", common.VolumeSpec{Name: testVolume, SizeBytes: maxDataBytes(0, false) + 1, Replicas: 2}, common.ErrInvalidArgument},
		{"unsupported filesystem", common.VolumeSpec{Name: testVolume, SizeBytes: testSize, FSType: "btrfs"}, common.ErrInvalidArgument},
		// A count this provider cannot honor is well-formed and served by the
		// local provider, so it is ErrUnsupported — "choose another backend" —
		// not a complaint about the argument.
		{"one replica is not replicated", common.VolumeSpec{Name: testVolume, SizeBytes: testSize, Replicas: 1}, common.ErrUnsupported},
		{"three replicas need a mesh", common.VolumeSpec{Name: testVolume, SizeBytes: testSize, Replicas: 3}, common.ErrUnsupported},
		// A negative count is meaningless against any backend.
		{"negative replicas", common.VolumeSpec{Name: testVolume, SizeBytes: testSize, Replicas: -1}, common.ErrInvalidArgument},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			_, err := p.Provision(context.Background(), tc.spec)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Provision = %v, want %v", err, tc.want)
			}
			if got := r.commands(); len(got) != 0 {
				t.Errorf("a rejected spec ran commands: %v", got)
			}
		})
	}
}

func TestProvisionAcceptsTwoReplicas(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, &common.VolumeSpec{Name: testVolume, SizeBytes: testSize, Replicas: 2})
}

// TestProvisionAcceptsTheLargestRepresentableSize is the boundary the refusals
// in TestProvisionValidation must not overshoot: the largest usable capacity
// whose backing still fits in an int64 has to be ATTEMPTED, not refused. Its
// backing is created at backingBytes(maxDataBytes(0, false)), which is exactly
// math.MaxInt64.
func TestProvisionAcceptsTheLargestRepresentableSize(t *testing.T) {
	p, r := newTestProvider(t)
	limit := maxDataBytes(0, false)
	r.scriptProvisionAt(testVolume, backingBytes(limit, false))

	vol, err := p.Provision(context.Background(), common.VolumeSpec{Name: testVolume, SizeBytes: limit, Replicas: 2})
	if err != nil {
		t.Fatalf("Provision at the representable maximum = %v, want it attempted", err)
	}
	if vol.Spec.SizeBytes != limit {
		t.Errorf("Volume.Spec.SizeBytes = %d, want the representable maximum %d", vol.Spec.SizeBytes, limit)
	}
	r.assertRan(t, fmt.Sprintf("lvcreate --yes --name vol1 --size %db vg0", backingBytes(limit, false)))
}

func TestProvisionRollback(t *testing.T) {
	tests := []struct {
		name       string
		breakIt    func(*fakeRunner)
		wantRan    []string
		wantNotRan []string
	}{
		{
			name: "lvcreate fails",
			breakIt: func(r *fakeRunner) {
				r.on(binLVCreate, "--yes", "--name", testVolume, "--size", strconv.FormatInt(backingBytes(testSize, false), 10)+"b", testVG).
					fails(5, "Volume group \"vg0\" has insufficient free space")
			},
			wantNotRan: []string{"lvremove", "drbdadm"},
		},
		{
			name: "create-md fails",
			breakIt: func(r *fakeRunner) {
				r.on(binDRBDAdm, "--", "--force", "create-md", testVolume).fails(1, "open(/dev/vg0/vol1) failed")
				r.on(binDRBDAdm, "down", testVolume).returns("")
				r.on(binLVRemove, "--force", "vg0/vol1").returns("")
			},
			wantRan: []string{"drbdadm down vol1", "lvremove --force vg0/vol1"},
		},
		{
			name: "up fails",
			breakIt: func(r *fakeRunner) {
				r.on(binDRBDAdm, "up", testVolume).fails(1, "Failure: (127) Device minor not allocated")
				r.on(binDRBDAdm, "down", testVolume).returns("")
				r.on(binLVRemove, "--force", "vg0/vol1").returns("")
			},
			wantRan: []string{"drbdadm down vol1", "lvremove --force vg0/vol1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			r.scriptProvision(testVolume, testSize)
			tc.breakIt(r)

			if _, err := p.Provision(context.Background(), *defaultSpec()); err == nil {
				t.Fatal("Provision succeeded, want an error")
			}

			for _, want := range tc.wantRan {
				r.assertRan(t, want)
			}
			for _, notWant := range tc.wantNotRan {
				r.assertNotRan(t, notWant)
			}

			// Nothing is left behind: the volume does not exist, and its minor
			// and port are free for the next attempt.
			if _, err := p.loadMeta(testVolume); !errors.Is(err, common.ErrNotFound) {
				t.Errorf("state record survived a failed Provision: %v", err)
			}
			if _, err := os.Stat(p.resPath(testVolume)); !os.IsNotExist(err) {
				t.Errorf("resource file survived a failed Provision: %v", err)
			}
			metas, err := p.listMeta()
			if err != nil {
				t.Fatalf("listMeta: %v", err)
			}
			if len(metas) != 0 {
				t.Errorf("state directory holds %+v after a failed Provision", metas)
			}
		})
	}
}

// TestProvisionRollbackRetainsWhatItCouldNotRemove is the other half of
// TestProvisionRollback: that one proves a cleanup which SUCCEEDS leaves
// nothing behind, and this one proves a cleanup which FAILS leaves everything
// behind, deliberately.
//
// Removing the two files regardless of whether the teardown worked is worse
// than keeping them. The resource file is what drbdadm needs to take a resource
// down, so deleting it after "drbdadm down" failed removes the means of
// cleaning up a resource that may still be live. The state record is what makes
// the reservation visible to listMeta, so deleting it hands the minor and port
// of that still-live resource to the next Provision. And together they are the
// only evidence an operator has that anything survived at all.
func TestProvisionRollbackRetainsWhatItCouldNotRemove(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(*fakeRunner)
		// wantNamed are the artifacts beyond the two files that the error has to
		// name, because they are what the operator has to go and deal with.
		wantNamed []string
		// wantNotRan are commands the rollback must not have reached.
		wantNotRan []string
	}{
		{
			name: "the resource would not go down, so it may still be live",
			breakIt: func(r *fakeRunner) {
				r.on(binDRBDAdm, "up", testVolume).fails(1, "Failure: (127) Device minor not allocated")
				r.on(binDRBDAdm, "down", testVolume).fails(11, "State change failed: Device is held open by someone")
				// Scripted to SUCCEED, so that its absence from the log is the
				// ordering refusing to run it and not a fake declining the
				// command. This is the sequence the old code ran: a failed down
				// followed by lvremove --force on a device the resource it
				// could not take down may still hold open.
				r.on(binLVRemove, "--force", "vg0/vol1").returns("")
			},
			wantNamed: []string{
				`drbd resource "vol1" may still be up`,
				"logical volume vg0/vol1",
			},
			wantNotRan: []string{"lvremove"},
		},
		{
			name: "the backing volume would not go away",
			breakIt: func(r *fakeRunner) {
				r.on(binDRBDAdm, "up", testVolume).fails(1, "Failure: (127) Device minor not allocated")
				// Down succeeded, so the device is closed and the refusal below
				// is about the volume itself. This branch still attempts the
				// removal, and retains when it is refused.
				r.on(binDRBDAdm, "down", testVolume).returns("")
				r.on(binLVRemove, "--force", "vg0/vol1").fails(5, "Logical volume vg0/vol1 in use")
			},
			wantNamed: []string{"logical volume vg0/vol1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			r.scriptProvision(testVolume, testSize)
			tc.breakIt(r)

			_, err := p.Provision(context.Background(), *defaultSpec())
			if err == nil {
				t.Fatal("Provision succeeded, want an error")
			}

			// (d) The error names what survived and where, or the operator has
			// no reason to go looking for any of it.
			for _, want := range append(tc.wantNamed, p.resPath(testVolume), p.metaPath(testVolume)) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the failure does not name %q, so it cannot be acted on:\n  %v", want, err)
				}
			}

			// A cleanup step that could destroy live data is not attempted
			// after the step that would have made it safe failed.
			for _, notWant := range tc.wantNotRan {
				r.assertNotRan(t, notWant)
			}

			// (a) The resource file is still there: it is what drbdadm needs to
			// take the resource down.
			if _, statErr := os.Stat(p.resPath(testVolume)); statErr != nil {
				t.Errorf("the resource file was removed even though the teardown failed: %v", statErr)
			}

			// (b) The reservation is still visible to the allocator. It stays
			// hidden from readers, which is what Incomplete is for.
			metas, listErr := p.listMeta()
			if listErr != nil {
				t.Fatalf("listMeta: %v", listErr)
			}
			if len(metas) != 1 || metas[0].Name != testVolume {
				t.Fatalf("the allocator sees %+v, want the retained reservation for %q", metas, testVolume)
			}
			if !metas[0].Incomplete {
				t.Error("the retained record is not marked incomplete, so readers would report the volume as real")
			}
			if _, loadErr := p.loadMeta(testVolume); !errors.Is(loadErr, common.ErrNotFound) {
				t.Errorf("a reader can see the half-built volume = %v, want ErrNotFound", loadErr)
			}

			// (c) And the numbers it reserves cannot be handed out again, which
			// is the whole point of keeping it: the resource may still hold them.
			kept := metas[0]
			spec := common.VolumeSpec{
				Name: "vol2", SizeBytes: testSize, Replicas: 2,
				Labels: map[string]string{
					LabelMinor: strconv.Itoa(kept.Minor),
					LabelPort:  strconv.Itoa(kept.Port),
				},
			}
			_, collideErr := p.Provision(context.Background(), spec)
			if !errors.Is(collideErr, common.ErrInvalidArgument) {
				t.Errorf("provisioning onto the retained minor/port = %v, want ErrInvalidArgument", collideErr)
			}
			if collideErr != nil && !strings.Contains(collideErr.Error(), testVolume) {
				t.Errorf("the collision does not say which volume holds the numbers: %v", collideErr)
			}
		})
	}
}

func TestProvisionAllocatesDistinctResources(t *testing.T) {
	p, r := newTestProvider(t)

	provision(t, p, r, &common.VolumeSpec{Name: "vol1", SizeBytes: testSize, Replicas: 2})
	provision(t, p, r, &common.VolumeSpec{Name: "vol2", SizeBytes: testSize, Replicas: 2})

	first, err := p.loadMeta("vol1")
	if err != nil {
		t.Fatalf("loadMeta(vol1): %v", err)
	}
	second, err := p.loadMeta("vol2")
	if err != nil {
		t.Fatalf("loadMeta(vol2): %v", err)
	}
	if first.Minor == second.Minor {
		t.Errorf("both volumes were given minor %d", first.Minor)
	}
	if first.Port == second.Port {
		t.Errorf("both volumes were given port %d", first.Port)
	}
}

func TestProvisionFromSnapshot(t *testing.T) {
	p, r := newTestProvider(t)

	// The source volume must be one this provider manages: a snapshot id is
	// caller input, and an LV that merely looks like ours is not ours.
	provision(t, p, r, &common.VolumeSpec{Name: "vol1", SizeBytes: testSize, Replicas: 2})
	r.reset()

	snapLV := "vol1.snap.nightly"
	// The origin of a snapshot this provider took is the BACKING volume, whose
	// size already includes DRBD's metadata. Restoring at the volume's usable
	// size must still be accepted.
	r.scriptLVS(lvsJSON(lvEntry{
		Name: snapLV, VG: testVG, Size: "214748364", Origin: "vol1",
		OriginSize: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10), Time: "2026-08-26 10:00:00 -0500", Attr: "swi-a-s---",
	}))

	r.scriptProvisionAt("vol2", originBacking())
	if _, err := p.Provision(context.Background(), common.VolumeSpec{
		Name: "vol2", SizeBytes: testSize, Replicas: 2,
		SourceSnapshotID: common.SnapshotID("vg0/" + snapLV),
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	assertCopied(t, r, "/dev/vg0/vol1.snap.nightly", "/dev/vg0/vol2")
	// Created at the SOURCE's size, not the caller's: the copy is whole-device,
	// and a longer destination strands the source's metadata inside it.
	r.assertRan(t, fmt.Sprintf("lvcreate --yes --name vol2 --size %db vg0", originBacking()))

	// The copy happens before DRBD metadata is written, so the metadata
	// describes the new device rather than the one the image came from.
	cmds := r.commands()
	copyAt, mdAt := -1, -1
	for i, c := range cmds {
		if strings.HasPrefix(c, "copy ") {
			copyAt = i
		}
		if strings.Contains(c, "create-md") {
			mdAt = i
		}
	}
	if copyAt < 0 || mdAt < 0 || copyAt > mdAt {
		t.Errorf("the copy must run before create-md; commands were:\n  %s", strings.Join(cmds, "\n  "))
	}
}

func TestProvisionFromSnapshotErrors(t *testing.T) {
	tests := []struct {
		name string
		// managed provisions vol1 first, making it a volume this provider owns.
		managed bool
		snapID  string
		lvs     string
		size    int64
		want    error
	}{
		{
			name: "unknown snapshot", managed: true, snapID: "vg0/vol1.snap.missing",
			lvs: lvsJSON(), size: testSize, want: common.ErrSnapshotNotFound,
		},
		{
			// An LV named like one of our snapshots, in our volume group, but
			// taken from a volume this provider has never heard of. Restoring
			// from it would copy an unmanaged device's contents.
			name: "snapshot of an unmanaged volume", managed: false, snapID: "vg0/vol1.snap.nightly",
			lvs: lvsJSON(lvEntry{
				Name: "vol1.snap.nightly", VG: testVG, Origin: "vol1",
				OriginSize: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
			}),
			size: testSize, want: common.ErrSnapshotNotFound,
		},
		{
			// A plain logical volume whose name happens to have the snapshot
			// shape: no origin, so it is not a snapshot at all.
			name: "not actually a snapshot", managed: true, snapID: "vg0/vol1.snap.nightly",
			lvs:  lvsJSON(lvEntry{Name: "vol1.snap.nightly", VG: testVG, Size: strconv.FormatInt(testSize, 10)}),
			size: testSize, want: common.ErrSnapshotNotFound,
		},
		{
			// The right name, but taken from a different volume.
			name: "snapshot of another volume", managed: true, snapID: "vg0/vol1.snap.nightly",
			lvs: lvsJSON(lvEntry{
				Name: "vol1.snap.nightly", VG: testVG, Origin: "vol2",
				OriginSize: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
			}),
			size: testSize, want: common.ErrSnapshotNotFound,
		},
		{
			// Without an origin size the copy cannot be sized, and guessing
			// would silently truncate the restored filesystem.
			name: "origin size missing from the lvs report", managed: true, snapID: "vg0/vol1.snap.nightly",
			lvs:  lvsJSON(lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: "vol1"}),
			size: testSize, want: common.ErrUnsupported,
		},
		{
			name: "shrinking during restore is refused", managed: true, snapID: "vg0/vol1.snap.nightly",
			lvs: lvsJSON(lvEntry{
				Name: "vol1.snap.nightly", VG: testVG, Origin: "vol1",
				OriginSize: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
			}),
			size: testSize / 2, want: common.ErrUnsupported,
		},
		{name: "malformed id", managed: true, snapID: "not-an-id", size: testSize, want: common.ErrInvalidArgument},
		{name: "id from another volume group", managed: true, snapID: "other/vol1.snap.nightly", size: testSize, want: common.ErrInvalidArgument},
		{name: "id that is not a snapshot", managed: true, snapID: "vg0/vol1", size: testSize, want: common.ErrInvalidArgument},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			if tc.managed {
				provision(t, p, r, &common.VolumeSpec{Name: "vol1", SizeBytes: testSize, Replicas: 2})
			}
			r.reset()
			if tc.lvs != "" {
				r.scriptLVS(tc.lvs)
			}

			_, err := p.Provision(context.Background(), common.VolumeSpec{
				Name: "vol2", SizeBytes: tc.size, Replicas: 2, SourceSnapshotID: common.SnapshotID(tc.snapID),
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Provision = %v, want %v", err, tc.want)
			}
			r.assertNotRan(t, "lvcreate")
			r.assertNotRan(t, "dd ")
			if _, err := p.loadMeta("vol2"); !errors.Is(err, common.ErrNotFound) {
				t.Errorf("a rejected restore left a state record: %v", err)
			}
		})
	}
}

// TestProvisionIsSerialised runs concurrent provisions and requires every
// volume to end up with a minor and port of its own.
func TestProvisionIsSerialised(t *testing.T) {
	p, r := newTestProvider(t)

	const n = 8
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("vol%d", i)
		r.scriptProvision(names[i], testSize)
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			_, errs[i] = p.Provision(context.Background(), common.VolumeSpec{Name: name, SizeBytes: testSize, Replicas: 2})
		}(i, name)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Provision(%q): %v", names[i], err)
		}
	}

	metas, err := p.listMeta()
	if err != nil {
		t.Fatalf("listMeta: %v", err)
	}
	if len(metas) != n {
		t.Fatalf("provisioned %d volumes, recorded %d", n, len(metas))
	}
	minors, ports := map[int]string{}, map[int]string{}
	for _, m := range metas {
		if other, dup := minors[m.Minor]; dup {
			t.Errorf("minor %d given to both %q and %q", m.Minor, other, m.Name)
		}
		if other, dup := ports[m.Port]; dup {
			t.Errorf("port %d given to both %q and %q", m.Port, other, m.Name)
		}
		minors[m.Minor], ports[m.Port] = m.Name, m.Name
	}
}

// -----------------------------------------------------------------------------
// Attach and Detach
// -----------------------------------------------------------------------------

func TestAttach(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Down, so this is the attach that has work to do.
	r.scriptStatus(emptyStatus)

	info, err := p.Attach(context.Background(), testVolume, testNode)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if info.DevicePath != "/dev/drbd0" {
		t.Errorf("DevicePath = %q, want /dev/drbd0", info.DevicePath)
	}
	if info.Node != testNode {
		t.Errorf("Node = %q, want %q", info.Node, testNode)
	}
	r.assertRan(t, "drbdadm up vol1")
	// Attaching is not promoting: the device exists in both roles.
	r.assertNotRan(t, "primary")
}

// TestAttachConvergesWhenAlreadyUp is Detach's already-down convergence in the
// other direction, and it is the ordinary path rather than an edge case:
// Provision brings the resource up before it returns, so a caller following the
// contract's Provision, Attach, Mount order finds it up.
//
// Repeating "drbdadm up" there may or may not be a no-op on a real node. This
// makes that irrelevant, which is the point — the behavior has never been run
// against hardware.
func TestAttachConvergesWhenAlreadyUp(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	// Scripted, so that its absence from the log is the convergence and not a
	// fake that would have refused the command.
	r.on(binDRBDAdm, "up", testVolume).returns("")

	info, err := p.Attach(context.Background(), testVolume, testNode)
	if err != nil {
		t.Fatalf("Attach of an already-up resource = %v, want nil", err)
	}
	if info.DevicePath != "/dev/drbd0" {
		t.Errorf("DevicePath = %q, want /dev/drbd0", info.DevicePath)
	}
	r.assertNotRan(t, "drbdadm up")
}

// TestAttachNodeSemantics separates the two ways a node can be unattachable.
// The peer is a real host of the resource, so asking for it is well-formed and
// this provider simply cannot serve it — ErrUnsupported. A name that is neither
// host names no node of this volume, which is a malformed request.
func TestAttachNodeSemantics(t *testing.T) {
	tests := []struct {
		name string
		node common.NodeID
		want error
	}{
		{"the peer is servable, but not from here", testPeer, common.ErrUnsupported},
		{"a node of no resource", "node-c", common.ErrInvalidArgument},
		{"empty node", "", common.ErrInvalidArgument},
		{"a hostile name", "node-a; rm -rf /", common.ErrInvalidArgument},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()

			_, err := p.Attach(context.Background(), testVolume, tc.node)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Attach to %q = %v, want %v", tc.node, err, tc.want)
			}
			if err := p.Detach(context.Background(), testVolume, tc.node); !errors.Is(err, tc.want) {
				t.Errorf("Detach from %q = %v, want %v", tc.node, err, tc.want)
			}
			if got := r.commands(); len(got) != 0 {
				t.Errorf("a rejected node ran commands: %v", got)
			}
		})
	}
}

func TestDetach(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.on(binDRBDAdm, "down", testVolume).returns("")

	if err := p.Detach(context.Background(), testVolume, testNode); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	r.assertRan(t, "drbdadm down vol1")
}

// TestAttachCannotLandInsideDeletesWindow is the case that shows the rule is
// not "serialize the methods that check something".
//
// Attach checks nothing about the resource's state, which is why it looked safe
// unlocked. The check it invalidates is Delete's: Delete sees the resource is
// not up, skips the teardown on that basis, and goes on to lvremove the backing
// volume and unlink the state files. A "drbdadm up" anywhere in that span
// activates a resource on storage that is about to be removed, and returns a
// device path for a volume that no longer has a record.
//
// The pause is on Delete's lvs listing, which sits between its status probe and
// its lvremove — inside the window, with the not-up observation already made.
func TestAttachCannotLandInsideDeletesWindow(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	inWindow := make(chan struct{})
	release := make(chan struct{})

	// Not up, so Delete skips the teardown and proceeds straight to removal.
	r.scriptStatus(emptyStatus)
	r.on(binLVS, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", lvsFields, testVG).
		returns(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)})).
		then(func() {
			close(inWindow)
			<-release
		})
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")
	r.on(binDRBDAdm, "up", testVolume).returns("")

	deleteErr := make(chan error, 1)
	go func() { deleteErr <- p.Delete(context.Background(), testVolume) }()
	<-inWindow

	attachErr := make(chan error, 1)
	go func() {
		_, err := p.Attach(context.Background(), testVolume, testNode)
		attachErr <- err
	}()

	for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline); {
		if indexOfCommand(r.commands(), "drbdadm up vol1") >= 0 {
			close(release)
			t.Fatalf("the resource was brought up while a delete sat between its status probe "+
				"and its lvremove:\n  %s", strings.Join(r.commands(), "\n  "))
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	if err := <-deleteErr; err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// The delete won, so the record is gone and the attach must say so rather
	// than bring up a resource whose backing volume has been removed.
	if err := <-attachErr; !errors.Is(err, common.ErrNotFound) {
		t.Errorf("Attach of a volume deleted out from under it = %v, want common.ErrNotFound", err)
	}
	r.assertNotRan(t, "drbdadm up")
}

func TestDetachRefusesPrimary(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	err := p.Detach(context.Background(), testVolume, testNode)
	if !errors.Is(err, ErrPrimary) {
		t.Fatalf("Detach of a Primary = %v, want ErrPrimary", err)
	}
	r.assertNotRan(t, "drbdadm down")
}

// TestDetachRefusesAnUnprovableRole is Delete's guard in the other destructive
// method. Taking the resource down on a node that may be Primary pulls the
// block device out from under whatever is serving writes to it, and a role that
// did not parse is not evidence that the node is not Primary.
func TestDetachRefusesAnUnprovableRole(t *testing.T) {
	for _, role := range []string{"Unknown", "Quorum-Pending-drbd10"} {
		t.Run(role, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()

			r.scriptStatus(statusJSON(testVolume, 0, role, "Connected", "Established", "UpToDate"))
			// Scripted so the guard is what stops the teardown, not a fake
			// that would have refused the command anyway.
			r.on(binDRBDAdm, "down", testVolume).returns("")

			err := p.Detach(context.Background(), testVolume, testNode)
			if !errors.Is(err, ErrRoleUnknown) {
				t.Fatalf("Detach of a resource reporting role %q = %v, want ErrRoleUnknown", role, err)
			}
			if !strings.Contains(err.Error(), role) {
				t.Errorf("the refusal should name the role drbdsetup reported: %v", err)
			}
			r.assertNotRan(t, "drbdadm down")
		})
	}
}

// TestPromoteCannotLandInsideDetachsWindow is the mirror of
// TestDemoteCannotLandInsideSnapshotsWindow, and the reason Detach holds the
// lock: it reads the role, finds Secondary, and then takes the resource down,
// which are two steps. A promotion between them leaves a caller that was told
// its volume is now Primary holding a volume whose device has just been
// removed — the precondition Detach checked stopped holding while Detach was
// still acting on it.
//
// Making a volume MORE writable is no more harmless than making it less so;
// only the method whose check it breaks differs.
func TestPromoteCannotLandInsideDetachsWindow(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	inWindow := make(chan struct{})
	release := make(chan struct{})

	// The status probe is Detach's role check; pausing as it is answered parks
	// Detach between the check and the drbdadm down.
	r.on(binDRBDSetup, "status", "--json").
		returns(secondaryStatus(testVolume, 0)).
		then(func() {
			close(inWindow)
			<-release
		})
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.on(binDRBDAdm, "primary", testVolume).returns("")

	detachErr := make(chan error, 1)
	go func() { detachErr <- p.Detach(context.Background(), testVolume, testNode) }()
	<-inWindow

	promoteErr := make(chan error, 1)
	go func() { promoteErr <- p.Promote(context.Background(), testVolume) }()

	for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline); {
		if indexOfCommand(r.commands(), "drbdadm primary vol1") >= 0 {
			close(release)
			t.Fatalf("the volume was promoted while a detach sat between its role check "+
				"and its teardown:\n  %s", strings.Join(r.commands(), "\n  "))
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	if err := <-detachErr; err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if err := <-promoteErr; err != nil {
		t.Fatalf("Promote: %v", err)
	}

	cmds := r.commands()
	downAt := indexOfCommand(cmds, "drbdadm down vol1")
	promoteAt := indexOfCommand(cmds, "drbdadm primary vol1")
	if downAt < 0 || promoteAt < 0 {
		t.Fatalf("expected both the teardown and the promotion to run; ran:\n  %s", strings.Join(cmds, "\n  "))
	}
	if downAt > promoteAt {
		t.Errorf("the promotion completed before the teardown, so its caller holds a device that is about to vanish:\n  %s",
			strings.Join(cmds, "\n  "))
	}
}

func TestDetachConvergesWhenAlreadyDown(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	if err := p.Detach(context.Background(), testVolume, testNode); err != nil {
		t.Fatalf("Detach of a resource that is not up = %v, want nil", err)
	}
	r.assertNotRan(t, "drbdadm down")
}

// -----------------------------------------------------------------------------
// Mount and Unmount
// -----------------------------------------------------------------------------

func TestMountFormatsAnEmptyDevice(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").fails(blkidNoSig, "")
	r.on("mkfs.ext4", "-q", "/dev/drbd0").returns("")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{Flags: []string{"noatime"}}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	r.assertRan(t, "mkfs.ext4 -q /dev/drbd0")
	assertMounted(t, m, "/dev/drbd0", testMountPoint, "ext4", mount.NoATime, "")
}

func TestMountLeavesAFormattedDeviceAlone(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("/dev/drbd0: UUID=\"3f1e\" BLOCK_SIZE=\"4096\" TYPE=\"ext4\"\n")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	r.assertNotRan(t, "mkfs")
}

// TestMountDoesNotFormatWhenProbingFails is the safety property behind the
// format-on-first-mount behavior: only blkid's "nothing here" answer permits a
// mkfs, and any other failure leaves the device untouched.
func TestMountDoesNotFormatWhenProbingFails(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").fails(4, "blkid: cannot open /dev/drbd0")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err == nil {
		t.Fatal("Mount succeeded despite an unreadable device")
	}
	r.assertNotRan(t, "mkfs")
	assertNoMount(t, m)
}

func TestMountReadOnly(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("/dev/drbd0: UUID=\"3f1e\" BLOCK_SIZE=\"4096\" TYPE=\"ext4\"\n")

	err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{
		ReadOnly: true, Flags: []string{"nosuid"},
	})
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	assertMounted(t, m, "/dev/drbd0", testMountPoint, "ext4", mount.ReadOnly|mount.NoSUID, "")
}

func TestMountRequiresPrimary(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
	if !errors.Is(err, common.ErrNotPrimary) {
		t.Fatalf("Mount on a Secondary = %v, want common.ErrNotPrimary", err)
	}
	assertNoMount(t, m)
	r.assertNotRan(t, "mkfs")
}

func TestMountRequiresAttach(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
	if !errors.Is(err, common.ErrNotAttached) {
		t.Fatalf("Mount of a resource that is not up = %v, want ErrNotAttached", err)
	}
}

func TestMountValidation(t *testing.T) {
	tests := []struct {
		name   string
		target string
		opts   common.MountOptions
		fsType string
		want   error
	}{
		{"relative target", "mnt/vol1", common.MountOptions{}, "ext4", common.ErrInvalidArgument},
		{"traversing target", "/mnt/../etc", common.MountOptions{}, "ext4", common.ErrInvalidArgument},
		{"root target", "/", common.MountOptions{}, "ext4", common.ErrInvalidArgument},
		{"disallowed flag", testMountPoint, common.MountOptions{Flags: []string{"bind"}}, "ext4", common.ErrInvalidArgument},
		{"ro smuggled through flags", testMountPoint, common.MountOptions{Flags: []string{"ro"}}, "ext4", common.ErrInvalidArgument},
		{"unsupported override", testMountPoint, common.MountOptions{FSType: "btrfs"}, "ext4", common.ErrInvalidArgument},
		{"raw volume has no filesystem", testMountPoint, common.MountOptions{}, "", common.ErrInvalidArgument},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			spec := defaultSpec()
			spec.FSType = tc.fsType
			provision(t, p, r, spec)
			r.reset()

			err := p.Mount(context.Background(), testVolume, tc.target, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Mount = %v, want %v", err, tc.want)
			}
			if got := r.commands(); len(got) != 0 {
				t.Errorf("a rejected Mount ran commands: %v", got)
			}
		})
	}
}

func TestUnmount(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptMount("/dev/drbd0", testMountPoint)

	if err := p.Unmount(context.Background(), testVolume, testMountPoint); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	assertUnmounted(t, m, testMountPoint)
}

func TestUnmountConvergesWhenNotMounted(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptMount("/dev/drbd0", "")

	if err := p.Unmount(context.Background(), testVolume, testMountPoint); err != nil {
		t.Fatalf("Unmount of an unmounted target = %v, want nil", err)
	}
	assertNoUnmount(t, m)
}

// TestUnmountFindsAMountMadeUnderAnAliasedDeviceName is the hole that comparing
// mount SOURCES left open.
//
// A DRBD device has several names — /dev/drbdN and the udev symlinks under
// /dev/drbd/by-res and /dev/drbd/by-disk — and the mount table records whichever
// one was used to mount it. Comparing that string against the single name this
// provider spells read a filesystem mounted through an alias as belonging to
// somebody else, and Unmount converged on "not mounted" while the filesystem
// stayed up. Identity is the device number, which is the same under every name.
func TestUnmountFindsAMountMadeUnderAnAliasedDeviceName(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptMountUnderAlias("/dev/drbd/by-res/vol1/0", "/dev/drbd0", testMountPoint)

	if err := p.Unmount(context.Background(), testVolume, testMountPoint); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	assertUnmounted(t, m, testMountPoint)
}

// TestUnmountConvergesWhenTheDeviceIsGone covers a teardown that has already
// taken the resource down: the device node is absent, so nothing of this volume
// can be mounted anywhere, and the unmount converges rather than failing on a
// device it cannot identify.
func TestUnmountConvergesWhenTheDeviceIsGone(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.failMountTable(&mountinfo.DeviceError{Path: "/dev/drbd0", Err: os.ErrNotExist})

	if err := p.Unmount(context.Background(), testVolume, testMountPoint); err != nil {
		t.Fatalf("Unmount with the device gone = %v, want nil", err)
	}
	assertNoUnmount(t, m)
}

// TestUnmountFailsClosedWhenTheMountTableItselfIsMissing is the other half of
// the convergence above, and the reason it tests the error's TYPE.
//
// A missing device node and an unopenable /proc/self/mountinfo both report
// os.ErrNotExist. The first means nothing of this volume is mounted anywhere;
// the second means nothing is known at all, and reading it as "not mounted" is
// exactly the fail-open this provider stopped asking findmnt to avoid.
func TestUnmountFailsClosedWhenTheMountTableItselfIsMissing(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.failMountTable(&mountinfo.ReadError{Path: mountinfo.ProcPath, Err: os.ErrNotExist})

	err := p.Unmount(context.Background(), testVolume, testMountPoint)
	if err == nil {
		t.Fatal("Unmount converged over a mount table it could not read")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Unmount = %v, want it to carry the read failure", err)
	}
	assertNoUnmount(t, m)
}

// TestUnmountLeavesAnOverMountedTargetAlone covers the target this volume is
// mounted at and no longer visible at, because something has been mounted over
// it. umount(2) detaches what is visible, so acting on the path would take that
// other filesystem down and leave this volume mounted underneath it.
func TestUnmountLeavesAnOverMountedTargetAlone(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptMount("/dev/drbd0", testMountPoint)
	r.overMount(testMountPoint, "/dev/sdb1")

	if err := p.Unmount(context.Background(), testVolume, testMountPoint); err != nil {
		t.Fatalf("Unmount of an over-mounted target = %v, want nil", err)
	}
	assertNoUnmount(t, m)
}

// TestUnmountLeavesAnotherDeviceAlone covers a target where something else has
// since been mounted. This volume is not mounted there, which the contract
// calls a converging no-op rather than an error — and the other device is not
// this provider's to unmount, so nothing happens to it either way.
func TestUnmountLeavesAnotherDeviceAlone(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptMount("/dev/sda1", testMountPoint)

	if err := p.Unmount(context.Background(), testVolume, testMountPoint); err != nil {
		t.Fatalf("Unmount of a target holding another device = %v, want nil", err)
	}
	assertNoUnmount(t, m)
}

// -----------------------------------------------------------------------------
// Resize
// -----------------------------------------------------------------------------

func TestResize(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Resize refuses a resource that is down, so every case here has one up.
	r.scriptStatus(primaryStatus(testVolume, 0))

	newSize := testSize * 2
	r.scriptLVS(lvsJSON(lvEntry{
		Name: "vol1", VG: testVG,
		Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
	}))
	r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(newSize, false), 10)+"b", "vg0/vol1").returns("")
	r.on(binDRBDAdm, "resize", testVolume).returns("")
	r.scriptMount("/dev/drbd0", "")
	// Unmounted ext4 on a Primary: checked, then grown offline.
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binE2fsck, "-f", "-p", "/dev/drbd0").returns("")
	r.on(binResize2fs, "/dev/drbd0").returns("")

	if err := p.Resize(context.Background(), testVolume, newSize); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	r.assertRan(t, fmt.Sprintf("lvextend --size %db vg0/vol1", backingBytes(newSize, false)))
	r.assertRan(t, "e2fsck -f -p /dev/drbd0")
	r.assertRan(t, "resize2fs /dev/drbd0")
	r.assertRan(t, "drbdadm resize vol1")

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.SizeBytes != newSize {
		t.Errorf("recorded size = %d, want %d", meta.SizeBytes, newSize)
	}
}

func TestResizeRefusesShrink(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Resize refuses a resource that is down, so every case here has one up.
	r.scriptStatus(primaryStatus(testVolume, 0))

	err := p.Resize(context.Background(), testVolume, testSize/2)
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Resize smaller = %v, want ErrUnsupported", err)
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("a refused Resize ran commands: %v", got)
	}
}

// TestResizeRepeatFinishesTheFilesystem covers the contract's requirement that
// a repeat of the same request completes a job whose device half landed and
// whose filesystem half did not. Treating an already-large-enough device as
// nothing to do would report success over a filesystem still at its old size.
func TestResizeRepeatFinishesTheFilesystem(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Resize refuses a resource that is down, so every case here has one up.
	r.scriptStatus(primaryStatus(testVolume, 0))

	// The device is already at the recorded size — the state a first attempt
	// leaves when its filesystem grow failed.
	r.scriptLVS(lvsJSON(lvEntry{
		Name: testVolume, VG: testVG,
		Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
	}))
	r.on(binDRBDAdm, "resize", testVolume).returns("")
	r.scriptMount("/dev/drbd0", testMountPoint)
	r.on(binResize2fs, "/dev/drbd0").returns("")

	if err := p.Resize(context.Background(), testVolume, testSize); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	// The device needed nothing, so no extend — but the filesystem was grown.
	r.assertNotRan(t, "lvextend")
	r.assertRan(t, "resize2fs /dev/drbd0")
}

// TestResizeRefusesASizeWhoseBackingOverflows is the regression test for #18.
//
// A newSize whose backing — data plus DRBD metadata, rounded up to an extent —
// exceeds int64 makes backingBytes wrap NEGATIVE. Unguarded, resizeLocked then
// finds entry.sizeBytes() < target false (target is negative), skips lvextend
// and the drbdadm resize after it, grows no filesystem, and STILL writes
// meta.SizeBytes = newSize and returns nil: silent success over a device that
// never moved. Every later legitimate Resize is then refused as a shrink
// against that fabricated recorded size — the volume is bricked through this
// API. The guard turns the malformed size into ErrInvalidArgument before any of
// that. Removing it reproduces the skipped-extend-with-recorded-size failure
// this asserts against.
func TestResizeRefusesASizeWhoseBackingOverflows(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Resize refuses a resource that is down, so keep one up throughout.
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{
		Name: testVolume, VG: testVG,
		Size:       strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
		ExtentSize: strconv.FormatInt(testExtentSize, 10),
	}))

	limit := maxDataBytes(testExtentSize, false)
	for _, tc := range []struct {
		name string
		size int64
	}{
		{"math.MaxInt64", math.MaxInt64},
		// The exact value at which backingBytes stops being representable once
		// the extent rounding is layered on: the largest representable size plus
		// one. A naive guard that bounded only the raw request, not its backing,
		// would let this through.
		{"one past the representable maximum", limit + 1},
	} {
		err := p.Resize(context.Background(), testVolume, tc.size)
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("Resize(%s) = %v, want ErrInvalidArgument", tc.name, err)
		}
	}

	// Nothing was extended or resized, and — the crux of the bug — the record
	// was NOT advanced to a size the device never reached.
	r.assertNotRan(t, "lvextend")
	r.assertNotRan(t, "drbdadm resize")
	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.SizeBytes != testSize {
		t.Errorf("recorded size = %d after refused resizes, want the unchanged %d", meta.SizeBytes, testSize)
	}
}

// TestResizeAttemptsTheLargestRepresentableSize is the boundary a naive guard
// gets wrong from the other side: the largest size whose backing is still
// representable must be ATTEMPTED, not refused. An off-by-one that rejected it
// would deny a request the provider can actually serve.
func TestResizeAttemptsTheLargestRepresentableSize(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	limit := maxDataBytes(testExtentSize, false)

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{
		Name: testVolume, VG: testVG,
		Size:       strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
		ExtentSize: strconv.FormatInt(testExtentSize, 10),
	}))
	r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(limit, false), 10)+"b", "vg0/vol1").returns("")
	r.on(binDRBDAdm, "resize", testVolume).returns("")
	r.scriptMount("/dev/drbd0", "")
	r.on(binE2fsck, "-f", "-p", "/dev/drbd0").returns("")
	r.on(binResize2fs, "/dev/drbd0").returns("")

	if err := p.Resize(context.Background(), testVolume, limit); err != nil {
		t.Fatalf("Resize to the representable maximum = %v, want it attempted", err)
	}
	// It reached the device rather than being turned away at the guard.
	r.assertRan(t, fmt.Sprintf("lvextend --size %db vg0/vol1", backingBytes(limit, false)))
	r.assertRan(t, "drbdadm resize vol1")

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.SizeBytes != limit {
		t.Errorf("recorded size = %d, want the representable maximum %d", meta.SizeBytes, limit)
	}
}

// -----------------------------------------------------------------------------
// Snapshots
// -----------------------------------------------------------------------------

func TestSnapshot(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10), Attr: "-wi-ao----"}))
	r.on(binLVCreate, "--yes", "--snapshot", "--name", "vol1.snap.nightly", "--extents", "20%ORIGIN", "vg0/vol1").returns("")

	id, err := p.Snapshot(context.Background(), testVolume, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if want := common.SnapshotID("vg0/vol1.snap.nightly"); id != want {
		t.Errorf("SnapshotID = %q, want %q", id, want)
	}
	r.assertRan(t, "lvcreate --yes --snapshot --name vol1.snap.nightly --extents 20%ORIGIN vg0/vol1")
}

// TestSnapshotRefusedOnSecondary encodes the crash-consistency rule: a
// Secondary's backing device is written by the replication stream with nothing
// above it ordering those writes, so there is no state worth capturing.
func TestSnapshotRefusedOnSecondary(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	_, err := p.Snapshot(context.Background(), testVolume, "nightly")
	if !errors.Is(err, common.ErrNotPrimary) {
		t.Fatalf("Snapshot on a Secondary = %v, want ErrNotPrimary", err)
	}
	r.assertNotRan(t, "lvcreate")
}

func TestSnapshotRefusedWhenResourceIsDown(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	_, err := p.Snapshot(context.Background(), testVolume, "nightly")
	if !errors.Is(err, common.ErrNotPrimary) {
		t.Fatalf("Snapshot of a resource that is not up = %v, want ErrNotPrimary", err)
	}
}

func TestSnapshotAlreadyExists(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(
		lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)},
		lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: "vol1"},
	))

	_, err := p.Snapshot(context.Background(), testVolume, "nightly")
	if !errors.Is(err, common.ErrAlreadyExists) {
		t.Fatalf("duplicate Snapshot = %v, want ErrAlreadyExists", err)
	}
	r.assertNotRan(t, "lvcreate")
}

func TestSnapshotRejectsHostileName(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	for _, name := range []string{"", "night.ly", "-rf", "nightly; rm -rf /"} {
		_, err := p.Snapshot(context.Background(), testVolume, name)
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("Snapshot(%q) = %v, want common.ErrInvalidArgument", name, err)
		}
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("a rejected Snapshot ran commands: %v", got)
	}
}

func TestListSnapshots(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptLVS(lvsJSON(
		lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10), Attr: "-wi-ao----"},
		// Active: LVM reports how much of the CoW area is used.
		lvEntry{Name: "vol1.snap.nightly", VG: testVG, Size: "214748364", Origin: "vol1", DataPercent: "25.00", OriginSize: strconv.FormatInt(testSize, 10), Time: "2026-08-26 03:00:00 -0500"},
		// Inactive: LVM reports nothing, because the kernel is not tracking it.
		lvEntry{Name: "vol1.snap.hourly", VG: testVG, Size: "107374182", Origin: "vol1", OriginSize: strconv.FormatInt(testSize, 10), Time: "2026-08-26 09:00:00 -0500"},
		// Another volume's snapshot, and an LV shaped like ours but taken from
		// something else: neither belongs to vol1.
		lvEntry{Name: "vol2.snap.nightly", VG: testVG, Origin: "vol2"},
		lvEntry{Name: "vol1.snap.impostor", VG: testVG, Origin: "vol2"},
	))

	snaps, err := p.ListSnapshots(context.Background(), testVolume)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %+v, want the two taken from vol1", snaps)
	}
	if snaps[0].Name != "hourly" || snaps[1].Name != "nightly" {
		t.Errorf("snapshots are not sorted by name: %+v", snaps)
	}
	if snaps[1].ID != common.SnapshotID("vg0/vol1.snap.nightly") {
		t.Errorf("ID = %q", snaps[1].ID)
	}
	if snaps[1].VolumeID != testVolume {
		t.Errorf("VolumeID = %q, want %q", snaps[1].VolumeID, testVolume)
	}
	// SizeBytes is what the snapshot OCCUPIES — a quarter of its CoW area —
	// not the area it was allocated. Reporting the allocation would say a
	// snapshot taken a second ago already fills a fifth of its origin.
	if want := int64(float64(214748364) * 25.0 / 100); snaps[1].SizeBytes != want {
		t.Errorf("SizeBytes = %d, want the occupied %d", snaps[1].SizeBytes, want)
	}
	// The inactive one reports nothing, and nothing means zero: LVM tracks
	// occupancy only while the kernel has the device mapped.
	if snaps[0].SizeBytes != 0 {
		t.Errorf("SizeBytes for an inactive snapshot = %d, want 0", snaps[0].SizeBytes)
	}
	if snaps[1].CreatedAt.IsZero() {
		t.Error("CreatedAt was not parsed from lv_time")
	}
}

// TestListSnapshotsRefusesAnUnreadableOccupancy is the accepted half of the
// data_percent review, at the level a caller sees.
//
// SizeBytes is a measurement, and a restore is sized against it. A field that
// cannot be read is not a measurement of zero — coercing it to one, which is
// what the parser used to do, hands back a fabricated number that looks exactly
// like a genuinely empty snapshot.
//
// The inactive-empty case is deliberately NOT here: it stays 0 and is asserted
// in TestListSnapshots, because an inactive snapshot reporting nothing is its
// ordinary state rather than a failure. See lvEntry.usedBytes.
func TestListSnapshotsRefusesAnUnreadableOccupancy(t *testing.T) {
	for _, pct := range []string{"lots", "-1", "120.00", "NaN"} {
		t.Run(pct, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()

			r.scriptLVS(lvsJSON(
				lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10), Attr: "-wi-ao----"},
				lvEntry{Name: "vol1.snap.nightly", VG: testVG, Size: "214748364", Origin: "vol1",
					DataPercent: pct, OriginSize: strconv.FormatInt(testSize, 10)},
			))

			snaps, err := p.ListSnapshots(context.Background(), testVolume)
			if err == nil {
				t.Fatalf("ListSnapshots with data_percent %q = %+v, want an error", pct, snaps)
			}
			for _, want := range []string{"vol1.snap.nightly", pct} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the failure does not name %q: %v", want, err)
				}
			}
		})
	}
}

// TestListSnapshotsEmpty pins the contract's distinction: no snapshots is an
// empty slice and a nil error, not ErrSnapshotNotFound.
func TestListSnapshotsEmpty(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)}))
	snaps, err := p.ListSnapshots(context.Background(), testVolume)
	if err != nil {
		t.Fatalf("ListSnapshots = %v, want nil", err)
	}
	if snaps == nil {
		t.Error("ListSnapshots returned a nil slice, want an empty one")
	}
	if len(snaps) != 0 {
		t.Errorf("snapshots = %+v, want none", snaps)
	}
}

func TestDeleteSnapshot(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: "vol1"}))
	r.on(binLVRemove, "--force", "vg0/vol1.snap.nightly").returns("")

	if err := p.DeleteSnapshot(context.Background(), "vg0/vol1.snap.nightly"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	r.assertRan(t, "lvremove --force vg0/vol1.snap.nightly")
}

func TestDeleteSnapshotErrors(t *testing.T) {
	tests := []struct {
		name    string
		managed bool
		id      common.SnapshotID
		lvs     string
		want    error
	}{
		{"unknown snapshot", true, "vg0/vol1.snap.missing", lvsJSON(), common.ErrSnapshotNotFound},
		{
			"name matches but the origin does not", true,
			"vg0/vol1.snap.nightly",
			lvsJSON(lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: "vol2"}),
			common.ErrSnapshotNotFound,
		},
		{
			"an LV with no origin is not a snapshot", true,
			"vg0/vol1.snap.nightly",
			lvsJSON(lvEntry{Name: "vol1.snap.nightly", VG: testVG, Size: strconv.FormatInt(testSize, 10)}),
			common.ErrSnapshotNotFound,
		},
		{
			// The id is well-formed and the LV is a real snapshot of a real
			// volume — just not a volume this provider manages. Removing it
			// would destroy an unmanaged LVM snapshot.
			"snapshot of an unmanaged volume", false,
			"vg0/vol1.snap.nightly",
			lvsJSON(lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: "vol1"}),
			common.ErrSnapshotNotFound,
		},
		{"malformed id", true, "nonsense", "", common.ErrInvalidArgument},
		{"another volume group", true, "other/vol1.snap.nightly", "", common.ErrInvalidArgument},
		{"not a snapshot name", true, "vg0/vol1", "", common.ErrInvalidArgument},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			if tc.managed {
				provision(t, p, r, defaultSpec())
			}
			r.reset()
			if tc.lvs != "" {
				r.scriptLVS(tc.lvs)
			}
			err := p.DeleteSnapshot(context.Background(), tc.id)
			if !errors.Is(err, tc.want) {
				t.Fatalf("DeleteSnapshot(%q) = %v, want %v", tc.id, err, tc.want)
			}
			r.assertNotRan(t, "lvremove")
		})
	}
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

func TestDelete(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)}))
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	if err := p.Delete(context.Background(), testVolume); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	r.assertRan(t, "drbdadm down vol1")
	r.assertRan(t, "lvremove --force vg0/vol1")

	if _, err := p.loadMeta(testVolume); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("state record survived Delete: %v", err)
	}
	if _, err := os.Stat(p.resPath(testVolume)); !os.IsNotExist(err) {
		t.Errorf("resource file survived Delete: %v", err)
	}
}

func TestDeleteRefusesPrimary(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	// No snapshots, so the role is what blocks it.
	r.scriptLVS(lvsJSON(lvEntry{Name: testVolume, VG: testVG, Size: strconv.FormatInt(testSize, 10)}))

	err := p.Delete(context.Background(), testVolume)
	if !errors.Is(err, ErrPrimary) {
		t.Fatalf("Delete of a Primary = %v, want ErrPrimary", err)
	}
	r.assertNotRan(t, "lvremove")
	r.assertNotRan(t, "drbdadm down")
}

// TestDeleteRefusesAnUnprovableRole is why the guard tests for "is Secondary"
// rather than "is Primary". Everything that is neither maps to
// ReplRoleUnknown with no error, so a guard phrased the other way lets it
// through — and the next two steps are drbdadm down and lvremove.
//
// Both routes to that mapping are covered: the literal "Unknown" drbdsetup
// reports in some states, which parses, and a role string this parser has never
// seen, which does not. Neither is evidence that the local node is not Primary,
// which is the only thing that makes the teardown safe.
func TestDeleteRefusesAnUnprovableRole(t *testing.T) {
	for _, role := range []string{"Unknown", "Quorum-Pending-drbd10"} {
		t.Run(role, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()

			r.scriptStatus(statusJSON(testVolume, 0, role, "Connected", "Established", "UpToDate"))
			// No snapshots, so the role is what blocks it.
			r.scriptLVS(lvsJSON(lvEntry{Name: testVolume, VG: testVG, Size: strconv.FormatInt(testSize, 10)}))
			// The teardown is scripted so that the guard is demonstrably what
			// stops it. Left unscripted, the fake would abort the first
			// destructive command on its own, and the test would pass on a
			// missing script rather than on the refusal.
			r.on(binDRBDAdm, "down", testVolume).returns("")
			r.on(binLVRemove, "--force", "vg0/vol1").returns("")

			err := p.Delete(context.Background(), testVolume)
			if !errors.Is(err, ErrRoleUnknown) {
				t.Fatalf("Delete of a resource reporting role %q = %v, want ErrRoleUnknown", role, err)
			}
			if errors.Is(err, ErrPrimary) {
				t.Errorf("an unprovable role was reported as Primary, which is a claim we cannot make: %v", err)
			}
			if !strings.Contains(err.Error(), role) {
				t.Errorf("the refusal should name the role drbdsetup reported, or it cannot be diagnosed: %v", err)
			}
			r.assertNotRan(t, "drbdadm down")
			r.assertNotRan(t, "lvremove")
		})
	}
}

func TestDeleteRefusesVolumeWithSnapshots(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(
		lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)},
		lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: "vol1"},
	))

	err := p.Delete(context.Background(), testVolume)
	if !errors.Is(err, common.ErrHasSnapshots) {
		t.Fatalf("Delete with snapshots = %v, want common.ErrHasSnapshots", err)
	}
	if !strings.Contains(err.Error(), "vol1.snap.nightly") {
		t.Errorf("the error should name the snapshots in the way: %v", err)
	}
	r.assertNotRan(t, "lvremove")
}

// newWipingProvider is a provider with wipe_on_delete turned on.
func newWipingProvider(t *testing.T) (*Provider, *fakeRunner) {
	t.Helper()
	p, r, _ := newTestProviderWith(t, func(s map[string]string) {
		s[SettingWipeOnDelete] = "true"
	})
	return p, r
}

// TestDeleteWipesTheBackingVolumeWhenConfigured covers the option's whole point
// and, more importantly, WHERE and WHEN the wipe happens.
//
// The target is the backing logical volume, not /dev/drbd0. The extents handed
// back to the volume group are the LV's, so the LV is what has to be
// overwritten; going through the DRBD device would also replicate every zero to
// the peer, resyncing a volume that is being destroyed.
//
// The ordering is the other half. DRBD holds its backing device open while the
// resource is up, so a wipe before "drbdadm down" would fail on a busy device,
// and one after lvremove would have nothing to address.
func TestDeleteWipesTheBackingVolumeWhenConfigured(t *testing.T) {
	p, r := newWipingProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10), Attr: attrActiveVolume}))
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	if err := p.Delete(context.Background(), testVolume); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Already active, so it is left exactly as found.
	r.assertNotRan(t, "lvchange")
	assertZeroed(t, r, "/dev/vg0/vol1", 0)
	// Not the replicated device: zeroing that would go to the peer as well.
	r.assertNotRan(t, "/dev/drbd0")

	cmds := r.commands()
	downAt := indexOfCommand(cmds, "drbdadm down vol1")
	wipeAt := indexOfCommand(cmds, "zeroout /dev/vg0/vol1 0")
	removeAt := indexOfCommand(cmds, "lvremove --force vg0/vol1")
	if downAt < 0 || wipeAt < 0 || removeAt < 0 {
		t.Fatalf("expected the teardown, the wipe and the removal; ran:\n  %s", strings.Join(cmds, "\n  "))
	}
	if downAt > wipeAt || wipeAt > removeAt {
		t.Errorf("wipe must fall between the teardown and the removal, got down=%d wipe=%d remove=%d:\n  %s",
			downAt, wipeAt, removeAt, strings.Join(cmds, "\n  "))
	}
}

// TestDeleteDoesNotWipeByDefault pins the default. A full-volume zero-fill on
// every deletion is minutes per terabyte on rotating disks, which is not
// something to impose on a deployment that did not ask for it.
func TestDeleteDoesNotWipeByDefault(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10), Attr: attrActiveVolume}))
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	if err := p.Delete(context.Background(), testVolume); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertNothingZeroed(t, r)
	r.assertRan(t, "lvremove --force vg0/vol1")
}

// TestDeleteStopsWhenTheWipeFails is the safe direction. The caller asked for
// the contents to be destroyed before the volume was; if that did not happen,
// removing the volume anyway would hand the extents back holding exactly the
// data the option exists to keep out of them.
func TestDeleteStopsWhenTheWipeFails(t *testing.T) {
	p, r := newWipingProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10), Attr: attrActiveVolume}))
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.failZeroOut(&blkdev.ZeroOutError{
		Device: "/dev/vg0/vol1",
		Err:    blkdev.ErrZeroOutUnsupported,
	})
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	err := p.Delete(context.Background(), testVolume)
	if err == nil {
		t.Fatal("Delete succeeded despite the wipe failing")
	}
	for _, want := range []string{"vg0/vol1", "does not support zeroing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not mention %q: %v", want, err)
		}
	}
	// The volume is still there to try again on, and so is its record.
	r.assertNotRan(t, "lvremove")
	if _, statErr := os.Stat(p.metaPath(testVolume)); statErr != nil {
		t.Errorf("the state record was removed after a failed wipe: %v", statErr)
	}
	if _, statErr := os.Stat(p.resPath(testVolume)); statErr != nil {
		t.Errorf("the resource file was removed after a failed wipe: %v", statErr)
	}
}

// TestDeleteWipesAnInactiveBackingVolume is the case my first pass assumed away.
//
// A DRBD backing volume is active whenever the resource has been up, so it is
// easy to conclude there is no inactive state to handle. But Delete deliberately
// serves volumes whose resource is already DOWN, and such a volume can have no
// device node at all: after a reboot without autoactivation, after an
// administrator deactivates it, or from a provisioning run that failed partway.
//
// Without the activation, the zeroing fails on a device that is not there, the
// wipe failure stops the delete by design, and wipe_on_delete becomes a
// PERMANENT block on a perfectly valid deletion — the operator cannot get past
// it without turning the option off. Fail-closed retention is meant to protect
// data, not to strand a volume.
func TestDeleteWipesAnInactiveBackingVolume(t *testing.T) {
	p, r := newWipingProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Resource down, and the backing volume carries no device node.
	r.scriptStatus(emptyStatus)
	r.scriptLVS(lvsJSON(lvEntry{
		Name: "vol1", VG: testVG,
		Size: strconv.FormatInt(testSize, 10), Attr: attrInactiveVolume,
	}))
	r.on(binLVChange, "--activate", "y", "--yes", "vg0/vol1").returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	if err := p.Delete(context.Background(), testVolume); err != nil {
		t.Fatalf("Delete of a volume with an inactive backing device: %v", err)
	}

	cmds := r.commands()
	activateAt := indexOfCommand(cmds, "lvchange --activate y --yes vg0/vol1")
	wipeAt := indexOfCommand(cmds, "zeroout /dev/vg0/vol1 0")
	removeAt := indexOfCommand(cmds, "lvremove --force vg0/vol1")
	if activateAt < 0 || wipeAt < 0 || removeAt < 0 {
		t.Fatalf("expected activation, wipe and removal; ran:\n  %s", strings.Join(cmds, "\n  "))
	}
	if activateAt > wipeAt || wipeAt > removeAt {
		t.Errorf("want activate then wipe then remove, got %d/%d/%d:\n  %s",
			activateAt, wipeAt, removeAt, strings.Join(cmds, "\n  "))
	}
	// The wipe succeeded, so lvremove takes the volume anyway; putting the
	// device node back first would be work with no observer.
	r.assertNotRan(t, "lvchange --activate n")
}

// TestFailedWipeRestoresAnInactiveVolume covers the other half of borrowing the
// activation. The delete does not happen when the wipe fails, so a volume the
// operator left deactivated must not be left activated by an operation they
// watched fail.
func TestFailedWipeRestoresAnInactiveVolume(t *testing.T) {
	p, r := newWipingProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	r.scriptLVS(lvsJSON(lvEntry{
		Name: "vol1", VG: testVG,
		Size: strconv.FormatInt(testSize, 10), Attr: attrInactiveVolume,
	}))
	r.on(binLVChange, "--activate", "y", "--yes", "vg0/vol1").returns("")
	r.failZeroOut(&blkdev.ZeroOutError{
		Device: "/dev/vg0/vol1",
		Err:    blkdev.ErrZeroOutUnsupported,
	})
	r.on(binLVChange, "--activate", "n", "--yes", "vg0/vol1").returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	err := p.Delete(context.Background(), testVolume)
	if err == nil {
		t.Fatal("Delete succeeded despite the wipe failing")
	}
	if !strings.Contains(err.Error(), "does not support zeroing") {
		t.Errorf("the wipe failure is not reported: %v", err)
	}
	r.assertRan(t, "lvchange --activate n --yes vg0/vol1")
	r.assertNotRan(t, "lvremove")
	// And the volume is still there to try again on.
	if _, statErr := os.Stat(p.metaPath(testVolume)); statErr != nil {
		t.Errorf("the state record was removed after a failed wipe: %v", statErr)
	}
}

// TestFailedRemovalRestoresAnInactiveVolume is the other error path out of a
// borrowed activation, and the one easiest to miss: the wipe SUCCEEDED here, so
// the code that borrowed the activation has already returned happy.
//
// lvremove can still fail — a transient LVM error, a device briefly busy — and
// then the volume survives with an activation left over from an operation the
// operator watched fail. Same leftover as the failed-wipe case, reached from the
// other side.
func TestFailedRemovalRestoresAnInactiveVolume(t *testing.T) {
	p, r := newWipingProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	r.scriptLVS(lvsJSON(lvEntry{
		Name: "vol1", VG: testVG,
		Size: strconv.FormatInt(testSize, 10), Attr: attrInactiveVolume,
	}))
	r.on(binLVChange, "--activate", "y", "--yes", "vg0/vol1").returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").fails(5, "Logical volume vg0/vol1 in use")
	r.on(binLVChange, "--activate", "n", "--yes", "vg0/vol1").returns("")

	err := p.Delete(context.Background(), testVolume)
	if err == nil {
		t.Fatal("Delete succeeded despite lvremove failing")
	}
	if !strings.Contains(err.Error(), "in use") {
		t.Errorf("the removal failure is not reported: %v", err)
	}
	r.assertRan(t, "lvchange --activate n --yes vg0/vol1")
	// The state record survives, so the delete can be retried.
	if _, statErr := os.Stat(p.metaPath(testVolume)); statErr != nil {
		t.Errorf("the state record was removed after a failed lvremove: %v", statErr)
	}
}

// TestFailedRemovalLeavesAnActiveVolumeAlone is the same path for a volume that
// was already active. Nothing was borrowed, so nothing is given back — a delete
// that fails must not deactivate a volume it found running.
func TestFailedRemovalLeavesAnActiveVolumeAlone(t *testing.T) {
	p, r := newWipingProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{
		Name: "vol1", VG: testVG,
		Size: strconv.FormatInt(testSize, 10), Attr: attrActiveVolume,
	}))
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").fails(5, "Logical volume vg0/vol1 in use")
	// Scripted to succeed, so its absence is the decision not to run it.
	r.on(binLVChange, "--activate", "n", "--yes", "vg0/vol1").returns("")

	if err := p.Delete(context.Background(), testVolume); err == nil {
		t.Fatal("Delete succeeded despite lvremove failing")
	}
	r.assertNotRan(t, "lvchange")
}

// TestBorrowedActivationIsGivenBackOnAFailedContext is the failure mode that
// makes the two restore paths worth having at all.
//
// A cancellation or timeout DURING the wipe is the likeliest way to reach them —
// the zeroing is the long step, minutes per terabyte — and the compensating
// lvchange must not inherit the context that just died. The production runner
// execs through exec.CommandContext, so a canceled context means the cleanup
// process never starts, and the restore silently does not happen while the code
// reads as though it did.
//
// The fake refuses any command issued on a done context, exactly as the real
// runner would, so the deactivation appearing in the log is the detached
// context doing its job.
func TestBorrowedActivationIsGivenBackOnAFailedContext(t *testing.T) {
	p, r := newWipingProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.scriptStatus(emptyStatus)
	r.scriptLVS(lvsJSON(lvEntry{
		Name: "vol1", VG: testVG,
		Size: strconv.FormatInt(testSize, 10), Attr: attrInactiveVolume,
	}))
	r.on(binLVChange, "--activate", "y", "--yes", "vg0/vol1").returns("")
	// The caller gives up while the wipe is running, which is what a deadline
	// on a long zeroing looks like from in here.
	r.onZeroOut(cancel)
	r.on(binLVChange, "--activate", "n", "--yes", "vg0/vol1").returns("")

	if err := p.Delete(ctx, testVolume); err == nil {
		t.Fatal("Delete succeeded despite the wipe failing")
	}
	r.assertRan(t, "lvchange --activate n --yes vg0/vol1")
}

// TestWipeNeverRunsUnderASnapshot is the measured copy-on-write constraint,
// pinned as a property rather than left to the reading order of Delete.
//
// Zeroing an origin that still has a snapshot is CoW's worst case: every block
// written pushes the block it replaced into the snapshot's CoW area, so the wipe
// duplicates the data it is destroying into extents lvremove then frees. The
// local lane measured it on LVM 2.03.16 — a 64 MiB origin under one snapshot
// went from 0% to 100% CoW occupancy and overflowed into an unreadable state.
//
// Delete's snapshot refusal is what keeps that unreachable here. This asserts
// the refusal still comes first with wiping ON, because the two are only
// connected by ordering, and nothing else in the file would notice if they came
// apart.
func TestWipeNeverRunsUnderASnapshot(t *testing.T) {
	p, r := newWipingProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(
		lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)},
		lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: "vol1"},
	))
	// Scripted to succeed: nothing here may run, and the reason must be the
	// refusal rather than an unscripted command.
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	err := p.Delete(context.Background(), testVolume)
	if !errors.Is(err, common.ErrHasSnapshots) {
		t.Fatalf("Delete with snapshots = %v, want common.ErrHasSnapshots", err)
	}
	assertNothingZeroed(t, r)
	r.assertNotRan(t, "lvremove")
	r.assertNotRan(t, "drbdadm down")
}

func TestDeleteWhenResourceIsDown(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)}))
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	if err := p.Delete(context.Background(), testVolume); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	r.assertNotRan(t, "drbdadm down")
	r.assertRan(t, "lvremove --force vg0/vol1")
}

// -----------------------------------------------------------------------------
// Status
// -----------------------------------------------------------------------------

func TestStatus(t *testing.T) {
	// The DRBD device presents the usable capacity, which under the
	// usable-capacity contract is AT LEAST what the caller asked for: the backing
	// volume is created at backingBytes(testSize, false), rounded up to a whole extent,
	// and only DRBD's internal metadata is carved off the end of that. This is
	// the "size" the status fixtures report, in KiB, and it must match the
	// literal in the fixtures. It works out to
	//   roundUpTo(backingBytes(testSize, false), testExtentSize) - metadataBytes(...),
	// which for a 1 GiB volume on 4 MiB extents is 1052600 KiB — comfortably
	// above testSize, where the pre-#11a fixtures pinned a value 4 KiB SHORT of
	// it, a device no volume this provider sizes could ever present.
	const deviceSize = int64(1052600) * statusSizeUnit

	tests := []struct {
		name string
		// status is the drbdsetup report, and mountedAt is where the mount
		// table says the DRBD device is mounted — empty for not mounted, which
		// the table reports as an empty answer rather than as a failure.
		status    string
		mountedAt string
		wantState common.VolumeState
		wantSize  int64
		wantConn  common.ReplConnState
		wantRole  common.ReplRole
		wantNodes []common.NodeID
	}{
		{
			// With no device to measure, the size falls back to the record.
			// The replication state is reported as down rather than left at the
			// zero value, which would claim the volume is not replicated; see
			// TestStatusAndReplicationStateAgreeWhenTheResourceIsDown.
			name: "not up", status: emptyStatus,
			wantState: common.VolumeStateAvailable, wantSize: testSize,
			wantConn: common.ReplStateDown, wantRole: common.ReplRoleUnknown,
		},
		{
			name:      "up and secondary",
			status:    secondaryStatus(testVolume, 0),
			wantState: common.VolumeStateAttached, wantSize: deviceSize, wantConn: common.ReplStateUpToDate,
			wantRole: common.ReplRoleSecondary, wantNodes: []common.NodeID{testNode, testPeer},
		},
		{
			name:      "mounted",
			status:    primaryStatus(testVolume, 0),
			mountedAt: testMountPoint,
			wantState: common.VolumeStateMounted, wantSize: deviceSize, wantConn: common.ReplStateUpToDate,
			wantRole: common.ReplRolePrimary, wantNodes: []common.NodeID{testNode, testPeer},
		},
		{
			name:      "disconnected peer is not reported as attached",
			status:    statusJSON(testVolume, 0, "Primary", "Connecting", "Off", "UpToDate"),
			wantState: common.VolumeStateAttached, wantSize: deviceSize, wantConn: common.ReplStateConnecting,
			wantRole: common.ReplRolePrimary, wantNodes: []common.NodeID{testNode},
		},
		{
			name:      "a failed disk outranks everything else",
			status:    statusJSON(testVolume, 0, "Primary", "Connected", "Established", "Failed"),
			wantState: common.VolumeStateError, wantSize: deviceSize, wantConn: common.ReplStateInconsistent,
			wantRole: common.ReplRolePrimary, wantNodes: []common.NodeID{testNode, testPeer},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()

			r.scriptStatus(tc.status)
			r.scriptMount("/dev/drbd0", tc.mountedAt)

			st, err := p.Status(context.Background(), testVolume)
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if st.ID != testVolume {
				t.Errorf("ID = %q, want %q", st.ID, testVolume)
			}
			if st.State != tc.wantState {
				t.Errorf("State = %q, want %q", st.State, tc.wantState)
			}
			if st.SizeBytes != tc.wantSize {
				t.Errorf("SizeBytes = %d, want %d", st.SizeBytes, tc.wantSize)
			}
			// The usable-capacity contract: a measured device never presents
			// LESS than the caller asked for. The up rows report the device
			// (deviceSize); assert that against the provisioned size directly, so
			// a fixture that regresses below it — as the pre-#11a ones did, a full
			// extent short — fails right here rather than only where deviceSize is
			// spelled out.
			if tc.wantSize == deviceSize && st.SizeBytes < testSize {
				t.Errorf("Status(up).SizeBytes = %d, want >= the provisioned %d", st.SizeBytes, testSize)
			}
			if st.Replication.Conn != tc.wantConn {
				t.Errorf("Replication.Conn = %q, want %q", st.Replication.Conn, tc.wantConn)
			}
			if st.Replication.Role != tc.wantRole {
				t.Errorf("Replication.Role = %q, want %q", st.Replication.Role, tc.wantRole)
			}
			if len(st.AttachedNodes) != len(tc.wantNodes) {
				t.Fatalf("AttachedNodes = %v, want %v", st.AttachedNodes, tc.wantNodes)
			}
			for i, want := range tc.wantNodes {
				if st.AttachedNodes[i] != want {
					t.Errorf("AttachedNodes[%d] = %q, want %q", i, st.AttachedNodes[i], want)
				}
			}
		})
	}
}

// TestStatusAndReplicationStateAgreeWhenTheResourceIsDown is written as one
// assertion about AGREEMENT rather than two about the methods separately,
// because the bug was not that either answer was unreachable — it was that the
// two disagreed about the same volume in the same state.
//
// Status left Replication at its zero value, which common.VolumeStatus reserves
// for a volume that is NOT REPLICATED. This provider has no such volumes: every
// one it creates is a two-host DRBD resource. So the zero value there was not
// merely uninformative, it was false, and false in the direction that matters —
// an HA controller reading it learns that a volume which is only down has no
// peer to fail over to.
//
// The value is pinned as exactly ReplStateDown rather than "not the zero value",
// since anything else non-zero would be a different wrong answer.
func TestStatusAndReplicationStateAgreeWhenTheResourceIsDown(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Configured, known to this provider, and not running.
	r.scriptStatus(emptyStatus)
	r.scriptMount("/dev/drbd0", "")

	st, err := p.Status(context.Background(), testVolume)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	rep, err := p.ReplicationState(context.Background(), testVolume)
	if err != nil {
		t.Fatalf("ReplicationState: %v", err)
	}

	if st.Replication != rep {
		t.Errorf("Status reports replication %+v and ReplicationState reports %+v for the same down volume",
			st.Replication, rep)
	}
	if st.Replication.Conn != common.ReplStateDown {
		t.Errorf("Status replication Conn = %q, want %q", st.Replication.Conn, common.ReplStateDown)
	}
	if rep.Conn != common.ReplStateDown {
		t.Errorf("ReplicationState Conn = %q, want %q", rep.Conn, common.ReplStateDown)
	}
	// The zero value is the specific wrong answer this guards against: it is
	// what common.VolumeStatus reserves for a volume with no replication.
	if (st.Replication == common.ReplState{}) {
		t.Error("Status reported the zero ReplState, which claims the volume is not replicated")
	}
}

// -----------------------------------------------------------------------------
// Promote, Demote, ReplicationState
// -----------------------------------------------------------------------------

func TestPromote(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.on(binDRBDAdm, "primary", testVolume).returns("")
	if err := p.Promote(context.Background(), testVolume); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	r.assertRan(t, "drbdadm primary vol1")
}

// TestPromoteNeverForces is the load-bearing test for this provider's policy: a
// promotion DRBD refuses must surface as a failure, never as a retry with
// --force, which would publish a stale or diverged copy and discard the peer's.
func TestPromoteNeverForces(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.on(binDRBDAdm, "primary", testVolume).
		fails(11, "vol1: State change failed: (-2) Need access to UpToDate data")

	err := p.Promote(context.Background(), testVolume)
	if err == nil {
		t.Fatal("Promote succeeded despite drbdadm refusing it")
	}
	if !strings.Contains(err.Error(), testVolume) {
		t.Errorf("the error should name the volume: %v", err)
	}

	r.assertNotRan(t, "--force")
	r.assertNotRan(t, "--overwrite-data-of-peer")
	r.assertNotRan(t, "new-current-uuid")
	if got := len(r.commands()); got != 1 {
		t.Errorf("Promote ran %d commands after a refusal, want 1: %v", got, r.commands())
	}
}

func TestDemote(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.on(binDRBDAdm, "secondary", testVolume).returns("")
	if err := p.Demote(context.Background(), testVolume); err != nil {
		t.Fatalf("Demote: %v", err)
	}
	r.assertRan(t, "drbdadm secondary vol1")
	r.assertNotRan(t, "--force")
}

// TestDemoteCannotLandInsideSnapshotsWindow is why Demote takes the provider
// lock even though demoting only ever makes a volume LESS writable.
//
// Snapshot requires the volume to be Primary on this node and then runs
// lvcreate, and those are two separate steps. A demotion between them leaves
// the snapshot taken off a Secondary's backing device — written by the
// replication stream with nothing above it ordering those writes — which is
// exactly the state the Primary check refuses. Less-writable is not harmless
// here; it is the direction that invalidates the checked precondition.
//
// The lvs listing is the step between the check and the lvcreate, so the fake
// pauses there and the demotion is started against a snapshot that is provably
// inside its window. Only Snapshot lists logical volumes in this test, so the
// pause fires exactly once.
func TestDemoteCannotLandInsideSnapshotsWindow(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	inWindow := make(chan struct{})
	release := make(chan struct{})

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binLVS, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", lvsFields, testVG).
		returns(lvsJSON(lvEntry{
			Name: "vol1", VG: testVG,
			Size: strconv.FormatInt(testSize, 10), Attr: "-wi-ao----",
		})).
		then(func() {
			close(inWindow)
			<-release
		})
	r.on(binLVCreate, "--yes", "--snapshot", "--name", "vol1.snap.nightly",
		"--extents", "20%ORIGIN", "vg0/vol1").returns("")
	r.on(binDRBDAdm, "secondary", testVolume).returns("")

	snapErr := make(chan error, 1)
	go func() {
		_, err := p.Snapshot(context.Background(), testVolume, "nightly")
		snapErr <- err
	}()
	<-inWindow

	demoteErr := make(chan error, 1)
	go func() { demoteErr <- p.Demote(context.Background(), testVolume) }()

	// The demotion is now racing a snapshot that is parked mid-window. Held
	// off by the lock it cannot reach drbdadm at all; unserialized it gets
	// there as soon as the goroutine is scheduled, which is far inside this
	// window — that asymmetry is what makes removing the lock fail the test.
	for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline); {
		if i := indexOfCommand(r.commands(), "drbdadm secondary vol1"); i >= 0 {
			close(release)
			t.Fatalf("the volume was demoted while a snapshot sat between its Primary check "+
				"and its lvcreate:\n  %s", strings.Join(r.commands(), "\n  "))
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	if err := <-snapErr; err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := <-demoteErr; err != nil {
		t.Fatalf("Demote: %v", err)
	}

	// Both finished, so both commands ran; the lock decided their order.
	cmds := r.commands()
	snapAt := indexOfCommand(cmds, "lvcreate --yes --snapshot --name vol1.snap.nightly --extents 20%ORIGIN vg0/vol1")
	demoteAt := indexOfCommand(cmds, "drbdadm secondary vol1")
	if snapAt < 0 || demoteAt < 0 {
		t.Fatalf("expected both the snapshot and the demotion to run; ran:\n  %s", strings.Join(cmds, "\n  "))
	}
	if snapAt > demoteAt {
		t.Errorf("the snapshot was created after the demotion, so it captured a Secondary:\n  %s",
			strings.Join(cmds, "\n  "))
	}
}

// indexOfCommand returns the position of an exact command line in a command
// log, or -1. Position rather than presence is what the ordering assertions
// need.
func indexOfCommand(cmds []string, want string) int {
	for i, got := range cmds {
		if got == want {
			return i
		}
	}
	return -1
}

func TestReplicationState(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		wantConn common.ReplConnState
		wantRole common.ReplRole
		wantPeer common.NodeID
		wantErr  error
	}{
		{"connected and uptodate", primaryStatus(testVolume, 0), common.ReplStateUpToDate, common.ReplRolePrimary, testPeer, nil},
		{
			"sync target", statusJSON(testVolume, 0, "Secondary", "Connected", "SyncTarget", "Inconsistent"),
			common.ReplStateSyncTarget, common.ReplRoleSecondary, testPeer, nil,
		},
		{
			"standalone", statusJSON(testVolume, 0, "Primary", "StandAlone", "Off", "UpToDate"),
			common.ReplStateStandalone, common.ReplRolePrimary, testPeer, nil,
		},
		{
			// A resource that is not up is configured for replication and not
			// running it — a definite answer, so down rather than unknown, and
			// no role at all.
			"resource not up", emptyStatus,
			common.ReplStateDown, common.ReplRoleUnknown, "", nil,
		},
		{
			// Only a resource with no peer at all is "not replicated".
			"no peer configured", fixtureNoPeer,
			common.ReplStateUnknown, common.ReplRoleUnknown, "", common.ErrNotReplicated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()

			r.scriptStatus(tc.status)
			state, err := p.ReplicationState(context.Background(), testVolume)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ReplicationState = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReplicationState: %v", err)
			}
			if state.Conn != tc.wantConn {
				t.Errorf("Conn = %q, want %q", state.Conn, tc.wantConn)
			}
			if state.Role != tc.wantRole {
				t.Errorf("Role = %q, want %q", state.Role, tc.wantRole)
			}
			if state.Peer != tc.wantPeer {
				t.Errorf("Peer = %q, want %q", state.Peer, tc.wantPeer)
			}
		})
	}
}

// fixtureNoPeer is a resource that is up with no connection configured, which
// is the only shape that means "not replicated".
const fixtureNoPeer = `[{
  "name": "vol1", "node-id": 0, "role": "Secondary", "suspended": false, "write-ordering": "flush",
  "devices": [{"volume": 0, "minor": 0, "disk-state": "UpToDate", "client": false, "quorum": true, "size": 1052600}],
  "connections": []
}]`

// -----------------------------------------------------------------------------
// Cross-cutting contract checks
// -----------------------------------------------------------------------------

// TestUnknownVolumeIsNotFound walks every method that takes a volume id and
// requires common.ErrNotFound, so no method can quietly invent a volume by
// running a command against a name that was never provisioned.
func TestUnknownVolumeIsNotFound(t *testing.T) {
	methods := map[string]func(*Provider) error{
		"Attach": func(p *Provider) error {
			_, err := p.Attach(context.Background(), "nosuch", testNode)
			return err
		},
		"Detach": func(p *Provider) error { return p.Detach(context.Background(), "nosuch", testNode) },
		"Mount": func(p *Provider) error {
			return p.Mount(context.Background(), "nosuch", "/mnt/x", common.MountOptions{FSType: "ext4"})
		},
		"Unmount": func(p *Provider) error { return p.Unmount(context.Background(), "nosuch", "/mnt/x") },
		"Resize":  func(p *Provider) error { return p.Resize(context.Background(), "nosuch", testSize) },
		"Snapshot": func(p *Provider) error {
			_, err := p.Snapshot(context.Background(), "nosuch", "s1")
			return err
		},
		"ListSnapshots": func(p *Provider) error {
			_, err := p.ListSnapshots(context.Background(), "nosuch")
			return err
		},
		"Delete": func(p *Provider) error { return p.Delete(context.Background(), "nosuch") },
		"Status": func(p *Provider) error {
			_, err := p.Status(context.Background(), "nosuch")
			return err
		},
		"Promote": func(p *Provider) error { return p.Promote(context.Background(), "nosuch") },
		"Demote":  func(p *Provider) error { return p.Demote(context.Background(), "nosuch") },
		"ReplicationState": func(p *Provider) error {
			_, err := p.ReplicationState(context.Background(), "nosuch")
			return err
		},
	}

	for name, call := range methods {
		t.Run(name, func(t *testing.T) {
			p, r := newTestProvider(t)
			if err := call(p); !errors.Is(err, common.ErrNotFound) {
				t.Fatalf("%s of an unknown volume = %v, want ErrNotFound", name, err)
			}
			if got := r.commands(); len(got) != 0 {
				t.Errorf("%s of an unknown volume ran commands: %v", name, got)
			}
		})
	}
}

// TestHostileVolumeIDIsNotFound requires a volume id that could never have been
// provisioned to be reported as missing rather than passed to a system tool.
func TestHostileVolumeIDIsNotFound(t *testing.T) {
	p, r := newTestProvider(t)
	for _, id := range []string{"../../etc/passwd", "vol1; rm -rf /", "all", "-rf", ""} {
		if err := p.Promote(context.Background(), id); !errors.Is(err, common.ErrNotFound) {
			t.Errorf("Promote(%q) = %v, want ErrNotFound", id, err)
		}
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("a hostile volume id ran commands: %v", got)
	}
}

// TestContextCancellationIsHonoured proves the context reaches the command
// seam, so a caller can bound a slow drbdadm.
func TestContextCancellationIsHonoured(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := p.Promote(ctx, testVolume); !errors.Is(err, context.Canceled) {
		t.Fatalf("Promote with a canceled context = %v, want context.Canceled", err)
	}
}

// TestProviderSatisfiesReplicatedContract is the runtime companion to the
// compile-time assertion in provider.go.
func TestProviderSatisfiesReplicatedContract(t *testing.T) {
	p, _ := newTestProvider(t)
	var v common.VolumeProvider = p
	if _, ok := v.(common.ReplicatedProvider); !ok {
		t.Fatal("Provider does not satisfy common.ReplicatedProvider")
	}
}

// TestProvisionRollbackSurvivesCancellation is the reason the rollback runs on
// a detached context. The most likely way a long Provision fails is the
// caller's deadline passing partway through, and a cleanup that reused that
// context would fail on its first command and leave behind exactly the
// half-built resource it exists to remove.
func TestProvisionRollbackSurvivesCancellation(t *testing.T) {
	p, r := newTestProvider(t)
	r.scriptProvision(testVolume, testSize)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// create-md fails, and the caller's context is canceled at the same
	// moment — the shape of a deadline expiring during a slow operation.
	r.on(binDRBDAdm, "--", "--force", "create-md", testVolume).
		fails(1, "interrupted").
		then(cancel)
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	if _, err := p.Provision(ctx, *defaultSpec()); err == nil {
		t.Fatal("Provision succeeded, want an error")
	}

	r.assertRan(t, "drbdadm down vol1")
	r.assertRan(t, "lvremove --force vg0/vol1")

	if _, err := p.loadMeta(testVolume); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("state record survived the rollback: %v", err)
	}
	if _, err := os.Stat(p.resPath(testVolume)); !os.IsNotExist(err) {
		t.Errorf("resource file survived the rollback: %v", err)
	}
}

// TestRestoreSizeBoundary pins what a restore is still judged by, now that a
// larger destination is grown into rather than refused: only a SMALLER one is a
// shrink. A real origin LV is always a whole number of extents, so the
// comparison is against the size lvcreate would give the destination.
func TestRestoreSizeBoundary(t *testing.T) {
	tests := []struct {
		name       string
		originSize int64
		request    int64
		wantErr    error
	}{
		{"exactly the original size", originBacking(), testSize, nil},
		{"one byte past the destination", originBacking() + 1, testSize, common.ErrUnsupported},
		{"half the original", originBacking(), testSize / 2, common.ErrUnsupported},
		// One past the largest size whose rounded backing is representable on
		// this extent. It clears Provision's own metadata-addition guard (that
		// bound is looser, without the extent rounding) and is caught in the
		// restore's own sizing, before dst wraps negative and reads the restore
		// as a shrink. Malformed input, not an unsupported shrink.
		{"a size whose rounded backing overflows", originBacking(), maxDataBytes(testExtentSize, false) + 1, common.ErrInvalidArgument},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, &common.VolumeSpec{Name: testVolume, SizeBytes: testSize, Replicas: 2})
			r.reset()

			const snapLV = "vol1.snap.nightly"
			r.scriptLVS(lvsJSON(lvEntry{
				Name: snapLV, VG: testVG, Origin: testVolume,
				OriginSize: strconv.FormatInt(tc.originSize, 10),
			}))
			if tc.wantErr == nil {
				r.scriptProvisionAt("vol2", tc.originSize)
			}

			_, err := p.Provision(context.Background(), common.VolumeSpec{
				Name: "vol2", SizeBytes: tc.request, Replicas: 2,
				SourceSnapshotID: common.SnapshotID("vg0/" + snapLV),
			})
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Provision = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Provision = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestProvisionPinnedMinorAndPort covers the labels a coordinating caller uses
// to make both halves of a pair render the same resource file. The minor and
// the port are written at resource scope, so a pair that allocated them
// independently from drifted state directories would produce two files that
// disagree and never connect.
func TestProvisionPinnedMinorAndPort(t *testing.T) {
	p, r := newTestProvider(t)

	spec := defaultSpec()
	spec.Labels = map[string]string{LabelMinor: "12", LabelPort: "7801"}
	provision(t, p, r, spec)

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.Minor != 12 || meta.Port != 7801 {
		t.Errorf("minor/port = %d/%d, want the pinned 12/7801", meta.Minor, meta.Port)
	}

	res, err := os.ReadFile(p.resPath(testVolume))
	if err != nil {
		t.Fatalf("reading resource file: %v", err)
	}
	got := string(res)
	if !strings.Contains(got, "device    minor 12;") {
		t.Errorf("resource file does not use the pinned minor:\n%s", got)
	}
	// Both hosts must carry the pinned port, or one connects to a port the
	// other is not listening on.
	if n := strings.Count(got, ":7801;"); n != 2 {
		t.Errorf("pinned port appears %d times, want 2:\n%s", n, got)
	}
}

func TestProvisionPinnedRejections(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
	}{
		{"only the minor is pinned", map[string]string{LabelMinor: "12"}},
		{"only the port is pinned", map[string]string{LabelPort: "7801"}},
		{"minor is not a number", map[string]string{LabelMinor: "twelve", LabelPort: "7801"}},
		{"port is not a number", map[string]string{LabelMinor: "12", LabelPort: "http"}},
		{"minor above the kernel ceiling", map[string]string{LabelMinor: "1048576", LabelPort: "7801"}},
		{"port above 65535", map[string]string{LabelMinor: "12", LabelPort: "65536"}},
		{"port zero", map[string]string{LabelMinor: "12", LabelPort: "0"}},
		{"negative minor", map[string]string{LabelMinor: "-1", LabelPort: "7801"}},
		// A typo under this provider's label prefix must not fall back to local
		// allocation, which is the failure the labels exist to prevent.
		{"mistyped label", map[string]string{"drbd.prt": "7801", LabelMinor: "12"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			spec := defaultSpec()
			spec.Labels = tc.labels

			_, err := p.Provision(context.Background(), *spec)
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Fatalf("Provision = %v, want common.ErrInvalidArgument", err)
			}
			if got := r.commands(); len(got) != 0 {
				t.Errorf("a rejected spec ran commands: %v", got)
			}
		})
	}
}

// TestProvisionPinnedCollision keeps a pinned value from claiming a minor or
// port another volume on this node already holds.
func TestProvisionPinnedCollision(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels map[string]string
	}{
		{"minor taken", map[string]string{LabelMinor: "0", LabelPort: "9000"}},
		{"port taken", map[string]string{LabelMinor: "50", LabelPort: strconv.Itoa(defaultPortBase)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			// vol1 takes minor 0 and the base port.
			provision(t, p, r, defaultSpec())
			r.reset()

			_, err := p.Provision(context.Background(), common.VolumeSpec{
				Name: "vol2", SizeBytes: testSize, Replicas: 2, Labels: tc.labels,
			})
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Fatalf("Provision = %v, want common.ErrInvalidArgument", err)
			}
			if !strings.Contains(err.Error(), testVolume) {
				t.Errorf("the error should name the volume holding it: %v", err)
			}
			if got := r.commands(); len(got) != 0 {
				t.Errorf("a rejected spec ran commands: %v", got)
			}
		})
	}
}

// TestNonPrefixedLabelsPassThrough checks the provider only claims its own
// namespace: VolumeSpec.Labels is caller metadata, and everything outside
// "drbd." is recorded untouched.
func TestNonPrefixedLabelsPassThrough(t *testing.T) {
	p, r := newTestProvider(t)

	spec := defaultSpec()
	spec.Labels = map[string]string{"tenant": "acme", "cost-center": "42", LabelMinor: "3", LabelPort: "7900"}
	provision(t, p, r, spec)

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.Labels["tenant"] != "acme" || meta.Labels["cost-center"] != "42" {
		t.Errorf("caller labels were not preserved: %v", meta.Labels)
	}
	if meta.Minor != 3 || meta.Port != 7900 {
		t.Errorf("minor/port = %d/%d, want 3/7900", meta.Minor, meta.Port)
	}
}

// TestProvisionDoesNotPublishUntilComplete checks the window between reserving
// a volume's minor and port and the volume actually existing. The reservation
// has to be visible to the allocator, but a concurrent reader must not see a
// volume whose backing device and resource file have not been created — it
// would report a volume that is not there, or run DRBD commands against a
// device that does not exist.
//
// Only the lock-free readers are probed from inside the hook, which runs on
// Provision's own goroutine while it holds the lock. Attach is not one of them:
// it mutates, so it takes that lock, and a concurrent caller therefore waits for
// the provision instead of seeing the reservation at all — checked below on a
// goroutine, since calling it here would deadlock on a mutex that is not
// reentrant. Waiting is the stronger property; ErrNotFound was only ever the
// best answer available to a caller allowed to look mid-flight.
func TestProvisionDoesNotPublishUntilComplete(t *testing.T) {
	p, r := newTestProvider(t)
	r.scriptProvision(testVolume, testSize)
	// Provision leaves the resource up, so the waiting Attach converges.
	r.scriptStatus(secondaryStatus(testVolume, 0))

	var midStatus, midRepl, attachErr error
	// Closed rather than sent on: a receive from a closed channel does not
	// consume anything, so the check inside the hook and the one after the
	// provision can both look. A buffered send would let the first take the
	// value and leave the second blocking forever, turning a failure into a
	// test-binary timeout instead of a message.
	attachDone := make(chan struct{})
	// The hook fires with the reservation on disk and nothing else done yet.
	r.on(binLVCreate, "--yes", "--name", testVolume, "--size",
		strconv.FormatInt(backingBytes(testSize, false), 10)+"b", testVG).
		returns("").
		then(func() {
			_, midStatus = p.Status(context.Background(), testVolume)
			_, midRepl = p.ReplicationState(context.Background(), testVolume)

			go func() {
				_, attachErr = p.Attach(context.Background(), testVolume, testNode)
				close(attachDone)
			}()
			// Long enough for that goroutine to reach the lock. It must not get
			// past it while this hook — and so the provision — is still running.
			time.Sleep(50 * time.Millisecond)
			select {
			case <-attachDone:
				t.Errorf("Attach completed with %v while the provision still held the lock", attachErr)
			default:
			}
		})

	if _, err := p.Provision(context.Background(), *defaultSpec()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	for name, err := range map[string]error{"Status": midStatus, "ReplicationState": midRepl} {
		if !errors.Is(err, common.ErrNotFound) {
			t.Errorf("%s during provisioning = %v, want ErrNotFound", name, err)
		}
	}
	// It waited, so it saw the finished volume rather than the reservation.
	<-attachDone
	if attachErr != nil {
		t.Errorf("Attach after the provision released the lock = %v, want nil", attachErr)
	}

	// And once Provision has returned, the volume is there.
	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta after Provision: %v", err)
	}
	if meta.Incomplete {
		t.Error("the record is still marked incomplete after a successful Provision")
	}
}

// TestIncompleteReservationStillHoldsItsNumbers pins the other half of the
// rule: hiding a half-built volume from readers must not free the minor and
// port it reserved, or a second volume would be built on top of them.
func TestIncompleteReservationStillHoldsItsNumbers(t *testing.T) {
	p, r := newTestProvider(t)

	reserved := resourceMeta{
		Name: "vol1", LV: "vol1", VG: testVG, SizeBytes: testSize,
		Minor: 0, Port: defaultPortBase, Incomplete: true,
	}
	if err := p.writeMeta(&reserved); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}

	// Hidden from a reader.
	if _, err := p.loadMeta("vol1"); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("loadMeta of an incomplete volume = %v, want ErrNotFound", err)
	}
	// Counted by the allocator.
	provision(t, p, r, &common.VolumeSpec{Name: "vol2", SizeBytes: testSize, Replicas: 2})
	next, err := p.loadMeta("vol2")
	if err != nil {
		t.Fatalf("loadMeta(vol2): %v", err)
	}
	if next.Minor == reserved.Minor {
		t.Errorf("vol2 was given the reserved minor %d", next.Minor)
	}
	if next.Port == reserved.Port {
		t.Errorf("vol2 was given the reserved port %d", next.Port)
	}
}

// TestProvisionAfterCrashedAttempt covers the record a process crash can leave
// behind: the name stays claimed, and Delete is what clears it.
func TestProvisionAfterCrashedAttempt(t *testing.T) {
	p, r := newTestProvider(t)

	if err := p.writeMeta(&resourceMeta{
		Name: testVolume, LV: testVolume, VG: testVG, SizeBytes: testSize,
		Minor: 0, Port: defaultPortBase, Incomplete: true,
	}); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}

	_, err := p.Provision(context.Background(), *defaultSpec())
	if !errors.Is(err, common.ErrAlreadyExists) {
		t.Fatalf("Provision over a half-provisioned name = %v, want ErrAlreadyExists", err)
	}
	if !strings.Contains(err.Error(), "half-provisioned") {
		t.Errorf("the error should say what happened: %v", err)
	}

	// Delete converges even though the backing device was never created.
	r.scriptStatus(emptyStatus)
	r.scriptLVS(lvsJSON())
	if err := p.Delete(context.Background(), testVolume); err != nil {
		t.Fatalf("Delete of a half-provisioned volume: %v", err)
	}
	r.assertNotRan(t, "lvremove")

	// And the name is free again.
	r.reset()
	provision(t, p, r, defaultSpec())
}

// TestMountDoesNotFormatAPartitionedDevice is the reason the probe asks blkid
// for everything rather than filtering to the filesystem type. A device holding
// a partition table and no filesystem reports only PTTYPE, so a TYPE-filtered
// probe exits successfully with empty output — indistinguishable from an empty
// device, and enough to mkfs over somebody's partitioned volume.
func TestMountDoesNotFormatAPartitionedDevice(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("PTTYPE=dos\n")
	// The mount then fails on its own, which is the right outcome: there is no
	// filesystem here, and destroying what is here to make one is not.
	m.FailMount(errors.New("mount: wrong fs type, bad option, bad superblock"))

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err == nil {
		t.Fatal("Mount succeeded on a device with no filesystem")
	}
	r.assertNotRan(t, "mkfs")
}

// TestListSnapshotsSkipsNamesWeCouldNotHaveCreated keeps hand-made LVs in the
// volume group from being reported as this provider's snapshots. A reported id
// has to be one DeleteSnapshot and restore will accept.
func TestListSnapshotsSkipsNamesWeCouldNotHaveCreated(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptLVS(lvsJSON(
		lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)},
		lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: "vol1"},
		// Names the allowlist forbids, so this provider cannot have made them.
		lvEntry{Name: "vol1.snap.bad.name", VG: testVG, Origin: "vol1"},
		lvEntry{Name: "vol1.snap.UPPER", VG: testVG, Origin: "vol1"},
		lvEntry{Name: "vol1.snap.-rf", VG: testVG, Origin: "vol1"},
	))

	snaps, err := p.ListSnapshots(context.Background(), testVolume)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 || snaps[0].Name != "nightly" {
		t.Fatalf("snapshots = %+v, want just the one this provider could have created", snaps)
	}
	// Every reported id must survive the parser the other methods use.
	for _, s := range snaps {
		if _, _, err := p.parseSnapshotID(string(s.ID)); err != nil {
			t.Errorf("ListSnapshots returned an id the parser rejects: %q: %v", s.ID, err)
		}
	}
}

// TestResizeConvergesAfterAPartialFailure covers the state a resize is left in
// when lvextend succeeded but a later step did not: the backing volume is grown
// and the record still holds the old size. Retrying must finish the job, not
// fail on an lvextend that LVM refuses because the volume is already that big.
func TestResizeConvergesAfterAPartialFailure(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Resize refuses a resource that is down, so every case here has one up.
	r.scriptStatus(primaryStatus(testVolume, 0))

	newSize := testSize * 2
	// The backing volume is already at the target; only the record is behind.
	r.scriptLVS(lvsJSON(lvEntry{
		Name: "vol1", VG: testVG,
		Size: strconv.FormatInt(roundUpTo(backingBytes(newSize, false), testExtentSize), 10),
	}))
	r.on(binDRBDAdm, "resize", testVolume).returns("")
	r.scriptMount("/dev/drbd0", "")
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binE2fsck, "-f", "-p", "/dev/drbd0").returns("")
	r.on(binResize2fs, "/dev/drbd0").returns("")

	if err := p.Resize(context.Background(), testVolume, newSize); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	r.assertNotRan(t, "lvextend")
	r.assertRan(t, "drbdadm resize vol1")

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.SizeBytes != newSize {
		t.Errorf("recorded size = %d, want %d", meta.SizeBytes, newSize)
	}
}

func TestResizeWithoutABackingVolume(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Resize refuses a resource that is down, so every case here has one up.
	r.scriptStatus(primaryStatus(testVolume, 0))

	r.scriptLVS(lvsJSON())
	if err := p.Resize(context.Background(), testVolume, testSize*2); err == nil {
		t.Fatal("Resize succeeded with no backing logical volume")
	}
	r.assertNotRan(t, "lvextend")
	r.assertNotRan(t, "drbdadm resize")
}

// TestMountReadOnlyDoesNotFormat covers the one write a read-only mount must
// never make. Formatting an empty volume to satisfy a request that asked not to
// change it would destroy nothing yet and surprise the caller entirely.
func TestMountReadOnlyDoesNotFormat(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").fails(blkidNoSig, "")

	err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{ReadOnly: true})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("read-only Mount of an unformatted volume = %v, want common.ErrInvalidArgument", err)
	}
	r.assertNotRan(t, "mkfs")
	assertNoMount(t, m)
}

// TestResizeGrowsTheFilesystem covers the half of a resize that a caller
// actually notices: growing the device leaves the filesystem on it exactly as
// large as it was, so a volume that was "resized" would still report the old
// free space.
func TestResizeGrowsTheFilesystem(t *testing.T) {
	tests := []struct {
		name    string
		fsType  string
		mounted string
		script  func(*fakeRunner)
		wantRan string
		wantNot string
		// wantNoLookup requires that the mount table was never read, which is
		// how a volume with no filesystem proves it looked nothing up.
		wantNoLookup bool
	}{
		{
			// resize2fs takes the device and finds the mount point itself.
			name: "mounted ext4", fsType: "ext4", mounted: testMountPoint,
			script:  func(r *fakeRunner) { r.on(binResize2fs, "/dev/drbd0").returns("") },
			wantRan: "resize2fs /dev/drbd0",
		},
		{
			// xfs_growfs takes the mount point; there is no offline form.
			name: "mounted xfs", fsType: "xfs", mounted: testMountPoint,
			script:  func(r *fakeRunner) { r.on(binXFSGrowfs, testMountPoint).returns("") },
			wantRan: "xfs_growfs " + testMountPoint,
		},
		{
			// ext4 grows offline too, once resize2fs's demand for a check is
			// satisfied. The check runs ONLY because the device is unmounted —
			// e2fsck against a mounted filesystem would corrupt it.
			name: "unmounted ext4 on a primary", fsType: "ext4", mounted: "",
			script: func(r *fakeRunner) {
				r.scriptStatus(primaryStatus(testVolume, 0))
				r.on(binE2fsck, "-f", "-p", "/dev/drbd0").returns("")
				r.on(binResize2fs, "/dev/drbd0").returns("")
			},
			wantRan: "e2fsck -f -p /dev/drbd0",
		},
		{
			// A Secondary's device cannot be opened at all, so there is no
			// offline route: the device grows and the call succeeds.
			name: "unmounted ext4 on a secondary", fsType: "ext4", mounted: "",
			script:  func(r *fakeRunner) { r.scriptStatus(secondaryStatus(testVolume, 0)) },
			wantNot: "resize2fs",
		},
		{
			name: "unmounted xfs", fsType: "xfs", mounted: "",
			wantNot: "xfs_growfs",
		},
		{
			// A raw volume has no filesystem, so nothing is looked up either:
			// no growth tool runs, and the mount table is never consulted.
			name: "raw volume", fsType: "", mounted: "",
			wantNoLookup: true,
		},
		{
			// The mounted ext4 path must NOT check: e2fsck against a mounted
			// filesystem corrupts it.
			name: "mounted ext4 is never checked", fsType: "ext4", mounted: testMountPoint,
			script:  func(r *fakeRunner) { r.on(binResize2fs, "/dev/drbd0").returns("") },
			wantNot: "e2fsck",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			spec := defaultSpec()
			spec.FSType = tc.fsType
			provision(t, p, r, spec)
			r.reset()

			// Resize refuses a resource that is down, so every case here has one up.
			r.scriptStatus(primaryStatus(testVolume, 0))

			newSize := testSize * 2
			r.scriptLVS(lvsJSON(lvEntry{
				Name: "vol1", VG: testVG,
				Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
			}))
			r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(newSize, false), 10)+"b", "vg0/vol1").returns("")
			r.on(binDRBDAdm, "resize", testVolume).returns("")
			if tc.fsType != "" {
				r.scriptMount("/dev/drbd0", tc.mounted)
			}
			if tc.script != nil {
				tc.script(r)
			}

			if err := p.Resize(context.Background(), testVolume, newSize); err != nil {
				t.Fatalf("Resize: %v", err)
			}
			if tc.wantRan != "" {
				r.assertRan(t, tc.wantRan)
			}
			if tc.wantNot != "" {
				r.assertNotRan(t, tc.wantNot)
			}
			if tc.wantNoLookup && r.mountLookups() != 0 {
				t.Errorf("the mount table was consulted %d times for a volume with no filesystem", r.mountLookups())
			}

			// The device grows either way, and the record follows it.
			r.assertRan(t, "drbdadm resize vol1")
			meta, err := p.loadMeta(testVolume)
			if err != nil {
				t.Fatalf("loadMeta: %v", err)
			}
			if meta.SizeBytes != newSize {
				t.Errorf("recorded size = %d, want %d", meta.SizeBytes, newSize)
			}
		})
	}
}

// TestResizeFailsWhenTheFilesystemGrowFails separates the two cases: a grow
// this provider declined to attempt is not an error, but one it attempted and
// could not finish is.
func TestResizeFailsWhenTheFilesystemGrowFails(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Resize refuses a resource that is down, so every case here has one up.
	r.scriptStatus(primaryStatus(testVolume, 0))

	newSize := testSize * 2
	r.scriptLVS(lvsJSON(lvEntry{
		Name: "vol1", VG: testVG,
		Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
	}))
	r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(newSize, false), 10)+"b", "vg0/vol1").returns("")
	r.on(binDRBDAdm, "resize", testVolume).returns("")
	r.scriptMount("/dev/drbd0", testMountPoint)
	r.on(binResize2fs, "/dev/drbd0").fails(1, "resize2fs: Device or resource busy")

	err := p.Resize(context.Background(), testVolume, newSize)
	if err == nil {
		t.Fatal("Resize succeeded despite the filesystem grow failing")
	}
	if !strings.Contains(err.Error(), "ext4") {
		t.Errorf("the error should say what failed: %v", err)
	}
	// The record is not advanced past a resize that did not finish, so a retry
	// runs the grow again.
	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.SizeBytes != testSize {
		t.Errorf("recorded size = %d, want the pre-resize %d", meta.SizeBytes, testSize)
	}
}

// TestMountRecordsTheFilesystemItCreates covers the gap between what is on the
// device and what the record says. MountOptions.FSType overrides the recorded
// type, so a first mount can format a volume as something other than what it
// was provisioned as — and a record left behind would send Resize at the wrong
// filesystem, or at none.
func TestMountRecordsTheFilesystemItCreates(t *testing.T) {
	tests := []struct {
		name        string
		provisioned string
		override    string
		wantMkfs    string
		wantRecord  string
	}{
		{"formats as provisioned", "ext4", "", "mkfs.ext4 -q /dev/drbd0", "ext4"},
		{"override formats and is recorded", "ext4", "xfs", "mkfs.xfs -q /dev/drbd0", "xfs"},
		{"a raw volume becomes what it was formatted as", "", "ext4", "mkfs.ext4 -q /dev/drbd0", "ext4"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			spec := defaultSpec()
			spec.FSType = tc.provisioned
			provision(t, p, r, spec)
			r.reset()

			fsType := tc.override
			if fsType == "" {
				fsType = tc.provisioned
			}
			r.scriptStatus(primaryStatus(testVolume, 0))
			r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").fails(blkidNoSig, "")
			r.on("mkfs."+fsType, "-q", "/dev/drbd0").returns("")

			err := p.Mount(context.Background(), testVolume, testMountPoint,
				common.MountOptions{FSType: tc.override})
			if err != nil {
				t.Fatalf("Mount: %v", err)
			}
			r.assertRan(t, tc.wantMkfs)

			meta, err := p.loadMeta(testVolume)
			if err != nil {
				t.Fatalf("loadMeta: %v", err)
			}
			if meta.FSType != tc.wantRecord {
				t.Errorf("recorded FSType = %q, want %q — Resize would grow the wrong filesystem",
					meta.FSType, tc.wantRecord)
			}
		})
	}
}

// TestMountLeavesTheRecordAloneWhenItDoesNotFormat checks the other side: an
// override used to mount an existing filesystem is a mount-time choice and says
// nothing about what is on the device.
func TestMountLeavesTheRecordAloneWhenItDoesNotFormat(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=ext4\n")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{FSType: "ext4"}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	r.assertNotRan(t, "mkfs")

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.FSType != "ext4" {
		t.Errorf("recorded FSType = %q, want it unchanged", meta.FSType)
	}
}

// TestSnapshotAndDeleteAreSerialized exercises the mutating snapshot operations
// against each other under the race detector.
//
// Every one of them is a resolve-then-act pair, and each pair is somebody
// else's window: Delete refuses a volume that still has snapshots, then removes
// it, and a Snapshot landing between those two steps creates something the
// removal destroys; Provision validates a restore source, then copies it, and a
// DeleteSnapshot landing between those destroys a source already accepted.
//
// What this test actually proves is the absence of unsynchronized state access,
// which is the race detector's job — the scripted runner cannot model an LVM
// listing that changes underneath a caller, so it cannot assert an ordering.
// The mutex is what makes the orderings safe; this is what proves the mutex is
// really being taken.
func TestSnapshotAndDeleteAreSerialized(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{
		Name: testVolume, VG: testVG,
		Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
	}))
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")
	r.on(binLVCreate, "--yes", "--snapshot", "--name", "vol1.snap.nightly",
		"--extents", "20%ORIGIN", "vg0/vol1").returns("")

	r.on(binLVRemove, "--force", "vg0/vol1.snap.nightly").returns("")

	var wg sync.WaitGroup
	var snapErr, delErr error
	wg.Add(3)
	go func() {
		defer wg.Done()
		_, snapErr = p.Snapshot(context.Background(), testVolume, "nightly")
	}()
	go func() {
		defer wg.Done()
		delErr = p.Delete(context.Background(), testVolume)
	}()
	go func() {
		defer wg.Done()
		// Outcome unasserted: whether this finds the snapshot depends on which
		// of the three got the lock first. It is here to be raced against.
		_ = p.DeleteSnapshot(context.Background(), common.SnapshotID("vg0/vol1.snap.nightly"))
	}()
	wg.Wait()

	// Either order is legitimate; what must not happen is both succeeding,
	// which would leave a snapshot of a volume that no longer exists.
	//
	// Snapshot needs a Primary and this fixture is Secondary, so the snapshot
	// arm always refuses — the point here is that the two serialize at all,
	// which the race detector is what actually checks.
	if snapErr == nil && delErr == nil {
		t.Error("a snapshot and the removal of its origin both succeeded")
	}
	if delErr != nil && !errors.Is(delErr, common.ErrHasSnapshots) {
		t.Errorf("Delete = %v, want nil or common.ErrHasSnapshots", delErr)
	}
}

// TestMountLookupsRunNoCommand pins where the answer comes from.
//
// Mount lookups used to be findmnt, whose default output prints a path's spaces
// literally while --raw escapes them — the opposite of what it sounds like, so
// a line-oriented parser was wrong in a way that read as correct on every path
// without a space in it. The lookups now read /proc/self/mountinfo, where the
// kernel does the escaping and internal/mountinfo undoes it.
//
// This fails if a mount lookup goes back to being a subprocess: both calls
// below ask where something is mounted, and neither may run anything to find
// out.
func TestMountLookupsRunNoCommand(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.scriptMount("/dev/drbd0", "")

	if _, err := p.Status(context.Background(), testVolume); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if err := p.Unmount(context.Background(), testVolume, testMountPoint); err != nil {
		t.Fatalf("Unmount: %v", err)
	}

	// One lookup by source for Status, one by mount point for Unmount.
	if got := r.mountLookups(); got != 2 {
		t.Errorf("the mount table was consulted %d times, want 2 (one by source, one by mount point)", got)
	}
	for _, cmd := range r.commands() {
		for _, forbidden := range []string{"findmnt", "mount", "lsblk"} {
			if strings.HasPrefix(cmd, forbidden+" ") {
				t.Errorf("a mount lookup ran %q; the mount table is read, not asked for", cmd)
			}
		}
	}
}

// TestMountPathsWithSpacesRoundTrip drives a mount point with a space all the
// way through mount and unmount, asserting the path reaches each tool exactly
// as the caller wrote it. Every path is its own argv element, so there is
// nothing to quote and nothing that may be trimmed.
func TestMountPathsWithSpacesRoundTrip(t *testing.T) {
	// A real directory, because Mount stats its target before mounting — and
	// one with a space in its name, which is the whole point.
	target := filepath.Join(t.TempDir(), "my volume")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("creating the mount point: %v", err)
	}

	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=ext4\n")
	if err := p.Mount(context.Background(), testVolume, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	r.scriptMount("/dev/drbd0", target)
	if err := p.Unmount(context.Background(), testVolume, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}

	// The comparison against the mounted source has to survive a target with a
	// space in it, or Unmount converges to a no-op on exactly the paths a
	// line-based parser would also have got wrong.
	assertUnmounted(t, m, target)
}

// TestProvisionResolvesUnsetReplicas pins the zero-value branch of
// VolumeSpec.Replicas: unset means unspecified, not one, so a caller that has
// chosen this provider and left the field alone gets the two-node pair the
// provider exists for rather than a refusal.
func TestProvisionResolvesUnsetReplicas(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, &common.VolumeSpec{Name: testVolume, SizeBytes: testSize})

	if _, err := p.loadMeta(testVolume); err != nil {
		t.Fatalf("a spec with Replicas unset was not provisioned: %v", err)
	}
	// The resource still describes two hosts — "unspecified" resolved to the
	// provider's natural count, it did not skip replication.
	res, err := os.ReadFile(p.resPath(testVolume))
	if err != nil {
		t.Fatalf("reading resource file: %v", err)
	}
	if n := strings.Count(string(res), "node-id "); n != drbdReplicas {
		t.Errorf("resource file names %d hosts, want %d:\n%s", n, drbdReplicas, res)
	}
}

// TestReplicationStateDistinguishesDownFromUnknown is the pair of facts a
// controller has to tell apart before it promotes anything: a volume that is
// definitely not replicating, and a volume whose state could not be read.
func TestReplicationStateDistinguishesDownFromUnknown(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Resource absent from a successful status: not up.
	r.scriptStatus(emptyStatus)
	state, err := p.ReplicationState(context.Background(), testVolume)
	if err != nil {
		t.Fatalf("ReplicationState: %v", err)
	}
	if state.Conn != common.ReplStateDown {
		t.Errorf("Conn for a resource that is not up = %q, want %q", state.Conn, common.ReplStateDown)
	}
	if state.Role != common.ReplRoleUnknown {
		t.Errorf("Role for a resource that is not up = %q, want unknown", state.Role)
	}

	// A state name the parser does not know: unknown, and not down.
	r.scriptStatus(statusJSON(testVolume, 0, "Primary", "Teleporting", "Established", "UpToDate"))
	state, err = p.ReplicationState(context.Background(), testVolume)
	if err != nil {
		t.Fatalf("ReplicationState: %v", err)
	}
	if state.Conn != common.ReplStateUnknown {
		t.Errorf("Conn for an unrecognized state = %q, want %q", state.Conn, common.ReplStateUnknown)
	}

	// Connected, replicating, local disk not current: inconsistent — a fact,
	// not an absence of one.
	r.scriptStatus(statusJSON(testVolume, 0, "Secondary", "Connected", "Established", "Outdated"))
	state, err = p.ReplicationState(context.Background(), testVolume)
	if err != nil {
		t.Fatalf("ReplicationState: %v", err)
	}
	if state.Conn != common.ReplStateInconsistent {
		t.Errorf("Conn for a connected-but-outdated disk = %q, want %q", state.Conn, common.ReplStateInconsistent)
	}
}

// TestOfflineExtGrowStopsOnAnUnfixableCheck separates e2fsck's two failure
// meanings. Exit 1 is "found errors and fixed them", which is a filesystem that
// can now be resized; 2 and above are errors it could not fix, an operational
// failure, or a check that did not finish, and resizing over any of those would
// build on a filesystem nobody has established is sound.
func TestOfflineExtGrowStopsOnAnUnfixableCheck(t *testing.T) {
	tests := []struct {
		name     string
		exit     int
		wantGrow bool
	}{
		{"clean", 0, true},
		{"errors found and corrected", e2fsckCorrected, true},
		{"errors left uncorrected", 4, false},
		{"operational error", 8, false},
		{"check did not finish", 9, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r := newTestProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()

			// Resize refuses a resource that is down, so every case here has one up.
			r.scriptStatus(primaryStatus(testVolume, 0))

			newSize := testSize * 2
			r.scriptLVS(lvsJSON(lvEntry{
				Name: testVolume, VG: testVG,
				Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
			}))
			r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(newSize, false), 10)+"b", "vg0/vol1").returns("")
			r.on(binDRBDAdm, "resize", testVolume).returns("")
			r.scriptMount("/dev/drbd0", "")
			r.scriptStatus(primaryStatus(testVolume, 0))
			if tc.exit == 0 {
				r.on(binE2fsck, "-f", "-p", "/dev/drbd0").returns("")
			} else {
				r.on(binE2fsck, "-f", "-p", "/dev/drbd0").fails(tc.exit, "e2fsck output")
			}
			r.on(binResize2fs, "/dev/drbd0").returns("")

			err := p.Resize(context.Background(), testVolume, newSize)
			if tc.wantGrow {
				if err != nil {
					t.Fatalf("Resize: %v", err)
				}
				r.assertRan(t, "resize2fs /dev/drbd0")
				return
			}
			if err == nil {
				t.Fatal("Resize succeeded over a filesystem the check could not vouch for")
			}
			r.assertNotRan(t, "resize2fs")
			// The record does not advance past a resize that did not finish, so
			// a repeat can complete it once the filesystem is repaired.
			meta, loadErr := p.loadMeta(testVolume)
			if loadErr != nil {
				t.Fatalf("loadMeta: %v", loadErr)
			}
			if meta.SizeBytes != testSize {
				t.Errorf("recorded size = %d, want the pre-resize %d", meta.SizeBytes, testSize)
			}
		})
	}
}

// TestMountRefusesASymlinkedTarget covers the ordering guard, which catches the
// straightforward case — a target whose final component is a symlink — before
// the device is formatted for it. The pin in internal/mount is what makes the
// mount itself safe; this is what keeps a doomed request from costing a format.
func TestMountRefusesASymlinkedTarget(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	base := t.TempDir()
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatalf("creating the decoy: %v", err)
	}
	link := filepath.Join(base, "target")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatalf("creating the symlink: %v", err)
	}

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=ext4\n")

	err := p.Mount(context.Background(), testVolume, link, common.MountOptions{})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Mount onto a symlink = %v, want ErrInvalidArgument", err)
	}
	assertNoMount(t, m)
}

// TestMountRefusesANonDirectoryTarget covers the other thing a stat settles: a
// mount target has to be a directory, and mount(8) would only say so after
// being asked to do something privileged.
func TestMountRefusesANonDirectoryTarget(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("creating the file: %v", err)
	}

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=ext4\n")

	err := p.Mount(context.Background(), testVolume, file, common.MountOptions{})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Mount onto a file = %v, want ErrInvalidArgument", err)
	}
	assertNoMount(t, m)
}

// TestMountRejectsABadTargetBeforeFormatting is the ordering that keeps a
// failed request from changing anything. An empty device plus an unusable
// target must not end with the volume formatted: the format is the destructive
// step, and validation belongs in front of it, not merely in front of the mount
// it was going to enable.
func TestMountRejectsABadTargetBeforeFormatting(t *testing.T) {
	base := t.TempDir()
	decoy := filepath.Join(base, "decoy")
	if err := os.MkdirAll(decoy, 0o755); err != nil {
		t.Fatalf("creating the decoy: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(decoy, link); err != nil {
		t.Fatalf("creating the symlink: %v", err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("creating the file: %v", err)
	}

	for name, target := range map[string]string{"symlink": link, "not a directory": file} {
		t.Run(name, func(t *testing.T) {
			p, r, m := newTestProviderWithMounter(t)
			provision(t, p, r, defaultSpec())
			r.reset()

			// A device with nothing on it — the case where Mount would format.
			r.scriptStatus(primaryStatus(testVolume, 0))
			r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").fails(blkidNoSig, "")

			err := p.Mount(context.Background(), testVolume, target, common.MountOptions{})
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Fatalf("Mount = %v, want ErrInvalidArgument", err)
			}
			r.assertNotRan(t, "mkfs")
			assertNoMount(t, m)

			// And the record is untouched: nothing was created, so nothing is
			// claimed to have been.
			meta, loadErr := p.loadMeta(testVolume)
			if loadErr != nil {
				t.Fatalf("loadMeta: %v", loadErr)
			}
			if meta.FSType != "ext4" {
				t.Errorf("recorded FSType = %q, want it unchanged", meta.FSType)
			}
		})
	}
}

// TestRestoreInheritsTheSourceFilesystem covers what a byte-for-byte copy
// implies: the restored volume carries the SOURCE volume's filesystem, so the
// record has to say so. Recording the spec's would describe an ext4 image as
// raw — or as xfs — and every later Mount and Resize would act on that.
func TestRestoreInheritsTheSourceFilesystem(t *testing.T) {
	p, r := newTestProvider(t)
	// vol1 is ext4; the restore does not mention a filesystem at all.
	provision(t, p, r, defaultSpec())
	r.reset()

	const snapLV = "vol1.snap.nightly"
	r.scriptLVS(lvsJSON(lvEntry{
		Name: snapLV, VG: testVG, Origin: testVolume,
		OriginSize: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
	}))
	r.scriptProvisionAt("vol2", originBacking())
	if _, err := p.Provision(context.Background(), common.VolumeSpec{
		Name: "vol2", SizeBytes: testSize, Replicas: 2,
		SourceSnapshotID: common.SnapshotID("vg0/" + snapLV),
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	meta, err := p.loadMeta("vol2")
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.FSType != "ext4" {
		t.Errorf("restored volume records FSType %q, want the source's ext4", meta.FSType)
	}
}

// TestProvisionRejectsAnFSTypeOnARestore is the other half: a caller cannot
// name a filesystem for a copy that already has one.
func TestProvisionRejectsAnFSTypeOnARestore(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name: "vol2", SizeBytes: testSize, Replicas: 2, FSType: "xfs",
		SourceSnapshotID: common.SnapshotID("vg0/vol1.snap.nightly"),
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Provision = %v, want ErrInvalidArgument", err)
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("a rejected restore ran commands: %v", got)
	}
}

// TestProvisionRejectsAStorageClass keeps the returned Volume honest. Every
// volume comes out of the one configured volume group, so accepting a class and
// ignoring it would hand back a Spec naming a placement the volume does not
// have. It is ErrUnsupported, not bad input: a backend with tiers could serve
// the same request.
func TestProvisionRejectsAStorageClass(t *testing.T) {
	p, r := newTestProvider(t)

	spec := defaultSpec()
	spec.StorageClass = "nvme"
	_, err := p.Provision(context.Background(), *spec)
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Provision with a storage class = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "nvme") {
		t.Errorf("error %q does not name the class asked for", err)
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("a rejected spec ran commands: %v", got)
	}
}

// TestMountRefusesASymlinkedParent covers the case a cheaper check would miss.
//
// The target's own final component is a real directory, so an Lstat on it says
// nothing is wrong — the symlink is one level up, and a path that resolves
// through one still resolves to a real directory. mount(8) would canonicalize
// the whole path and mount wherever the link led. The pin resolves with
// RESOLVE_NO_SYMLINKS, which makes the kernel refuse at ANY component, and the
// pre-format guard runs that same resolution so the two cannot disagree.
//
// The volume here is unformatted, which is the sharp part: if the guard let
// this path through, the mkfs would run and the volume would be formatted for
// a mount that was never going to happen.
//
// No privilege is needed — the refusal happens while resolving the path,
// before anything privileged is attempted.
func TestMountRefusesASymlinkedParent(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatalf("creating the directories: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("creating the symlink: %v", err)
	}
	// <base>/link/sub — the last component is a genuine directory, reached
	// through a symlink one level up.
	target := filepath.Join(link, "sub")

	r := newFakeRunner(t)
	p, err := New(testSettings(t), WithRunner(r), WithSecretProvider(testSecretProvider))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	provision(t, p, r, defaultSpec())
	r.reset()

	// An Lstat would be satisfied here, which is why the guard does not use one.
	if info, statErr := os.Lstat(target); statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("this test needs a real directory below a symlink; Lstat says otherwise (%v)", statErr)
	}

	r.scriptStatus(primaryStatus(testVolume, 0))
	// An UNFORMATTED device: if the guard misses, the mkfs runs.
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").fails(blkidNoSig, "")

	err = p.Mount(context.Background(), testVolume, target, common.MountOptions{})
	if err == nil {
		t.Fatal("Mount succeeded onto a path reached through a symlink")
	}
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("error = %v, want ErrInvalidArgument", err)
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("error %q does not say the path was refused for a symlink", err)
	}
	// Nothing was destroyed on the way to refusing.
	r.assertNotRan(t, "mkfs")
	meta, loadErr := p.loadMeta(testVolume)
	if loadErr != nil {
		t.Fatalf("loadMeta: %v", loadErr)
	}
	if meta.FSType != "ext4" {
		t.Errorf("recorded FSType = %q, want it unchanged", meta.FSType)
	}
}

// TestProviderMountsThroughThePinningSeam checks what a provider built without
// an injected mounter actually got. Every other mount test drives a fake, so
// without this the production path could be wired to nothing at all and the
// suite would not notice.
func TestProviderMountsThroughThePinningSeam(t *testing.T) {
	p, err := New(testSettings(t), WithRunner(newFakeRunner(t)), WithSecretProvider(testSecretProvider))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.mounter == nil {
		t.Fatal("a provider built without WithMounter has no mounter")
	}
	if _, isFake := p.mounter.(*mount.Fake); isFake {
		t.Error("the default mounter is the test fake, not the pinning implementation")
	}

	// And a nil one is refused rather than deferred to a panic at mount time.
	if _, err := New(testSettings(t), WithRunner(newFakeRunner(t)), WithMounter(nil)); !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("New with a nil mounter = %v, want ErrInvalidArgument", err)
	}
}

// TestMountAndUnmountDoNotExec pins the reason mounting left the command
// runner: an exec'd mount(8) cannot pin its target, so a provider that quietly
// went back to exec'ing one would be unsafe again with every test still green.
func TestMountAndUnmountDoNotExec(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=ext4\n")
	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	r.scriptMount("/dev/drbd0", testMountPoint)
	if err := p.Unmount(context.Background(), testVolume, testMountPoint); err != nil {
		t.Fatalf("Unmount: %v", err)
	}

	for _, cmd := range r.commands() {
		if strings.HasPrefix(cmd, "mount ") || strings.HasPrefix(cmd, "umount ") {
			t.Errorf("mounting was exec'd rather than pinned: %q", cmd)
		}
	}
	assertMounted(t, m, "/dev/drbd0", testMountPoint, "ext4", 0, "")
	assertUnmounted(t, m, testMountPoint)
}

// TestConcurrentFirstMountsFormatOnce is the reason probing, formatting and
// recording are one critical section. Separately each is harmless; together and
// unsynchronized they let two callers both find an empty device and both run
// mkfs on it — with different filesystems, if they asked for different ones.
//
// The fake follows the device: once mkfs has run, blkid starts reporting a
// filesystem, the way a real device would. So a second caller that took the
// lock after the first sees a formatted device and skips; one that raced past
// the probe would format again, and the count catches it.
func TestConcurrentFirstMountsFormatOnce(t *testing.T) {
	p, r, _ := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	const dev = "/dev/drbd0"
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", dev).fails(blkidNoSig, "")
	r.on("mkfs.ext4", "-q", dev).returns("").then(func() {
		// The device now carries a filesystem, so the probe must stop saying
		// it is empty.
		r.on(binBlkid, "-p", "-o", "export", dev).returns("TYPE=ext4\n")
	})

	const callers = 6
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Mount %d: %v", i, err)
		}
	}

	var formats int
	for _, cmd := range r.commands() {
		if strings.HasPrefix(cmd, "mkfs.") {
			formats++
		}
	}
	if formats != 1 {
		t.Errorf("the volume was formatted %d times, want exactly 1:\n  %s", formats, strings.Join(r.commands(), "\n  "))
	}
}

// TestMountCannotActOnAMinorThatWasRecycledUnderIt is why Mount is serialized
// with its lookup inside the lock, and why "it fails closed" was the wrong
// reason to leave it out.
//
// Mount used to read the record, then check the role, then probe and format
// /dev/drbd<minor>. The old argument for leaving that unlocked was that a
// demotion in the window makes the device open fail, since DRBD refuses every
// open of a Secondary. That is true and it only defends the volume staying the
// same volume. Minors are reusable: Delete frees the record, the next Provision
// takes the number — pinned here, which is exactly what a caller may do — and
// the stale call is now pointed at a different volume's device. The replacement
// is happily Primary, so the role check passes, the probe reads it as empty and
// the mkfs destroys it.
//
// The pause is on the role check, which sits between the lookup and the probe.
func TestMountCannotActOnAMinorThatWasRecycledUnderIt(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	// The numbers the replacement will be pinned onto, read from the record so
	// the test cannot pass by guessing them.
	original, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	r.reset()

	const dev = "/dev/drbd0"
	var once sync.Once
	inWindow := make(chan struct{})
	release := make(chan struct{})

	// Primary, and paused once: the later Delete probes status too, and this
	// must not park it as well.
	r.on(binDRBDSetup, "status", "--json").
		returns(primaryStatus(testVolume, 0)).
		then(func() {
			once.Do(func() {
				close(inWindow)
				<-release
			})
		})
	// The device reads as empty, so the stale call would format whatever it is
	// pointed at. That is the destructive step this is about.
	r.on(binBlkid, "-p", "-o", "export", dev).fails(blkidNoSig, "")
	r.on("mkfs.ext4", "-q", dev).returns("")

	// vol1's teardown and a replacement pinned onto the minor it frees.
	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)}))
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")
	r.scriptProvision("vol2", testSize)

	mountErr := make(chan error, 1)
	go func() {
		mountErr <- p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
	}()
	<-inWindow

	// The resource is down from here on, so Delete goes straight to removal.
	r.scriptStatus(emptyStatus)

	recycled := make(chan error, 1)
	go func() {
		if delErr := p.Delete(context.Background(), testVolume); delErr != nil {
			recycled <- delErr
			return
		}
		_, provErr := p.Provision(context.Background(), common.VolumeSpec{
			Name: "vol2", SizeBytes: testSize, Replicas: 2,
			Labels: map[string]string{
				LabelMinor: strconv.Itoa(original.Minor),
				LabelPort:  strconv.Itoa(original.Port),
			},
		})
		recycled <- provErr
	}()

	// Nothing may recycle the minor while the mount is parked on it.
	for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline); {
		if indexOfCommand(r.commands(), "lvremove --force vg0/vol1") >= 0 {
			close(release)
			t.Fatalf("vol1 was torn down while a mount sat between its lookup and its probe:\n  %s",
				strings.Join(r.commands(), "\n  "))
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	if err := <-mountErr; err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := <-recycled; err != nil {
		t.Fatalf("deleting vol1 and provisioning vol2 onto its minor: %v", err)
	}

	// The mount finished before the volume it named was removed, so everything
	// it touched belonged to vol1. Under the old ordering the format lands
	// after the replacement exists, against the replacement's device.
	cmds := r.commands()
	mkfsAt := indexOfCommand(cmds, "mkfs.ext4 -q "+dev)
	teardownAt := indexOfCommand(cmds, "lvremove --force vg0/vol1")
	if mkfsAt < 0 || teardownAt < 0 {
		t.Fatalf("expected both the format and the teardown to run; ran:\n  %s", strings.Join(cmds, "\n  "))
	}
	if mkfsAt > teardownAt {
		t.Errorf("the device was formatted after vol1 was removed, so the format hit whatever took its minor:\n  %s",
			strings.Join(cmds, "\n  "))
	}
	var formats int
	for _, c := range cmds {
		if strings.HasPrefix(c, "mkfs.") {
			formats++
		}
	}
	if formats != 1 {
		t.Errorf("the device was formatted %d times, want exactly 1:\n  %s", formats, strings.Join(cmds, "\n  "))
	}
	assertMounted(t, m, dev, testMountPoint, "ext4", 0, "")
}

// TestUnmountCannotActOnAMinorThatWasRecycledUnderIt is the symmetric hole, and
// the reason the device comparison in Unmount does not close it on its own.
//
// That comparison asks whether the device mounted at the target is the one this
// volume's record names — and it compares the MINOR, which is the thing being
// recycled. A stale record whose number a new volume has taken matches that new
// volume's device exactly, so the check passes and the unmount takes a
// filesystem out from under whoever is using it.
func TestUnmountCannotActOnAMinorThatWasRecycledUnderIt(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	const dev = "/dev/drbd0"
	var once sync.Once
	inWindow := make(chan struct{})
	release := make(chan struct{})

	// Reading the mount table is Unmount's first step, after the record lookup,
	// and the window this test needs is the one it opens.
	r.scriptMount(dev, testMountPoint)
	r.onMountTable(func() {
		once.Do(func() {
			close(inWindow)
			<-release
		})
	})
	r.scriptStatus(emptyStatus)
	r.scriptLVS(lvsJSON(lvEntry{Name: "vol1", VG: testVG, Size: strconv.FormatInt(testSize, 10)}))
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	unmountErr := make(chan error, 1)
	go func() {
		unmountErr <- p.Unmount(context.Background(), testVolume, testMountPoint)
	}()
	<-inWindow

	deleted := make(chan error, 1)
	go func() { deleted <- p.Delete(context.Background(), testVolume) }()

	for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline); {
		if indexOfCommand(r.commands(), "lvremove --force vg0/vol1") >= 0 {
			close(release)
			t.Fatalf("vol1 was removed while an unmount was still resolving its target:\n  %s",
				strings.Join(r.commands(), "\n  "))
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	if err := <-unmountErr; err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := <-deleted; err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// It unmounted the volume it was asked about, before that volume's number
	// could belong to anything else.
	assertUnmounted(t, m, testMountPoint)
}

// TestMountReconcilesAFormattedDeviceWithAStaleRecord covers the state a
// half-finished first mount leaves: mkfs succeeded and the record write did
// not, so the volume is formatted while its record still says raw.
//
// Without reconciliation that volume stays mis-described forever — the retry
// finds a non-empty device and returns, so the record is never corrected, and
// every later Mount has no filesystem to use while every later Resize grows
// nothing. The fix is that the probe already knows what is down there.
func TestMountReconcilesAFormattedDeviceWithAStaleRecord(t *testing.T) {
	p, r, _ := newTestProviderWithMounter(t)
	// Provisioned raw: the record says no filesystem.
	spec := defaultSpec()
	spec.FSType = ""
	provision(t, p, r, spec)
	r.reset()

	// The device nonetheless carries ext4, as it would after a format whose
	// record write failed.
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=ext4\n")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{FSType: "ext4"}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	r.assertNotRan(t, "mkfs")

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.FSType != "ext4" {
		t.Errorf("recorded FSType = %q, want the ext4 that is actually on the device", meta.FSType)
	}

	// And now a plain Mount works, which is the point: the volume is usable
	// again without the caller having to name the filesystem every time.
	r.reset()
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=ext4\n")
	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount without an explicit FSType: %v", err)
	}
}

// TestMountDoesNotReconcileAnUnsupportedFilesystem keeps the reconciliation
// from writing something the record cannot act on. The record drives mkfs and
// grow decisions that only make sense for the filesystems this provider
// supports, so a device carrying something else leaves it alone.
func TestMountDoesNotReconcileAnUnsupportedFilesystem(t *testing.T) {
	p, r, _ := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=btrfs\n")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.FSType != "ext4" {
		t.Errorf("recorded FSType = %q, want the record left alone", meta.FSType)
	}
}

// TestMountUsesTheFilesystemActuallyOnTheDevice is the other half of
// reconciliation. Correcting the record and then mounting with the type the
// caller walked in holding fixes the bookkeeping and fails the mount for the
// same reason the record was wrong.
//
// The sharp case is a retry after a first mount that formatted and then failed
// to record: the device is xfs, the record still says ext4, and mounting as
// ext4 fails on a filesystem that is right there.
func TestMountUsesTheFilesystemActuallyOnTheDevice(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	// Recorded as ext4.
	provision(t, p, r, defaultSpec())
	r.reset()

	// The device carries xfs.
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=xfs\n")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	r.assertNotRan(t, "mkfs")

	// Mounted as what is there, not as what the record said.
	assertMounted(t, m, "/dev/drbd0", testMountPoint, "xfs", 0, "")

	// And the record now agrees, so the next Resize grows the right filesystem.
	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.FSType != "xfs" {
		t.Errorf("recorded FSType = %q, want the xfs that is on the device", meta.FSType)
	}
}

// TestMountUsesTheCallersTypeForAnUnsupportedFilesystem pins the other branch:
// a device carrying something this provider does not manage leaves both the
// record and the caller's choice alone, rather than reaching for a filesystem
// it has no mkfs or grow path for.
func TestMountUsesTheCallersTypeForAnUnsupportedFilesystem(t *testing.T) {
	p, r, m := newTestProviderWithMounter(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.on(binBlkid, "-p", "-o", "export", "/dev/drbd0").returns("TYPE=btrfs\n")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	assertMounted(t, m, "/dev/drbd0", testMountPoint, "ext4", 0, "")

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.FSType != "ext4" {
		t.Errorf("recorded FSType = %q, want the record left alone", meta.FSType)
	}
}

// TestDeleteReportsSnapshotsBeforeTheRole covers the case neither single-
// condition test reached: a Primary that also has snapshots, where both
// conditions block and only one of them can be reported.
//
// Snapshots win. Demoting does not make a snapshot go away, so a caller told
// "demote first" would demote, retry, and only then discover it has restore
// points to decide about — the larger decision, found second. The condition
// that holds regardless of role is the more useful one to hear.
func TestDeleteReportsSnapshotsBeforeTheRole(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(
		lvEntry{Name: testVolume, VG: testVG, Size: strconv.FormatInt(testSize, 10)},
		lvEntry{Name: "vol1.snap.nightly", VG: testVG, Origin: testVolume},
	))

	err := p.Delete(context.Background(), testVolume)
	if !errors.Is(err, common.ErrHasSnapshots) {
		t.Fatalf("Delete of a Primary with snapshots = %v, want ErrHasSnapshots", err)
	}
	if errors.Is(err, ErrPrimary) {
		t.Error("the role was reported over the snapshots")
	}
	if !strings.Contains(err.Error(), "vol1.snap.nightly") {
		t.Errorf("error %q does not name the snapshot in the way", err)
	}
	// Nothing was torn down on the way to refusing.
	r.assertNotRan(t, "drbdadm down")
	r.assertNotRan(t, "lvremove")

	// Clear the snapshots and the role is what is left.
	r.scriptLVS(lvsJSON(lvEntry{Name: testVolume, VG: testVG, Size: strconv.FormatInt(testSize, 10)}))
	if err := p.Delete(context.Background(), testVolume); !errors.Is(err, ErrPrimary) {
		t.Fatalf("Delete after the snapshots are gone = %v, want ErrPrimary", err)
	}
}

// TestResizeRefusesADetachedResource covers a failure that used to leave the
// volume worse than it found it.
//
// drbdadm resize only works on a running resource, and the backing volume is
// where DRBD keeps its internal metadata — at the END of the device. Extending
// the LV under a resource that is down moves that end away from the metadata
// with no resize available to follow it: the call failed with the lower device
// already changed, the record still saying the old size, and a resource that
// would not come up because its metadata was no longer where it belonged.
func TestResizeRefusesADetachedResource(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// The resource is not up — Detach has been here.
	r.scriptStatus(emptyStatus)

	err := p.Resize(context.Background(), testVolume, testSize*2)
	if !errors.Is(err, common.ErrNotAttached) {
		t.Fatalf("Resize of a resource that is not up = %v, want ErrNotAttached", err)
	}

	// Refused BEFORE anything moved. This is the whole point: the backing
	// device is untouched, so nothing needs recovering.
	r.assertNotRan(t, "lvextend")
	r.assertNotRan(t, "drbdadm resize")

	meta, loadErr := p.loadMeta(testVolume)
	if loadErr != nil {
		t.Fatalf("loadMeta: %v", loadErr)
	}
	if meta.SizeBytes != testSize {
		t.Errorf("recorded size = %d, want the unchanged %d", meta.SizeBytes, testSize)
	}
}

// TestRestoreIntoALargerVolume is the case the contract permits and this
// provider used to refuse.
//
// VolumeSpec.SizeBytes may exceed the snapshot's, and it is reached by
// composing two things that already work rather than by copying into a longer
// device: the backing volume is created at the SOURCE's size, because a
// whole-device copy into a longer one strands the source's metadata partway
// through what the new volume presents as data, and the volume is then GROWN
// through the same sequence Resize runs — which relocates the metadata to the
// new end, that being what drbdadm resize is for.
//
// The lvextend and drbdadm resize assertions are the mutation check: delete the
// grow step and this fails, rather than passing on a volume quietly still the
// source's size.
func TestRestoreIntoALargerVolume(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, &common.VolumeSpec{Name: testVolume, SizeBytes: testSize, Replicas: 2})
	r.reset()

	const snapLV = "vol1.snap.nightly"
	requested := testSize * 4

	r.scriptLVS(lvsJSON(
		lvEntry{
			Name: snapLV, VG: testVG, Origin: testVolume,
			OriginSize: strconv.FormatInt(originBacking(), 10),
		},
		// The destination as it stands after lvcreate: the source's size, which
		// is what the grow then extends from.
		lvEntry{Name: "vol2", VG: testVG, Size: strconv.FormatInt(originBacking(), 10)},
	))
	r.scriptProvisionAt("vol2", originBacking())

	// The grow runs against a resource that is UP, because Provision brought it
	// up immediately before. That matters: Resize refuses to extend a detached
	// resource, and this path satisfies that guard rather than bypassing it.
	r.scriptStatus(statusJSON("vol2", 1, "Secondary", "Connected", "Established", "Inconsistent"))
	r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(requested, false), 10)+"b", "vg0/vol2").returns("")
	r.on(binDRBDAdm, "resize", "vol2").returns("")
	r.scriptMount("/dev/drbd1", "")

	vol, err := p.Provision(context.Background(), common.VolumeSpec{
		Name: "vol2", SizeBytes: requested, Replicas: 2,
		SourceSnapshotID: common.SnapshotID("vg0/" + snapLV),
	})
	if err != nil {
		t.Fatalf("Provision into a larger volume: %v", err)
	}

	r.assertRan(t, fmt.Sprintf("lvcreate --yes --name vol2 --size %db vg0", originBacking()))
	assertCopied(t, r, "/dev/vg0/"+snapLV, "/dev/vg0/vol2")
	r.assertRan(t, fmt.Sprintf("lvextend --size %db vg0/vol2", backingBytes(requested, false)))
	r.assertRan(t, "drbdadm resize vol2")

	// And in that order: extending a detached resource is exactly what the
	// up-first guard exists to refuse, so the grow has to come after bring-up.
	cmds := r.commands()
	upAt, extendAt := -1, -1
	for i, c := range cmds {
		if c == "drbdadm up vol2" {
			upAt = i
		}
		if strings.HasPrefix(c, "lvextend ") {
			extendAt = i
		}
	}
	if upAt < 0 || extendAt < 0 || upAt > extendAt {
		t.Errorf("the volume was extended before it was up:\n  %s", strings.Join(cmds, "\n  "))
	}

	if vol.Spec.SizeBytes != requested {
		t.Errorf("Volume.Spec.SizeBytes = %d, want the requested %d", vol.Spec.SizeBytes, requested)
	}
	meta, err := p.loadMeta("vol2")
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.SizeBytes != requested {
		t.Errorf("recorded size = %d, want the requested %d", meta.SizeBytes, requested)
	}
	if meta.Incomplete {
		t.Error("the record is still a reservation after a successful restore")
	}
}
