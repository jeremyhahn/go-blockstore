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
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// renderToFile writes a volume's resource file and reads it back.
//
// The production path renders straight to the descriptor, so a test that wants
// the text reads the file. There is deliberately no function returning the
// rendered resource as a value: the shared secret would be in it, on the heap,
// outliving the enclave — which is the whole reason the rendering was split.
func renderToFile(t *testing.T, p *Provider, m *resourceMeta) ([]byte, error) {
	t.Helper()
	if err := p.writeResourceFile(context.Background(), m); err != nil {
		return nil, err
	}
	return os.ReadFile(p.resPath(m.Name))
}

func TestRenderResource(t *testing.T) {
	p, _ := newTestProvider(t)

	meta := resourceMeta{
		Name:      testVolume,
		LV:        testVolume,
		VG:        testVG,
		SizeBytes: 1 << 30,
		Minor:     3,
		Port:      7792,
		CreatedAt: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
	}

	out, err := renderToFile(t, p, &meta)
	if err != nil {
		t.Fatalf("writeResourceFile: %v", err)
	}
	got := string(out)

	for _, want := range []string{
		`resource "vol1" {`,
		"device    minor 3;",
		`disk      "/dev/vg0/vol1";`,
		"meta-disk internal;",
		"protocol C;",
		`on "node-a" {`,
		"node-id 0;",
		"address ipv4 10.10.0.1:7792;",
		`on "node-b" {`,
		"node-id 1;",
		"address ipv4 10.10.0.2:7792;",
		"# Generated: 2026-08-26T12:00:00Z",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered resource is missing %q:\n%s", want, got)
		}
	}

	// Both hosts replicate over the same port; a resource with two different
	// ports would never connect.
	if strings.Count(got, ":7792;") != 2 {
		t.Errorf("both hosts should carry port 7792:\n%s", got)
	}

	// Protocol C is not a setting, and A or B would break the durability the
	// lease-gated failover assumes.
	for _, forbidden := range []string{"protocol A", "protocol B"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("rendered resource contains %q:\n%s", forbidden, got)
		}
	}

	// One resource block, balanced braces: proof that nothing interpolated has
	// opened a scope of its own.
	if n := strings.Count(got, "resource "); n != 1 {
		t.Errorf("resource blocks = %d, want 1:\n%s", n, got)
	}
	if strings.Count(got, "{") != strings.Count(got, "}") {
		t.Errorf("unbalanced braces:\n%s", got)
	}
}

func TestRenderResourceIPv6(t *testing.T) {
	r := newFakeRunner(t)
	settings := testSettings(t)
	settings[SettingNodeAddress] = "fd00:0:0:1::a"
	settings[SettingPeerAddress] = "fd00:0:0:1::b"
	p, err := New(settings, WithRunner(r), WithSecretProvider(testSecretProvider))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := renderToFile(t, p, &resourceMeta{Name: testVolume, LV: testVolume, VG: testVG, Minor: 0, Port: 7789})
	if err != nil {
		t.Fatalf("writeResourceFile: %v", err)
	}
	got := string(out)
	for _, want := range []string{"address ipv6 [fd00:0:0:1::a]:7789;", "address ipv6 [fd00:0:0:1::b]:7789;"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered resource is missing %q:\n%s", want, got)
		}
	}
}

// TestRenderResourceRejectsHostileValues is the backstop behind the validation
// at the API boundary: even called directly with a name that never passed
// validateName, rendering fails rather than emitting a file with an injected
// block in it.
func TestRenderResourceRejectsHostileValues(t *testing.T) {
	p, _ := newTestProvider(t)

	hostile := []string{
		"vol1\"; }\nresource \"stolen\" { disk \"/dev/sda\"; }\n#",
		"vol1 }",
		"../../etc/drbd.d/evil",
		"vol1\nresource evil {",
	}
	for _, name := range hostile {
		t.Run(name, func(t *testing.T) {
			if _, err := renderToFile(t, p, &resourceMeta{Name: name, LV: testVolume, VG: testVG}); err == nil {
				t.Fatalf("writeResourceFile accepted %q", name)
			}
			if _, err := renderToFile(t, p, &resourceMeta{Name: testVolume, LV: name, VG: testVG}); err == nil {
				t.Fatalf("writeResourceFile accepted an lv of %q", name)
			}
		})
	}
}

func TestAllocate(t *testing.T) {
	tests := []struct {
		name      string
		existing  []resourceMeta
		minorBase int
		portBase  int
		wantMinor int
		wantPort  int
	}{
		{"first volume takes the bases", nil, 0, 7789, 0, 7789},
		{
			"next free above the taken ones",
			[]resourceMeta{{Minor: 0, Port: 7789}, {Minor: 1, Port: 7790}},
			0, 7789, 2, 7791,
		},
		{
			"a hole is reused",
			[]resourceMeta{{Minor: 0, Port: 7789}, {Minor: 2, Port: 7791}},
			0, 7789, 1, 7790,
		},
		{
			"allocation starts at the configured bases",
			[]resourceMeta{{Minor: 0, Port: 7789}},
			100, 8000, 100, 8000,
		},
		{
			"records below the base do not block it",
			[]resourceMeta{{Minor: 100, Port: 8000}},
			100, 8000, 101, 8001,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			minor, port, err := allocate(tc.existing, tc.minorBase, tc.portBase)
			if err != nil {
				t.Fatalf("allocate: %v", err)
			}
			if minor != tc.wantMinor {
				t.Errorf("minor = %d, want %d", minor, tc.wantMinor)
			}
			if port != tc.wantPort {
				t.Errorf("port = %d, want %d", port, tc.wantPort)
			}
		})
	}
}

func TestAllocateExhausted(t *testing.T) {
	if _, _, err := allocate([]resourceMeta{{Minor: maxMinor, Port: 1}}, maxMinor, 1); err == nil {
		t.Error("allocate found a minor above the ceiling")
	}
	if _, _, err := allocate([]resourceMeta{{Minor: 0, Port: maxPort}}, 0, maxPort); err == nil {
		t.Error("allocate found a port above the ceiling")
	}
}

func TestMetaRoundTrip(t *testing.T) {
	p, _ := newTestProvider(t)

	want := resourceMeta{
		Name:      testVolume,
		LV:        testVolume,
		VG:        testVG,
		SizeBytes: 1 << 30,
		FSType:    "ext4",
		Minor:     2,
		Port:      7791,
		Labels:    map[string]string{"tenant": "acme"},
		CreatedAt: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
	}
	if err := p.writeMeta(&want); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}

	got, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if got.Name != want.Name || got.LV != want.LV || got.VG != want.VG ||
		got.SizeBytes != want.SizeBytes || got.FSType != want.FSType ||
		got.Minor != want.Minor || got.Port != want.Port ||
		!got.CreatedAt.Equal(want.CreatedAt) || got.Labels["tenant"] != "acme" {
		t.Errorf("loadMeta = %+v, want %+v", got, want)
	}

	// The record is private: it is the provider's view of what exists, and it
	// lives outside the directory DRBD globs.
	info, err := os.Stat(p.metaPath(testVolume))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file mode = %o, want 600", perm)
	}
	if filepath.Dir(p.metaPath(testVolume)) == filepath.Dir(p.resPath(testVolume)) {
		t.Error("state records must not share a directory with .res files")
	}
	if !strings.HasSuffix(p.resPath(testVolume), ".res") {
		t.Errorf("resource path %q must end in .res so drbd.conf includes it", p.resPath(testVolume))
	}
}

func TestLoadMetaMissing(t *testing.T) {
	p, _ := newTestProvider(t)
	_, err := p.loadMeta("nosuch")
	if !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("loadMeta of an unknown volume = %v, want ErrNotFound", err)
	}
}

// TestListMetaFailsClosedOnAnUnreadableRecord pins the direction this fails in.
//
// The only caller is minor and port allocation, and a record it cannot read is
// a volume it cannot see — while the DRBD resource and logical volume that
// record describes are still there. Skipping it would let the next Provision
// hand a new volume a minor or a port a live resource is already using, and two
// resources fighting over one minor does not announce itself. Refusing until
// somebody looks at the state directory is the cheaper outcome.
func TestListMetaFailsClosedOnAnUnreadableRecord(t *testing.T) {
	p, _ := newTestProvider(t)

	if err := p.writeMeta(&resourceMeta{Name: "good", LV: "good", VG: testVG, Minor: 0, Port: 7789}); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.Config().StateDir, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("writing corrupt record: %v", err)
	}

	if _, err := p.listMeta(); err == nil {
		t.Fatal("listMeta ignored a corrupt record; allocation would collide with whatever it describes")
	} else if !strings.Contains(err.Error(), "broken") {
		t.Errorf("error %q does not name the unreadable record", err)
	}

	// And provisioning stops rather than allocating blind.
	r := newFakeRunner(t)
	p2, err := New(map[string]string{
		SettingVolumeGroup: testVG,
		SettingConfigDir:   p.Config().ConfigDir,
		SettingStateDir:    p.Config().StateDir,
		SettingNodeName:    testNode,
		SettingNodeAddress: "10.10.0.1",
		SettingPeerNode:    testPeer,
		SettingPeerAddress: "10.10.0.2",

		// Same reason as testSettings: this test is about record handling, not
		// about whether this host has a drbd module and CAP_NET_ADMIN.
		SettingPreflight: "off",
	}, WithRunner(r), WithSecretProvider(testSecretProvider))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p2.Provision(context.Background(), common.VolumeSpec{Name: "vol9", SizeBytes: 1 << 30, Replicas: 2}); err == nil {
		t.Error("Provision succeeded with an unreadable record in the state directory")
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("Provision ran commands before it could see what was allocated: %v", got)
	}
}

// TestRecordsFromAnotherVolumeGroupAreRefused covers the state directory that
// outlives the configuration that wrote it — reused after volume_group changed,
// or copied between deployments.
//
// Every path that acts on a record builds "<configured vg>/<lv>" from the
// CURRENT configuration, so a record naming a different group stops describing
// what the operation would touch: Delete's lvremove goes at a same-named volume
// in the new group, destroying something this provider never created while
// leaving the real one behind.
//
// The scenario is built the way it actually happens — one state directory, a
// second provider configured for another group — rather than by forging a file,
// so the test would still hold if the record's shape changed.
func TestRecordsFromAnotherVolumeGroupAreRefused(t *testing.T) {
	p, _ := newTestProvider(t)
	if err := p.writeMeta(&resourceMeta{Name: "vol1", LV: "vol1", VG: testVG, Minor: 0, Port: 7789}); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}

	const otherVG = "vg9"
	r := newFakeRunner(t)
	moved, err := New(map[string]string{
		SettingVolumeGroup: otherVG,
		SettingConfigDir:   p.Config().ConfigDir,
		SettingStateDir:    p.Config().StateDir,
		SettingNodeName:    testNode,
		SettingNodeAddress: "10.10.0.1",
		SettingPeerNode:    testPeer,
		SettingPeerAddress: "10.10.0.2",

		// Same reason as testSettings: this test is about record handling, not
		// about whether this host has a drbd module and CAP_NET_ADMIN.
		SettingPreflight: "off",
	}, WithRunner(r), WithSecretProvider(testSecretProvider))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// readMeta is where it stops, so every reader inherits it.
	_, err = moved.loadMeta("vol1")
	if err == nil {
		t.Fatal("loadMeta accepted a record describing another volume group")
	}
	for _, want := range []string{testVG, otherVG, moved.metaPath("vol1")} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so it cannot be acted on: %v", want, err)
		}
	}

	// Delete reads through lookupAny, which skips the Incomplete filter and not
	// this one: it is the path that would have run the wrong lvremove.
	if err := moved.Delete(context.Background(), "vol1"); err == nil {
		t.Error("Delete acted on a record describing another volume group")
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("Delete reached the system before refusing: %v", got)
	}

	// And the composition with listMeta's fail-closed read: the record does not
	// quietly drop out of the allocator's view, which would free the minor and
	// port a live resource still holds. The listing fails, so no allocation
	// happens at all — the same protection an unparseable record gets, and
	// firmer than merely occupying its numbers.
	if _, err := moved.listMeta(); err == nil {
		t.Fatal("listMeta ignored a record describing another volume group")
	}
	if _, err := moved.Provision(context.Background(), common.VolumeSpec{
		Name: "vol9", SizeBytes: 1 << 30, Replicas: 2,
	}); err == nil {
		t.Error("Provision allocated with a foreign record in the state directory")
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("Provision ran commands before it could see what was allocated: %v", got)
	}
}

// TestListMetaIgnoresFilesThatAreNotRecords keeps the fail-closed rule from
// catching anything that lands in the directory. A stray file without the .json
// suffix is not a corrupt record, it is not a record.
func TestListMetaIgnoresFilesThatAreNotRecords(t *testing.T) {
	p, _ := newTestProvider(t)

	if err := p.writeMeta(&resourceMeta{Name: "good", LV: "good", VG: testVG, Minor: 0, Port: 7789}); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.Config().StateDir, "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("writing stray file: %v", err)
	}

	metas, err := p.listMeta()
	if err != nil {
		t.Fatalf("listMeta: %v", err)
	}
	if len(metas) != 1 || metas[0].Name != "good" {
		t.Fatalf("listMeta = %+v, want just the one record", metas)
	}
}

func TestWriteFileAtomicLeavesNoTemporaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vol1.res")
	if err := writeFileAtomic(path, []byte("contents\n"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "vol1.res" {
		t.Fatalf("directory holds %v, want just vol1.res", entries)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 644", perm)
	}
}

// fakeSyncDir replaces the directory-sync step for one test and restores it
// afterwards. The seam exists because fsync cannot be made to fail on a healthy
// filesystem, and the failure is the branch that matters.
func fakeSyncDir(t *testing.T, fn func(dir string) error) {
	t.Helper()
	restore := syncDir
	t.Cleanup(func() { syncDir = restore })
	syncDir = fn
}

// TestWriteFileAtomicSyncsTheDirectoryAfterTheRename pins the ORDER, which is
// the whole property. Syncing the directory before the rename persists the
// state the entry was in beforehand, which is the state without it — the sync
// has to follow the rename to make the new name durable.
//
// The check is that the destination already exists when the sync runs, rather
// than a log of two calls this test itself sequences: existence is the rename
// having actually completed.
func TestWriteFileAtomicSyncsTheDirectoryAfterTheRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vol1.json")

	real := syncDir
	var syncedDir string
	var destExisted, synced bool
	fakeSyncDir(t, func(d string) error {
		synced, syncedDir = true, d
		_, statErr := os.Stat(path)
		destExisted = statErr == nil
		return real(d)
	})

	if err := writeFileAtomic(path, []byte("contents\n"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if !synced {
		t.Fatal("the containing directory was never synced, so the entry is not durable")
	}
	if syncedDir != dir {
		t.Errorf("synced %q, want the directory holding the file, %q", syncedDir, dir)
	}
	if !destExisted {
		t.Error("the directory was synced before the rename, so what it persisted was the absence of the file")
	}
}

// TestWriteFileAtomicFailsWhenTheDirectorySyncFails is why the step is checked
// rather than best-effort. Reporting success here promises a record that a
// crash can still take away — and the state record is what reserves a minor and
// a port, including across the retention a failed rollback depends on.
func TestWriteFileAtomicFailsWhenTheDirectorySyncFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vol1.json")

	fakeSyncDir(t, func(string) error { return errors.New("simulated fsync failure") })

	err := writeFileAtomic(path, []byte("contents\n"), 0o600)
	if err == nil {
		t.Fatal("writeFileAtomic succeeded despite the directory sync failing")
	}
	for _, want := range []string{"simulated fsync failure", dir} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not mention %q: %v", want, err)
		}
	}
}

// TestBothStateFilesAreSyncedIntoTheirDirectory covers the two writers rather
// than the shared helper: the resource file streams its content and the state
// record does not, so they reach the durability step by different routes.
func TestBothStateFilesAreSyncedIntoTheirDirectory(t *testing.T) {
	p, _ := newTestProvider(t)

	real := syncDir
	var synced []string
	fakeSyncDir(t, func(d string) error {
		synced = append(synced, d)
		return real(d)
	})

	meta := resourceMeta{Name: "vol1", LV: "vol1", VG: testVG, SizeBytes: testSize, Minor: 0, Port: 7789}
	if err := p.writeMeta(&meta); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}
	if err := p.writeResourceFile(context.Background(), &meta); err != nil {
		t.Fatalf("writeResourceFile: %v", err)
	}

	if len(synced) != 2 {
		t.Fatalf("the directory was synced %d times for two file writes: %v", len(synced), synced)
	}
	if want := filepath.Dir(p.metaPath("vol1")); synced[0] != want {
		t.Errorf("the state record synced %q, want %q", synced[0], want)
	}
	if want := filepath.Dir(p.resPath("vol1")); synced[1] != want {
		t.Errorf("the resource file synced %q, want %q", synced[1], want)
	}
}

func TestDevicePath(t *testing.T) {
	if got, want := devicePath(0), "/dev/drbd0"; got != want {
		t.Errorf("devicePath(0) = %q, want %q", got, want)
	}
	if got, want := devicePath(17), "/dev/drbd17"; got != want {
		t.Errorf("devicePath(17) = %q, want %q", got, want)
	}
}

// TestBackingBytesReservesMetadata pins the sizing rule: with internal
// metadata DRBD carves its bitmap and activity log out of the END of the
// backing device, so a backing volume created at exactly the requested size
// would export a smaller volume than the caller asked for.
func TestBackingBytesReservesMetadata(t *testing.T) {
	sizes := []int64{
		1 << 20,         // 1 MiB
		128 << 20,       // exactly one bitmap unit
		(128 << 20) + 1, // one byte over
		1 << 30,         // 1 GiB
		1 << 40,         // 1 TiB
	}
	for _, size := range sizes {
		t.Run(strconv.FormatInt(size, 10), func(t *testing.T) {
			meta := metadataBytes(size)
			if meta <= 0 {
				t.Fatalf("metadataBytes(%d) = %d, want a positive reservation", size, meta)
			}
			// The fixed superblock and activity log alone are 36 KiB.
			if meta < superblockSectors*sectorBytes {
				t.Errorf("metadataBytes(%d) = %d, below the %d-byte superblock", size, meta, superblockSectors*sectorBytes)
			}
			// One bit of bitmap per 4 KiB of data, per peer, is the floor the
			// reservation has to clear.
			wantBitmap := size / (4 << 10) / 8 * drbdPeers
			if meta < wantBitmap {
				t.Errorf("metadataBytes(%d) = %d, below the %d bytes of bitmap the device needs", size, meta, wantBitmap)
			}
			if got := backingBytes(size, false); got != size+meta {
				t.Errorf("backingBytes(%d, false) = %d, want %d", size, got, size+meta)
			}
			// The reservation must stay small relative to the volume: a rule
			// that ballooned would waste the volume group.
			if meta > size/100+(1<<20) {
				t.Errorf("metadataBytes(%d) = %d, disproportionate to the volume", size, meta)
			}
		})
	}
}

// TestMetadataGrowsWithTheDevice checks the bitmap scales rather than being a
// constant that happens to fit small volumes.
func TestMetadataGrowsWithTheDevice(t *testing.T) {
	small := metadataBytes(1 << 30)
	large := metadataBytes(1 << 40)
	if large <= small {
		t.Errorf("metadataBytes(1TiB) = %d is not above metadataBytes(1GiB) = %d", large, small)
	}
}

// TestBackingBytesCheckedDetectsOverflow pins the guard the resize and provision
// paths lean on: backingBytes wraps NEGATIVE near the top of the int64 range,
// and the checked form has to report that rather than pass the wrapped value on.
func TestBackingBytesCheckedDetectsOverflow(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(strconv.FormatBool(encrypted), func(t *testing.T) {
			if _, ok := backingBytesChecked(math.MaxInt64, encrypted); ok {
				t.Errorf("backingBytesChecked(math.MaxInt64, false) = ok, want the overflow detected")
			}
			if _, ok := backingBytesChecked(-1, encrypted); ok {
				t.Errorf("backingBytesChecked(-1, false) = ok, want a negative size rejected")
			}
			// With no extent rounding, the largest representable usable size is
			// the one whose backing exactly fills the int64 range — anything
			// above it wraps.
			max := maxDataBytes(0, encrypted)
			backing, ok := backingBytesChecked(max, encrypted)
			if !ok {
				t.Fatalf("backingBytesChecked(maxDataBytes(0, false)=%d) = not ok, want representable", max)
			}
			if backing != math.MaxInt64 {
				t.Errorf("backing at the extent-free maximum = %d, want math.MaxInt64 = %d", backing, int64(math.MaxInt64))
			}
			if _, ok := backingBytesChecked(max+1, encrypted); ok {
				t.Errorf("backingBytesChecked(maxDataBytes(0, false)+1) = ok, want the overflow detected")
			}
		})
	}

	// The header addition is a step of its own that can wrap before the
	// metadata step ever runs: a usable size within HeaderBytes of the ceiling
	// has no representable data area at all on an encrypted provider, and the
	// unchecked arithmetic would hand a NEGATIVE data area to metadataBytes.
	if _, ok := backingBytesChecked(math.MaxInt64-luks.HeaderBytes+1, true); ok {
		t.Errorf("backingBytesChecked(MaxInt64-HeaderBytes+1, encrypted) = ok, want the header addition's overflow detected")
	}
}

// TestBackingBytesAllocatesTheLUKSHeaderOnTop pins the other half of the
// sizing contract, the half #13 first got wrong. common.VolumeSpec.SizeBytes is
// USABLE capacity, so on an encrypted provider the LUKS2 header is allocated
// on top of the request exactly as DRBD's metadata is — the data area DRBD
// exports is usable plus header, and the metadata reservation is computed
// from THAT, since the bitmap covers the header's blocks too. pkg/local has
// always done this; the two backends now agree.
//
// The expectations are literals worked out by hand from DRBD's formula, not a
// restatement of the function under test, so the table fails if the header is
// dropped (backing comes out 16 MiB short), doubled (16 MiB long), or added
// after the metadata step (the 120 MiB row crosses a 128 MiB bitmap unit only
// when the header is inside the data area, and comes out 4 KiB short
// otherwise).
func TestBackingBytesAllocatesTheLUKSHeaderOnTop(t *testing.T) {
	const header = luks.HeaderBytes
	if header != 16<<20 {
		t.Fatalf("luks.HeaderBytes = %d; the literals below were worked out for 16 MiB", header)
	}

	cases := []struct {
		usable        int64
		wantPlain     int64
		wantEncrypted int64
	}{
		{1 << 20, 1089536, 17866752},            // 1 MiB
		{(4 << 20) - 1, 4235263, 21012479},      // one byte under an extent
		{4 << 20, 4235264, 21012480},            // exactly one 4 MiB extent
		{120 << 20, 125870080, 142651392},       // header pushes the bitmap over a unit
		{128 << 20, 134262784, 151040000},       // exactly one bitmap unit
		{1 << 30, 1073815552, 1090592768},       // 1 GiB
		{1 << 40, 1099545223168, 1099562000384}, // 1 TiB
	}
	for _, tc := range cases {
		t.Run(strconv.FormatInt(tc.usable, 10), func(t *testing.T) {
			if got := backingBytes(tc.usable, false); got != tc.wantPlain {
				t.Errorf("backingBytes(%d, plain) = %d, want %d", tc.usable, got, tc.wantPlain)
			}
			if got := backingBytes(tc.usable, true); got != tc.wantEncrypted {
				t.Errorf("backingBytes(%d, encrypted) = %d, want %d", tc.usable, got, tc.wantEncrypted)
			}
			// The data area DRBD exports is what the header is added to, and
			// what Status subtracts it from.
			if got := dataBytes(tc.usable, true); got != tc.usable+header {
				t.Errorf("dataBytes(%d, encrypted) = %d, want %d", tc.usable, got, tc.usable+header)
			}
			if got := dataBytes(tc.usable, false); got != tc.usable {
				t.Errorf("dataBytes(%d, plain) = %d, want %d", tc.usable, got, tc.usable)
			}
			// The checked form agrees with the unchecked one wherever both are
			// representable; they are one rule, not two.
			for _, encrypted := range []bool{false, true} {
				checked, ok := backingBytesChecked(tc.usable, encrypted)
				if !ok || checked != backingBytes(tc.usable, encrypted) {
					t.Errorf("backingBytesChecked(%d, %v) = %d, %v; want %d, true", tc.usable, encrypted, checked, ok, backingBytes(tc.usable, encrypted))
				}
			}
		})
	}

	// Near the ceiling: an encrypted volume's backing is the plain backing of
	// a request one header larger, so the largest usable capacity an encrypted
	// provider can back is exactly one header below the plain one — for every
	// extent, since the rounding on top sees the same backing figure.
	for _, extent := range []int64{0, 1, 512, 4 << 20} {
		plain, encrypted := maxDataBytes(extent, false), maxDataBytes(extent, true)
		if encrypted != plain-header {
			t.Errorf("maxDataBytes(%d, encrypted) = %d, want maxDataBytes(%d, plain) - HeaderBytes = %d", extent, encrypted, extent, plain-header)
		}
		if got, ok := backingBytesChecked(encrypted, true); !ok || got != backingBytes(plain, false) {
			t.Errorf("backing at the encrypted maximum (extent %d) = %d, %v; want the plain maximum's backing %d", extent, got, ok, backingBytes(plain, false))
		}
	}
}

// TestMaxDataBytesIsTheOverflowBoundary checks maxDataBytes lands exactly on the
// last representable size: the maximum itself has a representable backing (so the
// providers must ATTEMPT it), and one past it does not (so they must refuse it).
// The extent-aware bound only tightens as the extent grows, never loosens.
func TestMaxDataBytesIsTheOverflowBoundary(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, extent := range []int64{0, 1, 512, 4 << 20} {
			t.Run(strconv.FormatBool(encrypted)+"/"+strconv.FormatInt(extent, 10), func(t *testing.T) {
				max := maxDataBytes(extent, encrypted)

				// The maximum is representable: its backing computes without
				// wrapping, and rounding that up to an extent stays positive and
				// no smaller than the backing it rounded.
				backing, ok := backingBytesChecked(max, encrypted)
				if !ok {
					t.Fatalf("backingBytesChecked(maxDataBytes(%d, false)=%d) = not ok, want representable", extent, max)
				}
				if rounded := roundUpTo(backing, extent); rounded < 0 || rounded < backing {
					t.Errorf("roundUpTo(%d, %d) = %d, want a positive value no smaller than the backing", backing, extent, rounded)
				}

				// One past it is not: either the backing addition wraps, or the
				// extent rounding layered on top of it would.
				if b, ok := backingBytesChecked(max+1, encrypted); ok && b <= maxRoundableBytes(extent) {
					t.Errorf("maxDataBytes(%d, false) = %d, but %d is still representable (backing %d, roundable ceiling %d): the bound is too low",
						extent, max, max+1, b, maxRoundableBytes(extent))
				}
			})
		}

		if withExtent, without := maxDataBytes(4<<20, encrypted), maxDataBytes(0, encrypted); withExtent > without {
			t.Errorf("maxDataBytes(4MiB, false) = %d exceeds maxDataBytes(0, false) = %d; extent rounding must only tighten the bound", withExtent, without)
		}
	}
}

// TestResourceFileIsByteIdenticalToTheGoldens is the refactor's safety net.
//
// Splitting the template at the secret so the bytes could go straight to the
// descriptor was a change to HOW the file is produced and must not be a change
// to WHAT it contains: drbdadm parses this, and a stray newline or a dropped
// indent is a config change nobody asked for. The goldens were captured from
// the single-template implementation this replaced.
func TestResourceFileIsByteIdenticalToTheGoldens(t *testing.T) {
	meta := resourceMeta{
		Name: testVolume, LV: testVolume, VG: testVG, Minor: 3, Port: 7792,
		CreatedAt: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
	}

	t.Run("authenticated", func(t *testing.T) {
		p, _ := newTestProvider(t)
		got, err := renderToFile(t, p, &meta)
		if err != nil {
			t.Fatalf("writeResourceFile: %v", err)
		}
		want := fixture(t, "golden-authenticated.res")
		if string(got) != want {
			t.Errorf("the rendered resource changed:\n--- got ---\n%s\n--- want ---\n%s", got, want)
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		settings := testSettings(t)
		settings[SettingAllowUnauthenticatedPeers] = "true"
		p, err := New(settings, WithRunner(newFakeRunner(t)))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		got, err := renderToFile(t, p, &meta)
		if err != nil {
			t.Fatalf("writeResourceFile: %v", err)
		}
		want := fixture(t, "golden-unauthenticated.res")
		if string(got) != want {
			t.Errorf("the rendered resource changed:\n--- got ---\n%s\n--- want ---\n%s", got, want)
		}
	})
}

// TestNothingCarriesTheSecretAsAValue is the structural guard.
//
// The finding this closes was not a bug in behavior — the old code produced the
// right file — it was that the secret existed as an ordinary Go string, then as
// a template's copy of it, then as the rendered slice: three GC-managed copies
// outliving the enclave's destruction, reachable in a core dump or a swapped
// page. The fix is that no function accepts or returns it as a string or a
// slice this package owns, and only the type system can keep that true.
//
// So this asserts on the SIGNATURES. A future change that reintroduces a
// render-to-bytes helper taking the secret will not compile against these.
func TestNothingCarriesTheSecretAsAValue(t *testing.T) {
	// Each of these is a compile-time assertion: the parameter type is the
	// signature being asserted, so a change that reintroduces the secret as a
	// value fails to build here rather than passing quietly.
	assertResourceWriter((*Provider)(nil).writeResourceFile)
	assertSecretStreamer((*Provider)(nil).writeSharedSecret)
	assertSecretValidator(validateSharedSecret)

	// And the rendering input has nowhere to put a secret. A field added here
	// would be a heap copy the template then duplicates into its output, which
	// is precisely the shape that was removed.
	//
	// The check is on field NAMES rather than on a count: a count breaks the
	// day somebody adds an unrelated field, which teaches people to update the
	// number rather than to think about it.
	fields := reflect.TypeOf(resourceParams{})
	for i := range fields.NumField() {
		name := fields.Field(i).Name
		if strings.Contains(strings.ToLower(name), "secret") {
			t.Errorf("resourceParams.%s puts the secret in the template's input, "+
				"where it becomes a heap copy the enclave cannot reclaim", name)
		}
	}
}

// The signatures the secret's confinement depends on, expressed as parameter
// types so the compiler checks them.

// assertResourceWriter: the only writer of a resource file takes a meta and a
// context. No secret parameter, and it returns an error rather than the file's
// bytes — so a caller cannot end up holding the rendered text with the secret
// in it.
func assertResourceWriter(func(context.Context, *resourceMeta) error) {}

// assertSecretStreamer: the only thing that touches the secret hands it to an
// io.Writer. It neither takes nor returns one, so the bytes exist solely inside
// the enclave borrow within.
func assertSecretStreamer(func(context.Context, string, io.Writer) error) {}

// assertSecretValidator: validation takes the borrowed slice rather than a copy.
func assertSecretValidator(func([]byte) error) {}
