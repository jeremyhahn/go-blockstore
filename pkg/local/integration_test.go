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

//go:build local_integration

// These tests drive the provider against real LVM, LUKS and filesystems. They
// need root, a loop device, and the lvm2, cryptsetup, e2fsprogs and util-linux
// tooling, so they are selected by a build tag rather than skipped at run time:
//
//	sudo -E go test -tags local_integration -race ./pkg/local/
//
// Selecting them with a tag and failing when the environment is not there is
// deliberate. A testing.Short guard, or a skip on "not root", turns a suite
// that never runs into a suite that always passes, and the whole reason these
// exist is to catch the things a fake CommandRunner cannot: an lvs column that
// changed name, a cryptsetup flag that moved, an option mount(8) rejects.

package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// backingSizeMB is the loopback file every test's volume group is carved from.
// It has to hold a volume, a grown volume and a snapshot's copy-on-write area.
const backingSizeMB = 512

// testVG builds a throwaway volume group on a loopback file and returns its
// name, tearing the whole thing down when the test ends.
func testVG(t *testing.T) string {
	t.Helper()
	requireRoot(t)

	vg := fmt.Sprintf("bsit%d", os.Getpid())
	backing := filepath.Join(t.TempDir(), "backing.img")

	run(t, "truncate", "-s", fmt.Sprintf("%dM", backingSizeMB), backing)

	out := run(t, "losetup", "--find", "--show", backing)
	loop := strings.TrimSpace(out)
	if loop == "" {
		t.Fatal("losetup produced no device")
	}
	t.Cleanup(func() { _ = exec.Command("losetup", "--detach", loop).Run() })

	run(t, "pvcreate", "--force", "--yes", loop)
	run(t, "vgcreate", vg, loop)
	t.Cleanup(func() { _ = exec.Command("vgremove", "--force", vg).Run() })

	return vg
}

// mustStaticKeyIT builds a passphrase provider for the integration suite. A
// kernel that will not lock memory is a broken host rather than a test failure,
// so it stops the test outright.
func mustStaticKeyIT(t *testing.T, passphrase string) KeyProvider {
	t.Helper()
	stored, err := enclave.NewMemoryEnclave([]byte(passphrase))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	kp, err := StaticKeyProvider(stored)
	if err != nil {
		t.Fatalf("StaticKeyProvider: %v", err)
	}
	return kp
}

// assertFIPSHeader reads a real LUKS2 header and checks the parameters that
// make the container FIPS-deployable. cryptsetup's defaults are not approved
// and have moved between versions, so these are pinned at format time and
// verified here rather than trusted.
func assertFIPSHeader(t *testing.T, device string) {
	t.Helper()
	dump := run(t, "cryptsetup", "luksDump", device)
	t.Logf("luksDump %s:\n%s", device, dump)

	// One "Iterations:" line per keyslot and digest, so the checks below are on
	// the fields that are single-valued or must hold everywhere they appear.
	for _, want := range []string{
		"PBKDF:      pbkdf2",
		"Hash:       sha512",
		"cipher: aes-xts-plain64",
		"Cipher:     aes-xts-plain64",
		"Key:        512 bits",
		"Cipher key: 512 bits",
		"AF hash:    sha512",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("luksDump does not report %q", want)
		}
	}

	// argon2 must appear nowhere: it is cryptsetup's LUKS2 default and is not
	// FIPS-approved, so its presence would mean a parameter did not take.
	if strings.Contains(strings.ToLower(dump), "argon2") {
		t.Error("luksDump mentions argon2; a pinned PBKDF did not take effect")
	}

	// Every iteration count in the header has to clear the SP 800-132 floor.
	for _, line := range strings.Split(dump, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Iterations:") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(trimmed, "Iterations:")))
		if err != nil {
			t.Errorf("could not read %q", trimmed)
			continue
		}
		if n < 1000 {
			t.Errorf("%q is below the PBKDF2 minimum of 1000", trimmed)
		}
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("these tests manage loop devices and LVM and must run as root; re-run with sudo -E")
	}
}

// run executes a setup command, failing the test with its output on error.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestIntegrationVolumeLifecycle(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 128 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: size, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateAvailable {
		t.Errorf("State after Provision = %q, want available", status.State)
	}
	if status.SizeBytes < size {
		t.Errorf("SizeBytes = %d, want at least %d", status.SizeBytes, size)
	}

	// Provisioning twice is ErrAlreadyExists, not a second volume.
	_, err = p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: size, FSType: "ext4"})
	if !errors.Is(err, common.ErrAlreadyExists) {
		t.Errorf("second Provision = %v, want ErrAlreadyExists", err)
	}

	// Mounting before attaching is a sequencing error the caller can act on.
	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); !errors.Is(err, common.ErrNotAttached) {
		t.Errorf("Mount before Attach = %v, want ErrNotAttached", err)
	}

	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if _, err := os.Stat(info.DevicePath); err != nil {
		t.Fatalf("attached device %s: %v", info.DevicePath, err)
	}

	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{Flags: []string{"noatime"}}); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	payload := filepath.Join(target, "payload")
	if err := os.WriteFile(payload, []byte("durable"), 0o600); err != nil {
		t.Fatalf("WriteFile on the mounted volume: %v", err)
	}

	status, err = p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateMounted {
		t.Errorf("State while mounted = %q, want mounted", status.State)
	}

	// Growing a mounted ext4 volume extends the filesystem too.
	if err := p.Resize(ctx, vol.ID, 192<<20); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	// Repeating the same request converges instead of looking like a shrink,
	// which is what it would be measured against the extent-rounded size.
	if err := p.Resize(ctx, vol.ID, 192<<20); err != nil {
		t.Fatalf("repeated Resize: %v", err)
	}
	// A size LVM rounds up is the same story with a size that is not a whole
	// number of extents.
	if err := p.Resize(ctx, vol.ID, 200000000); err != nil {
		t.Fatalf("Resize to a non-extent-aligned size: %v", err)
	}
	if err := p.Resize(ctx, vol.ID, 200000000); err != nil {
		t.Fatalf("repeated non-extent-aligned Resize: %v", err)
	}
	if err := p.Resize(ctx, vol.ID, 64<<20); !errors.Is(err, common.ErrUnsupported) {
		t.Errorf("shrinking Resize = %v, want ErrUnsupported", err)
	}

	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	// Unmounting again converges rather than failing.
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("second Unmount: %v", err)
	}

	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	if err := p.Delete(ctx, vol.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.Status(ctx, vol.ID); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("Status after Delete = %v, want ErrNotFound", err)
	}
}

// TestIntegrationMountTargetWithASpace drives the findmnt path against a real
// mountpoint whose name contains a space — the character whose spelling in
// findmnt's column output depends on the flags and the util-linux version, and
// which therefore decides whether Unmount can match the target it was given.
// Reading the report as JSON takes that dependency away, and this is what says
// so against the findmnt actually installed rather than against a fake.
func TestIntegrationMountTargetWithASpace(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	target := filepath.Join(t.TempDir(), "mount point with spaces")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	// The target has to come back from findmnt spelled the way it went in, or
	// none of what follows can match it.
	aliases := p.sourceAliases(vol.ID, p.lvPath(vol.ID))
	mounts, err := p.mountpointsFor(ctx, aliases)
	if err != nil {
		t.Fatalf("mountpointsFor: %v", err)
	}
	if !contains(mounts, target) {
		t.Fatalf("mountpointsFor = %v, want it to contain %q verbatim", mounts, target)
	}

	// Status sees it as mounted, and Unmount actually unmounts it rather than
	// reporting the convergent "not mounted there".
	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateMounted {
		t.Errorf("State = %q, want mounted", status.State)
	}

	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	after, err := p.mountpointsFor(ctx, aliases)
	if err != nil {
		t.Fatalf("mountpointsFor: %v", err)
	}
	if contains(after, target) {
		t.Fatalf("still mounted at %q after Unmount; the target did not round-trip", target)
	}
}

// TestIntegrationMountRefusesASymlinkedTarget drives the real mount path
// against a symlinked target. The mount here is privileged, so following the
// link would attach a filesystem wherever it points.
func TestIntegrationMountRefusesASymlinkedTarget(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	// A symlinked final component, and a symlinked parent.
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	viaParent := filepath.Join(base, "parent")
	if err := os.Symlink(base, viaParent); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	for name, target := range map[string]string{
		"final component":        link,
		"intermediate component": filepath.Join(viaParent, "real"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err == nil {
				_ = p.Unmount(ctx, vol.ID, target)
				t.Fatalf("Mount followed a symlink at %q", target)
			}
		})
	}

	// The real directory still mounts, so the refusal is about symlinks rather
	// than about the mount path being broken.
	if err := p.Mount(ctx, vol.ID, realDir, common.MountOptions{}); err != nil {
		t.Fatalf("Mount of a real directory: %v", err)
	}
	if err := p.Unmount(ctx, vol.ID, realDir); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
}

// TestIntegrationMountOptionsReachTheKernel is what the syscall rewrite has to
// earn: the generic options must arrive as kernel flags, not as a filesystem
// data string the kernel never reads. /proc/self/mounts is where that shows.
func TestIntegrationMountOptionsReachTheKernel(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{
		ReadOnly: true,
		Flags:    []string{"nosuid", "nodev", "noexec", "noatime"},
	}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	t.Cleanup(func() { _ = p.Unmount(ctx, vol.ID, target) })

	entry := ""
	data := run(t, "cat", "/proc/self/mounts")
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, target) {
			entry = line
		}
	}
	if entry == "" {
		t.Fatalf("no /proc/self/mounts entry for %s", target)
	}
	t.Logf("/proc/self/mounts: %s", entry)

	for _, want := range []string{"ro", "nosuid", "nodev", "noexec", "noatime"} {
		if !strings.Contains(entry, want) {
			t.Errorf("the kernel did not apply %q: %s", want, entry)
		}
	}
}

func TestIntegrationSnapshotAndRestore(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: size, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	// Put known contents on the volume before snapshotting it.
	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "before"), []byte("snapshotted"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	snaps, err := p.ListSnapshots(ctx, vol.ID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 0 {
		t.Errorf("ListSnapshots on a fresh volume = %v, want empty", snaps)
	}

	snapID, err := p.Snapshot(ctx, vol.ID, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Taking a snapshot must not attach anything. Measured on LVM 2.03.16,
	// lvcreate --snapshot over a detached origin whose autoactivation is off
	// leaves BOTH the origin and the new snapshot inactive, with no device
	// nodes — so a caller that had detached the volume still has it detached.
	// Asserted here rather than assumed, because the provider's whole
	// attach/detach model rests on it and a future LVM could change it.
	originStatus, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status of the origin: %v", err)
	}
	if originStatus.State != common.VolumeStateAvailable {
		t.Errorf("origin State after Snapshot = %q, want available: snapshotting must not attach it", originStatus.State)
	}
	if _, statErr := os.Stat(p.lvPath(vol.ID)); statErr == nil {
		t.Errorf("origin device node %s exists after Snapshot; the volume was left attached", p.lvPath(vol.ID))
	}

	if _, err := p.Snapshot(ctx, vol.ID, "nightly"); !errors.Is(err, common.ErrAlreadyExists) {
		t.Errorf("duplicate Snapshot = %v, want ErrAlreadyExists", err)
	}

	snaps, err = p.ListSnapshots(ctx, vol.ID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("ListSnapshots = %v, want one snapshot", snaps)
	}
	if snaps[0].ID != snapID || snaps[0].Name != "nightly" || snaps[0].VolumeID != vol.ID {
		t.Errorf("SnapshotInfo = %+v, want it to describe the snapshot just taken", snaps[0])
	}
	if snaps[0].CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; lv_time did not parse against a real lvs")
	}

	// Restoring below the origin's size is refused rather than truncating.
	_, err = p.Provision(ctx, common.VolumeSpec{Name: "toosmall", SizeBytes: 16 << 20, SourceSnapshotID: snapID})
	if !errors.Is(err, common.ErrUnsupported) {
		t.Errorf("undersized restore = %v, want ErrUnsupported", err)
	}

	restored, err := p.Provision(ctx, common.VolumeSpec{Name: "restored", SizeBytes: size, SourceSnapshotID: snapID})
	if err != nil {
		t.Fatalf("Provision from snapshot: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, restored.ID) })

	// The origin was detached when the restore ran, and reading the snapshot
	// activates the origin along with it. It has to end up detached again.
	originStatus, err = p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status of the origin: %v", err)
	}
	if originStatus.State != common.VolumeStateAvailable {
		t.Errorf("origin State after restore = %q, want available", originStatus.State)
	}

	// The restored volume carries the origin's filesystem and contents.
	restoreTarget := filepath.Join(t.TempDir(), "restored")
	if err := os.MkdirAll(restoreTarget, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, restored.ID, "test-node"); err != nil {
		t.Fatalf("Attach restored: %v", err)
	}
	if err := p.Mount(ctx, restored.ID, restoreTarget, common.MountOptions{}); err != nil {
		t.Fatalf("Mount restored: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(restoreTarget, "before"))
	if err != nil {
		t.Fatalf("reading the restored file: %v", err)
	}
	if string(got) != "snapshotted" {
		t.Errorf("restored contents = %q, want %q", got, "snapshotted")
	}
	if err := p.Unmount(ctx, restored.ID, restoreTarget); err != nil {
		t.Fatalf("Unmount restored: %v", err)
	}
	if err := p.Detach(ctx, restored.ID, "test-node"); err != nil {
		t.Fatalf("Detach restored: %v", err)
	}

	// Deleting the snapshot leaves the restored volume intact, because the
	// restore was a copy rather than a dependent volume.
	if err := p.DeleteSnapshot(ctx, snapID); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if err := p.DeleteSnapshot(ctx, snapID); !errors.Is(err, common.ErrSnapshotNotFound) {
		t.Errorf("second DeleteSnapshot = %v, want ErrSnapshotNotFound", err)
	}
	if _, err := p.Status(ctx, restored.ID); err != nil {
		t.Errorf("restored volume did not survive its snapshot: %v", err)
	}
}

// TestIntegrationRestoreDoesNotDisturbAnAttachedOrigin is the coupling that
// matters most in practice: LVM activates an origin and its snapshots as one
// unit, so a restore that switched the snapshot off afterwards takes the
// origin's device node with it.
//
// The origin here is attached but deliberately not mounted, which is the state
// that actually breaks. A mounted origin is protected by LVM itself — lvchange
// refuses to deactivate a logical volume with a filesystem open on it — so a
// test that mounted the origin would pass against the bug and prove nothing.
// TestIntegrationRestoreAfterGrowingTheOrigin drives the case where an origin's
// current size and the size its snapshot presents have diverged. LVM permits
// growing an origin that has snapshots while it is INACTIVE, which is the state
// this provider leaves volumes in, so the divergence arises through this API
// alone: Provision, Snapshot, Resize, restore.
func TestIntegrationRestoreAfterGrowingTheOrigin(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const imageSize = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: imageSize, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	// Known contents, so the restored copy can be checked rather than assumed.
	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "before"), []byte("point in time"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	snapID, err := p.Snapshot(ctx, vol.ID, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Grow the origin AFTER snapshotting. From here the two sizes differ.
	if err := p.Resize(ctx, vol.ID, 192<<20); err != nil {
		t.Fatalf("Resize the origin: %v", err)
	}

	snaps, err := p.ListSnapshots(ctx, vol.ID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("ListSnapshots = %v, want one", snaps)
	}

	// The restore is sized for the IMAGE, which is now smaller than the origin.
	// Sizing from the origin would reject this outright.
	restored, err := p.Provision(ctx, common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        imageSize,
		SourceSnapshotID: snapID,
	})
	if err != nil {
		t.Fatalf("restore sized for the snapshot image: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, restored.ID) })

	restoreTarget := filepath.Join(t.TempDir(), "restored")
	if err := os.MkdirAll(restoreTarget, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if _, err := p.Attach(ctx, restored.ID, "test-node"); err != nil {
		t.Fatalf("Attach restored: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, restored.ID, "test-node") })
	if err := p.Mount(ctx, restored.ID, restoreTarget, common.MountOptions{}); err != nil {
		t.Fatalf("Mount restored: %v", err)
	}
	t.Cleanup(func() { _ = p.Unmount(ctx, restored.ID, restoreTarget) })

	got, err := os.ReadFile(filepath.Join(restoreTarget, "before"))
	if err != nil {
		t.Fatalf("reading the restored file: %v", err)
	}
	if string(got) != "point in time" {
		t.Errorf("restored contents = %q, want the snapshot's", got)
	}
}

func TestIntegrationRestoreDoesNotDisturbAnAttachedOrigin(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "data", SizeBytes: size, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	snapID, err := p.Snapshot(ctx, vol.ID, "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = p.Detach(ctx, vol.ID, "test-node") })

	restored, err := p.Provision(ctx, common.VolumeSpec{Name: "restored", SizeBytes: size, SourceSnapshotID: snapID})
	if err != nil {
		t.Fatalf("Provision from snapshot: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, restored.ID) })

	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status of the origin: %v", err)
	}
	if status.State != common.VolumeStateAttached {
		t.Errorf("origin State after restore = %q, want it still attached", status.State)
	}
	if _, err := os.Stat(p.lvPath(vol.ID)); err != nil {
		t.Errorf("the origin's device node did not survive the restore: %v", err)
	}

	// And it is still a working block device, not just a listed one: mounting
	// it after the restore has to succeed.
	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("mounting the origin after the restore: %v", err)
	}
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
}

// TestIntegrationWipeOnDelete drives the wipe against a real logical volume:
// that blkdiscard --zeroout accepts the flag and the device, that it clears the
// volume, and that Delete still removes it afterwards.
//
// It deliberately does not try to demonstrate the exposure the wipe exists to
// close — that a deleted volume's contents survive in the extents LVM hands to
// the next volume. Whether they survive depends on the storage underneath: with
// devices/issue_discards=1 and a backing device that supports discard (a
// loopback file on a modern filesystem, which is what these tests build on),
// lvremove discards the extents and they read back as zeroes regardless of this
// option. The LVM default is issue_discards=0, and rotating disks do not
// discard at all, which is where the option earns its keep. A test asserting
// remanence here would pass for reasons that have nothing to do with the code.
func TestIntegrationWipeOnDelete(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node", WipeOnDelete: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const size = 32 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "secrets", SizeBytes: size})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	const marker = "SENSITIVE-TENANT-DATA"
	writeMarker(t, info.DevicePath, marker)
	if !markerPresent(t, info.DevicePath, marker) {
		t.Fatal("the marker did not reach the device; the rest of this test would prove nothing")
	}

	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if err := p.Delete(ctx, vol.ID); err != nil {
		t.Fatalf("Delete with WipeOnDelete: %v", err)
	}
	if _, err := p.Status(ctx, vol.ID); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("Status after a wiping Delete = %v, want ErrNotFound", err)
	}

	// The volume group is usable again: the wipe left nothing that stops the
	// extents being reallocated.
	next, err := p.Provision(ctx, common.VolumeSpec{Name: "next", SizeBytes: size, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision after a wiping Delete: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, next.ID) })
}

// markerOffset is where the wipe test places its marker: past the first few
// kilobytes, which lvcreate zeroes on its own.
const markerOffset = 8 << 20

// writeMarker puts a recognizable string into a block device.
func writeMarker(t *testing.T, device, marker string) {
	t.Helper()
	f, err := os.OpenFile(device, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", device, err)
	}
	defer func() { _ = f.Close() }()

	// Block devices take aligned writes, so the marker goes inside a full
	// sector rather than being written as a short string.
	sector := make([]byte, 4096)
	copy(sector, marker)
	if _, err := f.WriteAt(sector, markerOffset); err != nil {
		t.Fatalf("writing to %s: %v", device, err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("syncing %s: %v", device, err)
	}
}

// markerPresent reports whether the marker is readable back from the device.
func markerPresent(t *testing.T, device, marker string) bool {
	t.Helper()
	f, err := os.Open(device)
	if err != nil {
		t.Fatalf("opening %s: %v", device, err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 4096)
	if _, err := f.ReadAt(buf, markerOffset); err != nil {
		t.Fatalf("reading %s: %v", device, err)
	}
	return bytes.Contains(buf, []byte(marker))
}

func TestIntegrationEncryptedVolume(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "integration-test-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "secret", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	info, err := p.Attach(ctx, vol.ID, "test-node")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// The logical volume itself holds a LUKS container, not a filesystem. This
	// has to be probed while the volume is attached: Provision leaves it
	// deactivated, and a deactivated volume has no device node to probe.
	fsType, err := p.probeFSType(ctx, p.lvPath(vol.ID))
	if err != nil {
		t.Fatalf("probeFSType: %v", err)
	}
	if fsType != fsTypeLUKS {
		t.Fatalf("the provisioned volume is %q, want %q", fsType, fsTypeLUKS)
	}

	// What the header actually says, read off the real container. The unit test
	// asserts the argv; this asserts that cryptsetup did with it what the argv
	// was meant to achieve — the two fail for different reasons, and only this
	// one would catch cryptsetup reinterpreting a flag.
	assertFIPSHeader(t, p.lvPath(vol.ID))
	if info.DevicePath != p.cryptPath(vol.ID) {
		t.Errorf("DevicePath = %q, want the plaintext mapping %q", info.DevicePath, p.cryptPath(vol.ID))
	}

	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "payload"), []byte("encrypted at rest"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Growing an unlocked encrypted volume grows the container, the mapping
	// and the filesystem in that order.
	if err := p.Resize(ctx, vol.ID, 96<<20); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	// Locked again, the volume is not attached and cannot be mounted.
	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateAvailable {
		t.Errorf("State after Detach = %q, want available", status.State)
	}

	// Re-attaching unlocks it again and the data is still there.
	if _, err := p.Attach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("re-Attach: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{}); err != nil {
		t.Fatalf("re-Mount: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(target, "payload"))
	if err != nil {
		t.Fatalf("reading after re-unlock: %v", err)
	}
	if string(got) != "encrypted at rest" {
		t.Errorf("contents = %q, want them preserved across a lock/unlock cycle", got)
	}
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if err := p.Detach(ctx, vol.ID, "test-node"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
}

// TestIntegrationWrongKeyIsRejected checks that the passphrase is actually
// protecting the container rather than being accepted decoratively.
// TestIntegrationDetachedEncryptedResize proves the filesystem inside a locked
// container really grows. The volume is resized while DETACHED — the state
// where the provider has to unlock it itself, because Attach only opens a
// container and never grows what is inside one — and then attached and mounted
// so the filesystem's own idea of its size can be read back.
func TestIntegrationDetachedEncryptedResize(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "detached-resize-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const initial = 64 << 20
	vol, err := p.Provision(ctx, common.VolumeSpec{Name: "secret", SizeBytes: initial, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, vol.ID) })

	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	before := mountedFSBytes(t, ctx, p, vol.ID, target)

	// Resize with the volume detached and locked — Provision left it that way.
	status, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateAvailable {
		t.Fatalf("State = %q, want available: this test is about the detached path", status.State)
	}
	if err := p.Resize(ctx, vol.ID, 192<<20); err != nil {
		t.Fatalf("Resize while detached: %v", err)
	}

	// It has to come back the way it went in: detached, and still locked.
	status, err = p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status after resize: %v", err)
	}
	if status.State != common.VolumeStateAvailable {
		t.Errorf("State after resize = %q, want available: the volume was left unlocked or activated", status.State)
	}

	after := mountedFSBytes(t, ctx, p, vol.ID, target)
	t.Logf("filesystem bytes: before=%d after=%d", before, after)
	if after <= before {
		t.Errorf("filesystem is %d bytes after a resize from %d bytes; it was never grown", after, before)
	}
	if after < 128<<20 {
		t.Errorf("filesystem is %d bytes, want it grown to roughly the new 192 MiB volume", after)
	}
}

// mountedFSBytes attaches and mounts a volume, reads the filesystem's own total
// size, and puts the volume back as it found it.
func mountedFSBytes(t *testing.T, ctx context.Context, p *Provider, volID, target string) int64 {
	t.Helper()
	if _, err := p.Attach(ctx, volID, "test-node"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := p.Mount(ctx, volID, target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	defer func() {
		if err := p.Unmount(ctx, volID, target); err != nil {
			t.Fatalf("Unmount: %v", err)
		}
		if err := p.Detach(ctx, volID, "test-node"); err != nil {
			t.Fatalf("Detach: %v", err)
		}
	}()

	// The filesystem's own total, not the block device's — that is the number a
	// resize is supposed to move.
	out := strings.TrimSpace(run(t, "df", "--block-size=1", "--output=size", target))
	lines := strings.Split(out, "\n")
	size, err := strconv.ParseInt(strings.TrimSpace(lines[len(lines)-1]), 10, 64)
	if err != nil {
		t.Fatalf("reading df output %q: %v", out, err)
	}
	return size
}

// TestIntegrationForeignMappingIsRefused builds the hazard for real: a mapping
// opened by hand under this provider's deterministic name, over a DIFFERENT
// volume. cryptsetup reports it active under that name, so a provider trusting
// the name would return somebody else's decrypted device from Attach.
func TestIntegrationForeignMappingIsRefused(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "foreign-mapping-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ours, err := p.Provision(ctx, common.VolumeSpec{Name: "ours", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision ours: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, ours.ID) })

	theirs, err := p.Provision(ctx, common.VolumeSpec{Name: "theirs", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision theirs: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(ctx, theirs.ID) })

	// Open "theirs" by hand under the name the provider reserves for "ours".
	run(t, "lvchange", "--activate", "y", "--yes", p.lvRef(theirs.ID))
	stolen := p.mappingName(ours.ID)
	openCmd := exec.Command("cryptsetup", "open", "--type", "luks2", "--key-file", "-",
		p.lvPath(theirs.ID), stolen)
	openCmd.Stdin = strings.NewReader("foreign-mapping-passphrase")
	if out, openErr := openCmd.CombinedOutput(); openErr != nil {
		t.Fatalf("setting up the foreign mapping: %v\n%s", openErr, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("cryptsetup", "close", stolen).Run()
		_ = exec.Command("lvchange", "--activate", "n", "--yes", p.lvRef(theirs.ID)).Run()
	})

	// cryptsetup really does report it active under our name — the hazard is
	// present, not hypothetical.
	status := run(t, "cryptsetup", "status", stolen)
	t.Logf("cryptsetup status %s:\n%s", stolen, status)
	if !strings.Contains(status, "is active") {
		t.Fatalf("the foreign mapping is not active; this test proves nothing")
	}

	// The provider must refuse it rather than hand it back as "ours".
	info, err := p.Attach(ctx, ours.ID, "test-node")
	if err == nil {
		t.Fatalf("Attach adopted the foreign mapping and returned %q", info.DevicePath)
	}
	t.Logf("Attach correctly refused: %v", err)
}

func TestIntegrationWrongKeyIsRejected(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	good, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		Encrypted:   true,
		KeyProvider: mustStaticKeyIT(t, "the-right-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vol, err := good.Provision(ctx, common.VolumeSpec{Name: "secret", SizeBytes: 64 << 20, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = good.Delete(ctx, vol.ID) })

	bad, err := New(Options{
		VolumeGroup: vg,
		NodeID:      "test-node",
		KeyProvider: mustStaticKeyIT(t, "the-wrong-passphrase"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := bad.Attach(ctx, vol.ID, "test-node"); err == nil {
		t.Fatal("Attach succeeded with the wrong passphrase")
	}
}

// TestIntegrationHostileNamesNeverReachLVM re-checks the validation rule
// against the real tools: a rejected name must produce common.ErrInvalidArgument and leave the
// volume group untouched.
func TestIntegrationHostileNamesNeverReachLVM(t *testing.T) {
	vg := testVG(t)
	ctx := context.Background()

	p, err := New(Options{VolumeGroup: vg, NodeID: "test-node"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, hostile := range []string{"data; lvremove -f " + vg, "../etc", "-wipesignatures", "$(id)"} {
		_, err := p.Provision(ctx, common.VolumeSpec{Name: hostile, SizeBytes: 32 << 20})
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("Provision(%q) = %v, want common.ErrInvalidArgument", hostile, err)
		}
	}

	lvs, err := p.listLVs(ctx)
	if err != nil {
		t.Fatalf("listLVs: %v", err)
	}
	if len(lvs) != 0 {
		t.Errorf("the volume group holds %v after rejected requests, want nothing", lvs)
	}
}
