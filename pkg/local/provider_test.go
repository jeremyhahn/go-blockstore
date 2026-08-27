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
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

const (
	gib     = int64(1) << 30
	testKey = "correct-horse-battery-staple"
)

// encrypted configures a provider that provisions LUKS containers.
func encrypted(opts *Options) {
	opts.Encrypted = true
	opts.KeyProvider = mustStaticKey()
}

// withKey gives a provider the ability to unlock existing encrypted volumes
// without provisioning new ones as encrypted.
func withKey(opts *Options) {
	opts.KeyProvider = mustStaticKey()
}

// mustStaticKey builds the test passphrase provider, panicking if the kernel
// will not lock memory — which is a broken test host, not a test failure worth
// threading an error through every helper for.
func mustStaticKey() KeyProvider {
	stored, err := enclave.NewMemoryEnclave([]byte(testKey))
	if err != nil {
		panic("NewMemoryEnclave: " + err.Error())
	}
	kp, err := StaticKeyProvider(stored)
	if err != nil {
		panic("StaticKeyProvider: " + err.Error())
	}
	return kp
}

func assertLine(t *testing.T, runner *fakeRunner, want string) {
	t.Helper()
	for _, line := range runner.lines() {
		if line == want {
			return
		}
	}
	t.Fatalf("expected command %q; got:\n  %s", want, strings.Join(runner.lines(), "\n  "))
}

func assertNoLine(t *testing.T, runner *fakeRunner, unwanted string) {
	t.Helper()
	for _, line := range runner.lines() {
		if line == unwanted {
			t.Fatalf("did not expect command %q; got:\n  %s", unwanted, strings.Join(runner.lines(), "\n  "))
		}
	}
}

// assertKeyNeverOnArgv is the check behind passing key material on standard
// input: anything in argv is world-readable from /proc/<pid>/cmdline while the
// command runs.
// assertMounted checks that exactly the expected mount was performed.
func assertMounted(t *testing.T, runner *fakeRunner, want mount.Call) {
	t.Helper()
	got := runner.mountCalls()
	if len(got) != 1 {
		t.Fatalf("recorded %d mounts, want exactly one: %+v", len(got), got)
	}
	if got[0] != want {
		t.Errorf("mounted %+v, want %+v", got[0], want)
	}
}

func assertKeyNeverOnArgv(t *testing.T, runner *fakeRunner) {
	t.Helper()
	for _, call := range runner.snapshot() {
		for _, arg := range call.Args {
			if strings.Contains(arg, testKey) {
				t.Fatalf("key material appeared in argv of %q", call.line())
			}
		}
	}
}

// --- Provision -------------------------------------------------------------

func TestProvisionPlain(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	vol, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if vol.ID != "data" {
		t.Errorf("Volume.ID = %q, want %q", vol.ID, "data")
	}

	assertLine(t, runner, "lvcreate --yes --name data --size 1073741824b --setautoactivation n vg0")
	// No filesystem was requested, so none is created.
	runner.mustNotRun(t, "mkfs.ext4")
	// Provision yields an available volume, not an attached one.
	assertLine(t, runner, "lvchange --activate n --yes vg0/data")
}

// TestProvisionDisablesAutoActivation pins the flag that makes Detach mean
// anything. LVM autoactivation is on by default and udev reactivates a whole
// volume group on unrelated device events, so without this a detached volume
// silently comes back and Status starts reporting it attached. Found against
// real LVM, where a mkfs on one volume reactivated every other volume in the
// group within a second.
func TestProvisionDisablesAutoActivation(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	if _, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	create := runner.mustFind(t, "lvcreate")
	if !strings.Contains(create.line(), "--setautoactivation n") {
		t.Fatalf("lvcreate = %q, want --setautoactivation n", create.line())
	}
}

// TestSnapshotOmitsTheAutoActivationFlag is the exception to the rule above:
// lvcreate refuses --setautoactivation for a snapshot ("Option
// --setautoactivation is unsupported with snapshots", exit 3). A snapshot needs
// it no more than it can take it, because its activation is tied to the
// origin's and the origin already has autoactivation off.
func TestSnapshotOmitsTheAutoActivationFlag(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	if _, err := p.Snapshot(context.Background(), "data", "nightly"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	create := runner.mustFind(t, "lvcreate")
	if strings.Contains(create.line(), "--setautoactivation") {
		t.Fatalf("lvcreate = %q, but lvcreate rejects that flag for snapshots", create.line())
	}
}

// TestActivationAnswersTheSnapshotPrompt pins the --yes on lvchange. Activating
// a snapshot changes its origin's activation too, and lvchange stops to ask
// about it — a prompt no library call can answer, which real LVM turned into an
// "exit status 5" during a restore.
func TestActivationAnswersTheSnapshotPrompt(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "lvchange --activate y --yes vg0/data_snap_nightly")
}

func TestProvisionCreatesFilesystem(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "mkfs.ext4 -F /dev/vg0/data")
}

func TestProvisionCreatesXFSWithItsOwnForceFlag(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "xfs"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "mkfs.xfs -f /dev/vg0/data")
}

func TestProvisionEncrypted(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	assertLine(t, runner, "cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --hash sha512 --cipher aes-xts-plain64 --key-size 512 --key-file - /dev/vg0/data")
	assertLine(t, runner, "cryptsetup open --type luks2 --key-file - /dev/vg0/data bs-vg0_data")
	// The filesystem goes on the plaintext mapping, never on the container.
	assertLine(t, runner, "mkfs.ext4 -F /dev/mapper/bs-vg0_data")
	assertLine(t, runner, "cryptsetup close bs-vg0_data")

	format := runner.mustFind(t, "cryptsetup")
	if !bytes.Equal(format.Stdin, []byte(testKey)) {
		t.Errorf("luksFormat stdin = %q, want the passphrase", format.Stdin)
	}
	assertKeyNeverOnArgv(t, runner)
}

func TestProvisionAlreadyExists(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib})
	if !errors.Is(err, common.ErrAlreadyExists) {
		t.Fatalf("Provision = %v, want ErrAlreadyExists", err)
	}
	runner.mustNotRun(t, "lvcreate")
}

func TestProvisionRollsBackAPartialVolume(t *testing.T) {
	runner := newFakeRunner()
	runner.fail("mkfs.ext4", 1, "mkfs failed")
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"})
	if err == nil {
		t.Fatal("Provision succeeded, want the mkfs failure")
	}
	// Leaving the half-built volume behind would make the retry fail with
	// ErrAlreadyExists instead of working.
	assertLine(t, runner, "lvremove --force vg0/data")
}

// TestProvisionRollsBackWhenTheClosingDeactivationFails covers the last step of
// Provision. A volume left behind after a reported failure makes the retry come
// back ErrAlreadyExists for something the caller was told did not get created.
func TestProvisionRollsBackWhenTheClosingDeactivationFails(t *testing.T) {
	runner := newFakeRunner()
	runner.fail("lvchange", 5, "logical volume in use")
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib})
	if err == nil {
		t.Fatal("Provision succeeded, want the lvchange failure")
	}
	assertLine(t, runner, "lvremove --force vg0/data")
}

// TestProvisionRollsBackAnEncryptedVolumeThroughItsMapping covers the rollback
// path for an encrypted volume: lvremove will not touch a logical volume with an
// open dm-crypt mapping over it, so the mapping has to come down first or the
// cleanup quietly achieves nothing.
func TestProvisionRollsBackAnEncryptedVolumeThroughItsMapping(t *testing.T) {
	runner := newFakeRunner()
	runner.fail("mkfs.ext4", 1, "mkfs failed")
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"})
	if err == nil {
		t.Fatal("Provision succeeded, want the mkfs failure")
	}

	lines := runner.lines()
	closeAt, removeAt := -1, -1
	for i, line := range lines {
		switch line {
		case "cryptsetup close bs-vg0_data":
			closeAt = i
		case "lvremove --force vg0/data":
			removeAt = i
		}
	}
	if closeAt < 0 || removeAt < 0 {
		t.Fatalf("expected both a cryptsetup close and an lvremove; got:\n  %s", strings.Join(lines, "\n  "))
	}
	if closeAt > removeAt {
		t.Errorf("lvremove ran while the mapping was still open:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestProvisionRollsBackWhenTheLUKSCloseFails is the case that makes the
// ordering above matter: the close that buildVolume attempts fails, so the
// rollback's own close is the only thing standing between the caller and a
// volume that survives a failed Provision.
func TestProvisionRollsBackWhenTheLUKSCloseFails(t *testing.T) {
	closeAttempts := 0
	runner := newFakeRunner()
	runner.on("cryptsetup", func(args []string, _ []byte) ([]byte, error) {
		switch {
		case len(args) > 0 && args[0] == "status":
			// Ours, and still open — which is what makes the rollback try again.
			return []byte("/dev/mapper/bs-vg0_data is active.\n  device:  /dev/mapper/vg0-data\n"), nil
		case len(args) > 0 && args[0] == "close":
			closeAttempts++
			if closeAttempts == 1 {
				return nil, &ExitError{Name: "cryptsetup", Args: args, Code: 5, Stderr: "device busy"}
			}
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"})
	if err == nil {
		t.Fatal("Provision succeeded, want the cryptsetup close failure")
	}
	if closeAttempts < 2 {
		t.Errorf("the rollback did not retry the close; attempts = %d", closeAttempts)
	}
	assertLine(t, runner, "lvremove --force vg0/data")
}

// TestProvisionRejectsAStorageClass closes the last field this provider was
// accepting and ignoring. One volume group backs every volume and there are no
// tiers to select, so honoring a class is impossible — and returning a Volume
// whose Spec names a class the volume is not on is the same untruth as
// accepting an FSType on a restore.
// TestRollbackDoesNotCloseAForeignMapping keeps the cleanup path from doing
// what round 9 stopped every other path from doing. A rollback reaches for the
// volume's deterministic mapping name; if a stale or hand-made mapping over
// somebody else's device is sitting there, closing it by name would tear down a
// mapping this provision never opened.
func TestRollbackDoesNotCloseAForeignMapping(t *testing.T) {
	// A foreign mapping already holds the name, so the open FAILS the way
	// cryptsetup really fails when a name is in use — and the rollback then
	// reaches for that name.
	runner := newFakeRunner()
	runner.on("cryptsetup", func(args []string, _ []byte) ([]byte, error) {
		switch {
		case len(args) > 0 && args[0] == "status":
			return []byte("/dev/mapper/bs-vg0_data is active.\n  device:  /dev/mapper/vg0-somebodyelse\n"), nil
		case len(args) > 0 && args[0] == "open":
			return nil, &ExitError{Name: "cryptsetup", Args: args, Code: 5, Stderr: "Device bs-vg0_data already exists."}
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"})
	if err == nil {
		t.Fatal("Provision succeeded, want the failed unlock")
	}
	assertNoLine(t, runner, "cryptsetup close bs-vg0_data")
	// The volume it did create is still removed.
	assertLine(t, runner, "lvremove --force vg0/data")
}

// TestRollbackClosesItsOwnMapping is the other half: a mapping that IS this
// volume's still gets torn down.
func TestRollbackClosesItsOwnMapping(t *testing.T) {
	runner := newFakeRunner().withOpenMappings("bs-vg0_data")
	runner.fail("mkfs.ext4", 1, "mkfs failed")
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"})
	if err == nil {
		t.Fatal("Provision succeeded, want the mkfs failure")
	}
	assertLine(t, runner, "cryptsetup close bs-vg0_data")
	assertLine(t, runner, "lvremove --force vg0/data")
}

func TestProvisionRejectsAStorageClass(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:         "data",
		SizeBytes:    gib,
		StorageClass: "fast-nvme",
	})
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Provision = %v, want ErrUnsupported", err)
	}
	// Well formed but unservable here, so not ErrInvalidArgument: a backend
	// with tiers could take it.
	if errors.Is(err, common.ErrInvalidArgument) {
		t.Error("a servable-elsewhere request was reported as malformed")
	}
	runner.mustNotRun(t, "lvcreate")
}

func TestProvisionRejectsReplication(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, Replicas: 3})
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Provision = %v, want ErrUnsupported", err)
	}
}

// --- Provision from snapshot ----------------------------------------------

func snapshotFixtures() []lvFixture {
	return []lvFixture{
		{Name: "data", SizeBytes: gib, Active: false},
		{Name: "data" + snapSeparator + "nightly", SizeBytes: gib / 5, Origin: "data", DataPercent: "25.0"},
	}
}

func TestProvisionFromSnapshot(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	p := newTestProvider(t, runner)

	vol, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if vol.ID != "restored" {
		t.Errorf("Volume.ID = %q, want restored", vol.ID)
	}

	assertLine(t, runner, "lvcreate --yes --name restored --size 1073741824b --setautoactivation n vg0")
	assertLine(t, runner, "dd if=/dev/vg0/data_snap_nightly of=/dev/vg0/restored bs=4M conv=fsync status=none")
	// The origin was detached, so the pair goes back down after the copy. The
	// deactivation is aimed at the origin rather than the snapshot because LVM
	// moves the two together and the origin is the one whose state matters.
	assertLine(t, runner, "lvchange --activate n --yes vg0/data")
	assertLine(t, runner, "lvchange --activate n --yes vg0/restored")
	// A restore is a copy, so no filesystem is created over the copied data.
	runner.mustNotRun(t, "mkfs.ext4")
}

// TestProvisionFromSnapshotLeavesAnAttachedOriginAttached is the dangerous half
// of the origin/snapshot activation coupling: switching the snapshot off after
// the copy would take the origin's device node with it, out from under a caller
// that has the origin attached and very likely mounted.
func TestProvisionFromSnapshotLeavesAnAttachedOriginAttached(t *testing.T) {
	runner := newFakeRunner().withLVs(
		lvFixture{Name: "data", SizeBytes: gib, Active: true},
		lvFixture{Name: "data" + snapSeparator + "nightly", SizeBytes: gib / 5, Origin: "data", DataPercent: "25.0"},
	)
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	assertLine(t, runner, "lvchange --activate y --yes vg0/data")
	assertNoLine(t, runner, "lvchange --activate n --yes vg0/data")
	assertNoLine(t, runner, "lvchange --activate n --yes vg0/data_snap_nightly")
}

// TestEncryptedProviderRefusesAPlaintextRestore closes a silent downgrade: a
// restore is a byte copy, so restoring a plaintext snapshot on a provider
// configured to encrypt would produce a plaintext volume under a configuration
// whose entire purpose is that it does not.
func TestEncryptedProviderRefusesAPlaintextRestore(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	// The snapshot device carries a filesystem, not a LUKS container.
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": "ext4"})
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Provision = %v, want ErrUnsupported", err)
	}
	// Refused before anything was created, so no plaintext was ever written to
	// extents that would then be freed.
	runner.mustNotRun(t, "lvcreate")
	runner.mustNotRun(t, "dd")
}

// TestEncryptedProviderRestoresAnEncryptedSnapshot is the case that still works:
// the copied image is already a LUKS container, so the restored volume is
// encrypted too.
func TestEncryptedProviderRestoresAnEncryptedSnapshot(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": fsTypeLUKS})
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "dd if=/dev/vg0/data_snap_nightly of=/dev/vg0/restored bs=4M conv=fsync status=none")
	// The image is copied as it stands; it is not reformatted under a new header.
	runner.mustNotRun(t, "cryptsetup")
}

// TestRestoreRejectsAnFSType closes a lie in the returned Volume. A restore
// copies the snapshot's image, filesystem included, so an FSType has nothing to
// select — and accepting it silently would hand back a Volume whose Spec claims
// a filesystem the volume does not have.
func TestRestoreRejectsAnFSType(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		FSType:           "xfs",
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Provision = %v, want ErrInvalidArgument", err)
	}
	if calls := runner.lines(); len(calls) != 0 {
		t.Fatalf("a contradictory request still reached the system: %v", calls)
	}
}

// TestExactSizeRestoreSkipsTheTailZeroing is the companion to the oversized
// case. An origin's size is a whole number of extents, so restoring at exactly
// that size produces a volume with nothing past the copied image — and issuing
// a zero-length zeroout at EOF would make the ordinary restore depend on how the
// device handles it.
func TestExactSizeRestoreSkipsTheTailZeroing(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib, // exactly the origin's size
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "dd if=/dev/vg0/data_snap_nightly of=/dev/vg0/restored bs=4M conv=fsync status=none")
	runner.mustNotRun(t, "blkdiscard")
}

// grownOriginFixtures is a volume snapshotted at 1 GiB and grown to 4 GiB
// afterwards — which LVM permits while the origin is inactive, the state this
// provider leaves volumes in. The snapshot still presents the 1 GiB image.
func grownOriginFixtures() []lvFixture {
	return []lvFixture{
		{Name: "data", SizeBytes: 4 * gib},
		{
			Name:            "data" + snapSeparator + "nightly",
			SizeBytes:       gib / 5,
			Origin:          "data",
			OriginSizeBytes: gib, // the size when the snapshot was taken
		},
	}
}

// TestRestoreSizesFromTheSnapshotNotTheOrigin covers a volume grown after being
// snapshotted. Sizing from the origin's CURRENT size rejects a restore that is
// correctly sized for the image the snapshot actually presents.
func TestRestoreSizesFromTheSnapshotNotTheOrigin(t *testing.T) {
	runner := newFakeRunner().withLVs(grownOriginFixtures()...)
	p := newTestProvider(t, runner)

	// Exactly the image size: valid, though smaller than the origin is today.
	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("restore sized for the snapshot image = %v, want it accepted", err)
	}
	assertLine(t, runner, "lvcreate --yes --name restored --size 1073741824b --setautoactivation n vg0")
	// Nothing past the image, so no tail to clear.
	runner.mustNotRun(t, "blkdiscard")
}

// TestRestoreZeroesFromTheImageSize is the sharper half. dd copies the bytes the
// snapshot presents and stops, so the tail must be zeroed from THERE. Offsetting
// by the origin's current size would start past what was copied and leave the
// gap holding whatever the volume group's free extents held — exactly the stale
// data the zeroing exists to remove.
func TestRestoreZeroesFromTheImageSize(t *testing.T) {
	runner := newFakeRunner().withLVs(grownOriginFixtures()...)
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        8 * gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// 1 GiB — the image — not the origin's current 4 GiB.
	assertLine(t, runner, "blkdiscard --zeroout --offset 1073741824 /dev/vg0/restored")
	assertNoLine(t, runner, "blkdiscard --zeroout --offset 4294967296 /dev/vg0/restored")
}

// TestRestoreStillRefusesBelowTheImageSize keeps the shrink guard pinned to the
// image rather than to whichever number happens to be larger.
func TestRestoreStillRefusesBelowTheImageSize(t *testing.T) {
	runner := newFakeRunner().withLVs(grownOriginFixtures()...)
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib / 2,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Provision = %v, want ErrUnsupported", err)
	}
	runner.mustNotRun(t, "lvcreate")
}

func TestProvisionFromMissingSnapshot(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "missing"),
	})
	if !errors.Is(err, common.ErrSnapshotNotFound) {
		t.Fatalf("Provision = %v, want ErrSnapshotNotFound", err)
	}
	runner.mustNotRun(t, "lvcreate")
}

// TestProvisionFromNonSnapshot covers an ID that names a real logical volume
// which is not a snapshot: it is still ErrSnapshotNotFound, not ErrNotFound,
// because the caller asked about a snapshot.
func TestProvisionFromNonSnapshot(t *testing.T) {
	runner := newFakeRunner().withLVs(
		lvFixture{Name: "data", SizeBytes: gib},
		lvFixture{Name: "data" + snapSeparator + "nightly", SizeBytes: gib},
	)
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if !errors.Is(err, common.ErrSnapshotNotFound) {
		t.Fatalf("Provision = %v, want ErrSnapshotNotFound", err)
	}
}

func TestProvisionFromSnapshotRefusesToShrink(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib / 2,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Provision = %v, want ErrUnsupported", err)
	}
	runner.mustNotRun(t, "lvcreate")
}

// --- Attach / Detach -------------------------------------------------------

func TestAttachNotFound(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	_, err := p.Attach(context.Background(), "data", "node-a")
	if !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("Attach = %v, want ErrNotFound", err)
	}
}

func TestAttachPlain(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	info, err := p.Attach(context.Background(), "data", "node-a")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if info.DevicePath != "/dev/vg0/data" {
		t.Errorf("DevicePath = %q, want /dev/vg0/data", info.DevicePath)
	}
	if info.Node != "node-a" {
		t.Errorf("Node = %q, want node-a", info.Node)
	}
	assertLine(t, runner, "lvchange --activate y --yes vg0/data")
	// Nothing about a plain volume should require cryptsetup on the host.
	runner.mustNotRun(t, "cryptsetup")
}

func TestAttachUnlocksEncryptedVolume(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	p := newTestProvider(t, runner, withKey)

	info, err := p.Attach(context.Background(), "data", "node-a")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if info.DevicePath != "/dev/mapper/bs-vg0_data" {
		t.Errorf("DevicePath = %q, want the plaintext mapping", info.DevicePath)
	}
	assertLine(t, runner, "cryptsetup open --type luks2 --key-file - /dev/vg0/data bs-vg0_data")
	assertKeyNeverOnArgv(t, runner)
}

// TestAttachIsIdempotentOverAnUnlockedVolume checks that re-attaching does not
// try to unlock a container that is already open, which cryptsetup rejects.
func TestAttachIsIdempotentOverAnUnlockedVolume(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey)

	info, err := p.Attach(context.Background(), "data", "node-a")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if info.DevicePath != "/dev/mapper/bs-vg0_data" {
		t.Errorf("DevicePath = %q, want the plaintext mapping", info.DevicePath)
	}
	assertNoLine(t, runner, "cryptsetup open --type luks2 --key-file - /dev/vg0/data bs-vg0_data")
}

func TestAttachEncryptedWithoutKeyProvider(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	p := newTestProvider(t, runner)

	if _, err := p.Attach(context.Background(), "data", "node-a"); err == nil {
		t.Fatal("Attach succeeded without a KeyProvider, want an error")
	}
}

// TestAttachRollsBackActivationOnFailure keeps a failed Attach from leaving the
// volume active. The caller saw an error and has no reason to call Detach, so
// the activation would sit there unowned.
func TestAttachRollsBackActivationOnFailure(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	runner.on("cryptsetup", func(args []string, _ []byte) ([]byte, error) {
		if len(args) > 0 && args[0] == "open" {
			return nil, &ExitError{Name: "cryptsetup", Args: args, Code: 2, Stderr: "no key available"}
		}
		return nil, &ExitError{Name: "cryptsetup", Args: args, Code: 4}
	})
	p := newTestProvider(t, runner, withKey)

	if _, err := p.Attach(context.Background(), "data", "node-a"); err == nil {
		t.Fatal("Attach succeeded despite a failing cryptsetup open")
	}
	assertLine(t, runner, "lvchange --activate n --yes vg0/data")
}

// TestAttachLeavesAnAlreadyActiveVolumeAlone is the other half of that rule: an
// attach that fails over a volume someone else already attached must not
// deactivate it out from under them.
func TestAttachLeavesAnAlreadyActiveVolumeAlone(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	runner.on("cryptsetup", func(args []string, _ []byte) ([]byte, error) {
		if len(args) > 0 && args[0] == "open" {
			return nil, &ExitError{Name: "cryptsetup", Args: args, Code: 2, Stderr: "no key available"}
		}
		return nil, &ExitError{Name: "cryptsetup", Args: args, Code: 4}
	})
	p := newTestProvider(t, runner, withKey)

	if _, err := p.Attach(context.Background(), "data", "node-a"); err == nil {
		t.Fatal("Attach succeeded despite a failing cryptsetup open")
	}
	assertNoLine(t, runner, "lvchange --activate n --yes vg0/data")
}

func TestAttachRejectsAnotherNode(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	_, err := p.Attach(context.Background(), "data", "node-b")
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Attach = %v, want ErrUnsupported", err)
	}
	if calls := runner.lines(); len(calls) != 0 {
		t.Fatalf("expected no commands for a remote node; got %v", calls)
	}
}

func TestAttachEmptyNodeMeansThisNode(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	info, err := p.Attach(context.Background(), "data", "")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if info.Node != "node-a" {
		t.Errorf("Node = %q, want the provider's own node", info.Node)
	}
}

func TestDetachNotFound(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	if err := p.Detach(context.Background(), "data", "node-a"); !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("Detach = %v, want ErrNotFound", err)
	}
}

func TestDetachInactiveVolumeIsANoop(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false})
	p := newTestProvider(t, runner)

	if err := p.Detach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	runner.mustNotRun(t, "lvchange")
	runner.mustNotRun(t, "cryptsetup")
}

func TestDetachLocksAndDeactivates(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey)

	if err := p.Detach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	assertLine(t, runner, "cryptsetup close bs-vg0_data")
	assertLine(t, runner, "lvchange --activate n --yes vg0/data")
}

// --- Mount / Unmount -------------------------------------------------------

func TestMountNotFound(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("Mount = %v, want ErrNotFound", err)
	}
}

func TestMountNotAttached(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false})
	p := newTestProvider(t, runner)

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if !errors.Is(err, common.ErrNotAttached) {
		t.Fatalf("Mount = %v, want ErrNotAttached", err)
	}
	runner.mustNotRun(t, "mount")
}

// TestMountLockedEncryptedVolumeIsNotAttached covers the case an active-but-
// locked LUKS volume creates: there is a device node, but nothing mountable
// behind it, and the caller needs ErrNotAttached rather than a mount failure.
func TestMountLockedEncryptedVolumeIsNotAttached(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	p := newTestProvider(t, runner, withKey)

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{})
	if !errors.Is(err, common.ErrNotAttached) {
		t.Fatalf("Mount = %v, want ErrNotAttached", err)
	}
	runner.mustNotRun(t, "mount")
}

func TestMountProbesFilesystemType(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner)

	if err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	assertMounted(t, runner, mount.Call{
		Source: "/dev/vg0/data", Target: "/mnt/data", FSType: "ext4",
	})
}

func TestMountAssemblesOptions(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner)

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{
		ReadOnly: true,
		FSType:   "ext4",
		Flags:    []string{"noatime", "nodev"},
	})
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	// ReadOnly and the generic options become kernel flags; nothing here is a
	// filesystem option, so the data string stays empty. Handing nosuid or
	// nodev over as data would leave the kernel never applying them.
	assertMounted(t, runner, mount.Call{
		Source: "/dev/vg0/data", Target: "/mnt/data", FSType: "ext4",
		Flags: mount.ReadOnly | mount.NoATime | mount.NoDev,
	})
}

func TestMountEncryptedUsesThePlaintextMapping(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{
			"/dev/vg0/data":           fsTypeLUKS,
			"/dev/mapper/bs-vg0_data": "xfs",
		}).
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey)

	if err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	assertMounted(t, runner, mount.Call{
		Source: "/dev/mapper/bs-vg0_data", Target: "/mnt/data", FSType: "xfs",
	})
}

func TestUnmountNotFound(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	if err := p.Unmount(context.Background(), "data", "/mnt/data"); !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("Unmount = %v, want ErrNotFound", err)
	}
}

// TestUnmountConverges is the contract's "unmounting a target the volume is not
// mounted at is not an error", covering every way that can be true.
func TestUnmountConverges(t *testing.T) {
	cases := map[string]*fakeRunner{
		"volume not attached": newFakeRunner().
			withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}),
		"attached but not mounted": newFakeRunner().
			withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
			withBlkid(map[string]string{"/dev/vg0/data": "ext4"}),
		"mounted somewhere else": newFakeRunner().
			withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
			withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
			withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/other"}}),
	}

	for name, runner := range cases {
		t.Run(name, func(t *testing.T) {
			p := newTestProvider(t, runner)
			if err := p.Unmount(context.Background(), "data", "/mnt/data"); err != nil {
				t.Fatalf("Unmount: %v", err)
			}
			runner.mustNotRun(t, "umount")
		})
	}
}

func TestUnmountUnmounts(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})
	p := newTestProvider(t, runner)

	if err := p.Unmount(context.Background(), "data", "/mnt/data"); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if got := runner.unmountCalls(); len(got) != 1 || got[0] != "/mnt/data" {
		t.Fatalf("unmounted %v, want [/mnt/data]", got)
	}
}

// --- Resize ----------------------------------------------------------------

func TestResizeNotFound(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("Resize = %v, want ErrNotFound", err)
	}
}

// TestResizeRefusesUnrepresentableSizes is the caller-facing half of the
// overflow guard. Unguarded, Resize(math.MaxInt64) rounds to a negative target,
// compares as smaller than the current volume, and comes back ErrUnsupported —
// telling a caller that asked to grow that it had asked to shrink.
func TestResizeRefusesUnrepresentableSizes(t *testing.T) {
	const extent = 4 << 20

	for name, size := range map[string]int64{
		"max":      math.MaxInt64,
		"one over": math.MaxInt64 - (extent - 1) + 1,
	} {
		runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
		p := newTestProvider(t, runner)

		err := p.Resize(context.Background(), "data", size)
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("Resize(%s) = %v, want ErrInvalidArgument", name, err)
		}
		if errors.Is(err, common.ErrUnsupported) {
			t.Errorf("Resize(%s) reported a growth request as an unsupported shrink", name)
		}
		runner.mustNotRun(t, "lvextend")
	}

	// The largest size that CAN be rounded is still a growth request.
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)
	if err := p.Resize(context.Background(), "data", math.MaxInt64-(extent-1)); errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("Resize at the largest representable size = %v, want it attempted", err)
	}
}

func TestResizeRefusesToShrink(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: 2 * gib})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", gib); !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Resize = %v, want ErrUnsupported", err)
	}
	runner.mustNotRun(t, "lvextend")
}

func TestResizeToTheSameSizeIsANoop(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	runner.mustNotRun(t, "lvextend")
}

// TestResizeToleratesExtentRounding covers the request LVM has already rounded
// up. Asking for 100000000 bytes on a 4 MiB-extent group yields a 100663296-byte
// volume, and the identical second request must be a no-op rather than looking
// like a shrink.
func TestResizeToleratesExtentRounding(t *testing.T) {
	const requested = 100000000
	const rounded = 100663296

	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: rounded})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", requested); err != nil {
		t.Fatalf("repeating an already-rounded Resize = %v, want nil", err)
	}
	runner.mustNotRun(t, "lvextend")
}

// TestResizeRetriesTheFilesystemGrowth is the recovery path after a partial
// resize: lvextend landed, the filesystem growth after it did not. Repeating the
// call must finish the job instead of seeing a big enough block device and
// reporting success over a filesystem still at its old size.
func TestResizeRetriesTheFilesystemGrowth(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: 2 * gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	// The block device is already the requested size, so no lvextend...
	runner.mustNotRun(t, "lvextend")
	// ...but the filesystem still gets grown to fill it.
	assertLine(t, runner, "resize2fs /dev/vg0/data")
}

// TestMountRejectsReadWriteAgainstReadOnly closes the gap where a "rw" in Flags
// would win over ReadOnly: mount(8) takes the last of a conflicting -o ro,rw, so
// the volume would come up writable despite the explicit request.
func TestMountRejectsReadWriteAgainstReadOnly(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner)

	err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{
		ReadOnly: true,
		Flags:    []string{"noatime", "rw"},
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Mount = %v, want common.ErrInvalidArgument for ro/rw", err)
	}
	runner.mustNotRun(t, "mount")

	// "rw" on its own, with no read-only request, is still an ordinary flag.
	if err := p.Mount(context.Background(), "data", "/mnt/data", common.MountOptions{Flags: []string{"rw"}}); err != nil {
		t.Fatalf("Mount with rw alone = %v, want nil", err)
	}
}

func TestResizeGrowsDetachedRawVolume(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	assertLine(t, runner, "lvextend --size 2147483648b vg0/data")
	// A raw volume has no filesystem to grow.
	runner.mustNotRun(t, "resize2fs")
}

// TestResizeGrowsExtOnADetachedVolume is what keeps Resize meaning the same
// thing whether or not the volume is attached. ext grows offline, so a caller
// that resizes before attaching must not be handed a volume whose block device
// is bigger than its filesystem.
func TestResizeGrowsExtOnADetachedVolume(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	assertLine(t, runner, "resize2fs /dev/vg0/data")

	// It is activated only for the growth and handed back detached, the state
	// the caller left it in.
	lines := runner.lines()
	activate, deactivate, grow := -1, -1, -1
	for i, line := range lines {
		switch line {
		case "lvchange --activate y --yes vg0/data":
			activate = i
		case "lvchange --activate n --yes vg0/data":
			deactivate = i
		case "resize2fs /dev/vg0/data":
			grow = i
		}
	}
	if activate < 0 || deactivate < 0 {
		t.Fatalf("expected the volume to be activated and put back; got:\n  %s", strings.Join(lines, "\n  "))
	}
	if activate > grow || grow > deactivate {
		t.Errorf("the growth did not happen between activation and deactivation:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestResizeGrowsADetachedEncryptedFilesystem is the encrypted half of the
// detached-resize rule. Attach only OPENS a container, it does not grow what is
// inside one, so skipping this would leave the filesystem at its old size behind
// a block device that says otherwise — and Resize would have reported success.
//
// The sequence is the assertion: activate, unlock, grow the filesystem through
// the plaintext mapping, lock, deactivate. The volume has to end exactly as it
// was found.
func TestResizeGrowsADetachedEncryptedFilesystem(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{
			"/dev/vg0/data":           fsTypeLUKS,
			"/dev/mapper/bs-vg0_data": "ext4",
		})
	p := newTestProvider(t, runner, withKey)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	want := []string{
		"lvextend --size 2147483648b vg0/data",
		"lvchange --activate y --yes vg0/data",
		"cryptsetup open --type luks2 --key-file - /dev/vg0/data bs-vg0_data",
		"resize2fs /dev/mapper/bs-vg0_data",
		"cryptsetup close bs-vg0_data",
		"lvchange --activate n --yes vg0/data",
	}
	lines := runner.lines()
	at := -1
	for _, step := range want {
		found := -1
		for i := at + 1; i < len(lines); i++ {
			if lines[i] == step {
				found = i
				break
			}
		}
		if found < 0 {
			t.Fatalf("missing %q after position %d; got:\n  %s", step, at, strings.Join(lines, "\n  "))
		}
		at = found
	}

	// The passphrase reached cryptsetup on stdin, as everywhere else.
	assertKeyNeverOnArgv(t, runner)
}

// TestDetachedEncryptedResizeDoesNotResizeTheMapping records a deliberate
// omission. The mapping is opened AFTER the logical volume grew, and cryptsetup
// sizes a mapping to the device it finds — measured on 2.7.0, re-opening a
// grown volume took the mapping from 50331648 to 117440512 bytes with no resize
// asked for. Issuing one would borrow the passphrase a second time to achieve
// nothing, and every borrow is an exposure.
func TestDetachedEncryptedResizeDoesNotResizeTheMapping(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{
			"/dev/vg0/data":           fsTypeLUKS,
			"/dev/mapper/bs-vg0_data": "ext4",
		})
	p := newTestProvider(t, runner, withKey)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	assertNoLine(t, runner, "cryptsetup resize --key-file - bs-vg0_data")
}

// TestDetachedEncryptedResizeFailsWithoutAKey is the typed failure that replaced
// a silent skip: without a KeyProvider the filesystem cannot be reached, and
// saying so beats reporting a resize that only half happened.
func TestDetachedEncryptedResizeFailsWithoutAKey(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err == nil {
		t.Fatal("Resize succeeded over an encrypted volume it could not unlock")
	}
	// The block device still grew; it is the filesystem that could not be reached.
	assertLine(t, runner, "lvextend --size 2147483648b vg0/data")
	// And the volume is put back detached rather than left activated.
	assertLine(t, runner, "lvchange --activate n --yes vg0/data")
}

// TestRestoreZeroesTheTailOfAnOversizedVolume closes a stale-data path that
// looks like it cannot exist: dd writes the snapshot's image and stops, so a
// restore into a larger volume leaves everything past that image holding
// whatever the volume group's free extents held.
func TestRestoreZeroesTheTailOfAnOversizedVolume(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        4 * gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// The origin is 1 GiB, so everything past that byte is zeroed.
	assertLine(t, runner, "blkdiscard --zeroout --offset 1073741824 /dev/vg0/restored")

	lines := runner.lines()
	copyAt, zeroAt := -1, -1
	for i, line := range lines {
		switch line {
		case "dd if=/dev/vg0/data_snap_nightly of=/dev/vg0/restored bs=4M conv=fsync status=none":
			copyAt = i
		case "blkdiscard --zeroout --offset 1073741824 /dev/vg0/restored":
			zeroAt = i
		}
	}
	if copyAt < 0 || zeroAt < 0 || copyAt > zeroAt {
		t.Errorf("the tail was not zeroed after the copy:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestOfflineExtResizeChecksFirst pins the step resize2fs demands. Measured on
// e2fsprogs 1.47.0, an offline resize2fs answers "Please run 'e2fsck -f
// <device>' first." and exits 1 — even for a filesystem whose own state field
// reads clean — so an offline grow that skipped the check would fail every time.
func TestOfflineExtResizeChecksFirst(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	lines := runner.lines()
	check, grow := -1, -1
	for i, line := range lines {
		switch line {
		case "e2fsck -f -p /dev/vg0/data":
			check = i
		case "resize2fs /dev/vg0/data":
			grow = i
		}
	}
	if check < 0 || grow < 0 {
		t.Fatalf("expected a check then a grow; got:\n  %s", strings.Join(lines, "\n  "))
	}
	if check > grow {
		t.Errorf("resize2fs ran before the check it requires:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestMountedExtResizeDoesNotCheck is a safety property, not a preference:
// e2fsck against a MOUNTED filesystem corrupts it. Online resize2fs does not
// want the check anyway, so the mount table — not a flag — decides.
func TestMountedExtResizeDoesNotCheck(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	runner.mustNotRun(t, "e2fsck")
	assertLine(t, runner, "resize2fs /dev/vg0/data")
}

// TestExtCheckToleratesCorrectedErrors covers e2fsck's exit statuses. 1 means it
// found problems and fixed them, which leaves a filesystem that can be resized;
// anything above means errors it could not fix, an operational failure, or a
// check that did not finish, and none of those should be followed by a grow.
func TestExtCheckToleratesCorrectedErrors(t *testing.T) {
	for _, code := range []int{0, 1} {
		runner := newFakeRunner().
			withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
			withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
		if code != 0 {
			runner.fail("e2fsck", code, "")
		}
		p := newTestProvider(t, runner)

		if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
			t.Errorf("Resize with e2fsck exit %d = %v, want nil", code, err)
		}
	}

	for _, code := range []int{2, 4, 8, 16} {
		runner := newFakeRunner().
			withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
			withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
		runner.fail("e2fsck", code, "unrecoverable")
		p := newTestProvider(t, runner)

		if err := p.Resize(context.Background(), "data", 2*gib); err == nil {
			t.Errorf("Resize grew a filesystem after e2fsck exit %d", code)
		}
		runner.mustNotRun(t, "resize2fs")
	}
}

func TestResizeGrowsExt4(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	assertLine(t, runner, "lvextend --size 2147483648b vg0/data")
	assertLine(t, runner, "resize2fs /dev/vg0/data")
}

func TestResizeGrowsTheLUKSMappingBeforeTheFilesystem(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{
			"/dev/vg0/data":           fsTypeLUKS,
			"/dev/mapper/bs-vg0_data": "ext4",
		}).
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	lines := runner.lines()
	luksAt, fsAt := -1, -1
	for i, line := range lines {
		switch line {
		case "cryptsetup resize --key-file - bs-vg0_data":
			luksAt = i
		case "resize2fs /dev/mapper/bs-vg0_data":
			fsAt = i
		}
	}
	if luksAt < 0 || fsAt < 0 {
		t.Fatalf("expected both a cryptsetup resize and a resize2fs; got:\n  %s", strings.Join(lines, "\n  "))
	}
	// Growing the filesystem first would extend it past the mapping.
	if luksAt > fsAt {
		t.Errorf("cryptsetup resize ran after resize2fs:\n  %s", strings.Join(lines, "\n  "))
	}
	assertKeyNeverOnArgv(t, runner)
}

func TestResizeGrowsMountedXFS(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "xfs"}).
		withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	assertLine(t, runner, "xfs_growfs /mnt/data")
}

// TestResizeLeavesUnmountedXFSAlone records the documented limitation: XFS has
// no offline grow, so the block device is extended and the filesystem waits for
// a mount.
func TestResizeLeavesUnmountedXFSAlone(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "xfs"})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	assertLine(t, runner, "lvextend --size 2147483648b vg0/data")
	runner.mustNotRun(t, "xfs_growfs")
}

func TestResizeLeavesRawVolumesAlone(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	runner.mustNotRun(t, "resize2fs")
	runner.mustNotRun(t, "xfs_growfs")
}

// --- Snapshots -------------------------------------------------------------

func TestSnapshotNotFound(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	if _, err := p.Snapshot(context.Background(), "data", "nightly"); !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("Snapshot = %v, want ErrNotFound", err)
	}
}

func TestSnapshotCreates(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	id, err := p.Snapshot(context.Background(), "data", "nightly")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if want := common.SnapshotID("data" + snapSeparator + "nightly"); id != want {
		t.Errorf("SnapshotID = %q, want %q", id, want)
	}
	assertLine(t, runner, "lvcreate --snapshot --yes --name data_snap_nightly --extents 20%ORIGIN vg0/data")
}

func TestSnapshotHonorsConfiguredCoWPercent(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner, func(o *Options) { o.SnapshotCoWPercent = 50 })

	if _, err := p.Snapshot(context.Background(), "data", "nightly"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	assertLine(t, runner, "lvcreate --snapshot --yes --name data_snap_nightly --extents 50%ORIGIN vg0/data")
}

func TestSnapshotAlreadyExists(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	p := newTestProvider(t, runner)

	_, err := p.Snapshot(context.Background(), "data", "nightly")
	if !errors.Is(err, common.ErrAlreadyExists) {
		t.Fatalf("Snapshot = %v, want ErrAlreadyExists", err)
	}
	runner.mustNotRun(t, "lvcreate")
}

func TestListSnapshotsNotFound(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	if _, err := p.ListSnapshots(context.Background(), "data"); !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("ListSnapshots = %v, want ErrNotFound", err)
	}
}

// TestListSnapshotsOnAVolumeWithNone is the contract's "absence of snapshots is
// not ErrSnapshotNotFound".
func TestListSnapshotsOnAVolumeWithNone(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	snaps, err := p.ListSnapshots(context.Background(), "data")
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if snaps == nil {
		t.Error("ListSnapshots returned nil, want an empty slice")
	}
	if len(snaps) != 0 {
		t.Errorf("ListSnapshots returned %d snapshots, want 0", len(snaps))
	}
}

// TestListSnapshotsReportsCoWOccupancy checks the SnapshotInfo.SizeBytes rule:
// the space the snapshot occupies, not the origin's capacity.
func TestListSnapshotsReportsCoWOccupancy(t *testing.T) {
	runner := newFakeRunner().withLVs(
		lvFixture{Name: "data", SizeBytes: gib},
		lvFixture{
			Name:        "data" + snapSeparator + "nightly",
			SizeBytes:   1000,
			Origin:      "data",
			Active:      true,
			DataPercent: "25.0",
			Time:        "2026-08-26 09:30:00 -0400",
		},
		// A snapshot of a different volume must not show up here.
		lvFixture{Name: "other" + snapSeparator + "nightly", SizeBytes: 1000, Origin: "other"},
	)
	p := newTestProvider(t, runner)

	snaps, err := p.ListSnapshots(context.Background(), "data")
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("ListSnapshots returned %d snapshots, want 1", len(snaps))
	}

	got := snaps[0]
	if got.ID != common.SnapshotID("data"+snapSeparator+"nightly") {
		t.Errorf("ID = %q", got.ID)
	}
	if got.VolumeID != "data" {
		t.Errorf("VolumeID = %q, want data", got.VolumeID)
	}
	if got.Name != "nightly" {
		t.Errorf("Name = %q, want nightly", got.Name)
	}
	if got.SizeBytes != 250 {
		t.Errorf("SizeBytes = %d, want 250 (25%% of the 1000-byte CoW area)", got.SizeBytes)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero, want the parsed lv_time")
	}
	if y, m, d := got.CreatedAt.Date(); y != 2026 || m.String() != "August" || d != 26 {
		t.Errorf("CreatedAt = %v, want 2026-08-26", got.CreatedAt)
	}
}

// TestListSnapshotsSkipsSnapshotsItDidNotCreate keeps ListSnapshots from
// returning an ID the provider's own DeleteSnapshot rejects. A volume group is
// shared, so it can hold snapshots of this volume taken by hand or by other
// tooling — listing one would advertise something the caller cannot act on, and
// accepting it instead would let this provider delete another tool's snapshot.
func TestListSnapshotsSkipsSnapshotsItDidNotCreate(t *testing.T) {
	runner := newFakeRunner().withLVs(
		lvFixture{Name: "data", SizeBytes: gib},
		lvFixture{Name: "data" + snapSeparator + "nightly", SizeBytes: 1000, Origin: "data", DataPercent: "10.0"},
		// Same origin, but named by something other than this provider.
		lvFixture{Name: "handmade-backup", SizeBytes: 1000, Origin: "data", DataPercent: "50.0"},
	)
	p := newTestProvider(t, runner)

	snaps, err := p.ListSnapshots(context.Background(), "data")
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("ListSnapshots = %v, want only the snapshot this provider created", snaps)
	}
	if snaps[0].Name != "nightly" {
		t.Errorf("Name = %q, want nightly", snaps[0].Name)
	}

	// Every ID handed out has to survive the provider's own validation, or the
	// caller is given something it cannot use.
	for _, s := range snaps {
		if err := validateSnapshotID(s.ID); err != nil {
			t.Errorf("ListSnapshots returned ID %q that its own validation rejects: %v", s.ID, err)
		}
	}
}

func TestDeleteSnapshotNotFound(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	err := p.DeleteSnapshot(context.Background(), common.SnapshotID("data"+snapSeparator+"nightly"))
	if !errors.Is(err, common.ErrSnapshotNotFound) {
		t.Fatalf("DeleteSnapshot = %v, want ErrSnapshotNotFound", err)
	}
	runner.mustNotRun(t, "lvremove")
}

func TestDeleteSnapshotRejectsAPlainVolume(t *testing.T) {
	runner := newFakeRunner().withLVs(
		lvFixture{Name: "data", SizeBytes: gib},
		lvFixture{Name: "data" + snapSeparator + "nightly", SizeBytes: gib},
	)
	p := newTestProvider(t, runner)

	err := p.DeleteSnapshot(context.Background(), common.SnapshotID("data"+snapSeparator+"nightly"))
	if !errors.Is(err, common.ErrSnapshotNotFound) {
		t.Fatalf("DeleteSnapshot = %v, want ErrSnapshotNotFound", err)
	}
	runner.mustNotRun(t, "lvremove")
}

// TestSnapshotOwnershipIsCheckedNotAssumed covers a snapshot created out of
// band whose name matches this provider's pattern but whose real origin is a
// different volume. Trusting the name alone would let DeleteSnapshot remove
// somebody else's snapshot, and let a restore copy the wrong volume's data into
// a volume the caller believes came from its own snapshot.
func TestSnapshotOwnershipIsCheckedNotAssumed(t *testing.T) {
	// Named "data_snap_nightly", but actually a snapshot of "other".
	impostor := lvFixture{Name: "data" + snapSeparator + "nightly", SizeBytes: gib / 5, Origin: "other"}
	fixtures := []lvFixture{
		{Name: "data", SizeBytes: gib},
		{Name: "other", SizeBytes: 4 * gib},
		impostor,
	}
	snapID := common.SnapshotID("data" + snapSeparator + "nightly")

	t.Run("delete refuses it", func(t *testing.T) {
		runner := newFakeRunner().withLVs(fixtures...)
		p := newTestProvider(t, runner)

		if err := p.DeleteSnapshot(context.Background(), snapID); !errors.Is(err, common.ErrSnapshotNotFound) {
			t.Fatalf("DeleteSnapshot = %v, want ErrSnapshotNotFound", err)
		}
		runner.mustNotRun(t, "lvremove")
	})

	t.Run("restore refuses it", func(t *testing.T) {
		runner := newFakeRunner().withLVs(fixtures...)
		p := newTestProvider(t, runner)

		_, err := p.Provision(context.Background(), common.VolumeSpec{
			Name:             "restored",
			SizeBytes:        4 * gib,
			SourceSnapshotID: snapID,
		})
		if !errors.Is(err, common.ErrSnapshotNotFound) {
			t.Fatalf("Provision = %v, want ErrSnapshotNotFound", err)
		}
		runner.mustNotRun(t, "lvcreate")
		runner.mustNotRun(t, "dd")
	})

	t.Run("a doubled separator is not ours either", func(t *testing.T) {
		// splitSnapshotID cuts at the FIRST separator, so this parses with
		// owner "data" — but its second half holds an underscore that
		// validateName refuses, so every method that could act on it would
		// reject the ID that ListSnapshots handed out.
		runner := newFakeRunner().withLVs(
			lvFixture{Name: "data", SizeBytes: gib},
			lvFixture{Name: "data" + snapSeparator + "daily" + snapSeparator + "manual", SizeBytes: gib / 5, Origin: "data"},
		)
		p := newTestProvider(t, runner)

		snaps, err := p.ListSnapshots(context.Background(), "data")
		if err != nil {
			t.Fatalf("ListSnapshots: %v", err)
		}
		if len(snaps) != 0 {
			t.Fatalf("ListSnapshots = %v, want none: none of these can be acted on", snaps)
		}
	})

	t.Run("list refuses it", func(t *testing.T) {
		runner := newFakeRunner().withLVs(fixtures...)
		p := newTestProvider(t, runner)

		snaps, err := p.ListSnapshots(context.Background(), "data")
		if err != nil {
			t.Fatalf("ListSnapshots: %v", err)
		}
		if len(snaps) != 0 {
			t.Fatalf("ListSnapshots = %v, want none", snaps)
		}
	})
}

func TestDeleteSnapshotRemoves(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	p := newTestProvider(t, runner)

	if err := p.DeleteSnapshot(context.Background(), common.SnapshotID("data"+snapSeparator+"nightly")); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	assertLine(t, runner, "lvremove --force vg0/data_snap_nightly")
}

// --- Delete ----------------------------------------------------------------

func TestDeleteNotFound(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	if err := p.Delete(context.Background(), "data"); !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("Delete = %v, want ErrNotFound", err)
	}
}

func TestDeleteTearsDownFirst(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{
			"/dev/vg0/data":           fsTypeLUKS,
			"/dev/mapper/bs-vg0_data": "ext4",
		}).
		withOpenMappings("bs-vg0_data").
		withMounts(map[string][]string{"/dev/mapper/bs-vg0_data": {"/mnt/data"}})
	p := newTestProvider(t, runner, withKey)

	if err := p.Delete(context.Background(), "data"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if got := runner.unmountCalls(); len(got) != 1 || got[0] != "/mnt/data" {
		t.Fatalf("unmounted %v, want [/mnt/data]", got)
	}
	lines := runner.lines()
	closeAt, removeAt := -1, -1
	for i, line := range lines {
		switch line {
		case "cryptsetup close bs-vg0_data":
			closeAt = i
		case "lvremove --force vg0/data":
			removeAt = i
		}
	}
	if closeAt < 0 || removeAt < 0 {
		t.Fatalf("missing the lock or the removal:\n  %s", strings.Join(lines, "\n  "))
	}
	if closeAt > removeAt {
		t.Errorf("the volume was removed before its mapping was closed:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestDeleteDoesNotWipeByDefault records the default: LVM's own behavior, with
// no zero-fill imposed on every deletion.
func TestDeleteDoesNotWipeByDefault(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner)

	if err := p.Delete(context.Background(), "data"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	runner.mustNotRun(t, "blkdiscard")
	assertLine(t, runner, "lvremove --force vg0/data")
}

// TestDeleteWipesWhenAsked covers the option that closes LVM's data remanence:
// a deleted volume's extents go back to the free pool holding whatever was
// written to them, and lvcreate clears only the first few kilobytes of the
// volume that gets them next.
func TestDeleteWipesWhenAsked(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	p := newTestProvider(t, runner, func(o *Options) { o.WipeOnDelete = true })

	if err := p.Delete(context.Background(), "data"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	lines := runner.lines()
	wipeAt, removeAt := -1, -1
	for i, line := range lines {
		switch line {
		case "blkdiscard --zeroout /dev/vg0/data":
			wipeAt = i
		case "lvremove --force vg0/data":
			removeAt = i
		}
	}
	if wipeAt < 0 {
		t.Fatalf("expected a blkdiscard; got:\n  %s", strings.Join(lines, "\n  "))
	}
	if removeAt < wipeAt {
		t.Errorf("the volume was removed before it was wiped:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestDeleteWipesTheContainerNotTheMapping checks that an encrypted volume is
// zeroed at the logical volume. The ciphertext is what stays behind in the freed
// extents, so overwriting the plaintext mapping would wipe the wrong thing —
// and by then the mapping is closed anyway.
func TestDeleteWipesTheContainerNotTheMapping(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey, func(o *Options) { o.WipeOnDelete = true })

	if err := p.Delete(context.Background(), "data"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertLine(t, runner, "blkdiscard --zeroout /dev/vg0/data")
	assertNoLine(t, runner, "blkdiscard --zeroout /dev/mapper/bs-vg0_data")
}

// TestDeleteRefusesAVolumeWithSnapshots is the contract: Delete does not
// cascade. lvremove would take the snapshots with it — they are copy-on-write
// areas over an origin that cannot outlive it — and losing a restore point as
// a side effect of removing something else is the wrong default for a stack
// whose volumes are the ones people restore from.
func TestDeleteRefusesAVolumeWithSnapshots(t *testing.T) {
	for _, wipe := range []bool{false, true} {
		name := "without wipe"
		if wipe {
			name = "with wipe"
		}
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().withLVs(
				lvFixture{Name: "data", SizeBytes: gib},
				lvFixture{Name: "data" + snapSeparator + "nightly", SizeBytes: gib / 5, Origin: "data"},
				lvFixture{Name: "data" + snapSeparator + "weekly", SizeBytes: gib / 5, Origin: "data"},
			)
			p := newTestProvider(t, runner, func(o *Options) { o.WipeOnDelete = wipe })

			err := p.Delete(context.Background(), "data")
			if !errors.Is(err, common.ErrHasSnapshots) {
				t.Fatalf("Delete = %v, want ErrHasSnapshots", err)
			}
			// The caller has to know WHICH snapshots are in the way, or the
			// error tells it to go looking.
			for _, want := range []string{"data_snap_nightly", "data_snap_weekly"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
			// Nothing was destroyed, and nothing was torn down on the way to
			// refusing: the volume is exactly as the caller left it.
			runner.mustNotRun(t, "lvremove")
			runner.mustNotRun(t, "blkdiscard")
			runner.mustNotRun(t, "umount")
			runner.mustNotRun(t, "cryptsetup")
		})
	}
}

// TestDeleteProceedsOnceSnapshotsAreGone checks the other half: the refusal is
// about snapshots of THIS volume, and clearing them lets the delete through.
func TestDeleteProceedsOnceSnapshotsAreGone(t *testing.T) {
	runner := newFakeRunner().withLVs(
		lvFixture{Name: "data", SizeBytes: gib},
		// A snapshot of a different origin is not this volume's business.
		lvFixture{Name: "other" + snapSeparator + "nightly", SizeBytes: gib / 5, Origin: "other"},
	)
	p := newTestProvider(t, runner, func(o *Options) { o.WipeOnDelete = true })

	if err := p.Delete(context.Background(), "data"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertLine(t, runner, "blkdiscard --zeroout /dev/vg0/data")
	assertLine(t, runner, "lvremove --force vg0/data")
	// Another volume's snapshot is untouched.
	assertNoLine(t, runner, "lvremove --force vg0/other_snap_nightly")
}

// TestDeleteStopsWhenAWipeFails keeps a volume whose contents could not be
// destroyed from being released back to the free pool regardless.
func TestDeleteStopsWhenAWipeFails(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	runner.fail("blkdiscard", 1, "operation not supported")
	p := newTestProvider(t, runner, func(o *Options) { o.WipeOnDelete = true })

	if err := p.Delete(context.Background(), "data"); err == nil {
		t.Fatal("Delete succeeded despite a failing wipe")
	}
	runner.mustNotRun(t, "lvremove")
}

// TestFailedWipeLeavesTheVolumeAsItFoundIt covers the state a failed wiping
// Delete leaves behind. The wipe has to activate the volume to have a device to
// write to, and blkdiscard is exactly the step that fails on a host not
// supporting it — so without undoing that activation, a volume the caller left
// available comes back attached after an operation the caller saw fail.
func TestFailedWipeLeavesTheVolumeAsItFoundIt(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false})
	runner.fail("blkdiscard", 1, "operation not supported")
	p := newTestProvider(t, runner, func(o *Options) { o.WipeOnDelete = true })

	if err := p.Delete(context.Background(), "data"); err == nil {
		t.Fatal("Delete succeeded despite a failing wipe")
	}
	assertLine(t, runner, "lvchange --activate n --yes vg0/data")
}

// TestFailedWipeLeavesAnAttachedVolumeAttached is the other half: a volume that
// was already active belongs to whoever attached it, and a failed delete must
// not detach it either.
func TestFailedWipeLeavesAnAttachedVolumeAttached(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	runner.fail("blkdiscard", 1, "operation not supported")
	p := newTestProvider(t, runner, func(o *Options) { o.WipeOnDelete = true })

	if err := p.Delete(context.Background(), "data"); err == nil {
		t.Fatal("Delete succeeded despite a failing wipe")
	}
	assertNoLine(t, runner, "lvchange --activate n --yes vg0/data")
}

// TestProvisionRejectsNegativeReplicas separates malformed from unsupported.
// VolumeSpec.Replicas counts upward from the 0-or-1 non-replicated request, so
// a negative count is not a number of replicas any backend could serve — it is
// a bad argument, and provisioning a volume for it would serve a request nobody
// made.
func TestProvisionRejectsNegativeReplicas(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, Replicas: -1})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Provision = %v, want ErrInvalidArgument", err)
	}
	if errors.Is(err, common.ErrUnsupported) {
		t.Error("a negative replica count was reported as unsupported rather than malformed")
	}
	runner.mustNotRun(t, "lvcreate")
}

// TestFailedRemovalAfterAWipeRestoresActivation covers the last step of a
// wiping Delete. The wipe activates the volume to have a device to write to and
// leaves it that way, because the removal is about to happen; when the removal
// is what fails, that activation is left over from an operation the caller
// watched fail.
func TestFailedRemovalAfterAWipeRestoresActivation(t *testing.T) {
	runner := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false})
	runner.fail("lvremove", 5, "logical volume in use")
	p := newTestProvider(t, runner, func(o *Options) { o.WipeOnDelete = true })

	if err := p.Delete(context.Background(), "data"); err == nil {
		t.Fatal("Delete succeeded despite a failing lvremove")
	}
	assertLine(t, runner, "blkdiscard --zeroout /dev/vg0/data")
	assertLine(t, runner, "lvchange --activate n --yes vg0/data")
}

// TestFailedRemovalLeavesAnAttachedVolumeAttached is the other half: a volume
// that was already active belongs to whoever attached it.
func TestFailedRemovalLeavesAnAttachedVolumeAttached(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	runner.fail("lvremove", 5, "logical volume in use")
	p := newTestProvider(t, runner, func(o *Options) { o.WipeOnDelete = true })

	if err := p.Delete(context.Background(), "data"); err == nil {
		t.Fatal("Delete succeeded despite a failing lvremove")
	}
	assertNoLine(t, runner, "lvchange --activate n --yes vg0/data")
}

// TestDeleteFailsClosedOnAnUnreadableMountTable is the hazard the mount-table
// rework exists for. Delete acts on "nothing is mounted" by running a forced
// lvremove, so a findmnt failure that read as "nothing is mounted" would take a
// live filesystem's volume out from under it. Every failure mode has to stop
// the delete instead.
func TestDeleteFailsClosedOnAnUnreadableMountTable(t *testing.T) {
	cases := map[string]responder{
		"findmnt missing": func([]string, []byte) ([]byte, error) {
			return nil, errors.New("exec: findmnt: executable file not found in $PATH")
		},
		"exit 1": func(args []string, _ []byte) ([]byte, error) {
			return nil, &ExitError{Name: "findmnt", Args: args, Code: 1}
		},
		"unparseable": func([]string, []byte) ([]byte, error) {
			return []byte("not json"), nil
		},
	}

	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
				withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
			runner.on("findmnt", handler)
			p := newTestProvider(t, runner)

			if err := p.Delete(context.Background(), "data"); err == nil {
				t.Fatal("Delete succeeded over a mount table it could not read")
			}
			runner.mustNotRun(t, "lvremove")
		})
	}
}

// TestUnmountFailsClosedOnAnUnreadableMountTable covers the same rule on the
// convergence check: "not mounted there" has to mean a mount table that was
// read and did not hold this volume, never a mount table that could not be read.
func TestUnmountFailsClosedOnAnUnreadableMountTable(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	runner.on("findmnt", func(args []string, _ []byte) ([]byte, error) {
		return nil, &ExitError{Name: "findmnt", Args: args, Code: 1}
	})
	p := newTestProvider(t, runner)

	if err := p.Unmount(context.Background(), "data", "/mnt/data"); err == nil {
		t.Fatal("Unmount reported convergence over a mount table it could not read")
	}
}

// TestResizeFailsClosedOnAnUnreadableMountTable covers the XFS branch, which
// decides whether the filesystem can be grown at all by asking where it is
// mounted.
func TestResizeFailsClosedOnAnUnreadableMountTable(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "xfs"})
	runner.on("findmnt", func(args []string, _ []byte) ([]byte, error) {
		return nil, &ExitError{Name: "findmnt", Args: args, Code: 1}
	})
	p := newTestProvider(t, runner)

	if err := p.Resize(context.Background(), "data", 2*gib); err == nil {
		t.Fatal("Resize skipped the filesystem growth over a mount table it could not read")
	}
}

// TestMountDiscoveryIgnoresOtherVolumes checks the local filter: the provider
// now reads the WHOLE mount table, so it has to pick out its own device rather
// than acting on every row it finds.
func TestMountDiscoveryIgnoresOtherVolumes(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/other": {"/mnt/other"}})
	p := newTestProvider(t, runner)

	status, err := p.Status(context.Background(), "data")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != common.VolumeStateAttached {
		t.Errorf("State = %q, want attached: another volume's mount is not ours", status.State)
	}
}

// TestDeleteUnmountsNestedMountsChildFirst covers one volume mounted at both a
// path and a path inside it. The kernel refuses to unmount the parent while the
// child is still there, so an arbitrary order makes Delete fail to tear down
// mounts it is supposed to clear itself.
func TestDeleteUnmountsNestedMountsChildFirst(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		withMounts(map[string][]string{
			"/dev/vg0/data": {"/mnt/data", "/mnt/data/sub", "/mnt/data/sub/deeper"},
		})
	p := newTestProvider(t, runner)

	if err := p.Delete(context.Background(), "data"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	order := runner.unmountCalls()
	want := []string{"/mnt/data/sub/deeper", "/mnt/data/sub", "/mnt/data"}
	if len(order) != len(want) {
		t.Fatalf("unmounted %v, want all three", order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("unmount order = %v, want deepest first %v", order, want)
		}
	}
}

func TestDeepestFirstIsStable(t *testing.T) {
	got := deepestFirst([]string{"/mnt/b", "/mnt/a", "/mnt/a/deep"})
	want := []string{"/mnt/a/deep", "/mnt/a", "/mnt/b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("deepestFirst = %v, want %v", got, want)
		}
	}
}

// TestDeleteStopsWhenUnmountFails keeps a busy filesystem from having its
// backing volume removed out from under it.
func TestDeleteStopsWhenUnmountFails(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}})
	runner.failUnmount(errors.New("target is busy"))
	p := newTestProvider(t, runner)

	if err := p.Delete(context.Background(), "data"); err == nil {
		t.Fatal("Delete succeeded, want the umount failure")
	}
	runner.mustNotRun(t, "lvremove")
}

// --- Status ----------------------------------------------------------------

func TestStatusNotFound(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner)

	if _, err := p.Status(context.Background(), "data"); !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("Status = %v, want ErrNotFound", err)
	}
}

func TestStatusProgression(t *testing.T) {
	cases := []struct {
		name      string
		runner    *fakeRunner
		wantState common.VolumeState
		wantNodes int
	}{
		{
			name:      "available",
			runner:    newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}),
			wantState: common.VolumeStateAvailable,
		},
		{
			name: "attached",
			runner: newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
				withBlkid(map[string]string{"/dev/vg0/data": "ext4"}),
			wantState: common.VolumeStateAttached,
			wantNodes: 1,
		},
		{
			name: "mounted",
			runner: newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
				withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
				withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}}),
			wantState: common.VolumeStateMounted,
			wantNodes: 1,
		},
		{
			name: "locked encryption reads as available",
			runner: newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
				withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}),
			wantState: common.VolumeStateAvailable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t, tc.runner, withKey)

			status, err := p.Status(context.Background(), "data")
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if status.State != tc.wantState {
				t.Errorf("State = %q, want %q", status.State, tc.wantState)
			}
			if status.ID != "data" {
				t.Errorf("ID = %q, want data", status.ID)
			}
			if status.SizeBytes != gib {
				t.Errorf("SizeBytes = %d, want %d", status.SizeBytes, gib)
			}
			if len(status.AttachedNodes) != tc.wantNodes {
				t.Errorf("AttachedNodes = %v, want %d entries", status.AttachedNodes, tc.wantNodes)
			}
		})
	}
}

// --- Construction ----------------------------------------------------------

func TestNewRequiresKeyProviderWhenEncrypted(t *testing.T) {
	_, err := New(Options{VolumeGroup: "vg0", Encrypted: true, Runner: newFakeRunner()})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New = %v, want common.ErrInvalidArgument", err)
	}
}

func TestNewRejectsOutOfRangeCoWPercent(t *testing.T) {
	for _, pct := range []int{-1, 101, 1000} {
		_, err := New(Options{VolumeGroup: "vg0", SnapshotCoWPercent: pct, Runner: newFakeRunner()})
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("New(SnapshotCoWPercent=%d) = %v, want common.ErrInvalidArgument", pct, err)
		}
	}
}

func TestNewDefaultsNodeIDToTheHostname(t *testing.T) {
	p, err := New(Options{VolumeGroup: "vg0", Runner: newFakeRunner()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.NodeID() == "" {
		t.Error("NodeID is empty, want the system hostname")
	}
}

// TestListLVsSurfacesAnLvsFailure checks that a broken volume group is an error
// rather than an empty listing, which every method would otherwise read as
// ErrNotFound.
func TestListLVsSurfacesAnLvsFailure(t *testing.T) {
	runner := newFakeRunner()
	runner.fail("lvs", 5, "Volume group \"vg0\" not found")
	p := newTestProvider(t, runner)

	_, err := p.Status(context.Background(), "data")
	if err == nil {
		t.Fatal("Status succeeded over a failing lvs")
	}
	if errors.Is(err, common.ErrNotFound) {
		t.Fatalf("a missing volume group was reported as a missing volume: %v", err)
	}
}
