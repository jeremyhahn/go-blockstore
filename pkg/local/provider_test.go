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

	assertLine(t, runner, "luks format /dev/vg0/data")
	assertLine(t, runner, "luks open /dev/vg0/data bs-vg0_data")
	// The filesystem goes on the plaintext mapping, never on the container.
	assertLine(t, runner, "mkfs.ext4 -F /dev/mapper/bs-vg0_data")
	assertLine(t, runner, "luks close bs-vg0_data")

	format := runner.mustFind(t, luksBinary)
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
		case "luks close bs-vg0_data":
			closeAt = i
		case "lvremove --force vg0/data":
			removeAt = i
		}
	}
	if closeAt < 0 || removeAt < 0 {
		t.Fatalf("expected both a LUKS close and an lvremove; got:\n  %s", strings.Join(lines, "\n  "))
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
	runner.on(luksBinary, func(args []string, _ []byte) ([]byte, error) {
		switch {
		case len(args) > 0 && args[0] == "mapping":
			// Ours, and still open — which is what makes the rollback try again.
			return []byte(defaultBackingFor("bs-vg0_data")), nil
		case len(args) > 0 && args[0] == "identity":
			return []byte(fakeDeviceIdentity(args[len(args)-1])), nil
		case len(args) > 0 && args[0] == "close":
			closeAttempts++
			if closeAttempts == 1 {
				return nil, errors.New("device-mapper remove: device or resource busy")
			}
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"})
	if err == nil {
		t.Fatal("Provision succeeded, want the LUKS close failure")
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
	// go-luks2 really fails when a name is in use — and the rollback then
	// reaches for that name.
	runner := newFakeRunner()
	runner.on(luksBinary, func(args []string, _ []byte) ([]byte, error) {
		switch {
		case len(args) > 0 && args[0] == "mapping":
			return []byte("/dev/mapper/vg0-somebodyelse"), nil
		case len(args) > 0 && args[0] == "identity":
			return []byte(fakeDeviceIdentity(args[len(args)-1])), nil
		case len(args) > 0 && args[0] == "open":
			return nil, errors.New("device mapper 'bs-vg0_data' already exists")
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib, FSType: "ext4"})
	if err == nil {
		t.Fatal("Provision succeeded, want the failed unlock")
	}
	assertNoLine(t, runner, "luks close bs-vg0_data")
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
	assertLine(t, runner, "luks close bs-vg0_data")
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

// TestEncryptedProviderReencryptsAPlaintextRestore is the path that replaced a
// refusal. A provider configured to encrypt no longer turns away a plaintext
// snapshot; it formats the destination and copies the image THROUGH the
// plaintext mapping, so dm-crypt encrypts it in flight.
//
// The assertion that matters is the dd destination. Copying to /dev/vg0/restored
// instead would write the plaintext straight onto the extents, which is the
// silent downgrade the old refusal existed to prevent — and it would look
// identical from every other angle.
func TestEncryptedProviderReencryptsAPlaintextRestore(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	// The snapshot device carries a filesystem, not a LUKS container.
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": "ext4"})
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Sized for the caller's capacity plus the header the provider is about to
	// write, so the mapping holds the gibibyte that was asked for.
	assertLine(t, runner, "lvcreate --yes --name restored --size 1090519040b --setautoactivation n vg0")
	assertLine(t, runner, "luks format /dev/vg0/restored")
	assertLine(t, runner, "luks open /dev/vg0/restored bs-vg0_restored")
	// Through the mapping. This is the whole point.
	assertLine(t, runner, "dd if=/dev/vg0/data_snap_nightly of=/dev/mapper/bs-vg0_restored bs=4M conv=fsync status=none")
	assertNoLine(t, runner, "dd if=/dev/vg0/data_snap_nightly of=/dev/vg0/restored bs=4M conv=fsync status=none")
	// And left locked, the way Attach expects to find a volume.
	assertLine(t, runner, "luks close bs-vg0_restored")
	assertKeyNeverOnArgv(t, runner)
}

// TestReencryptingRestoreRemovesThePartialVolumeOnFailure covers the failure
// path of the same operation. Everything written to the volume by then is
// ciphertext, so removing it is safe — but it has to actually be removed, and
// the mapping closed first, or lvremove refuses it.
func TestReencryptingRestoreRemovesThePartialVolumeOnFailure(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": "ext4"})
	runner.withOpenMappings("bs-vg0_restored")
	runner.fail("dd", 1, "dd: writing: No space left on device")
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err == nil {
		t.Fatal("Provision succeeded over a failed copy")
	}
	assertLine(t, runner, "luks close bs-vg0_restored")
	assertLine(t, runner, "lvremove --force vg0/restored")
}

// TestEncryptedProviderRestoresAnEncryptedSnapshot is the byte-copy case: the
// image is already a LUKS container, and it is copied as it stands.
//
// Reformatting it would be destructive rather than merely different — a fresh
// header carries a fresh master key, and the ciphertext copied over it was
// encrypted under the old one — so the absence of a luksFormat here is the
// assertion, not an accident of how the fake is wired.
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
	// Onto the logical volume, header and all — not through a mapping.
	assertLine(t, runner, "dd if=/dev/vg0/data_snap_nightly of=/dev/vg0/restored bs=4M conv=fsync status=none")
	assertNoLine(t, runner, "dd if=/dev/vg0/data_snap_nightly of=/dev/mapper/bs-vg0_restored bs=4M conv=fsync status=none")

	// The image is copied as it stands; it is not reformatted under a new
	// header, and no mapping is opened over it.
	for _, line := range runner.lines() {
		if strings.HasPrefix(line, "luks format ") {
			t.Errorf("the restore reformatted the copied container: %q", line)
		}
		if strings.HasPrefix(line, "luks open ") {
			t.Errorf("the restore unlocked the copied container: %q", line)
		}
	}

	// The volume is sized for the caller's capacity plus the header it
	// inherits from the source.
	assertLine(t, runner, "lvcreate --yes --name restored --size 1090519040b --setautoactivation n vg0")
	// And the key it will need was checked against the source's header before
	// anything was created.
	assertLine(t, runner, "luks test-key /dev/vg0/data_snap_nightly")
	assertKeyNeverOnArgv(t, runner)
}

// TestEncryptedRestoreRefusesAKeyThatWouldNotOpenIt is the check that keeps this
// path from producing a volume nobody can read. KeyProvider is per volume, and
// a restored volume opens with its SOURCE's passphrase, so an implementation
// answering for the new name with a different key would hand back a volume that
// restores cleanly and fails at its first Attach.
func TestEncryptedRestoreRefusesAKeyThatWouldNotOpenIt(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": fsTypeLUKS})
	runner.withWrongKeyFor("/dev/vg0/data_snap_nightly")
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Provision = %v, want ErrInvalidArgument", err)
	}
	// Refused before anything was created, so there is no unreadable volume to
	// clean up and nothing was copied.
	runner.mustNotRun(t, "lvcreate")
	runner.mustNotRun(t, "dd")
}

// TestEncryptedRestoreRefusesWithoutAKeyProvider is the same refusal for a
// provider that has no key at all: the restore would produce a container this
// provider could never open, and could not even check.
func TestEncryptedRestoreRefusesWithoutAKeyProvider(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": fsTypeLUKS})
	p := newTestProvider(t, runner)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("Provision = %v, want ErrInvalidArgument", err)
	}
	runner.mustNotRun(t, "lvcreate")
	runner.mustNotRun(t, "dd")
}

// TestEncryptedRestoreSizesFromTheSourcesOwnHeader pins the half of the sizing
// rule that a constant cannot express. The restored volume inherits the
// SOURCE's header, so the capacity added on top is that header's size — not the
// 16 MiB this package formats with.
func TestEncryptedRestoreSizesFromTheSourcesOwnHeader(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": fsTypeLUKS})
	runner.withLUKSHeader("/dev/vg0/data_snap_nightly", 4<<20)
	p := newTestProvider(t, runner, encrypted)

	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "lvcreate --yes --name restored --size 1077936128b --setautoactivation n vg0")
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
	// Nothing about a plain volume should reach the LUKS backend at all.
	runner.mustNotRun(t, luksBinary)
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
	assertLine(t, runner, "luks open /dev/vg0/data bs-vg0_data")
	assertKeyNeverOnArgv(t, runner)
}

// TestAttachIsIdempotentOverAnUnlockedVolume checks that re-attaching does not
// try to unlock a container that is already open, which go-luks2 rejects.
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
	assertNoLine(t, runner, "luks open /dev/vg0/data bs-vg0_data")
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
	runner.on(luksBinary, func(args []string, _ []byte) ([]byte, error) {
		if len(args) > 0 && args[0] == "open" {
			return nil, errors.New("no key available with this passphrase")
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, withKey)

	if _, err := p.Attach(context.Background(), "data", "node-a"); err == nil {
		t.Fatal("Attach succeeded despite a failing unlock")
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
	runner.on(luksBinary, func(args []string, _ []byte) ([]byte, error) {
		if len(args) > 0 && args[0] == "open" {
			return nil, errors.New("no key available with this passphrase")
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, withKey)

	if _, err := p.Attach(context.Background(), "data", "node-a"); err == nil {
		t.Fatal("Attach succeeded despite a failing unlock")
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
	runner.mustNotRun(t, luksBinary)
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
	assertLine(t, runner, "luks close bs-vg0_data")
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
		// newSize plus the volume's LUKS header, so the PLAINTEXT mapping ends
		// up the 2 GiB that was asked for rather than 16 MiB short of it.
		"lvextend --size 2164260864b vg0/data",
		"lvchange --activate y --yes vg0/data",
		"luks open /dev/vg0/data bs-vg0_data",
		"resize2fs /dev/mapper/bs-vg0_data",
		"luks close bs-vg0_data",
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

	// The passphrase reached the LUKS backend as a borrowed slice, as
	// everywhere else — never as an argument.
	assertKeyNeverOnArgv(t, runner)
}

// TestDetachedEncryptedResizeDoesNotResizeTheMapping records a deliberate
// omission. The mapping is opened AFTER the logical volume grew, and the
// container's data segment is "dynamic", so whoever opens it sizes the mapping
// to the device it finds — measured on cryptsetup 2.7.0, re-opening a grown
// volume took the mapping from 50331648 to 117440512 bytes with no resize asked
// for, and go-luks2 computes the same length the same way. Issuing a resize
// would borrow the passphrase a second time to achieve nothing, and every
// borrow is an exposure.
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
	assertNoLine(t, runner, "luks resize /dev/vg0/data bs-vg0_data")
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
	// The block device still grew, by the requested capacity plus the header;
	// it is the filesystem that could not be reached.
	assertLine(t, runner, "lvextend --size 2164260864b vg0/data")
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

// TestResizeRefusesAnAttachedEncryptedVolumeWithoutTouchingTheMapping is the
// regression test for the close-then-hope resize.
//
// Growing a dm-crypt mapping in place needs the device-mapper table reloaded
// underneath the live device, which needs the container's master key.
// go-luks2 v0.1.8-alpha exposes neither, so the only way to make the mapping
// bigger through it is to REMOVE the mapping and unlock again — and if the
// second half fails, the caller is left with no plaintext device at all. It is
// not hypothetical: a KeyProvider mis-rotated since the volume was attached
// makes the teardown succeed and the rebuild fail, which is exactly what this
// test stages. The previous cryptsetup implementation resized the live mapping
// and had no such failure mode, so this would be a regression introduced by the
// migration.
//
// So the operation is refused instead, and refused BEFORE anything moves: no
// lvextend, and nothing at all issued against the mapping. A caller that means
// it detaches and resizes again, which is the path
// TestResizeGrowsADetachedEncryptedFilesystem covers and which cannot lose a
// mapping because there is none to lose.
func TestResizeRefusesAnAttachedEncryptedVolumeWithoutTouchingTheMapping(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{
			"/dev/vg0/data":           fsTypeLUKS,
			"/dev/mapper/bs-vg0_data": "ext4",
		}).
		withOpenMappings("bs-vg0_data")
	// The key has been rotated out from under the attachment: whatever the
	// provider holds now will not re-open the container it is already using.
	runner.on(luksBinary, func(args []string, stdin []byte) ([]byte, error) {
		if len(args) > 0 && args[0] == "open" {
			return nil, errors.New("failed to unlock any keyslot: incorrect passphrase")
		}
		return runner.luks(args, stdin)
	})
	p := newTestProvider(t, runner, withKey)

	err := p.Resize(context.Background(), "data", 2*gib)
	if err == nil {
		t.Fatal("Resize grew an attached encrypted volume; it cannot do that without risking the mapping")
	}
	if !errors.Is(err, ErrResizeWhileAttached) {
		t.Errorf("Resize = %v, want ErrResizeWhileAttached so a caller knows to detach and retry", err)
	}
	if !strings.Contains(err.Error(), "Detach") {
		t.Errorf("error = %q, want it to name the remedy", err)
	}

	// THE assertion: the mapping the caller is using is untouched. Not closed,
	// not re-opened, not resized.
	for _, forbidden := range []string{
		"luks close bs-vg0_data",
		"luks open /dev/vg0/data bs-vg0_data",
		"luks resize /dev/vg0/data bs-vg0_data",
	} {
		assertNoLine(t, runner, forbidden)
	}
	open, openErr := p.luksIsOpen(context.Background(), "data")
	if openErr != nil || !open {
		t.Fatalf("the mapping is gone after a failed Resize: luksIsOpen = (%v, %v)", open, openErr)
	}

	// And nothing partial was left behind either: the refusal comes before the
	// logical volume is grown, so a re-run after a Detach starts from a clean
	// state rather than from a volume whose backing device already moved.
	runner.mustNotRun(t, "lvextend")
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
		case "luks close bs-vg0_data":
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
			runner.mustNotRun(t, luksBinary)
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

		// wantSize is USABLE capacity, which for an encrypted volume is the
		// logical volume less its header.
		wantSize int64
	}{
		{
			// A detached PLAIN volume: no tag, nothing encrypted, backing and
			// usable are the same number.
			name:      "available",
			runner:    newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}),
			wantState: common.VolumeStateAvailable,
			wantSize:  gib,
		},
		{
			// THE RULING: a detached ENCRYPTED volume reports usable capacity.
			// It cannot be probed — an inactive logical volume has no device
			// node — so the tag is what carries the fact into a state where
			// discovery cannot run, and Status still takes no lock and
			// activates nothing.
			name: "detached encryption reports usable capacity from its tag",
			runner: newFakeRunner().withLVs(lvFixture{
				Name: "data", SizeBytes: gib, Active: false, Tags: []string{encryptedTagFor(luksHeaderBytes)},
			}),
			wantState: common.VolumeStateAvailable,
			wantSize:  gib - luksHeaderBytes,
		},
		{
			// A volume provisioned before the tag existed. It reports the
			// backing size, which is the old deviation now scoped to legacy
			// volumes — and its next Attach tags it, so this is self-limiting.
			name:      "detached and untagged falls back to the backing size",
			runner:    newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}),
			wantState: common.VolumeStateAvailable,
			wantSize:  gib,
		},
		{
			name: "attached",
			runner: newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
				withBlkid(map[string]string{"/dev/vg0/data": "ext4"}),
			wantState: common.VolumeStateAttached,
			wantNodes: 1,
			wantSize:  gib,
		},
		{
			name: "mounted",
			runner: newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
				withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
				withMounts(map[string][]string{"/dev/vg0/data": {"/mnt/data"}}),
			wantState: common.VolumeStateMounted,
			wantNodes: 1,
			wantSize:  gib,
		},
		{
			// Locked, but ACTIVE — so it can be probed, and the header it is
			// known to carry comes off the reported capacity even though there
			// is no mapping to measure.
			name: "locked encryption reads as available",
			runner: newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
				withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}),
			wantState: common.VolumeStateAvailable,
			wantSize:  gib - luksHeaderBytes,
		},
		{
			// Unlocked and mounted, and encrypted: the same subtraction, with
			// the volume all the way up.
			name: "unlocked encryption reports usable capacity",
			runner: newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
				withBlkid(map[string]string{
					"/dev/vg0/data":           fsTypeLUKS,
					"/dev/mapper/bs-vg0_data": "ext4",
				}).
				withOpenMappings("bs-vg0_data").
				withMounts(map[string][]string{"/dev/mapper/bs-vg0_data": {"/mnt/data"}}),
			wantState: common.VolumeStateMounted,
			wantNodes: 1,
			wantSize:  gib - luksHeaderBytes,
		},
		{
			// A volume restored from somebody else's snapshot carries THEIR
			// header, so the figure subtracted is read from the header rather
			// than assumed to be this package's.
			name: "a foreign header is measured, not assumed",
			runner: newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
				withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
				withLUKSHeader("/dev/vg0/data", 4<<20),
			wantState: common.VolumeStateAvailable,
			wantSize:  gib - (4 << 20),
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
			if status.SizeBytes != tc.wantSize {
				t.Errorf("SizeBytes = %d, want %d", status.SizeBytes, tc.wantSize)
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
	// PreflightOff because this test is about the node ID default, and the
	// provider leaves the Mounter and the LUKS backend at their real
	// implementations — so with the checks on, the result would depend on
	// whether the machine running the test can call mount(2).
	p, err := New(Options{VolumeGroup: "vg0", Runner: newFakeRunner(), Preflight: PreflightOff})
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

// --- Usable capacity -------------------------------------------------------
//
// VolumeSpec.SizeBytes is the capacity the CALLER CAN USE, and this provider
// puts its LUKS header on top of it rather than taking it out of the middle.
// These pin the arithmetic on every path that sizes a volume.

// TestProvisionEncryptedSizesForUsableCapacity is the headline of the rule: an
// encrypted volume asked for at a gibibyte gets a logical volume a header
// LARGER, so the plaintext mapping a caller eventually mounts holds the
// gibibyte it asked for. Sizing the logical volume at the bare request instead
// would hand back a mapping 16 MiB short, silently, and only the data would
// notice.
func TestProvisionEncryptedSizesForUsableCapacity(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner, encrypted)

	if _, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "lvcreate --yes --name data --size 1090519040b --setautoactivation n vg0")

	// A PLAIN volume is unchanged: usable and backing are the same thing when
	// there is no header, and a spurious addend here would be just as wrong.
	plain := newFakeRunner()
	pp := newTestProvider(t, plain)
	if _, err := pp.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, plain, "lvcreate --yes --name data --size 1073741824b --setautoactivation n vg0")
}

// TestProvisionRefusesASizeThatCannotCarryItsHeader is the overflow boundary the
// addend introduced. A signed overflow in Go wraps rather than trapping, so
// without the guard a size near the top of the range would reach lvcreate as a
// NEGATIVE byte count.
func TestProvisionRefusesASizeThatCannotCarryItsHeader(t *testing.T) {
	for name, size := range map[string]int64{
		"max":      math.MaxInt64,
		"one over": math.MaxInt64 - luksHeaderBytes + 1,
	} {
		runner := newFakeRunner()
		p := newTestProvider(t, runner, encrypted)

		_, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: size})
		if !errors.Is(err, common.ErrInvalidArgument) {
			t.Errorf("Provision(%s) = %v, want ErrInvalidArgument", name, err)
		}
		runner.mustNotRun(t, "lvcreate")
	}

	// The largest size that still fits its header is accepted, and reaches
	// lvcreate as a positive number.
	runner := newFakeRunner()
	p := newTestProvider(t, runner, encrypted)
	if _, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:      "data",
		SizeBytes: math.MaxInt64 - luksHeaderBytes,
	}); errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("Provision at the largest representable capacity = %v, want it attempted", err)
	}
	create := runner.mustFind(t, "lvcreate")
	for _, arg := range create.Args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.HasPrefix(arg, "-9") {
			t.Fatalf("lvcreate was handed a negative size: %q", create.line())
		}
	}

	// An UNENCRYPTED provider has no header to make room for, so the same size
	// is not near any boundary for it.
	plain := newFakeRunner()
	pp := newTestProvider(t, plain)
	if _, err := pp.Provision(context.Background(), common.VolumeSpec{
		Name:      "data",
		SizeBytes: math.MaxInt64,
	}); errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("Provision on a plain provider = %v, want it attempted", err)
	}
}

// TestResizeRefusesUnrepresentableEncryptedSizes is the same boundary on Resize,
// where it is LOWER than for a plain volume by exactly the header: the backing
// device has to hold the request plus the header and then round up.
func TestResizeRefusesUnrepresentableEncryptedSizes(t *testing.T) {
	const extent = 4 << 20
	limit := int64(math.MaxInt64) - (extent - 1) - luksHeaderBytes

	encryptedRunner := func() *fakeRunner {
		return newFakeRunner().
			withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
			withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	}

	runner := encryptedRunner()
	p := newTestProvider(t, runner, withKey)
	if err := p.Resize(context.Background(), "data", limit+1); !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("Resize one past the limit = %v, want ErrInvalidArgument", err)
	}
	runner.mustNotRun(t, "lvextend")

	// One byte lower is representable, and is a growth request rather than a
	// wrapped-around shrink.
	runner = encryptedRunner()
	p = newTestProvider(t, runner, withKey)
	if err := p.Resize(context.Background(), "data", limit); errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("Resize at the limit = %v, want it attempted", err)
	}
	if err := p.Resize(context.Background(), "data", limit); errors.Is(err, common.ErrUnsupported) {
		t.Errorf("Resize at the limit reported a growth request as an unsupported shrink")
	}

	// That size WOULD be representable on a plain volume, which is what makes
	// this a property of the volume rather than of the volume group.
	plain := newFakeRunner().withLVs(lvFixture{Name: "data", SizeBytes: gib})
	pp := newTestProvider(t, plain)
	if err := pp.Resize(context.Background(), "data", limit+1); errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("the same size on a plain volume = %v, want it attempted", err)
	}
}

// TestResizeGrowsAPreRulingEncryptedVolume is the migration case. A volume
// provisioned before SizeBytes meant usable capacity has a logical volume sized
// at the bare request, so its mapping is a header short. Asking for the size it
// was originally provisioned at has to GROW it into conformance rather than
// come back as a shrink.
func TestResizeGrowsAPreRulingEncryptedVolume(t *testing.T) {
	runner := newFakeRunner().
		// Exactly a gibibyte of backing: what the old rule created for a
		// gibibyte request, leaving only gib-16MiB usable.
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{
			"/dev/vg0/data":           fsTypeLUKS,
			"/dev/mapper/bs-vg0_data": "ext4",
		})
	// The container is locked. It is the arithmetic that is under test here,
	// and an unlocked one would be refused before reaching it — see
	// TestResizeRefusesAnAttachedEncryptedVolumeWithoutTouchingTheMapping.
	p := newTestProvider(t, runner, withKey)

	if err := p.Resize(context.Background(), "data", gib); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	assertLine(t, runner, "lvextend --size 1090519040b vg0/data")
}

// TestEncryptedRestoreThresholdIsUsableCapacity pins which units the "does it
// fit" check is in. The image includes the source's header and the request never
// does, so comparing the request against the raw image size would demand an
// extra header's worth of capacity and reject restores that fit exactly.
func TestEncryptedRestoreThresholdIsUsableCapacity(t *testing.T) {
	encryptedSnapshot := func() *fakeRunner {
		r := newFakeRunner().withLVs(snapshotFixtures()...)
		r.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": fsTypeLUKS})
		return r
	}

	// The image is a gibibyte of container, so its USABLE capacity is a
	// gibibyte less the header. Asking for exactly that is a fit.
	runner := encryptedSnapshot()
	p := newTestProvider(t, runner, encrypted)
	if _, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib - luksHeaderBytes,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	}); err != nil {
		t.Fatalf("restore at exactly the source's usable capacity: %v", err)
	}
	// And it produces a volume the size of the image, with nothing over.
	assertLine(t, runner, "lvcreate --yes --name restored --size 1073741824b --setautoactivation n vg0")
	runner.mustNotRun(t, "blkdiscard")

	// One byte less does not fit, and is refused before anything is created.
	runner = encryptedSnapshot()
	p = newTestProvider(t, runner, encrypted)
	_, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib - luksHeaderBytes - 1,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	})
	if !errors.Is(err, common.ErrUnsupported) {
		t.Fatalf("Provision = %v, want ErrUnsupported", err)
	}
	runner.mustNotRun(t, "lvcreate")
}

// TestRestoreZeroesTheExtentRoundingSlice is the stale-data path the addend
// opened up.
//
// An origin's size is a whole number of extents, so a restore into exactly the
// image size used to produce a volume with nothing past the image — which is
// why skipping the zeroing there was safe. A backing size is now a usable
// capacity with a header added to it and is extent-aligned only by luck, so on
// a volume group whose extents do not divide the header there IS a tail, and it
// arrives holding whatever the previous tenant of those extents wrote.
func TestRestoreZeroesTheExtentRoundingSlice(t *testing.T) {
	runner := newFakeRunner().
		withLVs(snapshotFixtures()...).
		// 32 MiB extents do not divide the 16 MiB header, so gib+16MiB rounds
		// up and leaves a slice past the image.
		withExtentSize(32 << 20)
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": "ext4"})
	p := newTestProvider(t, runner, encrypted)

	if _, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib, // exactly the image size: the case that used to skip
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// From the end of the image ON THE LOGICAL VOLUME, which is past the header.
	assertLine(t, runner, "blkdiscard --zeroout --offset 1090519040 /dev/vg0/restored")

	// On a volume group whose extents DO divide the header there is no slice,
	// and the zeroing is skipped as before.
	aligned := newFakeRunner().withLVs(snapshotFixtures()...)
	aligned.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": "ext4"})
	ap := newTestProvider(t, aligned, encrypted)
	if _, err := ap.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	aligned.mustNotRun(t, "blkdiscard")
}

// TestReencryptingRestoreZeroesPastTheHeader checks the offset itself. The image
// lands INSIDE the container, so the tail starts a header further along the
// logical volume than it would on a plaintext restore — and zeroing from the
// bare image size would leave the last header's worth of the previous tenant's
// data in place while looking like it had done the job.
func TestReencryptingRestoreZeroesPastTheHeader(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": "ext4"})
	p := newTestProvider(t, runner, encrypted)

	if _, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        2 * gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "blkdiscard --zeroout --offset 1090519040 /dev/vg0/restored")
	assertNoLine(t, runner, "blkdiscard --zeroout --offset 1073741824 /dev/vg0/restored")
}

// TestStatusSurvivesAVolumeMovingUnderIt covers the race Status invites by
// design. It holds no lock, so between the probe that identifies a LUKS
// container and the read of that container's header the volume can be detached
// or deleted by somebody else — and reading the header of a device that is no
// longer there fails.
//
// Before the header read existed, both races degraded quietly: blkid and the
// mapping lookup report a vanished device as "nothing here" rather than as a
// failure. Turning them into a hard error would make Status unreliable in
// exactly the concurrent use it exists for, so a failed read is re-checked
// against the volume group rather than believed on its own.
func TestStatusSurvivesAVolumeMovingUnderIt(t *testing.T) {
	active := []lvFixture{{Name: "data", SizeBytes: gib, Active: true}}

	t.Run("deleted underneath reports ErrNotFound", func(t *testing.T) {
		runner := newFakeRunner().
			withLVsThen(active, nil).
			withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
			withLUKSDumpFailure("/dev/vg0/data")
		p := newTestProvider(t, runner, withKey)

		_, err := p.Status(context.Background(), "data")
		if !errors.Is(err, common.ErrNotFound) {
			t.Fatalf("Status = %v, want ErrNotFound for a volume deleted mid-read", err)
		}
	})

	t.Run("detached underneath reports the backing size", func(t *testing.T) {
		detached := []lvFixture{{Name: "data", SizeBytes: gib, Active: false}}
		runner := newFakeRunner().
			withLVsThen(active, detached).
			withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
			withLUKSDumpFailure("/dev/vg0/data")
		p := newTestProvider(t, runner, withKey)

		status, err := p.Status(context.Background(), "data")
		if err != nil {
			t.Fatalf("Status failed over a volume detached mid-read: %v", err)
		}
		// The state a detached volume reports anyway, per the Status doc.
		if status.SizeBytes != gib {
			t.Errorf("SizeBytes = %d, want the backing size %d", status.SizeBytes, gib)
		}
	})

	t.Run("nothing moved surfaces the unreadable header", func(t *testing.T) {
		runner := newFakeRunner().
			withLVsThen(active, active).
			withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
			withLUKSDumpFailure("/dev/vg0/data")
		p := newTestProvider(t, runner, withKey)

		_, err := p.Status(context.Background(), "data")
		if err == nil {
			t.Fatal("Status succeeded over a header it could not read")
		}
		if errors.Is(err, common.ErrNotFound) {
			t.Fatalf("an unreadable header was reported as a missing volume: %v", err)
		}
		// And it does not invent a capacity to paper over the failure.
		if !strings.Contains(err.Error(), "LUKS header") {
			t.Errorf("error = %v, want it to name the header it could not read", err)
		}
	})
}

// --- Remembering encryption ------------------------------------------------
//
// Encryption is DISCOVERED while a volume is active and REMEMBERED for when it
// is not. An inactive logical volume has no device node, so a detached volume
// cannot be probed at all, and Status holds no lock and will not activate one
// to look. The tag is what lets a detached volume still report usable capacity.

// TestProvisionTagsAnEncryptedVolume pins where the tag is written: after
// luksFormat, not at lvcreate. Tagging at creation would be one command fewer
// and would leave a window in which the tag claims an encryption that a failed
// format never delivered.
func TestProvisionTagsAnEncryptedVolume(t *testing.T) {
	runner := newFakeRunner()
	p := newTestProvider(t, runner, encrypted)

	if _, err := p.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "lvchange --addtag blockstore.luks-header=16777216 vg0/data")

	// After the container exists, not before it.
	lines := runner.lines()
	format, tag := -1, -1
	for i, line := range lines {
		if strings.HasPrefix(line, "luks format ") {
			format = i
		}
		if strings.Contains(line, "--addtag") {
			tag = i
		}
	}
	if format < 0 || tag < 0 || tag < format {
		t.Errorf("the tag must be written after luksFormat; got format at %d, tag at %d in:\n  %s",
			format, tag, strings.Join(lines, "\n  "))
	}

	// A PLAIN volume is never tagged; the tag means encrypted, not "made here".
	plain := newFakeRunner()
	pp := newTestProvider(t, plain)
	if _, err := pp.Provision(context.Background(), common.VolumeSpec{Name: "data", SizeBytes: gib}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertNoLine(t, plain, "lvchange --addtag blockstore.luks-header=16777216 vg0/data")
}

// TestRestoreTagsTheEncryptedResult covers both restores that produce a
// container. They become encrypted at different moments — one when this
// provider formats it, the other when the copied ciphertext lands — and both
// have to end up tagged, or Status would misreport them once detached.
func TestRestoreTagsTheEncryptedResult(t *testing.T) {
	t.Run("re-encrypting restore", func(t *testing.T) {
		runner := newFakeRunner().withLVs(snapshotFixtures()...)
		runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": "ext4"})
		p := newTestProvider(t, runner, encrypted)

		if _, err := p.Provision(context.Background(), common.VolumeSpec{
			Name:             "restored",
			SizeBytes:        gib,
			SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
		}); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		assertLine(t, runner, "lvchange --addtag blockstore.luks-header=16777216 vg0/restored")
	})

	t.Run("verbatim restore of an encrypted image", func(t *testing.T) {
		runner := newFakeRunner().withLVs(snapshotFixtures()...)
		runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": fsTypeLUKS})
		p := newTestProvider(t, runner, encrypted)

		if _, err := p.Provision(context.Background(), common.VolumeSpec{
			Name:             "restored",
			SizeBytes:        gib,
			SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
		}); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		// There is no luksFormat on this path to hang the tag on; it is the
		// copy landing that makes the volume a container.
		assertLine(t, runner, "lvchange --addtag blockstore.luks-header=16777216 vg0/restored")
		lines := runner.lines()
		dd, tag := -1, -1
		for i, line := range lines {
			if strings.HasPrefix(line, "dd ") {
				dd = i
			}
			if strings.Contains(line, "--addtag") {
				tag = i
			}
		}
		if dd < 0 || tag < 0 || tag < dd {
			t.Errorf("the tag must follow the copy; got dd at %d, tag at %d", dd, tag)
		}
	})

	t.Run("a plaintext restore is not tagged", func(t *testing.T) {
		runner := newFakeRunner().withLVs(snapshotFixtures()...)
		p := newTestProvider(t, runner)

		if _, err := p.Provision(context.Background(), common.VolumeSpec{
			Name:             "restored",
			SizeBytes:        gib,
			SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
		}); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		assertNoLine(t, runner, "lvchange --addtag blockstore.luks-header=16777216 vg0/restored")
	})
}

// TestAttachRepairsAMissingTag is how a fleet provisioned before the tag existed
// heals. Attach is the only operation that both holds the volume's lock and has
// already proved the volume is a container by probing it.
func TestAttachRepairsAMissingTag(t *testing.T) {
	encryptedLV := func(tags ...string) *fakeRunner {
		return newFakeRunner().
			withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true, Tags: tags}).
			withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	}

	// Untagged legacy volume: attaching it writes the tag.
	runner := encryptedLV()
	p := newTestProvider(t, runner, withKey)
	if _, err := p.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	assertLine(t, runner, "lvchange --addtag blockstore.luks-header=16777216 vg0/data")

	// Already tagged: nothing to repair, and no redundant write.
	tagged := encryptedLV(encryptedTagFor(luksHeaderBytes))
	tp := newTestProvider(t, tagged, withKey)
	if _, err := tp.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	assertNoLine(t, tagged, "lvchange --addtag blockstore.luks-header=16777216 vg0/data")

	// A PLAIN volume is never tagged by an attach.
	plain := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	pp := newTestProvider(t, plain, withKey)
	if _, err := pp.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	assertNoLine(t, plain, "lvchange --addtag blockstore.luks-header=16777216 vg0/data")
}

// TestAttachSurvivesAFailedTagRepair pins the deliberate non-fatality of the
// repair.
//
// The volume attaches perfectly well without a tag — it stays in the
// untagged-legacy state Status already falls back for — and there is a real
// configuration where only the tag write fails: a volume group whose metadata
// is read-only still ACTIVATES volumes, because activation writes no metadata,
// so Attach gets past its own lvchange and only the tag write is refused.
// Mounting existing volumes from such a group is a normal recovery; failing the
// attach to record a capacity hint would be the wrong trade.
func TestAttachSurvivesAFailedTagRepair(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	// Only the TAG write fails, exactly as a read-only volume group behaves.
	// Failing every lvchange would break the activation too and prove nothing
	// about the repair specifically.
	runner.on("lvchange", func(args []string, _ []byte) ([]byte, error) {
		if contains(args, "--addtag") {
			return nil, &ExitError{Name: "lvchange", Args: args, Code: 5,
				Stderr: "Volume group \"vg0\" metadata is read-only"}
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, withKey)

	info, err := p.Attach(context.Background(), "data", "node-a")
	if err != nil {
		t.Fatalf("Attach failed because a bookkeeping tag could not be written: %v", err)
	}
	if info.DevicePath != "/dev/mapper/bs-vg0_data" {
		t.Errorf("DevicePath = %q, want the plaintext mapping", info.DevicePath)
	}
	// It did try, and it will try again on the next attach.
	assertLine(t, runner, "lvchange --addtag blockstore.luks-header=16777216 vg0/data")
}

// TestStatusRefusesATagThatContradictsTheDisk is the divergence case. A tag
// claiming encryption over a volume blkid can see is NOT encrypted means the tag
// was applied to the wrong volume or somebody rewrote the container out of band.
// Letting discovery quietly win would leave the lie in place for the next
// reader — including the detached path, which has no probe to correct it.
func TestStatusRefusesATagThatContradictsTheDisk(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true, Tags: []string{encryptedTagFor(luksHeaderBytes)}}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner, withKey)

	_, err := p.Status(context.Background(), "data")
	if err == nil {
		t.Fatal("Status accepted a tag that contradicts what is on the disk")
	}
	for _, want := range []string{encryptedTagPrefix, "ext4", "deltag"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// The reverse direction is NOT an error: an untagged encrypted volume is
	// the ordinary legacy case, and discovery handles it exactly as before.
	legacy := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	lp := newTestProvider(t, legacy, withKey)
	status, err := lp.Status(context.Background(), "data")
	if err != nil {
		t.Fatalf("Status over an untagged encrypted volume: %v", err)
	}
	if status.SizeBytes != gib-luksHeaderBytes {
		t.Errorf("SizeBytes = %d, want discovery to report usable capacity %d",
			status.SizeBytes, gib-luksHeaderBytes)
	}
}

// TestActiveStatusRefusesATagThatDisagreesWithTheHeader completes the tag's
// authority contract. "On an active volume discovery decides" was applied only
// to whether the volume is a container at all; it has to apply to the header
// SIZE too, which is the part the tag actually carries.
//
// A tag recording 16 MiB over a container whose header is really 32 MiB returns
// the right number while the volume is up, because the value is measured — and
// then over-states usable capacity by 16 MiB the moment it is detached and the
// stale tag becomes the only source. Succeeding here would be the last moment
// anything could catch that.
func TestActiveStatusRefusesATagThatDisagreesWithTheHeader(t *testing.T) {
	for name, tc := range map[string]struct {
		tags       []string
		realHeader int64
		wantErr    string
	}{
		"tag smaller than the header": {
			tags: []string{encryptedTagFor(luksHeaderBytes)}, realHeader: 32 << 20, wantErr: "records",
		},
		"tag larger than the header": {
			tags: []string{encryptedTagFor(32 << 20)}, realHeader: luksHeaderBytes, wantErr: "records",
		},
		"tag unreadable": {
			tags: []string{encryptedTagPrefix + "sixteen"}, realHeader: luksHeaderBytes, wantErr: "unreadably",
		},
		"two disagreeing tags": {
			tags:       []string{encryptedTagFor(4 << 20), encryptedTagFor(luksHeaderBytes)},
			realHeader: luksHeaderBytes, wantErr: "unreadably",
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true, Tags: tc.tags}).
				withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
				withLUKSHeader("/dev/vg0/data", tc.realHeader)
			p := newTestProvider(t, runner, withKey)

			_, err := p.Status(context.Background(), "data")
			if err == nil {
				t.Fatal("Status accepted a tag that disagrees with the container's own header")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
			// It says how to fix it, and the fix is an attach — the only place
			// holding the lock needed to rewrite a tag.
			if !strings.Contains(strings.ToLower(err.Error()), "attach the volume") {
				t.Errorf("error %q does not point at the repair", err)
			}
		})
	}
}

// TestActiveStatusAcceptsAnAgreeingOrAbsentTag is the other half: the check must
// refuse a WRONG tag, not any tag. An agreeing tag and an untagged legacy volume
// both report the measured capacity.
func TestActiveStatusAcceptsAnAgreeingOrAbsentTag(t *testing.T) {
	for name, tags := range map[string][]string{
		"tag agrees with the header": {encryptedTagFor(4 << 20)},
		"untagged legacy volume":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true, Tags: tags}).
				withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
				withLUKSHeader("/dev/vg0/data", 4<<20)
			p := newTestProvider(t, runner, withKey)

			status, err := p.Status(context.Background(), "data")
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			// Measured, not assumed: the container's real 4 MiB header.
			if status.SizeBytes != gib-(4<<20) {
				t.Errorf("SizeBytes = %d, want the measured %d", status.SizeBytes, gib-(4<<20))
			}
		})
	}
}

// TestAttachRefusesToLeaveAKnownWrongTagInPlace is the other side of the
// tolerated tag-write failure.
//
// Tolerating it is right for an UNTAGGED legacy volume: nothing gets worse, and
// the volume simply stays in the documented fallback. It is NOT right when a
// tag already exists and is known to be wrong, because the repair failing
// leaves a lie in place that detachedSize will then treat as authoritative —
// fail-open, and in the over-stating direction.
func TestAttachRefusesToLeaveAKnownWrongTagInPlace(t *testing.T) {
	failTagWrites := func(r *fakeRunner) {
		r.on("lvchange", func(args []string, _ []byte) ([]byte, error) {
			if contains(args, "--addtag") || contains(args, "--deltag") {
				return nil, &ExitError{Name: "lvchange", Args: args, Code: 5,
					Stderr: "Volume group \"vg0\" metadata is read-only"}
			}
			return nil, nil
		})
	}

	// An existing tag that disagrees with the container: the repair failing
	// must fail the Attach.
	for name, tags := range map[string][]string{
		"stale offset":    {encryptedTagFor(luksHeaderBytes)},
		"unreadable":      {encryptedTagPrefix + "sixteen"},
		"duplicated tags": {encryptedTagFor(4 << 20), encryptedTagFor(luksHeaderBytes)},
	} {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().
				withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true, Tags: tags}).
				withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
				withLUKSHeader("/dev/vg0/data", 32<<20)
			failTagWrites(runner)
			p := newTestProvider(t, runner, withKey)

			if _, err := p.Attach(context.Background(), "data", "node-a"); err == nil {
				t.Fatal("Attach succeeded leaving a known-incorrect header tag in place")
			}
		})
	}

	// An UNTAGGED legacy volume keeps the tolerance: the attach still succeeds,
	// because nothing is left behind that lies.
	t.Run("untagged legacy is still tolerated", func(t *testing.T) {
		runner := newFakeRunner().
			withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
			withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
			withLUKSHeader("/dev/vg0/data", 32<<20)
		failTagWrites(runner)
		p := newTestProvider(t, runner, withKey)

		if _, err := p.Attach(context.Background(), "data", "node-a"); err != nil {
			t.Fatalf("Attach failed for an untagged legacy volume whose tag write failed: %v", err)
		}
	})
}

// TestParseLVTagsHandlesTheEmptyCase guards the parse directly. lvs renders an
// untagged volume's lv_tags as the empty string, and splitting that yields one
// empty tag rather than none — which would make hasTag("") true and, worse,
// make a volume look tagged to any future check written against length.
func TestParseLVTagsHandlesTheEmptyCase(t *testing.T) {
	for raw, want := range map[string]int{
		"":                              0,
		"   ":                           0,
		"blockstore.encrypted":          1,
		"blockstore.encrypted,zzz.mine": 2,
		"a,,b":                          2,
	} {
		if got := len(parseLVTags(raw)); got != want {
			t.Errorf("parseLVTags(%q) returned %d tags, want %d", raw, got, want)
		}
	}
	if parseLVTags("") != nil {
		t.Error("an untagged volume must yield no tags at all")
	}
}

// TestDetachedStatusUsesTheRecordedHeaderNotTheDefault is the bug that made the
// tag carry a SIZE rather than a boolean.
//
// A volume restored verbatim from an outside snapshot carries THAT snapshot's
// header, which need not be the 16 MiB this package formats. The restore
// measured it in order to size the volume, so recording only "encrypted" would
// throw away a number already in hand — and the resulting error is not small
// and not safe: against a header LARGER than the default, Status over-states
// usable capacity, and a caller sizing data to the answer overruns the volume.
func TestDetachedStatusUsesTheRecordedHeaderNotTheDefault(t *testing.T) {
	for name, header := range map[string]int64{
		"smaller than the default": 4 << 20,
		"the default":              luksHeaderBytes,
		"larger than the default":  32 << 20,
	} {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().withLVs(lvFixture{
				Name: "data", SizeBytes: gib, Active: false,
				Tags: []string{encryptedTagFor(header)},
			})
			p := newTestProvider(t, runner, withKey)

			status, err := p.Status(context.Background(), "data")
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if status.SizeBytes != gib-header {
				t.Errorf("SizeBytes = %d, want %d (backing %d less this volume's own %d-byte header)",
					status.SizeBytes, gib-header, gib, header)
			}
			// Specifically NOT the default, where the two differ.
			if header != luksHeaderBytes && status.SizeBytes == gib-luksHeaderBytes {
				t.Error("Status subtracted this package's header size instead of the volume's own")
			}
		})
	}
}

// TestVerbatimRestoreRecordsTheSourcesHeader is the write half of the same bug:
// the size that reaches the tag has to be the one the restore measured, not the
// one this package would have formatted.
func TestVerbatimRestoreRecordsTheSourcesHeader(t *testing.T) {
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	runner.withBlkid(map[string]string{"/dev/vg0/data_snap_nightly": fsTypeLUKS})
	runner.withLUKSHeader("/dev/vg0/data_snap_nightly", 4<<20)
	p := newTestProvider(t, runner, encrypted)

	if _, err := p.Provision(context.Background(), common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        gib,
		SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertLine(t, runner, "lvchange --addtag blockstore.luks-header=4194304 vg0/restored")
	assertNoLine(t, runner, "lvchange --addtag blockstore.luks-header=16777216 vg0/restored")
}

// TestStatusToleratesADetachRace is Status's other lockless hazard. It lists a
// volume as active and then probes it; a Detach in between takes the device
// node away, and blkid reports a device that is not there with the same status
// it uses for one carrying no signature. Reporting that as "tagged but not a
// container" would turn an ordinary detach into a tampering error.
func TestStatusToleratesADetachRace(t *testing.T) {
	active := []lvFixture{{
		Name: "data", SizeBytes: gib, Active: true,
		Tags: []string{encryptedTagFor(luksHeaderBytes)},
	}}
	detached := []lvFixture{{
		Name: "data", SizeBytes: gib, Active: false,
		Tags: []string{encryptedTagFor(luksHeaderBytes)},
	}}

	// Listed active, probed after a detach: blkid finds nothing.
	runner := newFakeRunner().withLVsThen(active, detached)
	p := newTestProvider(t, runner, withKey)

	status, err := p.Status(context.Background(), "data")
	if err != nil {
		t.Fatalf("Status reported a detach race as a contradiction: %v", err)
	}
	// Answered as the detached path would, from the tag.
	if status.SizeBytes != gib-luksHeaderBytes {
		t.Errorf("SizeBytes = %d, want the tagged detached answer %d", status.SizeBytes, gib-luksHeaderBytes)
	}

	// Deleted mid-read is ErrNotFound rather than a contradiction.
	gone := newFakeRunner().withLVsThen(active, nil)
	gp := newTestProvider(t, gone, withKey)
	if _, err := gp.Status(context.Background(), "data"); !errors.Is(err, common.ErrNotFound) {
		t.Fatalf("Status = %v, want ErrNotFound for a volume deleted mid-read", err)
	}
}

// TestStatusRefusesAnUnreadableHeaderTag guards the one tag state no path in
// this package can produce. It means the tag was hand-edited or two writers
// disagreed, and answering with a capacity anyway would be inventing one.
func TestStatusRefusesAnUnreadableHeaderTag(t *testing.T) {
	for name, tags := range map[string][]string{
		"not a number":    {encryptedTagPrefix + "sixteen"},
		"not positive":    {encryptedTagPrefix + "0"},
		"negative":        {encryptedTagPrefix + "-4194304"},
		"two disagreeing": {encryptedTagFor(4 << 20), encryptedTagFor(16 << 20)},
	} {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().withLVs(lvFixture{
				Name: "data", SizeBytes: gib, Active: false, Tags: tags,
			})
			p := newTestProvider(t, runner, withKey)

			_, err := p.Status(context.Background(), "data")
			if err == nil {
				t.Fatal("Status invented a capacity for a volume whose recorded header is unreadable")
			}
			if !strings.Contains(err.Error(), "attach the volume") {
				t.Errorf("error %q does not say how to repair it", err)
			}
		})
	}
}

// TestAttachRecordsTheMeasuredHeader pins that the repair writes a MEASURED
// number. Attach is the only place that both holds the lock and can read the
// real offset out of the container, so a tag it writes is never an assumption.
func TestAttachRecordsTheMeasuredHeader(t *testing.T) {
	// A legacy volume whose container is not the size this package formats.
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withLUKSHeader("/dev/vg0/data", 4<<20)
	p := newTestProvider(t, runner, withKey)

	if _, err := p.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	assertLine(t, runner, "lvchange --addtag blockstore.luks-header=4194304 vg0/data")

	// A tag that has DRIFTED from the container is corrected, and the stale one
	// removed in the same lvchange so the volume is never carrying both.
	drifted := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{encryptedTagFor(luksHeaderBytes)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withLUKSHeader("/dev/vg0/data", 4<<20)
	dp := newTestProvider(t, drifted, withKey)
	if _, err := dp.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	assertLine(t, drifted, "lvchange --deltag blockstore.luks-header=16777216 --addtag blockstore.luks-header=4194304 vg0/data")

	// An already-correct tag is left alone; no redundant metadata write.
	correct := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{encryptedTagFor(luksHeaderBytes)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	cp := newTestProvider(t, correct, withKey)
	if _, err := cp.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	for _, line := range correct.lines() {
		if strings.Contains(line, "--addtag") || strings.Contains(line, "--deltag") {
			t.Errorf("a correctly tagged volume was re-tagged: %q", line)
		}
	}
}

// TestDetachRaceThroughTheHeaderReadStillSubtractsTheHeader is the seam where
// this PR's two halves meet, and where they disagreed.
//
// The path: Status finds the volume active and a LUKS container, goes to read
// the header for an exact answer, and the header read fails because a
// concurrent Detach took the device node away. The re-check then finds the
// volume inactive — which is the DETACHED case, and the detached case consults
// the tag. Returning the backing size there instead reports a gibibyte of
// usable capacity on a volume that has a gibibyte MINUS a header, which is the
// fail-open overfill the tag exists to prevent.
//
// Both detached routes — the ordinary one and this post-race re-check — must
// give the same answer for the same volume, which is why they share one
// function rather than agreeing by inspection.
func TestDetachRaceThroughTheHeaderReadStillSubtractsTheHeader(t *testing.T) {
	tagged := func(active bool) []lvFixture {
		return []lvFixture{{
			Name: "data", SizeBytes: gib, Active: active,
			Tags: []string{encryptedTagFor(luksHeaderBytes)},
		}}
	}

	// Listed active and probed as a container, then detached underneath the
	// header read.
	runner := newFakeRunner().
		withLVsThen(tagged(true), tagged(false)).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withLUKSDumpFailure("/dev/vg0/data")
	p := newTestProvider(t, runner, withKey)

	status, err := p.Status(context.Background(), "data")
	if err != nil {
		t.Fatalf("Status failed over a detach race: %v", err)
	}
	if status.SizeBytes != gib-luksHeaderBytes {
		t.Errorf("SizeBytes = %d, want %d — the post-race detached answer must consult the tag, "+
			"like the ordinary detached path does; reporting the backing size here over-states "+
			"usable capacity by a whole header", status.SizeBytes, gib-luksHeaderBytes)
	}

	// The SAME volume asked the ordinary way must give the SAME number.
	plainRead := newFakeRunner().withLVs(tagged(false)...)
	pr := newTestProvider(t, plainRead, withKey)
	ordinary, err := pr.Status(context.Background(), "data")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if ordinary.SizeBytes != status.SizeBytes {
		t.Errorf("the two detached paths disagree: post-race says %d, ordinary says %d",
			status.SizeBytes, ordinary.SizeBytes)
	}

	// And an UNTAGGED legacy volume still gets the migration fallback on the
	// same path — the fix must not turn the legacy answer into a subtraction.
	legacy := func(active bool) []lvFixture {
		return []lvFixture{{Name: "data", SizeBytes: gib, Active: active}}
	}
	legacyRunner := newFakeRunner().
		withLVsThen(legacy(true), legacy(false)).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withLUKSDumpFailure("/dev/vg0/data")
	lp := newTestProvider(t, legacyRunner, withKey)
	legacyStatus, err := lp.Status(context.Background(), "data")
	if err != nil {
		t.Fatalf("Status over an untagged legacy volume in a detach race: %v", err)
	}
	if legacyStatus.SizeBytes != gib {
		t.Errorf("untagged legacy SizeBytes = %d, want the backing size %d", legacyStatus.SizeBytes, gib)
	}
}

// TestAttachClearsAHeaderTagFromAPlainVolume closes the other direction of the
// contradiction. Status already refuses a plain volume carrying a header tag;
// Attach is the operation that can actually DO something about it, because it
// holds the lock and has just probed the volume. Letting it succeed and leave
// the tag would keep a false claim authoritative for every detached read after
// it — "the next attach either re-records the tag or refuses" has to hold when
// the right answer is that there should be no tag at all.
func TestAttachClearsAHeaderTagFromAPlainVolume(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{encryptedTagFor(luksHeaderBytes)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner, withKey)

	info, err := p.Attach(context.Background(), "data", "node-a")
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if info.DevicePath != "/dev/vg0/data" {
		t.Errorf("DevicePath = %q, want the plain volume", info.DevicePath)
	}
	assertLine(t, runner, "lvchange --deltag blockstore.luks-header=16777216 vg0/data")
	assertNoLine(t, runner, "lvchange --addtag blockstore.luks-header=16777216 vg0/data")

	// A plain volume with NO header tag is untouched — the repair fires on a
	// false claim, not on every plain attach.
	clean := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	cp := newTestProvider(t, clean, withKey)
	if _, err := cp.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	for _, line := range clean.lines() {
		if strings.Contains(line, "--deltag") || strings.Contains(line, "--addtag") {
			t.Errorf("a plain untagged volume was re-tagged: %q", line)
		}
	}

	// And if the removal fails, the Attach fails: a known-false tag left in
	// place is the same fail-open as a known-wrong one.
	failing := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{encryptedTagFor(luksHeaderBytes)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	failing.on("lvchange", func(args []string, _ []byte) ([]byte, error) {
		if contains(args, "--deltag") {
			return nil, &ExitError{Name: "lvchange", Args: args, Code: 5, Stderr: "metadata is read-only"}
		}
		return nil, nil
	})
	fp := newTestProvider(t, failing, withKey)
	if _, err := fp.Attach(context.Background(), "data", "node-a"); err == nil {
		t.Error("Attach succeeded leaving a false header tag on a plain volume")
	}
}

// TestResizeReconcilesTheHeaderTag closes the last operation that held the lock
// and the measured header at the same time and did nothing with them.
//
// Resize is CORRECT either way — it sizes from the measured offset, never from
// the tag — so this is not about the resize being wrong. It is that a volume
// which is only ever resized, never attached, would keep a lying tag forever,
// and the contract says a tag can only stay wrong for as long as the volume
// stays detached.
//
// The encrypted fixtures here are LOCKED containers, which is what a volume
// being resized looks like: an unlocked one is refused before the reconciliation
// would matter.
func TestResizeReconcilesTheHeaderTag(t *testing.T) {
	t.Run("a drifted tag on an encrypted volume is re-recorded", func(t *testing.T) {
		runner := newFakeRunner().
			withLVs(lvFixture{
				Name: "data", SizeBytes: gib, Active: true,
				Tags: []string{encryptedTagFor(4 << 20)},
			}).
			withBlkid(map[string]string{
				"/dev/vg0/data":           fsTypeLUKS,
				"/dev/mapper/bs-vg0_data": "ext4",
			})
		p := newTestProvider(t, runner, withKey)

		if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
			t.Fatalf("Resize: %v", err)
		}
		assertLine(t, runner, "lvchange --deltag blockstore.luks-header=4194304 --addtag blockstore.luks-header=16777216 vg0/data")
	})

	t.Run("a false tag on a plain volume is removed", func(t *testing.T) {
		runner := newFakeRunner().
			withLVs(lvFixture{
				Name: "data", SizeBytes: gib, Active: true,
				Tags: []string{encryptedTagFor(luksHeaderBytes)},
			}).
			withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
		p := newTestProvider(t, runner)

		if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
			t.Fatalf("Resize: %v", err)
		}
		assertLine(t, runner, "lvchange --deltag blockstore.luks-header=16777216 vg0/data")
	})

	t.Run("a correct tag is left alone", func(t *testing.T) {
		runner := newFakeRunner().
			withLVs(lvFixture{
				Name: "data", SizeBytes: gib, Active: true,
				Tags: []string{encryptedTagFor(luksHeaderBytes)},
			}).
			withBlkid(map[string]string{
				"/dev/vg0/data":           fsTypeLUKS,
				"/dev/mapper/bs-vg0_data": "ext4",
			})
		p := newTestProvider(t, runner, withKey)

		if err := p.Resize(context.Background(), "data", 2*gib); err != nil {
			t.Fatalf("Resize: %v", err)
		}
		for _, line := range runner.lines() {
			if strings.Contains(line, "--deltag") || strings.Contains(line, "--addtag") {
				t.Errorf("a correctly tagged volume was re-tagged during Resize: %q", line)
			}
		}
	})
}

// TestDetachReconcilesBeforeItLeaves is the transition that matters most.
//
// Detach is the moment a volume enters the state where the tag becomes the ONLY
// source of its capacity, and it is the last moment the container is readable.
// A wrong tag surviving a detach is therefore not a latent problem: it is
// immediately load-bearing, on the very next Status, with no probe left to
// contradict it.
func TestDetachReconcilesBeforeItLeaves(t *testing.T) {
	t.Run("a drifted tag on an encrypted volume is re-recorded", func(t *testing.T) {
		runner := newFakeRunner().
			withLVs(lvFixture{
				Name: "data", SizeBytes: gib, Active: true,
				Tags: []string{encryptedTagFor(4 << 20)},
			}).
			withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
			withOpenMappings("bs-vg0_data")
		p := newTestProvider(t, runner, withKey)

		if err := p.Detach(context.Background(), "data", "node-a"); err != nil {
			t.Fatalf("Detach: %v", err)
		}
		assertLine(t, runner, "lvchange --deltag blockstore.luks-header=4194304 --addtag blockstore.luks-header=16777216 vg0/data")

		// And the repair happened while the volume was still up — after that
		// deactivation there is no header left to read.
		lines := runner.lines()
		tag, deact := -1, -1
		for i, line := range lines {
			if strings.Contains(line, "--addtag") {
				tag = i
			}
			if line == "lvchange --activate n --yes vg0/data" {
				deact = i
			}
		}
		if tag < 0 || deact < 0 || tag > deact {
			t.Errorf("the tag must be recorded before the deactivation; tag at %d, deactivate at %d in:\n  %s",
				tag, deact, strings.Join(lines, "\n  "))
		}
	})

	t.Run("a false tag on a plain volume is removed", func(t *testing.T) {
		runner := newFakeRunner().
			withLVs(lvFixture{
				Name: "data", SizeBytes: gib, Active: true,
				Tags: []string{encryptedTagFor(luksHeaderBytes)},
			}).
			withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
		p := newTestProvider(t, runner)

		if err := p.Detach(context.Background(), "data", "node-a"); err != nil {
			t.Fatalf("Detach: %v", err)
		}
		assertLine(t, runner, "lvchange --deltag blockstore.luks-header=16777216 vg0/data")
	})

	t.Run("a correct tag costs no write", func(t *testing.T) {
		runner := newFakeRunner().
			withLVs(lvFixture{
				Name: "data", SizeBytes: gib, Active: true,
				Tags: []string{encryptedTagFor(luksHeaderBytes)},
			}).
			withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
			withOpenMappings("bs-vg0_data")
		p := newTestProvider(t, runner, withKey)

		if err := p.Detach(context.Background(), "data", "node-a"); err != nil {
			t.Fatalf("Detach: %v", err)
		}
		for _, line := range runner.lines() {
			if strings.Contains(line, "--deltag") || strings.Contains(line, "--addtag") {
				t.Errorf("a correctly tagged volume was re-tagged on Detach: %q", line)
			}
		}
	})
}

// TestDeleteDoesNotFailOverATagRepair is the deliberate exception. Delete is
// removing the volume, tag and all, so refusing to destroy it because a piece of
// bookkeeping could not be rewritten would be pure obstruction — there is no
// later reader to mislead.
func TestDeleteDoesNotFailOverATagRepair(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{encryptedTagFor(4 << 20)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data")
	runner.on("lvchange", func(args []string, _ []byte) ([]byte, error) {
		if contains(args, "--addtag") || contains(args, "--deltag") {
			return nil, &ExitError{Name: "lvchange", Args: args, Code: 5, Stderr: "metadata is read-only"}
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, withKey)

	if err := p.Delete(context.Background(), "data"); err != nil {
		t.Fatalf("Delete refused to remove a volume because a tag could not be rewritten: %v", err)
	}
	assertLine(t, runner, "lvremove --force vg0/data")
}
