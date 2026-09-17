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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

// TestEncryptionNeedsAWayToObtainThePassphrase is a startup refusal rather than
// a failure at the first failover, which is the worst possible moment to
// discover a deployment mistake.
func TestEncryptionNeedsAWayToObtainThePassphrase(t *testing.T) {
	settings := testSettings(t)
	settings[SettingEncrypted] = "true"

	_, err := New(settings, WithRunner(newFakeRunner(t)), WithSecretProvider(testSecretProvider))
	if err == nil {
		t.Fatal("New accepted encryption with no key file and no KeyProvider")
	}
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("err = %v, want common.ErrInvalidArgument", err)
	}
	if !strings.Contains(err.Error(), SettingLUKSKeyFile) {
		t.Errorf("the refusal should name %s: %v", SettingLUKSKeyFile, err)
	}
}

// TestAPassphraseWithoutEncryptionIsRefused covers the mistake in the other
// direction, which is the dangerous one: a deployment that configured a key,
// believes it is encrypting, and is not.
func TestAPassphraseWithoutEncryptionIsRefused(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "luks.key")
	if err := os.WriteFile(keyFile, []byte("a-test-passphrase-long-enough"), 0o600); err != nil {
		t.Fatalf("writing the key file: %v", err)
	}
	settings := testSettings(t)
	settings[SettingLUKSKeyFile] = keyFile

	_, err := New(settings, WithRunner(newFakeRunner(t)), WithSecretProvider(testSecretProvider))
	if err == nil {
		t.Fatal("New accepted a LUKS key file with encryption off, so nothing would have been encrypted")
	}
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("err = %v, want common.ErrInvalidArgument", err)
	}
}

// TestTheTwoSecretsMustBeDifferentFiles is a configuration that reads as
// defense in depth and is not: the replication secret is SHARED WITH THE PEER
// so DRBD can authenticate it, so pointing both settings at one path gives the
// peer-authentication secret the additional job of protecting the data.
func TestTheTwoSecretsMustBeDifferentFiles(t *testing.T) {
	shared := "/etc/go-blockstore/secret"
	settings := testSettings(t)
	settings[SettingEncrypted] = "true"
	settings[SettingLUKSKeyFile] = shared
	settings[SettingReplicationSecretFile] = shared

	_, err := ParseConfig(settings)
	if err == nil {
		t.Fatal("ParseConfig accepted one file as both the peer secret and the volume passphrase")
	}
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("err = %v, want common.ErrInvalidArgument", err)
	}
}

// TestMappingNamesAreNamespacedAgainstTheLocalProvider pins the two properties
// the namespace has to have. Device-mapper names are a single flat namespace
// for the whole host, and a node can legitimately run both providers over one
// volume group.
func TestMappingNamesAreNamespacedAgainstTheLocalProvider(t *testing.T) {
	p, _, _ := newEncryptedProvider(t)

	got := p.crypt.MappingName(testVolume)
	if want := "bsr-vg0.vol1"; got != want {
		t.Fatalf("MappingName = %q, want %q", got, want)
	}

	// The prefixes must not be prefixes of one another, or a scope and a volume
	// ID could spell a name belonging to the other provider.
	if strings.HasPrefix(luks.ReplicatedMappingPrefix, luks.MappingPrefix) ||
		strings.HasPrefix(luks.MappingPrefix, luks.ReplicatedMappingPrefix) {
		t.Errorf("%q and %q: neither may be a prefix of the other",
			luks.MappingPrefix, luks.ReplicatedMappingPrefix)
	}

	// The separator has to be a character validateName rejects, or a volume
	// group and a volume ID can trade one and spell the same mapping name as a
	// different pair. DRBD resource names ACCEPT underscores, which is why this
	// package cannot use pkg/local's separator.
	if err := validateName("volume", "a.b"); err == nil {
		t.Error("validateName accepts a dot, so the mapping namespace is ambiguous")
	}
	if err := validateName("volume", "a_b"); err != nil {
		t.Errorf("validateName rejects an underscore (%v), so this test's premise is stale", err)
	}
}

// -----------------------------------------------------------------------------
// Promote — where the container is opened
// -----------------------------------------------------------------------------

// TestPromoteOpensTheContainerAfterTheRoleChange is the ruling this work
// implements, asserted as an ORDER rather than as two facts.
//
// The unlock cannot come first: DRBD refuses every open of a Secondary's
// device, read-only opens included, so a promotion is the earliest moment the
// container over /dev/drbdN can be opened at all.
func TestPromoteOpensTheContainerAfterTheRoleChange(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus) // not up, so not already Primary
	r.on(binDRBDAdm, "primary", testVolume).returns("")
	r.blkidReports(devicePath(0), fsTypeLUKS)

	if err := p.Promote(context.Background(), testVolume); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	assertOrder(t, r,
		"drbdadm primary vol1",
		"luks open /dev/drbd0 "+cryptName(testVolume),
	)
	if _, open := crypt.open[cryptName(testVolume)]; !open {
		t.Error("the container is not open after a successful Promote")
	}
	// The container is opened, not created: this device already had one.
	assertNotRun(t, r, "luks format /dev/drbd0")
}

// TestMountDoesNotTouchTheCryptLifecycle is the other half of the ruling, and
// it is the half the measurement decided.
//
// Counted against pkg/local's fake, Attach performs the container probe and the
// unlock and Mount performs NEITHER — the crypt lifecycle lives at the layer
// that makes a device usable, not at the mount. Promote is this provider's
// counterpart of that layer, so Mount here must open and close nothing.
func TestMountDoesNotTouchTheCryptLifecycle(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	crypt.unlocked(cryptName(testVolume), devicePath(0))
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.blkidReports(cryptPath(testVolume), "ext4")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	for _, unwanted := range []string{
		"luks open " + devicePath(0) + " " + cryptName(testVolume),
		"luks close " + cryptName(testVolume),
		"luks format " + devicePath(0),
	} {
		assertNotRun(t, r, unwanted)
	}
}

// TestFirstPromoteFormatsAnEmptyDevice is where an encrypted volume's container
// comes from. It cannot come from Provision: the resource comes up Secondary on
// both nodes and DRBD will not let anything write to it.
//
// The guard is the one this package already applies to its mkfs — only a device
// blkid reports as carrying NOTHING AT ALL is formatted.
func TestFirstPromoteFormatsAnEmptyDevice(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	r.on(binDRBDAdm, "primary", testVolume).returns("")
	r.blkidEmpty(devicePath(0))

	if err := p.Promote(context.Background(), testVolume); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	assertOrder(t, r,
		"drbdadm primary vol1",
		"luks format /dev/drbd0",
		"luks open /dev/drbd0 "+cryptName(testVolume),
	)
}

// TestPromoteRefusesToFormatOverAFilesystem is the destructive case the
// emptiness guard exists for: a volume provisioned before encryption was
// configured carries a filesystem, and formatting a container over it would
// destroy every byte of it.
func TestPromoteRefusesToFormatOverAFilesystem(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	r.on(binDRBDAdm, "primary", testVolume).returns("")
	r.on(binDRBDAdm, "secondary", testVolume).returns("")
	r.blkidReports(devicePath(0), "ext4")

	err := p.Promote(context.Background(), testVolume)
	if err == nil {
		t.Fatal("Promote formatted a container over an existing filesystem")
	}
	if !strings.Contains(err.Error(), "ext4") {
		t.Errorf("the refusal should say what it found: %v", err)
	}
	assertNotRun(t, r, "luks format /dev/drbd0")
	// And the promotion this call performed goes back, so the pair is not left
	// with its only writable copy on a node that cannot serve it.
	assertOrder(t, r, "drbdadm primary vol1", "drbdadm secondary vol1")
}

// TestPromoteRollsBackTheRoleOnItsOwnContext is the finding that a compensating
// action reusing the caller's context does nothing at all.
//
// The most likely reason to be unwinding is that ctx was canceled partway
// through, and the production runner execs through exec.CommandContext — so a
// rollback on the caller's context fails instantly and leaves behind exactly
// the state it exists to undo, while the code reads as though it had restored
// it. The test cancels ctx as the promotion returns and then requires the
// demotion to have run anyway.
func TestPromoteRollsBackTheRoleOnItsOwnContext(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.scriptStatus(emptyStatus)
	r.on(binDRBDAdm, "primary", testVolume).returns("").then(cancel)
	r.on(binDRBDAdm, "secondary", testVolume).returns("")
	r.blkidReports(devicePath(0), fsTypeLUKS)

	err := p.Promote(ctx, testVolume)
	if err == nil {
		t.Fatal("Promote succeeded after its context was canceled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to carry context.Canceled", err)
	}

	// The assertion that matters: the demotion ran even though the context the
	// caller passed in is dead. On the caller's context every command fails
	// before it starts, so this line is the difference between a rollback and
	// a comment claiming one.
	assertOrder(t, r, "drbdadm primary vol1", "drbdadm secondary vol1")
}

// TestPromoteRollsBackTheRoleWhenTheUnlockFails is the same unwind reached
// through an ordinary failure rather than a cancellation.
//
// A Primary with no plaintext device is a volume nothing can mount, holding the
// pair's only writable copy away from the peer. The promotion this call
// performed goes back.
func TestPromoteRollsBackTheRoleWhenTheUnlockFails(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	r.on(binDRBDAdm, "primary", testVolume).returns("")
	r.on(binDRBDAdm, "secondary", testVolume).returns("")
	r.blkidReports(devicePath(0), fsTypeLUKS)
	crypt.fails("open", errors.New("no keyslot matched the passphrase"))

	err := p.Promote(context.Background(), testVolume)
	if err == nil {
		t.Fatal("Promote succeeded with an unlock that failed")
	}
	if !strings.Contains(err.Error(), "no keyslot matched") {
		t.Errorf("the unlock failure should reach the caller: %v", err)
	}
	assertOrder(t, r, "drbdadm primary vol1", "drbdadm secondary vol1")
}

// TestPromoteKeepsARoleItDidNotTake mirrors pkg/local's Attach, which rolls its
// activation back only when the volume was not already active.
//
// A promotion this call did not perform is not this call's to undo. Demoting it
// would take the volume away from whoever promoted it first — and on a
// replicated pair that is the node currently serving writes.
func TestPromoteKeepsARoleItDidNotTake(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0)) // already Primary here
	r.on(binDRBDAdm, "primary", testVolume).returns("")
	r.blkidReports(devicePath(0), fsTypeLUKS)
	crypt.fails("open", errors.New("device-mapper refused the mapping"))

	if err := p.Promote(context.Background(), testVolume); err == nil {
		t.Fatal("Promote succeeded with an unlock that failed")
	}
	assertNotRun(t, r, "drbdadm secondary vol1")
}

// -----------------------------------------------------------------------------
// Demote — where the container is closed
// -----------------------------------------------------------------------------

// TestDemoteClosesTheContainerBeforeTheRoleChange is the second half of the
// ruling, and the ORDER is the operation rather than a detail of it.
//
// An open dm-crypt mapping holds /dev/drbdN open, and DRBD refuses to demote a
// device somebody has open. Closing afterwards would make every demotion of an
// encrypted volume fail on a busy device — and report it as though a workload
// still held the volume.
func TestDemoteClosesTheContainerBeforeTheRoleChange(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	crypt.unlocked(cryptName(testVolume), devicePath(0))
	r.reset()

	r.on(binDRBDAdm, "secondary", testVolume).returns("")

	if err := p.Demote(context.Background(), testVolume); err != nil {
		t.Fatalf("Demote: %v", err)
	}

	assertOrder(t, r,
		"luks close "+cryptName(testVolume),
		"drbdadm secondary vol1",
	)
	if _, open := crypt.open[cryptName(testVolume)]; open {
		t.Error("the mapping is still open after Demote")
	}
}

// TestDemoteStopsWhenTheContainerWillNotClose is the failure path, and it is the
// half that proves the close is load-bearing rather than decorative.
//
// A close that fails must stop the demotion. Carrying on would run drbdadm
// secondary against a device the mapping still holds open — which DRBD refuses,
// so the caller would get a busy-device error naming the wrong problem — and if
// it somehow succeeded, the node would be Secondary with a live plaintext
// mapping over a device the replication stream is now writing underneath it.
func TestDemoteStopsWhenTheContainerWillNotClose(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	crypt.unlocked(cryptName(testVolume), devicePath(0))
	r.reset()

	r.on(binDRBDAdm, "secondary", testVolume).returns("")
	crypt.fails("close", errors.New("device or resource busy"))

	err := p.Demote(context.Background(), testVolume)
	if err == nil {
		t.Fatal("Demote succeeded with a container that would not close")
	}
	if !strings.Contains(err.Error(), "device or resource busy") {
		t.Errorf("the close failure should reach the caller: %v", err)
	}
	assertNotRun(t, r, "drbdadm secondary vol1")
	if _, open := crypt.open[cryptName(testVolume)]; !open {
		t.Error("the mapping was recorded as closed by a close that failed")
	}
}

// TestDemoteConvergesOverAVolumeWithNoMapping keeps a teardown path from having
// to work out how far setup got: a volume with nothing open is demoted, not
// refused.
func TestDemoteConvergesOverAVolumeWithNoMapping(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.on(binDRBDAdm, "secondary", testVolume).returns("")

	if err := p.Demote(context.Background(), testVolume); err != nil {
		t.Fatalf("Demote over a volume with no mapping: %v", err)
	}
	r.assertRan(t, "drbdadm secondary vol1")
	assertNotRun(t, r, "luks close "+cryptName(testVolume))
}

// TestDemoteRefusesAForeignMapping is the fail-open the ownership check exists
// for, reached from the teardown side. The mapping name is deterministic, so a
// stale mapping from another run — or one an operator opened by hand — sits
// under exactly the name this provider looks for. Closing it on the strength of
// the name would tear down somebody else's plaintext device.
func TestDemoteRefusesAForeignMapping(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	crypt.unlocked(cryptName(testVolume), "/dev/drbd99") // not this volume's device
	r.reset()

	r.on(binDRBDAdm, "secondary", testVolume).returns("")

	err := p.Demote(context.Background(), testVolume)
	if err == nil {
		t.Fatal("Demote closed a mapping over a device that is not this volume's")
	}
	if !strings.Contains(err.Error(), "/dev/drbd99") {
		t.Errorf("the refusal should name the device it found: %v", err)
	}
	assertNotRun(t, r, "luks close "+cryptName(testVolume))
	assertNotRun(t, r, "drbdadm secondary vol1")
}

// -----------------------------------------------------------------------------
// The other state changes that need the device free
// -----------------------------------------------------------------------------

// TestDetachClosesAStrandedMappingBeforeTakingTheResourceDown covers the
// mapping nobody closed — a run that ended between the demotion and the detach,
// or one opened by hand. It has to go before drbdadm down, which fails on a
// device something still holds open.
func TestDetachClosesAStrandedMappingBeforeTakingTheResourceDown(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	crypt.unlocked(cryptName(testVolume), devicePath(0))
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.on(binDRBDAdm, "down", testVolume).returns("")

	if err := p.Detach(context.Background(), testVolume, testNode); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	assertOrder(t, r,
		"luks close "+cryptName(testVolume),
		"drbdadm down vol1",
	)
}

// TestDeleteClosesTheContainerBeforeTearingTheVolumeDown is the same ordering
// at the end of a volume's life. It runs only while the resource is UP, because
// that is when the device a mapping could be over exists at all.
func TestDeleteClosesTheContainerBeforeTearingTheVolumeDown(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	crypt.unlocked(cryptName(testVolume), devicePath(0))
	r.reset()

	r.scriptStatus(secondaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{Name: testVolume, VG: testVG, Size: strconv.FormatInt(testSize, 10)}))
	r.on(binDRBDAdm, "down", testVolume).returns("")
	r.on(binLVRemove, "--force", "vg0/vol1").returns("")

	if err := p.Delete(context.Background(), testVolume); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertOrder(t, r,
		"luks close "+cryptName(testVolume),
		"drbdadm down vol1",
	)
}

// -----------------------------------------------------------------------------
// The plaintext device is what the filesystem lives on
// -----------------------------------------------------------------------------

// TestMountUsesThePlaintextDevice is the mistake fsDevice exists to prevent. A
// mkfs against /dev/drbdN on an encrypted volume writes a filesystem over the
// LUKS header, which destroys the container and everything in it.
func TestMountUsesThePlaintextDevice(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	crypt.unlocked(cryptName(testVolume), devicePath(0))
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.blkidEmpty(cryptPath(testVolume))
	r.on("mkfs.ext4", "-q", cryptPath(testVolume)).returns("")

	if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	r.assertRan(t, "mkfs.ext4 -q "+cryptPath(testVolume))
	assertNotRun(t, r, "mkfs.ext4 -q "+devicePath(0))
	assertNotRun(t, r, "blkid -p -o export "+devicePath(0))
}

// TestMountRefusesAVolumeWhoseContainerIsNotOpen is the "error, not a pass"
// rule: crypt state that cannot be established is reported as a failure rather
// than assumed to be fine.
//
// Primary ordinarily implies an open container, because Promote opens one — but
// ordinarily is not a guarantee, and reading the role as proof would hand
// mount(2) a device node that does not exist and return an error saying nothing
// about what is actually wrong.
func TestMountRefusesAVolumeWhoseContainerIsNotOpen(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))

	err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
	if err == nil {
		t.Fatal("Mount succeeded over a volume whose container is not open")
	}
	if !errors.Is(err, ErrNotUnlocked) {
		t.Errorf("err = %v, want ErrNotUnlocked", err)
	}
	assertNotRun(t, r, "mkfs.ext4 -q "+cryptPath(testVolume))
}

// TestUnmountLooksUpThePlaintextDevice: the filesystem is mounted from the
// mapping, so asking the mount table about /dev/drbdN would find nothing and
// converge to a no-op over a volume that IS mounted.
func TestUnmountLooksUpThePlaintextDevice(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	crypt.unlocked(cryptName(testVolume), devicePath(0))
	r.scriptMount(cryptPath(testVolume), testMountPoint)
	r.reset()

	if err := p.Unmount(context.Background(), testVolume, testMountPoint); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if r.mountLookups() == 0 {
		t.Fatal("Unmount consulted the mount table for no device")
	}
}

// TestAnUnencryptedProviderPerformsNoLUKSOperation is the regression guard for
// every deployment that does not encrypt: the crypt lifecycle must be inert,
// not merely correct.
func TestAnUnencryptedProviderPerformsNoLUKSOperation(t *testing.T) {
	p, r := newTestProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	r.scriptStatus(emptyStatus)
	r.on(binDRBDAdm, "primary", testVolume).returns("")
	if err := p.Promote(context.Background(), testVolume); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	r.on(binDRBDAdm, "secondary", testVolume).returns("")
	if err := p.Demote(context.Background(), testVolume); err != nil {
		t.Fatalf("Demote: %v", err)
	}

	for _, got := range r.commands() {
		if strings.HasPrefix(got, luksBinary+" ") {
			t.Errorf("an unencrypted provider performed a LUKS operation: %q", got)
		}
	}
	// And it does not probe the device to decide, either: the configuration
	// settles it, so an unencrypted promotion costs exactly what it always did.
	if got := len(r.commands()); got != 2 {
		t.Errorf("Promote and Demote ran %d commands, want 2: %v", got, r.commands())
	}
}

// -----------------------------------------------------------------------------
// Resize — the mapping is sized when Promote opens it, and nothing reloads it
// -----------------------------------------------------------------------------

// encryptedDeviceBytes is the size of the DRBD device an encrypted volume of
// usable capacity `usable` presents: the backing volume as LVM rounded it, less
// DRBD's metadata. It is what sysfs reports for /dev/drbdN, and the number a
// mapping opened over it is sized from (less the header).
func encryptedDeviceBytes(usable int64) int64 {
	backing := roundUpTo(backingBytes(usable, true), testExtentSize)
	return backing - metadataBytes(dataBytes(usable, true))
}

// scriptEncryptedResize scripts the device half of a Resize from testSize to
// newSize on an up resource in the given role: the lvs that finds the backing
// volume at its current size, the lvextend to the new one, and the drbdadm
// resize — which, through its hook, GROWS THE DEVICE the fake LUKS backend
// sees, exactly when the real one would.
func scriptEncryptedResize(r *fakeRunner, crypt *fakeLUKS, status string, newSize int64) {
	r.scriptStatus(status)
	r.scriptLVS(lvsJSON(lvEntry{
		Name: testVolume, VG: testVG,
		Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, true), testExtentSize), 10),
	}))
	r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(newSize, true), 10)+"b", "vg0/"+testVolume).returns("")
	r.on(binDRBDAdm, "resize", testVolume).returns("").then(func() {
		crypt.sized(devicePath(0), encryptedDeviceBytes(newSize))
	})
	// Whether the mapping's node exists follows the container: closed, a
	// lookup of it fails the way production's stat(2) does.
	if _, open := crypt.open[cryptName(testVolume)]; !open {
		r.deviceAbsent(cryptPath(testVolume))
	}
}

// TestResizeRefusesToGrowTheFilesystemIntoAStaleMapping is the defect issue #62
// is about, pinned from the side that reports success.
//
// The dm-crypt mapping over /dev/drbdN is sized from the replicated device at
// the moment Promote opens it, and go-luks2 exposes no table reload. So after
// the lvextend and the drbdadm resize the plaintext device is still the size it
// was unlocked at, and a resize2fs against it would grow the filesystem to the
// OLD size and exit 0 — after which the record would say the new size over a
// filesystem that never reached it. The refusal has to come AFTER the device
// half, which is idempotent and is not what is wrong, and BEFORE the grow tool
// runs; and it has to name the remedy, because the caller's request is fine
// and only the mapping is in the wrong state.
//
// Removing the freshness check in growFilesystem makes every case here pass
// the resize and run resize2fs against the stale mapping.
func TestResizeRefusesToGrowTheFilesystemIntoAStaleMapping(t *testing.T) {
	newSize := testSize * 2
	cases := []struct {
		name    string
		fsType  string
		mounted string
		// growTool is the command that must NOT have run: the grow that would
		// have fit the filesystem to the stale mapping.
		growTool string
	}{
		{name: "mounted ext4", fsType: "ext4", mounted: testMountPoint, growTool: "resize2fs"},
		{name: "unmounted ext4", fsType: "ext4", mounted: "", growTool: "e2fsck"},
		{name: "mounted xfs", fsType: "xfs", mounted: testMountPoint, growTool: "xfs_growfs"},
		// A raw volume has no filesystem to grow, and its consumer still uses
		// the plaintext device — which is short. Recording the new size over
		// it is the same wrong answer with no tool in the way.
		{name: "raw", fsType: "", mounted: "", growTool: "resize2fs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, r, crypt := newEncryptedProvider(t)
			spec := defaultSpec()
			spec.FSType = tc.fsType
			provision(t, p, r, spec)
			// Opened at the CURRENT device size, as Promote would have.
			crypt.sized(devicePath(0), encryptedDeviceBytes(testSize))
			crypt.unlocked(cryptName(testVolume), devicePath(0))
			r.reset()

			scriptEncryptedResize(r, crypt, primaryStatus(testVolume, 0), newSize)
			if tc.fsType != "" {
				r.scriptMount(cryptPath(testVolume), tc.mounted)
			}
			// Were the refusal missing, these are what the grow would run.
			r.on(binE2fsck, "-f", "-p", cryptPath(testVolume)).returns("")
			r.on(binResize2fs, cryptPath(testVolume)).returns("")
			r.on(binXFSGrowfs, testMountPoint).returns("")

			err := p.Resize(context.Background(), testVolume, newSize)
			if !errors.Is(err, ErrMappingStale) {
				t.Fatalf("Resize over a stale mapping = %v, want ErrMappingStale", err)
			}
			// The request is well-formed and one role cycle serves it; that is
			// the opposite of what ErrUnsupported tells a caller.
			if errors.Is(err, common.ErrUnsupported) {
				t.Errorf("ErrMappingStale wraps common.ErrUnsupported, which tells the caller not to bother: %v", err)
			}
			for _, word := range []string{"Demote", "Promote", "Resize"} {
				if !strings.Contains(err.Error(), word) {
					t.Errorf("the refusal does not name the remedy step %q: %v", word, err)
				}
			}

			// The device half happened — it is the half that converges — and
			// the filesystem half did not.
			r.assertRan(t, fmt.Sprintf("lvextend --size %db vg0/vol1", backingBytes(newSize, true)))
			r.assertRan(t, "drbdadm resize vol1")
			r.assertNotRan(t, tc.growTool)
			r.assertNotRan(t, "resize2fs")

			// And the record was NOT advanced past a filesystem that did not
			// move, nor marked as owing a grow: the repeat is the caller's.
			meta, loadErr := p.loadMeta(testVolume)
			if loadErr != nil {
				t.Fatalf("loadMeta: %v", loadErr)
			}
			if meta.SizeBytes != testSize {
				t.Errorf("recorded size = %d after a refused grow, want the unchanged %d", meta.SizeBytes, testSize)
			}
			if meta.FSGrowPending {
				t.Error("a refused Resize recorded a deferred grow; the record must not claim a size it did not reach")
			}
			// The mapping is left exactly as found — no Close, no re-open: see
			// internal/luks.Backend for why this seam offers no such thing.
			assertNotRun(t, r, "luks close "+cryptName(testVolume))
		})
	}
}

// TestResizeCompletesWhenTheContainerIsClosed is the size-at-open path from
// the side where nothing is stale. A Secondary's container is never open —
// DRBD refuses every open of a Secondary's device — so the device grows, the
// record follows it, and the filesystem is owed a grow that the next Promote
// sizes the mapping for and the next Mount performs. That owed grow is
// RECORDED, so that Mount knows to finish it; a raw volume owes nothing.
func TestResizeCompletesWhenTheContainerIsClosed(t *testing.T) {
	newSize := testSize * 2
	for _, tc := range []struct {
		name        string
		fsType      string
		wantPending bool
	}{
		{name: "ext4 owes its grow to the next Mount", fsType: "ext4", wantPending: true},
		{name: "xfs owes its grow to the next Mount", fsType: "xfs", wantPending: true},
		{name: "a raw volume owes nothing", fsType: "", wantPending: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r, crypt := newEncryptedProvider(t)
			spec := defaultSpec()
			spec.FSType = tc.fsType
			provision(t, p, r, spec)
			crypt.sized(devicePath(0), encryptedDeviceBytes(testSize))
			r.reset()

			scriptEncryptedResize(r, crypt, secondaryStatus(testVolume, 0), newSize)
			// Closed means the mapping's node is not there; a lookup of it
			// would fail as production's does.
			r.deviceAbsent(cryptPath(testVolume))

			if err := p.Resize(context.Background(), testVolume, newSize); err != nil {
				t.Fatalf("Resize on a Secondary with the container closed: %v", err)
			}
			r.assertRan(t, fmt.Sprintf("lvextend --size %db vg0/vol1", backingBytes(newSize, true)))
			r.assertRan(t, "drbdadm resize vol1")
			r.assertNotRan(t, "resize2fs")
			r.assertNotRan(t, "e2fsck")
			r.assertNotRan(t, "xfs_growfs")
			// Nothing was opened to look: a Secondary's device cannot be.
			assertNotRun(t, r, "luks open "+devicePath(0)+" "+cryptName(testVolume))

			meta, err := p.loadMeta(testVolume)
			if err != nil {
				t.Fatalf("loadMeta: %v", err)
			}
			if meta.SizeBytes != newSize {
				t.Errorf("recorded size = %d, want %d: the device half is done", meta.SizeBytes, newSize)
			}
			if meta.FSGrowPending != tc.wantPending {
				t.Errorf("FSGrowPending = %v, want %v", meta.FSGrowPending, tc.wantPending)
			}
		})
	}
}

// TestResizeGrowsTheFilesystemThroughAFreshMapping is the repeat the refusal's
// remedy ends in, and the ordinary online resize of a volume whose peer was
// grown first. The mapping was opened AFTER the device reached its new size, so
// it covers the whole data area and the filesystem is grown through it — to
// the mapping's path, never to /dev/drbdN, which carries the ciphertext.
func TestResizeGrowsTheFilesystemThroughAFreshMapping(t *testing.T) {
	newSize := testSize * 2
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	// The device is already at the new size — the peer resized, or the
	// earlier attempt's device half landed — and the mapping was opened over
	// it as it is now.
	crypt.sized(devicePath(0), encryptedDeviceBytes(newSize))
	crypt.unlocked(cryptName(testVolume), devicePath(0))
	r.reset()

	r.scriptStatus(primaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{
		Name: testVolume, VG: testVG,
		Size: strconv.FormatInt(roundUpTo(backingBytes(newSize, true), testExtentSize), 10),
	}))
	r.on(binDRBDAdm, "resize", testVolume).returns("")
	r.scriptMount(cryptPath(testVolume), testMountPoint)
	r.on(binResize2fs, cryptPath(testVolume)).returns("")

	if err := p.Resize(context.Background(), testVolume, newSize); err != nil {
		t.Fatalf("Resize through a fresh mapping: %v", err)
	}
	r.assertNotRan(t, "lvextend")
	r.assertRan(t, "resize2fs "+cryptPath(testVolume))
	r.assertNotRan(t, "resize2fs "+devicePath(0))

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.SizeBytes != newSize {
		t.Errorf("recorded size = %d, want %d", meta.SizeBytes, newSize)
	}
	if meta.FSGrowPending {
		t.Error("the filesystem was grown, yet the record still owes a grow")
	}
}

// TestFilesystemGrowRefusesAStaleMapping guards the last line of defense
// directly. Every path that grows a filesystem — Resize, a restore that grows,
// a Mount finishing a deferred grow — goes through growFilesystem, so this is
// the one place the check cannot be routed around; a quiet nil here would let
// each of those callers record a size the filesystem never reached.
func TestFilesystemGrowRefusesAStaleMapping(t *testing.T) {
	p, r, crypt := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	crypt.sized(devicePath(0), encryptedDeviceBytes(testSize))
	crypt.unlocked(cryptName(testVolume), devicePath(0))
	crypt.sized(devicePath(0), encryptedDeviceBytes(testSize*2)) // the device grew; the mapping did not
	r.reset()

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	r.scriptMount(cryptPath(testVolume), testMountPoint)
	r.on(binResize2fs, cryptPath(testVolume)).returns("")

	grown, err := p.growFilesystem(context.Background(), &meta)
	if !errors.Is(err, ErrMappingStale) {
		t.Fatalf("growFilesystem over a stale mapping = (%v, %v), want ErrMappingStale", grown, err)
	}
	if grown {
		t.Error("growFilesystem reported the filesystem grown while refusing")
	}
	r.assertNotRan(t, "resize2fs")

	// A measurement that cannot be made is a refusal too, not a pass: the
	// whole point of measuring is to refuse what cannot be established.
	crypt.fails("data-offset", errors.New("header unreadable"))
	if _, err := p.growFilesystem(context.Background(), &meta); err == nil {
		t.Error("growFilesystem grew a filesystem over a mapping whose size could not be established")
	}
	r.assertNotRan(t, "resize2fs")
}

// TestMountFinishesADeferredGrow is where an owed grow is paid. Promote sized
// the mapping when it opened the container — over a device that had already
// grown — and Mount is the first point at which both filesystems this package
// manages can be grown ONLINE: resize2fs against a mounted ext4 needs no
// check, and xfs_growfs has no other form at all. It is not done at Promote,
// where the only ext4 route is a forced e2fsck of the whole filesystem in the
// failover path, and where XFS cannot be grown at all; see Provider.Mount.
//
// The unencrypted case is here because the record means the same thing for
// both: the volume was resized while it was Secondary.
func TestMountFinishesADeferredGrow(t *testing.T) {
	newSize := testSize * 2

	t.Run("encrypted ext4: Resize while Secondary, Promote, Mount", func(t *testing.T) {
		p, r, crypt, m := newEncryptedProviderWithMounter(t)
		provision(t, p, r, defaultSpec())
		crypt.sized(devicePath(0), encryptedDeviceBytes(testSize))
		r.reset()
		scriptEncryptedResize(r, crypt, secondaryStatus(testVolume, 0), newSize)
		if err := p.Resize(context.Background(), testVolume, newSize); err != nil {
			t.Fatalf("Resize: %v", err)
		}

		// Promote opens the container over the device AS IT IS NOW, which is
		// what sizes the mapping — and grows nothing itself.
		r.reset()
		r.scriptStatus(secondaryStatus(testVolume, 0))
		r.on(binDRBDAdm, "primary", testVolume).returns("")
		r.blkidReports(devicePath(0), fsTypeLUKS)
		if err := p.Promote(context.Background(), testVolume); err != nil {
			t.Fatalf("Promote: %v", err)
		}
		assertOrder(t, r, "drbdadm primary vol1", "luks open /dev/drbd0 "+cryptName(testVolume))
		r.devicePresent(cryptPath(testVolume)) // the open created the node
		r.assertNotRan(t, "resize2fs")
		r.assertNotRan(t, "e2fsck")
		if got := crypt.mappingSize[cryptName(testVolume)]; got != encryptedDeviceBytes(newSize)-luks.HeaderBytes {
			t.Fatalf("the mapping Promote opened is %d bytes, want %d: the fixture's premise is off", got, encryptedDeviceBytes(newSize)-luks.HeaderBytes)
		}

		// Mount pays the debt, online, after the mount and never before it.
		r.reset()
		r.scriptStatus(primaryStatus(testVolume, 0))
		r.blkidReports(cryptPath(testVolume), "ext4")
		r.on(binResize2fs, cryptPath(testVolume)).returns("").then(func() {
			if len(m.MountCalls()) != 1 {
				t.Error("resize2fs ran before mount(2) — the grow must be the online one")
			}
		})
		// mount(2) puts the device in the table; the grow reads it there.
		m.OnMount(func() { r.scriptMount(cryptPath(testVolume), testMountPoint) })
		if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
			t.Fatalf("Mount: %v", err)
		}
		r.assertRan(t, "resize2fs "+cryptPath(testVolume))
		r.assertNotRan(t, "e2fsck")

		meta, err := p.loadMeta(testVolume)
		if err != nil {
			t.Fatalf("loadMeta: %v", err)
		}
		if meta.FSGrowPending {
			t.Error("Mount grew the filesystem and left the record owing a grow")
		}
		if meta.SizeBytes != newSize {
			t.Errorf("recorded size = %d, want %d", meta.SizeBytes, newSize)
		}

		// Paid once: the next Mount owes nothing and runs no grow tool.
		r.reset()
		r.scriptStatus(primaryStatus(testVolume, 0))
		r.blkidReports(cryptPath(testVolume), "ext4")
		if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
			t.Fatalf("second Mount: %v", err)
		}
		r.assertNotRan(t, "resize2fs")
	})

	t.Run("xfs grows through its mount point", func(t *testing.T) {
		p, r, crypt, m := newEncryptedProviderWithMounter(t)
		spec := defaultSpec()
		spec.FSType = "xfs"
		provision(t, p, r, spec)
		crypt.sized(devicePath(0), encryptedDeviceBytes(testSize))
		r.reset()
		scriptEncryptedResize(r, crypt, secondaryStatus(testVolume, 0), newSize)
		if err := p.Resize(context.Background(), testVolume, newSize); err != nil {
			t.Fatalf("Resize: %v", err)
		}
		crypt.unlocked(cryptName(testVolume), devicePath(0)) // what Promote does, at the new size
		r.devicePresent(cryptPath(testVolume))

		r.reset()
		r.scriptStatus(primaryStatus(testVolume, 0))
		r.blkidReports(cryptPath(testVolume), "xfs")
		r.on(binXFSGrowfs, testMountPoint).returns("")
		m.OnMount(func() { r.scriptMount(cryptPath(testVolume), testMountPoint) })
		if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
			t.Fatalf("Mount: %v", err)
		}
		r.assertRan(t, "xfs_growfs "+testMountPoint)
		meta, err := p.loadMeta(testVolume)
		if err != nil {
			t.Fatalf("loadMeta: %v", err)
		}
		if meta.FSGrowPending {
			t.Error("Mount grew the filesystem and left the record owing a grow")
		}
	})

	t.Run("unencrypted ext4 resized while Secondary", func(t *testing.T) {
		p, r, m := newTestProviderWithMounter(t)
		provision(t, p, r, defaultSpec())
		r.reset()
		r.scriptStatus(secondaryStatus(testVolume, 0))
		r.scriptLVS(lvsJSON(lvEntry{
			Name: testVolume, VG: testVG,
			Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
		}))
		r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(newSize, false), 10)+"b", "vg0/"+testVolume).returns("")
		r.on(binDRBDAdm, "resize", testVolume).returns("")
		if err := p.Resize(context.Background(), testVolume, newSize); err != nil {
			t.Fatalf("Resize: %v", err)
		}
		meta, err := p.loadMeta(testVolume)
		if err != nil {
			t.Fatalf("loadMeta: %v", err)
		}
		if !meta.FSGrowPending {
			t.Fatal("a Resize on a Secondary did not record the grow it could not perform")
		}

		r.reset()
		r.scriptStatus(primaryStatus(testVolume, 0))
		r.blkidReports(devicePath(0), "ext4")
		r.on(binResize2fs, devicePath(0)).returns("")
		m.OnMount(func() { r.scriptMount(devicePath(0), testMountPoint) })
		if err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{}); err != nil {
			t.Fatalf("Mount: %v", err)
		}
		r.assertRan(t, "resize2fs "+devicePath(0))
		assertMounted(t, m, devicePath(0), testMountPoint, "ext4", 0, "")
		assertNoUnmount(t, m)
	})
}

// TestMountUnwindsWhenTheDeferredGrowFails is the other half of paying the
// debt: a Mount that returns an error has mounted nothing, the same promise
// the propagation check keeps. Leaving the volume mounted behind an error
// would report a mount that did not happen; leaving the grow silently undone
// behind a success would report a size the filesystem never reached. The
// record keeps owing the grow either way, so the next Mount tries again.
func TestMountUnwindsWhenTheDeferredGrowFails(t *testing.T) {
	newSize := testSize * 2

	deferred := func(t *testing.T) (*Provider, *fakeRunner, *fakeLUKS, *mount.Fake) {
		t.Helper()
		p, r, crypt, m := newEncryptedProviderWithMounter(t)
		provision(t, p, r, defaultSpec())
		crypt.sized(devicePath(0), encryptedDeviceBytes(testSize))
		r.reset()
		scriptEncryptedResize(r, crypt, secondaryStatus(testVolume, 0), newSize)
		if err := p.Resize(context.Background(), testVolume, newSize); err != nil {
			t.Fatalf("Resize: %v", err)
		}
		r.reset()
		return p, r, crypt, m
	}

	t.Run("the grow tool fails", func(t *testing.T) {
		p, r, crypt, m := deferred(t)
		crypt.unlocked(cryptName(testVolume), devicePath(0))
		r.devicePresent(cryptPath(testVolume))
		r.scriptStatus(primaryStatus(testVolume, 0))
		r.blkidReports(cryptPath(testVolume), "ext4")
		r.on(binResize2fs, cryptPath(testVolume)).fails(1, "resize2fs: Operation not permitted while trying to resize")
		m.OnMount(func() { r.scriptMount(cryptPath(testVolume), testMountPoint) })

		err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
		if err == nil {
			t.Fatal("Mount succeeded although the grow it owed failed")
		}
		if !strings.Contains(err.Error(), "resize2fs") {
			t.Errorf("the error does not carry the tool's failure: %v", err)
		}
		assertUnmounted(t, m, testMountPoint)
		meta, loadErr := p.loadMeta(testVolume)
		if loadErr != nil {
			t.Fatalf("loadMeta: %v", loadErr)
		}
		if !meta.FSGrowPending {
			t.Error("a failed grow cleared the record's debt")
		}
	})

	t.Run("the mapping is stale", func(t *testing.T) {
		p, r, crypt, m := deferred(t)
		// Opened BEFORE the device reached its size — a Primary promoted in
		// the middle of the pair's resize — and never reloaded.
		crypt.sized(devicePath(0), encryptedDeviceBytes(testSize))
		crypt.unlocked(cryptName(testVolume), devicePath(0))
		r.devicePresent(cryptPath(testVolume))
		crypt.sized(devicePath(0), encryptedDeviceBytes(newSize))
		r.scriptStatus(primaryStatus(testVolume, 0))
		r.blkidReports(cryptPath(testVolume), "ext4")
		r.on(binResize2fs, cryptPath(testVolume)).returns("")
		m.OnMount(func() { r.scriptMount(cryptPath(testVolume), testMountPoint) })

		err := p.Mount(context.Background(), testVolume, testMountPoint, common.MountOptions{})
		if !errors.Is(err, ErrMappingStale) {
			t.Fatalf("Mount over a stale mapping with a grow owed = %v, want ErrMappingStale", err)
		}
		r.assertNotRan(t, "resize2fs")
		assertUnmounted(t, m, testMountPoint)
	})
}

// TestRestoreIntoALargerEncryptedVolumeGrowsAndDefersTheFilesystem closes the
// other road to the same defect. A restore that asks for more than its source
// held is finished by the same grow sequence Resize runs, and on an encrypted
// provider that sequence now completes the way a Secondary's Resize does: the
// device grows, the record follows, and the filesystem — the SOURCE's, copied
// byte for byte into a container the first Promote will open at the new size
// — is owed a grow that Mount pays. A restore at the source's own size involves
// no grow and owes nothing.
func TestRestoreIntoALargerEncryptedVolumeGrowsAndDefersTheFilesystem(t *testing.T) {
	const snapLV = "vol1.snap.nightly"
	snapshot := common.SnapshotID("vg0/" + snapLV)

	// The snapshot is of an ENCRYPTED volume, so its origin is the encrypted
	// backing size; a plain origin would already be a grow on this provider.
	origin := roundUpTo(backingBytes(testSize, true), testExtentSize)
	script := func(r *fakeRunner) {
		r.scriptLVS(lvsJSON(
			lvEntry{
				Name: snapLV, VG: testVG, Origin: testVolume,
				OriginSize: strconv.FormatInt(origin, 10),
			},
			lvEntry{Name: "vol2", VG: testVG, Size: strconv.FormatInt(origin, 10)},
		))
	}

	t.Run("larger is grown and the filesystem deferred", func(t *testing.T) {
		newSize := testSize * 4
		p, r, _ := newEncryptedProvider(t)
		provision(t, p, r, defaultSpec())
		r.reset()
		script(r)
		r.scriptProvisionAt("vol2", origin)
		// The restored resource comes up Secondary; the grow runs against it.
		r.scriptStatus(secondaryStatus("vol2", 1))
		r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(newSize, true), 10)+"b", "vg0/vol2").returns("")
		r.on(binDRBDAdm, "resize", "vol2").returns("")

		vol, err := p.Provision(context.Background(), common.VolumeSpec{
			Name: "vol2", SizeBytes: newSize, Replicas: 2, SourceSnapshotID: snapshot,
		})
		if err != nil {
			t.Fatalf("restore into a larger encrypted volume: %v", err)
		}
		assertCopied(t, r, "/dev/vg0/"+snapLV, "/dev/vg0/vol2")
		r.assertRan(t, fmt.Sprintf("lvextend --size %db vg0/vol2", backingBytes(newSize, true)))
		r.assertRan(t, "drbdadm resize vol2")
		r.assertNotRan(t, "resize2fs")
		if vol.Spec.SizeBytes != newSize {
			t.Errorf("Volume.Spec.SizeBytes = %d, want %d", vol.Spec.SizeBytes, newSize)
		}
		meta, err := p.loadMeta("vol2")
		if err != nil {
			t.Fatalf("loadMeta: %v", err)
		}
		if meta.SizeBytes != newSize {
			t.Errorf("recorded size = %d, want %d", meta.SizeBytes, newSize)
		}
		if !meta.FSGrowPending {
			t.Error("the restored volume's filesystem is the source's, and the record does not owe it a grow")
		}
	})

	t.Run("the source's own size is not a grow", func(t *testing.T) {
		p, r, _ := newEncryptedProvider(t)
		provision(t, p, r, defaultSpec())
		r.reset()
		script(r)
		r.scriptProvisionAt("vol2", origin)

		vol, err := p.Provision(context.Background(), common.VolumeSpec{
			Name: "vol2", SizeBytes: testSize, Replicas: 2, SourceSnapshotID: snapshot,
		})
		if err != nil {
			t.Fatalf("restore at the source's size on an encrypted provider: %v", err)
		}
		assertCopied(t, r, "/dev/vg0/"+snapLV, "/dev/vg0/vol2")
		assertNotRun(t, r, "lvextend")
		if vol.Spec.SizeBytes != testSize {
			t.Errorf("Volume.Spec.SizeBytes = %d, want %d", vol.Spec.SizeBytes, testSize)
		}
		meta, err := p.loadMeta("vol2")
		if err != nil {
			t.Fatalf("loadMeta: %v", err)
		}
		if meta.FSGrowPending {
			t.Error("a same-size restore owes no grow")
		}
	})
}

// -----------------------------------------------------------------------------
// Sizing
// -----------------------------------------------------------------------------

// encryptedDeviceKiB is the size, in the KiB drbdsetup reports, of the DRBD
// device an encrypted testSize volume presents: the backing volume as LVM
// rounded it, less DRBD's metadata. The literal in the shared status fixtures
// is the PLAIN volume's, and an encrypted one is larger by the header.
func encryptedDeviceKiB() int64 {
	backing := roundUpTo(backingBytes(testSize, true), testExtentSize)
	return (backing - metadataBytes(dataBytes(testSize, true))) / statusSizeUnit
}

// encryptedStatus is a status fixture whose device is that size.
func encryptedStatus(role string) string {
	doc := statusJSON(testVolume, 0, role, "Connected", "Established", "UpToDate")
	return strings.Replace(doc, `"size": 1052600`, fmt.Sprintf(`"size": %d`, encryptedDeviceKiB()), 1)
}

// TestProvisionAllocatesTheLUKSHeaderOnTop is the sizing contract at the
// command line: an encrypted volume's backing logical volume is created
// backingBytes(size, encrypted) large, header included, so the filesystem
// inside the container has the whole of what the caller asked for. The earlier
// revision created it at the plain size and took the header out of the
// request, 16 MiB short.
func TestProvisionAllocatesTheLUKSHeaderOnTop(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())

	want := fmt.Sprintf("lvcreate --yes --name vol1 --size %db vg0", backingBytes(testSize, true))
	r.assertRan(t, want)
	if plain := backingBytes(testSize, false); backingBytes(testSize, true)-plain < luks.HeaderBytes {
		t.Errorf("encrypted backing %d is not a header above the plain %d", backingBytes(testSize, true), plain)
	}

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if meta.SizeBytes != testSize {
		t.Errorf("recorded size = %d, want the usable %d", meta.SizeBytes, testSize)
	}
}

// TestStatusReportsUsableCapacityOnAnEncryptedVolume pins what Status says
// about an encrypted volume in every state: USABLE capacity, per
// VolumeStatus.SizeBytes, which above a LUKS container is the DRBD device
// less the header — the device itself is ciphertext, header included, and is
// not what the caller can write to. Down, the record is already usable and is
// reported as it is. In no state is the figure below what was requested.
func TestStatusReportsUsableCapacityOnAnEncryptedVolume(t *testing.T) {
	device := encryptedDeviceKiB() * statusSizeUnit
	usable := device - luks.HeaderBytes

	tests := []struct {
		name     string
		status   string
		open     bool
		wantSize int64
	}{
		{name: "down", status: emptyStatus, wantSize: testSize},
		{name: "secondary", status: encryptedStatus("Secondary"), wantSize: usable},
		{name: "primary", status: encryptedStatus("Primary"), open: true, wantSize: usable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r, crypt := newEncryptedProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()
			r.scriptStatus(tc.status)
			// The mapping exists only while the container is open; closed,
			// its path has no node behind it, as in production.
			if tc.open {
				crypt.unlocked(cryptName(testVolume), devicePath(0))
				r.scriptMount(cryptPath(testVolume), "")
			} else {
				r.deviceAbsent(cryptPath(testVolume))
			}

			status, err := p.Status(context.Background(), testVolume)
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if status.SizeBytes != tc.wantSize {
				t.Errorf("SizeBytes = %d, want %d (device %d less the %d-byte header)", status.SizeBytes, tc.wantSize, device, int64(luks.HeaderBytes))
			}
			if status.SizeBytes < testSize {
				t.Errorf("SizeBytes = %d is below the %d requested", status.SizeBytes, testSize)
			}
		})
	}
}

// TestStatusDoesNotLookForAMappingThatIsNotThere is the #69 review finding.
//
// On an encrypted provider the filesystem device is /dev/mapper/<name>, which
// exists only while the container is open. Production's mount-table lookup
// resolves a device by stat(2) BEFORE reading the table, so asking about a
// closed container's mapping is a DeviceError, not "not mounted" — and Status
// asked unconditionally. Every Secondary after a Demote, and every volume
// resized Secondary-side with its container closed (which this branch
// explicitly supports), therefore failed Status. The earlier fixture answered
// an empty list for any path and hid it.
//
// The gate is the container's state, and it is the same ownership check
// everything else uses: a closed container is not mounted and is not looked
// up; an open one is looked up and answers mounted or not; a mapping under our
// name over some OTHER device is an error, surfaced rather than read as
// "closed".
func TestStatusDoesNotLookForAMappingThatIsNotThere(t *testing.T) {
	t.Run("secondary with the container closed", func(t *testing.T) {
		p, r, _ := newEncryptedProvider(t)
		provision(t, p, r, defaultSpec())
		r.reset()
		r.scriptStatus(encryptedStatus("Secondary"))
		r.deviceAbsent(cryptPath(testVolume))

		status, err := p.Status(context.Background(), testVolume)
		if err != nil {
			t.Fatalf("Status on a Secondary whose container is closed: %v", err)
		}
		if status.State != common.VolumeStateAttached {
			t.Errorf("State = %v, want Attached", status.State)
		}
		if r.mountLookups() != 0 {
			t.Errorf("the mount table was consulted %d times about a mapping that does not exist", r.mountLookups())
		}
	})

	t.Run("primary with the container open answers the mount table", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			target string
			want   common.VolumeState
		}{
			{name: "mounted", target: testMountPoint, want: common.VolumeStateMounted},
			{name: "not mounted", target: "", want: common.VolumeStateAttached},
		} {
			t.Run(tc.name, func(t *testing.T) {
				p, r, crypt := newEncryptedProvider(t)
				provision(t, p, r, defaultSpec())
				crypt.unlocked(cryptName(testVolume), devicePath(0))
				r.reset()
				r.scriptStatus(encryptedStatus("Primary"))
				r.scriptMount(cryptPath(testVolume), tc.target)

				status, err := p.Status(context.Background(), testVolume)
				if err != nil {
					t.Fatalf("Status: %v", err)
				}
				if status.State != tc.want {
					t.Errorf("State = %v, want %v", status.State, tc.want)
				}
			})
		}
	})

	t.Run("a mapping over another device is an error, not closed", func(t *testing.T) {
		p, r, crypt := newEncryptedProvider(t)
		provision(t, p, r, defaultSpec())
		crypt.unlocked(cryptName(testVolume), "/dev/drbd9")
		r.reset()
		r.scriptStatus(encryptedStatus("Primary"))
		r.scriptMount(cryptPath(testVolume), "")

		if _, err := p.Status(context.Background(), testVolume); err == nil {
			t.Fatal("Status read a mapping over somebody else's device as this volume's closed container")
		}
	})
}

// TestStatusRefusesADeviceSmallerThanTheHeader is the fail-closed edge of the
// subtraction. A DRBD device on an encrypted provider that is not even a
// header long cannot be one this provider sized, and reporting it as zero or
// negative usable capacity would be an invented number.
func TestStatusRefusesADeviceSmallerThanTheHeader(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()
	doc := strings.Replace(primaryStatus(testVolume, 0), `"size": 1052600`, `"size": 8192`, 1)
	r.scriptStatus(doc)

	_, err := p.Status(context.Background(), testVolume)
	if err == nil {
		t.Fatal("Status over a device smaller than the LUKS header succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "header") {
		t.Errorf("error %q does not say what the device is smaller than", err)
	}
}

// TestRestoreOfAnEncryptedSnapshotIsSizedLikeAProvision closes the sizing loop
// through the restore path. A snapshot of an encrypted volume has the
// encrypted backing size as its origin, so a restore of it at the same usable
// size must plan the same backing size a fresh Provision would — no grow, no
// shrink — or a same-size restore would read as one or the other.
func TestRestoreOfAnEncryptedSnapshotIsSizedLikeAProvision(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	const snapLV = "vol1.snap.nightly"
	origin := roundUpTo(backingBytes(testSize, true), testExtentSize)
	r.scriptLVS(lvsJSON(
		lvEntry{Name: snapLV, VG: testVG, Origin: testVolume, OriginSize: strconv.FormatInt(origin, 10)},
		lvEntry{Name: "vol2", VG: testVG, Size: strconv.FormatInt(origin, 10)},
	))
	r.scriptProvisionAt("vol2", origin)

	vol, err := p.Provision(context.Background(), common.VolumeSpec{
		Name: "vol2", SizeBytes: testSize, Replicas: 2,
		SourceSnapshotID: common.SnapshotID("vg0/" + snapLV),
	})
	if err != nil {
		t.Fatalf("same-size restore of an encrypted snapshot: %v", err)
	}
	r.assertRan(t, fmt.Sprintf("lvcreate --yes --name vol2 --size %db vg0", origin))
	assertNotRun(t, r, "lvextend")
	if vol.Spec.SizeBytes != testSize {
		t.Errorf("Volume.Spec.SizeBytes = %d, want the usable %d", vol.Spec.SizeBytes, testSize)
	}

	// And the plain origin size, which the earlier revision would have
	// accepted as same-size, now reads as what it is on this provider: a
	// source one header too small for a request of testSize usable.
	if plain := roundUpTo(backingBytes(testSize, false), testExtentSize); plain >= origin {
		t.Errorf("plain origin %d is not below the encrypted origin %d", plain, origin)
	}
}
