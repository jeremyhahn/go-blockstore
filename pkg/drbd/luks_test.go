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
// Resize
// -----------------------------------------------------------------------------

// TestResizeIsRefusedOnAnEncryptedVolume pins the fail-closed answer this
// revision gives to growing an encrypted volume.
//
// The dm-crypt mapping is sized from the replicated device at the moment
// Promote opens it and go-luks2 exposes no table reload, so after a drbdadm
// resize the plaintext device is still its old size and the filesystem inside
// it CANNOT be grown to the new one. An earlier revision grew the device
// anyway, skipped the filesystem, and recorded the new size — reporting a
// resize as complete over a filesystem that had not moved, and letting a
// same-size retry "succeed" without doing anything. The refusal has to come
// before the first command, so that nothing partial is left behind either.
func TestResizeIsRefusedOnAnEncryptedVolume(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	// Were the refusal missing, these would let the resize proceed: an up
	// Primary, a backing volume at its current size, a clean extend.
	r.scriptStatus(primaryStatus(testVolume, 0))
	r.scriptLVS(lvsJSON(lvEntry{
		Name: "vol1", VG: testVG,
		Size: strconv.FormatInt(roundUpTo(backingBytes(testSize, false), testExtentSize), 10),
	}))
	r.on(binLVExtend, "--size", strconv.FormatInt(backingBytes(testSize*2, false), 10)+"b", "vg0/vol1").returns("")
	r.on(binDRBDAdm, "resize", testVolume).returns("")

	err := p.Resize(context.Background(), testVolume, testSize*2)
	if !errors.Is(err, ErrResizeEncrypted) {
		t.Fatalf("Resize of an encrypted volume = %v, want ErrResizeEncrypted", err)
	}
	// ErrUnsupported is the portable reading: this backend cannot serve the
	// request as configured, and no retry changes that until #62 lands.
	if !errors.Is(err, common.ErrUnsupported) {
		t.Errorf("ErrResizeEncrypted does not wrap common.ErrUnsupported: %v", err)
	}
	if !strings.Contains(err.Error(), "#62") {
		t.Errorf("the refusal does not name the issue that lifts it: %v", err)
	}

	// Nothing partial: not the lvextend, not the drbdadm resize, not even the
	// role query that precedes them.
	if got := r.commands(); len(got) != 0 {
		t.Errorf("a refused Resize ran commands:\n  %s", strings.Join(got, "\n  "))
	}
	meta, loadErr := p.loadMeta(testVolume)
	if loadErr != nil {
		t.Fatalf("loadMeta: %v", loadErr)
	}
	if meta.SizeBytes != testSize {
		t.Errorf("recorded size = %d after a refused Resize, want the unchanged %d", meta.SizeBytes, testSize)
	}
}

// TestRestoreIntoALargerVolumeIsRefusedOnAnEncryptedProvider closes the other
// road to the same defect. A restore that asks for more than its source held is
// finished by the same grow sequence Resize runs, and on an encrypted provider
// that sequence would record the larger size over a container whose filesystem
// is still the source's. The plan refuses before a logical volume exists, so
// there is nothing to roll back; a restore at the source's own size involves no
// grow and is untouched.
func TestRestoreIntoALargerVolumeIsRefusedOnAnEncryptedProvider(t *testing.T) {
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

	t.Run("larger is refused before anything is created", func(t *testing.T) {
		p, r, _ := newEncryptedProvider(t)
		provision(t, p, r, defaultSpec())
		r.reset()
		script(r)
		r.scriptProvisionAt("vol2", origin)

		_, err := p.Provision(context.Background(), common.VolumeSpec{
			Name: "vol2", SizeBytes: testSize * 4, Replicas: 2, SourceSnapshotID: snapshot,
		})
		if !errors.Is(err, ErrResizeEncrypted) {
			t.Fatalf("restore into a larger encrypted volume = %v, want ErrResizeEncrypted", err)
		}
		for _, got := range r.commands() {
			if !strings.HasPrefix(got, binLVS+" ") {
				t.Errorf("a refused restore ran %q; only the snapshot lookup may run", got)
			}
		}
		if len(r.copyCalls()) != 0 {
			t.Errorf("a refused restore copied a device: %v", r.copyCalls())
		}
		if _, loadErr := p.loadMeta("vol2"); loadErr == nil {
			t.Error("a refused restore left a record for vol2")
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
	})
}

// TestFilesystemGrowFailsLoudlyOverAnEncryptedVolume guards the last line of
// defense. Resize and restoreSource refuse an encrypted volume before the grow
// is reached, so growFilesystem should never see one; if a future caller gets
// there anyway, the device above has grown under a stale mapping and a quiet
// nil would let the caller record a size the filesystem never reached. An
// earlier revision returned exactly that nil.
func TestFilesystemGrowFailsLoudlyOverAnEncryptedVolume(t *testing.T) {
	p, r, _ := newEncryptedProvider(t)
	provision(t, p, r, defaultSpec())
	r.reset()

	meta, err := p.loadMeta(testVolume)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	meta.FSType = "ext4"

	// Were it to proceed, this is the mount lookup it would make first.
	r.scriptMount(cryptPath(testVolume), testMountPoint)
	err = p.growFilesystem(context.Background(), &meta)
	if !errors.Is(err, ErrResizeEncrypted) {
		t.Fatalf("growFilesystem over an encrypted volume = %v, want ErrResizeEncrypted", err)
	}
	if got := r.commands(); len(got) != 0 {
		t.Errorf("growFilesystem over an encrypted volume ran commands: %v", got)
	}
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
		wantSize int64
	}{
		{name: "down", status: emptyStatus, wantSize: testSize},
		{name: "secondary", status: encryptedStatus("Secondary"), wantSize: usable},
		{name: "primary", status: encryptedStatus("Primary"), wantSize: usable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, r, _ := newEncryptedProvider(t)
			provision(t, p, r, defaultSpec())
			r.reset()
			r.scriptStatus(tc.status)
			r.scriptMount(cryptPath(testVolume), "")

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
