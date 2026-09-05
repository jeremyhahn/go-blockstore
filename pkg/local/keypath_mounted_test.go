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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// substitutingAt makes the fake's Mount do what mount(2) does to path
// resolution: it puts the volume's own contents where the target is, and
// records the mount in the table the rollback reads.
//
// It is the whole reason these tests can exist. Every earlier key-path test
// asserts on a filesystem that never changes across the mount, so a check that
// runs before mount(2) and a check that runs after it are indistinguishable to
// them — which is precisely why three rounds of review could each correct the
// predicate and each still leave a hole.
func substitutingAt(t *testing.T, runner *fakeRunner, device, target string, populate func() error) {
	t.Helper()
	runner.OnMount(func() {
		if err := populate(); err != nil {
			t.Errorf("populating the volume as it is mounted: %v", err)
			return
		}
		runner.withMounts(map[string][]string{device: {target}})
	})
}

// TestAKeyPathTheMountSubstitutesIsRefusedAgainstTheMountedFilesystem is the
// case that defeats a pre-mount prediction, and it defeats it in a way no
// correction to the predicate reaches.
//
// The configured key path reaches the volume through a symlink whose
// DESTINATION DOES NOT EXIST until the volume is mounted. resolveKeyFile
// therefore cannot follow the link — it resolves the path against its deepest
// existing ancestor and hands back the literal, host-side location, which is
// outside the volume and correctly so, at that instant. Mount a filesystem
// carrying keys/vol.key at the target and the same configured path resolves
// into the volume and reads the volume's own bytes.
//
// This is not a direction of the predicate that was got backwards. The
// pre-mount filesystem does not contain the answer, and the fallback that hides
// it is the one a deployment placing key material after startup depends on. The
// test asserts BOTH halves: that the pre-mount check accepts this fixture (so
// the case really is one prediction lets through) and that the post-mount
// observation refuses it.
func TestAKeyPathTheMountSubstitutesIsRefusedAgainstTheMountedFilesystem(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "mnt")
	etc := filepath.Join(base, "etc")
	for _, dir := range []string{target, etc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", dir, err)
		}
	}
	// The configured path looks entirely respectable and, before the mount, IS.
	// /etc/keys points at a directory that does not exist while the mount point
	// is empty.
	link := filepath.Join(etc, "keys")
	if err := os.Symlink(filepath.Join(target, "keys"), link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	keyFile := filepath.Join(link, "vol.key")

	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := keyed(t, runner, keyFile)

	// The first half of the evidence: asked of the filesystem as it stands
	// before mount(2), the containment check says the key is outside. If this
	// ever starts refusing, the fixture has stopped being the case #51 is
	// about and everything below proves nothing.
	if err := p.checkKeyFileOutside(target, "the path this volume is being mounted on"); err != nil {
		t.Fatalf("the pre-mount check refused before anything was mounted: %v\n"+
			"this fixture must be one prediction ACCEPTS, or the test is not measuring the gap", err)
	}
	if resolved, err := resolveKeyFile(keyFile); err != nil || resolved != keyFile {
		t.Fatalf("before the mount resolveKeyFile(%q) = %q, %v; want the literal path, "+
			"which is the fallback that makes this case invisible", keyFile, resolved, err)
	}

	// The mount substitutes: this volume carries keys/vol.key at that relative
	// position, so the configured path comes to mean the volume's file.
	substitutingAt(t, runner, "/dev/vg0/data", target, func() error {
		if err := os.MkdirAll(filepath.Join(target, "keys"), 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(target, "keys", "vol.key"), []byte("VOLUME-KEY"), 0o600)
	})

	err := p.Mount(context.Background(), "data", target, common.MountOptions{})
	if err == nil {
		t.Fatal("Mount published the volume with the group's unlock credential resolvable inside it")
	}
	if !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount = %v, want ErrKeyFileInsideVolume", err)
	}
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("the refusal is not in the ErrInvalidArgument family: %v", err)
	}

	// The mount HAPPENED. That is the point: prediction let it through, so the
	// only place the truth was available was after the fact. A test that
	// asserted no mount was made would be asserting the old behavior.
	if got := runner.mountCalls(); len(got) != 1 {
		t.Fatalf("mount calls = %v, want exactly one: the pre-mount check accepts this case", got)
	}
	// And it was undone, because the refusal means a credential is readable at
	// the target.
	if got := runner.unmountCalls(); len(got) != 1 || got[0] != target {
		t.Errorf("unmount calls = %v, want [%s]: a refused mount must not be left standing", got, target)
	}

	// The exposure was real rather than merely computed: the configured path
	// now reads the volume's own bytes, not the host's.
	inside := filepath.Join(target, "keys", "vol.key")
	if body, readErr := os.ReadFile(keyFile); readErr != nil || string(body) != "VOLUME-KEY" {
		t.Errorf("reading %s = %q, %v; want the volume's own bytes, which is what makes this an exposure",
			keyFile, string(body), readErr)
	}
	// The operator is sent to where the key actually is, not to the path they
	// configured — those differ here, which is the whole difficulty.
	if !strings.Contains(err.Error(), inside) {
		t.Errorf("the refusal does not name %s, where the key resolved to: %v", inside, err)
	}
}

// TestAMountThatSubstitutesAPathIntoAnotherVolumeIsRefused is why the
// post-mount observation re-asks the CROSS-VOLUME question and not only the
// question about the target.
//
// Mounting volume B substitutes a symlink that leads into volume A's mount, so
// after the mount the configured key path resolves inside A — a volume this
// call never touched. Neither pre-mount check can see it: before the mount the
// symlink does not exist, so the path resolves to its literal host location and
// is inside nothing.
func TestAMountThatSubstitutesAPathIntoAnotherVolumeIsRefused(t *testing.T) {
	base := t.TempDir()
	mountOfA := filepath.Join(base, "a")
	target := filepath.Join(base, "b")
	etc := filepath.Join(base, "etc")
	for _, dir := range []string{mountOfA, target, etc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", dir, err)
		}
	}
	// The key lives in volume A, reached through a hop that volume B carries.
	if err := os.WriteFile(filepath.Join(mountOfA, "shared.key"), []byte("passphrase"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(etc, "keys")
	if err := os.Symlink(filepath.Join(target, "hop"), link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	keyFile := filepath.Join(link, "shared.key")

	runner := newFakeRunner().
		withLVs(
			lvFixture{Name: "a", SizeBytes: gib, Active: true},
			lvFixture{Name: "b", SizeBytes: gib, Active: true},
		).
		withBlkid(map[string]string{"/dev/vg0/a": "ext4", "/dev/vg0/b": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/a": {mountOfA}})
	p := keyed(t, runner, keyFile)

	if err := p.checkKeyFileOutsideOurVolumes(context.Background(), []lvInfo{
		{Name: "a"}, {Name: "b"},
	}); err != nil {
		t.Fatalf("the pre-mount cross-volume check refused before anything was mounted: %v", err)
	}

	runner.OnMount(func() {
		// Volume B's filesystem carries a symlink out into volume A.
		if err := os.Symlink(mountOfA, filepath.Join(target, "hop")); err != nil {
			t.Errorf("Symlink inside the mounted volume: %v", err)
			return
		}
		runner.withMounts(map[string][]string{"/dev/vg0/a": {mountOfA}, "/dev/vg0/b": {target}})
	})

	err := p.Mount(context.Background(), "b", target, common.MountOptions{})
	if !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount of B = %v, want the key that now resolves inside A refused", err)
	}
	if !strings.Contains(err.Error(), "volume a") {
		t.Errorf("the refusal does not name which volume holds the key: %v", err)
	}
	if got := runner.mountCalls(); len(got) != 1 {
		t.Fatalf("mount calls = %v, want exactly one", got)
	}
	if got := runner.unmountCalls(); len(got) != 1 || got[0] != target {
		t.Errorf("unmount calls = %v, want [%s]", got, target)
	}
}

// TestAMountThatSubstitutesNothingRelevantIsAccepted is the other direction of
// the mutation requirement, and it is the one a guard is least forgiven for
// getting wrong.
//
// The volume's contents land at the target and change no path the key is
// reached through. The observation must accept it, leave the mount standing,
// and unmount nothing.
func TestAMountThatSubstitutesNothingRelevantIsAccepted(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "mnt")
	keys := filepath.Join(base, "keys")
	for _, dir := range []string{target, keys} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", dir, err)
		}
	}
	keyFile := filepath.Join(keys, "volume.key")
	if err := os.WriteFile(keyFile, []byte("passphrase"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := keyed(t, runner, keyFile)

	substitutingAt(t, runner, "/dev/vg0/data", target, func() error {
		if err := os.MkdirAll(filepath.Join(target, "payload"), 0o755); err != nil {
			return err
		}
		// Even a file with the key's own NAME, somewhere the key path does not
		// reach. Containment is a question about paths, not about names.
		return os.WriteFile(filepath.Join(target, "payload", "volume.key"), []byte("unrelated"), 0o600)
	})

	if err := p.Mount(context.Background(), "data", target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount of a correctly separated key file = %v, want nil", err)
	}
	if got := runner.unmountCalls(); len(got) != 0 {
		t.Errorf("unmounted %v: an accepted mount must be left standing", got)
	}
}

// TestAKeyPathRefusalIsNotUnwoundOverSomebodyElsesFilesystem keeps the rollback
// from doing damage of its own.
//
// umount(2) takes a path and detaches whatever is VISIBLE there. Between
// mount(2) returning and the observation refusing, anything on the host can
// mount over the target — and unmounting the path would then take that
// filesystem down while the refused mount stayed underneath it. The finding is
// still reported; so is the fact that the mount is still there, because both
// are true and an operator needs both.
func TestAKeyPathRefusalIsNotUnwoundOverSomebodyElsesFilesystem(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "mnt")
	etc := filepath.Join(base, "etc")
	for _, dir := range []string{target, etc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", dir, err)
		}
	}
	link := filepath.Join(etc, "keys")
	if err := os.Symlink(filepath.Join(target, "keys"), link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	keyFile := filepath.Join(link, "vol.key")

	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := keyed(t, runner, keyFile)

	substitutingAt(t, runner, "/dev/vg0/data", target, func() error {
		if err := os.MkdirAll(filepath.Join(target, "keys"), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(target, "keys", "vol.key"), []byte("VOLUME-KEY"), 0o600); err != nil {
			return err
		}
		// Somebody else lands on the target in the window the rollback has to
		// survive.
		runner.overMount(target, "/dev/somebody-else")
		return nil
	})

	err := p.Mount(context.Background(), "data", target, common.MountOptions{})
	if !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount = %v, want the key-path finding reported", err)
	}
	if !errors.Is(err, errUnwindTargetTakenOver) {
		t.Errorf("Mount = %v, want the failed rollback joined onto the finding", err)
	}
	if got := runner.unmountCalls(); len(got) != 0 {
		t.Errorf("unmounted %v, which is not this provider's filesystem", got)
	}
}

// TestTheObservationSurvivesACallerWhoGaveUp covers the window the completion
// context exists for.
//
// A caller whose deadline passes during mount(2) leaves a mount that nothing
// has checked and nothing will clean up — and reusing their dead context makes
// every read that would find it fail first, so the code reads as though it had
// cleaned up. The observation and its rollback run on a detached context for
// the same reason verifyMountPropagation's do.
//
// The fixture is the CROSS-VOLUME one on purpose. The target-side half of the
// observation resolves paths and reads no mount table, so it cannot notice a
// dead context at all; only the half that asks the kernel where this group's
// volumes are mounted can. A version of this test built on the target-side case
// passes whether the context is detached or not, which is a test that names a
// behavior it does not reach.
func TestTheObservationSurvivesACallerWhoGaveUp(t *testing.T) {
	base := t.TempDir()
	mountOfA := filepath.Join(base, "a")
	target := filepath.Join(base, "b")
	etc := filepath.Join(base, "etc")
	for _, dir := range []string{mountOfA, target, etc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(mountOfA, "shared.key"), []byte("passphrase"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(etc, "keys")
	if err := os.Symlink(filepath.Join(target, "hop"), link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	keyFile := filepath.Join(link, "shared.key")

	runner := newFakeRunner().
		withLVs(
			lvFixture{Name: "a", SizeBytes: gib, Active: true},
			lvFixture{Name: "b", SizeBytes: gib, Active: true},
		).
		withBlkid(map[string]string{"/dev/vg0/a": "ext4", "/dev/vg0/b": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/a": {mountOfA}})
	p := keyed(t, runner, keyFile)

	ctx, cancel := context.WithCancel(context.Background())
	runner.OnMount(func() {
		if err := os.Symlink(mountOfA, filepath.Join(target, "hop")); err != nil {
			t.Errorf("Symlink inside the mounted volume: %v", err)
			return
		}
		runner.withMounts(map[string][]string{"/dev/vg0/a": {mountOfA}, "/dev/vg0/b": {target}})
		// The caller gives up in the instant after mount(2) returned.
		cancel()
	})
	defer cancel()

	err := p.Mount(ctx, "b", target, common.MountOptions{})
	if !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount = %v, want the observation to have reached its answer despite the dead context", err)
	}
	if errors.Is(err, ErrKeyFileUnresolvable) {
		t.Errorf("Mount = %v: the mount-table read gave up with the caller instead of completing", err)
	}
	if got := runner.unmountCalls(); len(got) != 1 || got[0] != target {
		t.Errorf("unmount calls = %v, want [%s]: the mount a caller abandoned is exactly the one nothing else will remove", got, target)
	}
}

// TestTheTargetIsAskedAboutEvenWhenTheMountTableGoesBlind is why the
// observation asks about the TARGET and not only about where this group's
// volumes are mounted.
//
// The cross-volume question is answered by resolving each of this provider's
// devices and reading the kernel's mount table for it. A device that is not
// there is deliberately not an error — for any volume, one of the two spellings
// it is asked under does not exist, which is the ordinary case — so that lookup
// CONTINUES past it. When it is the mounted volume's own node that has gone
// between mount(2) and the observation, every lookup continues past and the
// cross-volume question returns "nothing found" rather than a refusal.
//
// The target-side question does not go through the mount table at all. It
// resolves paths, which is why it still sees the substitution here.
func TestTheTargetIsAskedAboutEvenWhenTheMountTableGoesBlind(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "mnt")
	etc := filepath.Join(base, "etc")
	for _, dir := range []string{target, etc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", dir, err)
		}
	}
	link := filepath.Join(etc, "keys")
	if err := os.Symlink(filepath.Join(target, "keys"), link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	keyFile := filepath.Join(link, "vol.key")

	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := keyed(t, runner, keyFile)

	runner.OnMount(func() {
		if err := os.MkdirAll(filepath.Join(target, "keys"), 0o755); err != nil {
			t.Errorf("MkdirAll inside the mounted volume: %v", err)
			return
		}
		if err := os.WriteFile(filepath.Join(target, "keys", "vol.key"), []byte("VOLUME-KEY"), 0o600); err != nil {
			t.Errorf("WriteFile inside the mounted volume: %v", err)
			return
		}
		// The device node is gone by the time the observation looks, so every
		// mount-table lookup reports it absent and is continued past.
		runner.failMountTable(os.ErrNotExist)
	})

	// The cross-volume question really cannot see it: same fixture, same
	// moment, and it reports no exposure.
	err := p.Mount(context.Background(), "data", target, common.MountOptions{})
	if !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount = %v, want the substituted key path refused by the target-side question", err)
	}
	// The rollback needs the same table, so it cannot confirm the mount is
	// still ours and refuses to unmount by path — reported alongside the
	// finding rather than in place of it, because both are true.
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Mount = %v, want the failed rollback joined onto the finding", err)
	}
	if got := runner.unmountCalls(); len(got) != 0 {
		t.Errorf("unmounted %v without being able to confirm the filesystem there is ours", got)
	}
}
