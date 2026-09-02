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

// keyed builds a provider whose key file is at the given path, by the settings
// route — the only route where this package can see the path at all.
func keyed(t *testing.T, runner *fakeRunner, keyFile string) *Provider {
	t.Helper()
	return newTestProvider(t, runner, func(o *Options) {
		o.KeyProvider = FileKeyProvider(keyFile)
		o.luksKeyFile = keyFile
	})
}

// TestKeyFileInsideTheMountIsRefused is the exposure this guard exists for. The
// volume unlocks, nothing errors, and the credential is published to the
// container that was designed never to see it.
func TestKeyFileInsideTheMountIsRefused(t *testing.T) {
	target := t.TempDir()
	keyFile := filepath.Join(target, "volume.key")

	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		// The volume is ALREADY mounted here, so the key file is inside its
		// filesystem rather than underneath a mount point. That distinction is
		// the whole thing: a file in a directory about to be mounted over is
		// HIDDEN by the mount, not published by it.
		withMounts(map[string][]string{"/dev/vg0/data": {target}})
	p := keyed(t, runner, keyFile)

	err := p.Mount(context.Background(), "data", target, common.MountOptions{})
	if err == nil {
		t.Fatal("Mount published the key file to the workload")
	}
	if !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount = %v, want ErrKeyFileInsideVolume", err)
	}
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("the refusal is not in the ErrInvalidArgument family: %v", err)
	}
	// Nothing was mounted: the exposure begins with the mount, so the refusal
	// has to come first.
	if got := runner.mountCalls(); len(got) != 0 {
		t.Errorf("mounted %v despite refusing", got)
	}
}

// TestKeyFileReachedByASymlinkIntoTheMountIsRefused is the case a string
// comparison misses entirely: the configured path is outside, and the bytes
// come from inside.
func TestKeyFileReachedByASymlinkIntoTheMountIsRefused(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	real := filepath.Join(target, "volume.key")
	if err := os.WriteFile(real, []byte("passphrase"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// The configured path looks entirely respectable.
	keyFile := filepath.Join(base, "etc-keys.key")
	if err := os.Symlink(real, keyFile); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/data": {target}})
	p := keyed(t, runner, keyFile)

	err := p.Mount(context.Background(), "data", target, common.MountOptions{})
	if !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount = %v, want the symlinked key file refused", err)
	}
	// The message must name where it actually resolved, or an operator looking
	// at the configured path will not believe it.
	if !strings.Contains(err.Error(), real) {
		t.Errorf("the refusal does not say where the key really is: %v", err)
	}
}

// TestKeyFileOutsideTheMountIsAccepted is the other half of the mutation
// requirement: the guard must not refuse a correct configuration.
func TestKeyFileOutsideTheMountIsAccepted(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "mnt")
	keys := filepath.Join(base, "keys")
	for _, dir := range []string{target, keys} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
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

	if err := p.Mount(context.Background(), "data", target, common.MountOptions{}); err != nil {
		t.Fatalf("Mount of a correctly separated key file = %v, want nil", err)
	}
}

// TestASiblingPathIsNotInsideTheMount pins the comparison. A prefix test on raw
// strings says /mnt/database is inside /mnt/data, and refusing that would break
// a deployment that did nothing wrong.
func TestASiblingPathIsNotInsideTheMount(t *testing.T) {
	cases := map[string]struct {
		key, dir string
		want     bool
	}{
		"inside":            {"/mnt/data/k.key", "/mnt/data", true},
		"the directory":     {"/mnt/data", "/mnt/data", true},
		"deep inside":       {"/mnt/data/a/b/k.key", "/mnt/data", true},
		"sibling by prefix": {"/mnt/database/k.key", "/mnt/data", false},
		"entirely apart":    {"/etc/keys/k.key", "/mnt/data", false},
		"parent":            {"/mnt/k.key", "/mnt/data", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := withinPath(tc.key, tc.dir); got != tc.want {
				t.Errorf("withinPath(%q, %q) = %v, want %v", tc.key, tc.dir, got, tc.want)
			}
		})
	}
}

// TestAKeyFileThatDoesNotExistYetIsStillJudged covers the deployment order that
// would otherwise slip past: the directory is inside the volume and the file
// arrives later. It is the same exposure the moment it appears.
func TestAKeyFileThatDoesNotExistYetIsStillJudged(t *testing.T) {
	target := t.TempDir()
	keyFile := filepath.Join(target, "not-yet", "volume.key")

	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/data": {target}})
	p := keyed(t, runner, keyFile)

	if err := p.Mount(context.Background(), "data", target, common.MountOptions{}); !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount = %v, want the not-yet-created key file refused", err)
	}
}

// TestARelativeKeyPathIsRefused fails closed on a path this provider cannot
// resolve to a location at all.
func TestARelativeKeyPathIsRefused(t *testing.T) {
	target := t.TempDir()
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/data": {target}})
	p := keyed(t, runner, "keys/volume.key")

	err := p.Mount(context.Background(), "data", target, common.MountOptions{})
	if !errors.Is(err, ErrKeyFileUnresolvable) {
		t.Fatalf("Mount = %v, want ErrKeyFileUnresolvable", err)
	}
}

// TestNoKeyFileConfiguredIsNotChecked keeps the guard off the path it cannot
// see. A caller supplying its own KeyProvider closes over whatever it reads,
// and inventing a check there would be a check of nothing.
func TestNoKeyFileConfiguredIsNotChecked(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner, withKey)

	if err := p.Mount(context.Background(), "data", t.TempDir(), common.MountOptions{}); err != nil {
		t.Fatalf("Mount with an opaque KeyProvider = %v, want nil", err)
	}
}

// TestTheSettingsRouteCarriesTheKeyPath is what makes any of this reachable in
// the deployment it protects: the path is knowable only because NewFromSettings
// kept it.
func TestTheSettingsRouteCarriesTheKeyPath(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "volume.key")
	if err := os.WriteFile(keyFile, []byte("passphrase"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p, err := NewFromSettings(map[string]string{
		SettingVolumeGroup: "vg0",
		SettingPreflight:   "off",
		SettingLUKSKeyFile: keyFile,
	})
	if err != nil {
		t.Fatalf("NewFromSettings: %v", err)
	}
	if p.keyFile != keyFile {
		t.Errorf("keyFile = %q, want the configured path so containment can be checked", p.keyFile)
	}
}

// TestASecondMountCannotPublishAKeyInsideTheFirst is the bypass: the new target
// does not contain the key, so checking only the new target passes — while the
// mount publishes the same volume, key and all, at a second path.
//
// The order matters and it is reachable: attach, write the key file into the
// volume through the mount it already has, then mount it somewhere else.
func TestASecondMountCannotPublishAKeyInsideTheFirst(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	keyFile := filepath.Join(first, "volume.key")

	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		// Already mounted at the first path, which is where the key now lives.
		withMounts(map[string][]string{"/dev/vg0/data": {first}})
	p := keyed(t, runner, keyFile)

	err := p.Mount(context.Background(), "data", second, common.MountOptions{})
	if err == nil {
		t.Fatal("a second mount published a key file living inside the first")
	}
	if !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount = %v, want ErrKeyFileInsideVolume", err)
	}
	if got := runner.mountCalls(); len(got) != 0 {
		t.Errorf("mounted %v despite refusing", got)
	}
}

// TestAKeyPathTraversingDotDotIsRefused closes a bypass that reads as correct.
//
// filepath.Clean collapses "link/.." to the parent of the link; the kernel
// follows the symlink and goes up from its TARGET. So a configured path can
// clean to somewhere harmless while os.Open reads from inside the volume, and a
// guard comparing the cleaned path would allow exactly the exposure it exists
// to stop.
func TestAKeyPathTraversingDotDotIsRefused(t *testing.T) {
	base := t.TempDir()
	volume := filepath.Join(base, "mnt")
	inside := filepath.Join(volume, "dir")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// The key really is inside the volume.
	if err := os.WriteFile(filepath.Join(volume, "volume.key"), []byte("passphrase"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// Built by concatenation, NOT filepath.Join: Join cleans its result, so it
	// would collapse the ".." before the kernel ever saw the path — the very
	// lexical-versus-kernel difference this test is about, arriving in the test
	// itself.
	traversing := link + "/../volume.key"
	if _, err := os.ReadFile(traversing); err != nil {
		t.Fatalf("the fixture does not reproduce the kernel's resolution: %v", err)
	}
	if cleaned := filepath.Clean(traversing); cleaned == filepath.Join(volume, "volume.key") {
		t.Fatal("Clean agrees with the kernel here, so this test proves nothing")
	}

	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"}).
		withMounts(map[string][]string{"/dev/vg0/data": {volume}})
	p := keyed(t, runner, traversing)

	err := p.Mount(context.Background(), "data", volume, common.MountOptions{})
	if !errors.Is(err, ErrKeyFileUnresolvable) {
		t.Fatalf("Mount = %v, want the traversing key path refused", err)
	}
}

// TestAKeyFileUnderTheMountPointIsRefused pins a rule whose REASON is not the
// obvious one, and which two review rounds pulled in opposite directions.
//
// Mounting does not publish the file underneath — it hides it. Measured: a file
// in a directory is unreadable at that path the moment anything is mounted over
// it. So "the mount publishes the key" is false, and a guard justified that way
// is justified wrongly.
//
// The rule survives on a different reason. After the mount the configured path
// MEANS SOMETHING ELSE, and which something depends on the volume's contents:
// either nothing is there and the provider can no longer read its own key, or
// the volume has a file at that path and the provider's key is now a file
// inside the volume it just handed over — attacker-controllable if the volume's
// contents are. Measured: a path reading HOST-KEY before the mount reads
// VOLUME-KEY after. Neither case is knowable from outside, so the class is
// refused.
func TestAKeyFileUnderTheMountPointIsRefused(t *testing.T) {
	target := t.TempDir()
	keyFile := filepath.Join(target, "volume.key")
	if err := os.WriteFile(keyFile, []byte("passphrase"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Nothing of this volume is mounted anywhere: this is the FIRST mount, the
	// case the existing-mounts check cannot see.
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := keyed(t, runner, keyFile)

	err := p.Mount(context.Background(), "data", target, common.MountOptions{})
	if !errors.Is(err, ErrKeyFileInsideVolume) {
		t.Fatalf("Mount = %v, want the key path under the mount point refused", err)
	}
	if got := runner.mountCalls(); len(got) != 0 {
		t.Errorf("mounted %v despite refusing", got)
	}
}
