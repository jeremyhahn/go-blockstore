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

//go:build kernel_keypath

package local

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Checks on the live kernel, in a user and mount namespace, that a mount changes what the key path resolves to; tag kernel_keypath, refusals fail.

// keypathNamespaceEnv marks the re-executed child. Its presence is the only
// difference between the two halves of this test.
const keypathNamespaceEnv = "GO_BLOCKSTORE_KEYPATH_KERNEL_CHILD"

// keypathBaseEnv carries the scratch directory from parent to child, because
// the child cannot use the parent's t.TempDir — it is a fresh process with its
// own T.
const keypathBaseEnv = "GO_BLOCKSTORE_KEYPATH_KERNEL_BASE"

// TestAgainstARunningKernelAMountSubstitutesWhatTheKeyPathResolvesTo: a dangling symlink into the target resolves into the volume after mount.
func TestAgainstARunningKernelAMountSubstitutesWhatTheKeyPathResolvesTo(t *testing.T) {
	if os.Getenv(keypathNamespaceEnv) != "" {
		runKeyPathSubstitutionChild(t)
		return
	}
	relaunchKeyPathTestInMountNamespace(t, "mnt", "etc")
}

// relaunchKeyPathTestInMountNamespace reruns this test inside a user and mount namespace.
func relaunchKeyPathTestInMountNamespace(t *testing.T, dirs ...string) {
	t.Helper()

	base := t.TempDir()
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o755); err != nil {
			t.Fatalf("preparing %s: %v", dir, err)
		}
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), keypathNamespaceEnv+"=1", keypathBaseEnv+"="+base)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		// Mapping this user to uid 0 inside the namespace is what makes the
		// mounts permitted there. It confers nothing outside it.
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}

	output, err := cmd.CombinedOutput()
	reportKernelChildResult(t, string(output), err)
}

// runKeyPathSubstitutionChild is the half that runs as root inside the
// namespace.
func runKeyPathSubstitutionChild(t *testing.T) {
	base := os.Getenv(keypathBaseEnv)
	if base == "" {
		t.Fatalf("%s is unset, so the child has no directory to mount in", keypathBaseEnv)
	}
	// Nothing this child mounts may reach the caller's namespace.
	if err := unix.Mount("none", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatalf("UNSUPPORTED: making / private: %v", err)
	}

	target := filepath.Join(base, "mnt")
	link := filepath.Join(base, "etc", "keys")
	if linkErr := os.Symlink(filepath.Join(target, "keys"), link); linkErr != nil {
		t.Fatalf("Symlink: %v", linkErr)
	}
	keyFile := filepath.Join(link, "vol.key")

	// The provider is given the key PATH but a static key provider, not
	// FileKeyProvider: this test measures the containment check, which reads
	// p.keyFile, and never reads the key. Handing a path derived from the
	// environment to a file reader would also be a taint gosec is right to
	// object to in a package whose whole subject is untrusted paths.
	p := newTestProvider(t, newFakeRunner(), withKey, func(o *Options) { o.luksKeyFile = keyFile })
	const why = "the path this volume is being mounted on"

	// ---- before the mount ----
	resolvedBefore, resolveErr := resolveKeyFile(keyFile)
	if resolveErr != nil {
		t.Fatalf("resolveKeyFile before the mount: %v", resolveErr)
	}
	if resolvedBefore != keyFile {
		t.Fatalf("before the mount resolveKeyFile(%q) = %q, want the literal path: "+
			"the dangling link is what makes this case invisible to prediction", keyFile, resolvedBefore)
	}
	if acceptErr := p.checkKeyFileOutside(target, why); acceptErr != nil {
		t.Fatalf("before the mount the check refused (%v); this fixture must be one "+
			"a pre-mount check ACCEPTS or it does not measure the gap", acceptErr)
	}
	if _, readErr := os.ReadFile(keyFile); !os.IsNotExist(readErr) {
		t.Fatalf("before the mount reading %s = %v, want ENOENT", keyFile, readErr)
	}
	devBefore := deviceOfPath(t, target)
	t.Logf("before mount(2): resolves to %s, check accepts, read is ENOENT, target is on device %d:%d",
		resolvedBefore, unix.Major(devBefore), unix.Minor(devBefore))

	// ---- the substitution, by mount(2) ----
	if mountErr := unix.Mount("tmpVOL", target, "tmpfs", 0, "size=1m"); mountErr != nil {
		t.Fatalf("UNSUPPORTED: mounting tmpfs at %s: %v", target, mountErr)
	}
	if mkErr := os.MkdirAll(filepath.Join(target, "keys"), 0o755); mkErr != nil {
		t.Fatalf("creating keys/ inside the mounted volume: %v", mkErr)
	}
	if writeErr := os.WriteFile(filepath.Join(target, "keys", "vol.key"), []byte("VOLUME-KEY"), 0o600); writeErr != nil {
		t.Fatalf("writing the volume's own key file: %v", writeErr)
	}

	// After the mount: assert from the target's device number that a filesystem was mounted.
	devMounted := deviceOfPath(t, target)
	if devMounted == devBefore {
		t.Fatalf("target is still on device %d:%d after mount(2): nothing was substituted",
			unix.Major(devBefore), unix.Minor(devBefore))
	}
	// The configured path now reads the volume's bytes.
	body, readErr := os.ReadFile(keyFile)
	if readErr != nil {
		t.Fatalf("after the mount reading %s: %v", keyFile, readErr)
	}
	if string(body) != "VOLUME-KEY" {
		t.Fatalf("after the mount %s reads %q, want the volume's own bytes: "+
			"without that this test is not the substitution case", keyFile, string(body))
	}

	inside := filepath.Join(target, "keys", "vol.key")
	resolvedAfter, resolveAfterErr := resolveKeyFile(keyFile)
	if resolveAfterErr != nil {
		t.Fatalf("resolveKeyFile after the mount: %v", resolveAfterErr)
	}
	if resolvedAfter != inside {
		t.Errorf("after the mount resolveKeyFile(%q) = %q, want %q", keyFile, resolvedAfter, inside)
	}
	refusal := p.checkKeyFileOutside(target, why)
	if !errors.Is(refusal, ErrKeyFileInsideVolume) {
		t.Fatalf("after the mount the check = %v, want ErrKeyFileInsideVolume: "+
			"the same configured path, the same code, a different filesystem", refusal)
	}
	t.Logf("after mount(2): resolves to %s, check refuses, read is %q", resolvedAfter, string(body))

	// ---- and back ----
	//
	// The substitution is reversible, which is the property that makes it a
	// substitution rather than a one-way effect — and the reason one
	// observation of it always looks like hiding OR publishing but never both.
	if umountErr := unix.Unmount(target, 0); umountErr != nil {
		t.Fatalf("unmounting %s: %v", target, umountErr)
	}
	if devAfter := deviceOfPath(t, target); devAfter != devBefore {
		t.Errorf("target is on device %d:%d after umount(2), want the original %d:%d",
			unix.Major(devAfter), unix.Minor(devAfter), unix.Major(devBefore), unix.Minor(devBefore))
	}
	if _, readErr := os.ReadFile(inside); !os.IsNotExist(readErr) {
		t.Errorf("reading %s after the unmount = %v, want ENOENT: the volume's file went with the mount", inside, readErr)
	}
	if acceptErr := p.checkKeyFileOutside(target, why); acceptErr != nil {
		t.Errorf("after the unmount the check = %v, want it to accept again", acceptErr)
	}
	t.Logf("after umount(2): target is back on device %d:%d and the check accepts again",
		unix.Major(devBefore), unix.Minor(devBefore))
}

// deviceOfPath reports the device a path resolves to, which is the kernel's own
// answer to "is a different filesystem here now".
func deviceOfPath(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Dev
}
