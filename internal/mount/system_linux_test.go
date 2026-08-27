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

//go:build linux

package mount

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// These exercise the resolution itself, which needs a real filesystem but no
// root and no LVM: pinning a directory is an ordinary unprivileged operation.

// TestPinDirectoryRefusesSymlinks is the finding. Lexical validation accepts any
// clean absolute path, so whether the path IS a directory — rather than a
// symlink aimed somewhere else — is decided here or nowhere.
func TestPinDirectoryRefusesSymlinks(t *testing.T) {
	base := t.TempDir()

	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	// A plain directory pins.
	fd, err := pinDirectory(real)
	if err != nil {
		t.Fatalf("pinDirectory of a real directory: %v", err)
	}
	_ = unix.Close(fd)

	cases := map[string]func() string{
		"final component is a symlink": func() string {
			link := filepath.Join(base, "final")
			if err := os.Symlink(real, link); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			return link
		},
		"an intermediate component is a symlink": func() string {
			mid := filepath.Join(base, "mid")
			if err := os.Symlink(base, mid); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			return filepath.Join(mid, "real")
		},
		"symlink to the root filesystem": func() string {
			link := filepath.Join(base, "toroot")
			if err := os.Symlink("/", link); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			return link
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			path := build()
			fd, err := pinDirectory(path)
			if err == nil {
				_ = unix.Close(fd)
				t.Fatalf("pinDirectory followed a symlink at %q", path)
			}
		})
	}
}

// TestPinDirectoryRefusesMagicLinks covers RESOLVE_NO_MAGICLINKS. Without it a
// target under /proc/self/fd reaches whatever the process has open, which is a
// second way to aim a privileged mount somewhere it was never checked against.
func TestPinDirectoryRefusesMagicLinks(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	if fd, err := pinDirectory(fdPath(int(f.Fd()))); err == nil {
		_ = unix.Close(fd)
		t.Fatal("pinDirectory resolved a magic link")
	}
}

// TestPinnedTargetSurvivesASwap is the race the pinning exists for, made
// deterministic. The directory is resolved, then MOVED aside and replaced by a
// symlink aimed somewhere else, and only then is the descriptor used — which is
// the shape of the attack: validation sees a directory, the operation sees a
// symlink. A lexical design follows the swap. A pinned one still addresses the
// directory it resolved.
func TestPinnedTargetSurvivesASwap(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	elsewhere := filepath.Join(base, "elsewhere")
	for _, d := range []string{target, elsewhere} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
	}

	// Resolve first, exactly as Mount does.
	fd, err := pinDirectory(target)
	if err != nil {
		t.Fatalf("pinDirectory: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()

	// Swap the path: the original directory moves aside and a symlink takes its
	// name. Moving rather than deleting keeps the original addressable, which
	// is what lets the test say WHICH one the descriptor holds.
	moved := filepath.Join(base, "moved")
	if err := os.Rename(target, moved); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := os.Symlink(elsewhere, target); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// The descriptor still refers to the directory that was resolved, not to
	// whatever now answers to its name.
	var pinned unix.Stat_t
	if err := unix.Fstat(fd, &pinned); err != nil {
		t.Fatalf("Fstat: %v", err)
	}
	inodeOf := func(path string) uint64 {
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			t.Fatalf("Stat %s: %v", path, err)
		}
		return st.Ino
	}
	if pinned.Ino != inodeOf(moved) {
		t.Error("the pinned descriptor no longer refers to the directory it resolved")
	}
	if pinned.Ino == inodeOf(elsewhere) {
		t.Fatal("the pinned descriptor followed the swap and reached the symlink's destination")
	}

	// Writing through the descriptor lands in the original directory.
	if err := os.WriteFile(filepath.Join(fdPath(fd), "marker"), []byte("pinned"), 0o600); err != nil {
		t.Fatalf("writing through the pinned descriptor: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(moved, "marker")); err != nil {
		t.Errorf("the write did not land in the resolved directory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "marker")); err == nil {
		t.Error("the write landed where the symlink points")
	}

	// And the swapped path no longer resolves at all — which is what a lexical
	// design would have sailed straight through.
	if fd2, err := pinDirectory(target); err == nil {
		_ = unix.Close(fd2)
		t.Error("the swapped path still resolved; a symlink was accepted as a target")
	}
}

// TestSystemMounterRefusesUnpinnableTargets covers the real Mounter's refusal
// paths, which need no privilege: resolution fails before either syscall is
// reached. The success paths need root and are covered by the integration suite.
func TestSystemMounterRefusesUnpinnableTargets(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()

	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	viaLink := filepath.Join(link, "under")

	var m systemMounter

	if err := m.Mount(ctx, "/dev/null", link, "ext4", 0, ""); err == nil {
		t.Error("Mount accepted a symlinked target")
	}
	if err := m.Unmount(ctx, viaLink); err == nil {
		t.Error("Unmount accepted a target beneath a symlinked parent")
	}

	// A real directory gets past resolution and fails in the syscall instead —
	// the other branch of each, and the reason these are separate errors.
	if err := m.Mount(ctx, "/dev/null", realDir, "ext4", 0, ""); err == nil {
		t.Error("Mount of /dev/null as ext4 succeeded")
	}
	if err := m.Unmount(ctx, realDir); err == nil {
		t.Error("Unmount of a directory that is not a mount point succeeded")
	}
}

// TestMountArgumentsSplitsFlagsFromData is the classification that mount(2)
// makes load-bearing. A generic option handed over as data is not applied by the
// kernel and not rejected either — nosuid would simply not take.
func TestMountArgumentsSplitsFlagsFromData(t *testing.T) {
	flags, data := Arguments(true,
		[]string{"nosuid", "nodev", "noexec", "noatime", "data=ordered", "errors=remount-ro"})

	for name, bit := range map[string]uintptr{
		"MS_RDONLY":  msRDONLY,
		"MS_NOSUID":  msNOSUID,
		"MS_NODEV":   msNODEV,
		"MS_NOEXEC":  msNOEXEC,
		"MS_NOATIME": msNOATIME,
	} {
		if flags&bit == 0 {
			t.Errorf("%s was not set", name)
		}
	}
	if data != "data=ordered,errors=remount-ro" {
		t.Errorf("data = %q, want only the filesystem options", data)
	}
}

// TestMountArgumentsTreatsDefaultsAsNoOps checks the options that name a kernel
// default: they are accepted for clarity and set nothing.
func TestMountArgumentsTreatsDefaultsAsNoOps(t *testing.T) {
	flags, data := Arguments(false,
		[]string{"rw", "suid", "dev", "exec", "async", "atime", "diratime"})
	if flags != 0 {
		t.Errorf("flags = %#x, want none set", flags)
	}
	if data != "" {
		t.Errorf("data = %q, want empty", data)
	}
}

// TestCheckAgreesWithMount is the property the pre-format guard in a provider
// depends on: Check must accept exactly what a Mount would pin and refuse
// exactly what it would refuse. A cheaper lookalike — an Lstat, say — passes a
// path whose PARENT is a symlink, and a provider that formatted a volume on the
// strength of it would have destroyed something for a mount that then failed.
func TestCheckAgreesWithMount(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatalf("creating directories: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("creating file: %v", err)
	}

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"a real directory", real, true},
		{"a directory below a real directory", filepath.Join(real, "sub"), true},
		{"the symlink itself", filepath.Join(base, "link"), false},
		{"a real directory below a SYMLINKED parent", filepath.Join(base, "link", "sub"), false},
		{"a regular file", file, false},
		{"a path that does not exist", filepath.Join(base, "absent"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.target)
			if (err == nil) != tc.want {
				t.Fatalf("Check(%q) = %v, want accepted=%v", tc.target, err, tc.want)
			}
			// And the pin itself reaches the same verdict, since Check is how a
			// caller asks the question the pin will answer later.
			fd, pinErr := pinDirectory(tc.target)
			if pinErr == nil {
				_ = unix.Close(fd)
			}
			if (pinErr == nil) != (err == nil) {
				t.Errorf("Check and pinDirectory disagree on %q: %v vs %v", tc.target, err, pinErr)
			}
		})
	}
}
