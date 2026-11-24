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
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The MS_* bits the option table names, aliased so the table itself compiles on
// every platform while only Linux supplies real values.
const (
	msRDONLY      = unix.MS_RDONLY
	msNOSUID      = unix.MS_NOSUID
	msNODEV       = unix.MS_NODEV
	msNOEXEC      = unix.MS_NOEXEC
	msSYNCHRONOUS = unix.MS_SYNCHRONOUS
	msDIRSYNC     = unix.MS_DIRSYNC
	msNOATIME     = unix.MS_NOATIME
	msNODIRATIME  = unix.MS_NODIRATIME
	msRELATIME    = unix.MS_RELATIME
	msSTRICTATIME = unix.MS_STRICTATIME
	msLAZYTIME    = unix.MS_LAZYTIME
	msNOSYMFOLLOW = unix.MS_NOSYMFOLLOW
)

// systemMounter is the real Mounter: it pins a path to a descriptor and then
// operates on the descriptor.
type systemMounter struct{}

// pinDirectory resolves an absolute directory path to an O_PATH descriptor with openat2, refusing symlinks and magic links.
func pinDirectory(path string) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}

	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	switch {
	case err == nil:
		return fd, nil
	case errors.Is(err, unix.ENOSYS):
		// No fallback. The racy path is the vulnerability this exists to close,
		// so a kernel that cannot pin gets a refusal rather than a mount that
		// looks checked and is not.
		return -1, fmt.Errorf("go-blockstore/mount: resolving %q needs openat2, which this kernel does not provide; "+
			"Linux 5.6 or newer is required to mount safely: %w", path, err)
	case errors.Is(err, unix.ELOOP):
		return -1, fmt.Errorf("go-blockstore/mount: %q, or a directory above it, is a symbolic link; "+
			"a mount target must be a real directory: %w", path, err)
	default:
		return -1, fmt.Errorf("go-blockstore/mount: resolving %q: %w", path, err)
	}
}

// Check reports whether a target can be pinned, using exactly the resolution a
// Mount would — the same openat2 call, the same refusals — and then lets it go.
//
// It exists so a caller can find out that a target is unusable BEFORE doing
// something it cannot take back. A provider that formats a raw volume on its
// first mount needs to fail a doomed request before the mkfs, and a check that
// merely resembled the real one would pass for a path the mount then refuses:
// an Lstat, for instance, says nothing about a symlink at a PARENT, which the
// pin rejects. Sharing the call is what keeps the two from ever disagreeing.
//
// A target that passes here can still fail at Mount — the path may be swapped
// in between, which is the race the pin exists to survive. That is not a
// weakness of this function: Mount resolves again, from scratch, and mounts
// against what IT pinned.
func Check(target string) error {
	fd, err := pinDirectory(target)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// Mount attaches source at the pinned target.
func (systemMounter) Mount(_ context.Context, source, target, fsType string, flags uintptr, data string) error {
	fd, err := pinDirectory(target)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	// Address the pinned descriptor through its /proc/self/fd path.
	if err := unix.Mount(source, fdPath(fd), fsType, flags, data); err != nil {
		return fmt.Errorf("go-blockstore/mount: mounting %s at %s: %w", source, target, err)
	}
	return nil
}

// Unmount detaches whatever is mounted at target.
//
// The PARENT is pinned here, not the target. A descriptor on the target resolves
// to the root of the mounted filesystem and holds it open, so the unmount that
// follows fails with EBUSY — measured. Pinning the parent fixes every directory
// above the mount point, and UMOUNT_NOFOLLOW covers the one component left:
// the kernel refuses rather than following a symlink in the final position, so
// a swapped final component cannot redirect the unmount onto somebody else's
// mount.
func (systemMounter) Unmount(_ context.Context, target string) error {
	parent, name := filepath.Dir(target), filepath.Base(target)

	fd, err := pinDirectory(parent)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Unmount(filepath.Join(fdPath(fd), name), unix.UMOUNT_NOFOLLOW); err != nil {
		return fmt.Errorf("go-blockstore/mount: unmounting %s: %w", target, err)
	}
	return nil
}

// fdPath names an open descriptor as a path, for the syscalls that take one.
func fdPath(fd int) string {
	return fmt.Sprintf("/proc/self/fd/%d", fd)
}

// The MS_* bits, exported for callers that assert on what a mount was given.
// The table above is written against the lowercase aliases; these are the same
// values under the names a caller outside this package would look for.
const (
	ReadOnly    = msRDONLY
	NoSUID      = msNOSUID
	NoDev       = msNODEV
	NoExec      = msNOEXEC
	Synchronous = msSYNCHRONOUS
	DirSync     = msDIRSYNC
	NoATime     = msNOATIME
	NoDirATime  = msNODIRATIME
	RelATime    = msRELATIME
	StrictATime = msSTRICTATIME
	LazyTime    = msLAZYTIME
	NoSymFollow = msNOSYMFOLLOW
)
