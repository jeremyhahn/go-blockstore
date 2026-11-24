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

// Package mount performs the two filesystem operations a storage provider
// cannot route through an exec'd binary: mounting and unmounting.
//
// It is internal and shared rather than per-provider because the reason it
// exists is the same for every backend that mounts. Validating a path and then
// handing the STRING to mount(8) — or to mount(2) — leaves a window in which
// the path can become a symlink, and the mount that follows is privileged: it
// lands wherever the link points, including over /. Closing that window means
// resolving the path to a descriptor with symlink resolution refused and then
// operating on the descriptor, which no amount of argument checking around an
// exec'd binary reproduces.
//
// One copy, because a security-relevant mechanism duplicated per provider is
// one that drifts per provider. pkg/local and pkg/drbd both consume this, and
// pkg/cephrbd will make three.
package mount

import "context"

// Mounter performs the two operations this provider cannot route through
// CommandRunner: mounting and unmounting.
//
// They are not exec'd like everything else because the target has to be PINNED.
// Validating a path and then handing the string to mount(8) leaves a window in
// which the path can become a symlink — and the mount that follows it is
// privileged and lands wherever the symlink points, including over /. Closing
// that window means resolving the path to a descriptor with symlink resolution
// refused and then operating on the descriptor, which no amount of argument
// checking around an exec'd binary can reproduce.
//
// It is an interface for the same reason a command runner is: so tests can
// drive every path around it without root or a real filesystem. System() is
// used unless a provider is given one.
type Mounter interface {
	// Mount attaches source at target. flags are MS_* bits and data is the
	// filesystem-specific option string, split by mountArguments.
	Mount(ctx context.Context, source, target, fsType string, flags uintptr, data string) error

	// Unmount detaches whatever is mounted at target.
	Unmount(ctx context.Context, target string) error
}

// System returns the real Mounter: it pins a target to a descriptor and then
// operates on the descriptor. Off Linux it refuses, because a target cannot be
// pinned there.
func System() Mounter { return systemMounter{} }
