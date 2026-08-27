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
// It is an interface for the same reason CommandRunner is: so tests can drive
// every path around it without root or a real filesystem. The real
// implementation is used unless one is injected.
type Mounter interface {
	// Mount attaches source at target. flags are MS_* bits and data is the
	// filesystem-specific option string, split by mountArguments.
	Mount(ctx context.Context, source, target, fsType string, flags uintptr, data string) error

	// Unmount detaches whatever is mounted at target.
	Unmount(ctx context.Context, target string) error
}
