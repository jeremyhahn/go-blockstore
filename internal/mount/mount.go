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

// Package mount mounts and unmounts through descriptors pinned without following symlinks, shared by every provider that mounts.
package mount

import "context"

// Mounter mounts and unmounts against a pinned descriptor; System() is used unless a provider is given one.
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
