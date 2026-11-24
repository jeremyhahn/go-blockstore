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

	"github.com/jeremyhahn/go-blockstore/internal/mountguard"
	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
)

// MountPropagationPolicy selects whether Mount verifies the new mount is visible outside this namespace.
// It is off by default; Posture reports it either way. The check is internal/mountguard, shared with pkg/local.
type MountPropagationPolicy = mountguard.Policy

const (
	// MountPropagationUnchecked does not verify propagation after mounting. It
	// is the zero value, so a deployment that says nothing gets the behavior
	// this provider had before the guard existed.
	MountPropagationUnchecked = mountguard.Unchecked

	// MountPropagationShared requires each mount to be SHARED, and refuses with
	// a typed error naming the required setting when it is not.
	MountPropagationShared = mountguard.Shared
)

// MountPropagationReader is the optional half of the mount-table seam; a table without it is refused when the guard is on.
type MountPropagationReader = mountinfo.PropagationReader

// mountGuard is this provider's policy over its mount table, built at each call site.
func (p *Provider) mountGuard() mountguard.Guard {
	return mountguard.Guard{Policy: p.cfg.MountPropagation, Table: p.mountTable}
}

// verifyMountPropagation checks the mount at target propagates; a table that cannot answer is a refusal.
func (p *Provider) verifyMountPropagation(ctx context.Context, device, target string) (uint32, error) {
	return p.mountGuard().Verify(ctx, device, target)
}

// unwindUnverifiedMount removes a refused mount on its own context; see mountguard.Guard.Unwind.
func (p *Provider) unwindUnverifiedMount(ctx context.Context, device, target string, id uint32, finding error) error {
	return p.mountGuard().Unwind(ctx, device, target, id, finding, p.mounter.Unmount)
}
