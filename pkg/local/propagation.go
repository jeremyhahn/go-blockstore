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

	"github.com/jeremyhahn/go-blockstore/internal/mountguard"
)

// MountPropagationPolicy selects whether Mount verifies that the mount it just
// made can be seen outside this mount namespace.
//
// Wrong mount propagation is the quietest failure in the whole deployment
// model. mount(2) succeeds, the provider reports success, and the workload in
// its own namespace walks to the path and finds the directory exactly as it was
// before anything was mounted on it. There is no error, no log line and no
// non-zero exit anywhere; the first evidence is a workload writing to its own
// filesystem, and the second is somebody wondering where the data went.
//
// It is an alias for the shared policy, not a copy of it: pkg/drbd asks the same
// question of the same mount table, and two policies would be two chances to
// answer it differently. See internal/mountguard.
type MountPropagationPolicy = mountguard.Policy

const (
	// MountPropagationUnchecked does not verify propagation after mounting. It
	// is the zero value; see mountguard.Unchecked for why.
	MountPropagationUnchecked = mountguard.Unchecked

	// MountPropagationShared requires each mount to be SHARED, and refuses with
	// a typed error naming the required setting when it is not.
	MountPropagationShared = mountguard.Shared
)

// errUnwindTargetTakenOver reports a rollback that did not happen because the
// mount at the target stopped being the one this call made.
var errUnwindTargetTakenOver = mountguard.ErrTargetTakenOver

// mountPropagationSpellings returns the accepted settings values in a stable
// order, for the error a misspelling produces.
func mountPropagationSpellings() []string { return mountguard.Spellings() }

// mountGuard is this provider's policy over its mount table.
//
// It is built at each call site rather than held as a field, so the policy the
// guard enforces and the policy Posture reports are the same one value.
func (p *Provider) mountGuard() mountguard.Guard {
	return mountguard.Guard{Policy: p.mountPropagation, Table: p.mountTable}
}

// verifyMountPropagation checks that the mount at target propagates, and is
// what turns the silent failure into a refusal. See mountguard.Guard.Verify.
func (p *Provider) verifyMountPropagation(ctx context.Context, device, target string) (uint32, error) {
	return p.mountGuard().Verify(ctx, device, target)
}

// unwindUnverifiedMount removes a mount the propagation guard refused. See
// mountguard.Guard.Unwind.
func (p *Provider) unwindUnverifiedMount(ctx context.Context, device, target string, id uint32, finding error) error {
	return p.mountGuard().Unwind(ctx, device, target, id, finding, p.umount)
}
