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

// MountPropagationPolicy selects whether Mount verifies that the mount it just
// made can be seen outside this mount namespace.
//
// # Why a replicated provider has this at all
//
// A DRBD volume is mounted by the same kind of component, for the same kind of
// consumer, as a local one: a storage service in one mount namespace mounting on
// behalf of a workload in another. Replication changes which device is under the
// filesystem, and changes nothing about whether the mount is visible where the
// workload looks for it. The failure is identical and just as quiet — mount(2)
// succeeds, this provider reports success, and the workload walks to the path
// and finds the directory as it was.
//
// It was left out of #34 because extending a new refusal into the replication
// provider is a behavior change that lane had not been asked for, not because
// the question does not arise here. #40 asked it and the answer is this: the
// guard exists here, and it is OFF unless a deployment says otherwise.
//
// # Why off by default
//
// A DRBD deployment is a replicated cluster before it is a container handoff. A
// private mount on a node where nothing consumes it from another namespace is
// legitimate rather than broken, and defaulting the refusal on would convert
// working clusters into failing ones on upgrade to protect against a failure
// mode those nodes do not have. The trigger for the guard is "a workload
// elsewhere consumes this mount" — a property of the deployment, which this
// package cannot observe, so it is configured rather than inferred.
//
// Off is not the same as absent: Posture reports this guard by name whether it
// is on or off, so an operator who never enabled it can still see that it is
// there. An off-by-default guard with no way to see it is silently missing,
// which is the defect rather than the fix.
//
// The type is an alias for the shared policy, and the check behind it is
// internal/mountguard — the same code pkg/local runs. Two copies would be two
// chances to lose the two subtleties in it; see that package.
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

// MountPropagationReader is the optional half of the mount-table seam: the
// question of whether a mount is visible outside this namespace.
//
// A MountTable that also implements it enables the mount-propagation guard; one
// that does not is refused by a provider configured to require propagation,
// rather than being quietly waved through. It is separate from MountTable so
// that a caller injecting its own table is not forced to implement a method for
// a guard it never turns on.
type MountPropagationReader = mountinfo.PropagationReader

// mountGuard is this provider's policy over its mount table.
//
// It is built at each call site rather than held as a field, so the policy the
// guard enforces and the policy Posture reports are the same one value.
func (p *Provider) mountGuard() mountguard.Guard {
	return mountguard.Guard{Policy: p.cfg.MountPropagation, Table: p.mountTable}
}

// verifyMountPropagation checks that the mount at target propagates, and is what
// turns the silent failure into a refusal.
//
// A table that cannot answer is a refusal too, not a pass: see
// mountguard.Guard.Verify. That is the case this provider is most likely to meet
// — its mount table is a seam, and a caller who injected one without the
// propagation half while asking for the guard would otherwise get a guard that
// reports exactly what a passing one reports.
func (p *Provider) verifyMountPropagation(ctx context.Context, device, target string) (uint32, error) {
	return p.mountGuard().Verify(ctx, device, target)
}

// unwindUnverifiedMount removes a mount the propagation guard refused, so a
// Mount that returns an error does not leave a filesystem mounted.
//
// It runs on a context of its own and refuses a target that is no longer this
// call's mount; see mountguard.Guard.Unwind for why both matter. The rollback
// context is that package's, not this one's cleanupContext: what it waits on is
// a mount-table read and umount(2), not drbdadm.
func (p *Provider) unwindUnverifiedMount(ctx context.Context, device, target string, id uint32, finding error) error {
	return p.mountGuard().Unwind(ctx, device, target, id, finding, p.mounter.Unmount)
}
