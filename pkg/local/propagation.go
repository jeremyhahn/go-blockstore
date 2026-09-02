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
	"sort"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// errMountTableCannotReportPropagation reports a mount table injected by the
// caller that cannot answer the propagation question, in a provider configured
// to require an answer.
var errMountTableCannotReportPropagation = errors.New(
	"the configured mount table does not implement PropagationOf, so propagation cannot be established")

// MountPropagationPolicy selects whether Mount verifies that the mount it just
// made can be seen outside this mount namespace.
//
// Wrong mount propagation is the quietest failure in the whole deployment
// model. mount(2) succeeds, the provider reports success, and the workload in
// its own namespace walks to the path and finds the directory exactly as it was
// before anything was mounted on it. There is no error, no log line and no
// non-zero exit anywhere; the first evidence is a workload writing to its own
// filesystem, and the second is somebody wondering where the data went.
type MountPropagationPolicy int

const (
	// MountPropagationUnchecked does not verify propagation after mounting.
	//
	// It is the zero value, and deliberately so: a mount is PRIVATE by default
	// on an ordinary host, which is correct there and is what every
	// non-containerized caller of this library has. Requiring propagation by
	// default would refuse those deployments for a property they have no reason
	// to want — the guard would be rejecting a correct environment, which is
	// the failure mode a guard is least forgiven for.
	MountPropagationUnchecked MountPropagationPolicy = iota

	// MountPropagationShared requires each mount to be SHARED, and refuses with
	// a typed error naming the required setting when it is not.
	//
	// This is the setting for the deployment this library was built for: a
	// storage component that mounts on behalf of a workload living in another
	// mount namespace. Declaring it is how the provider learns that a private
	// mount is a failure rather than the normal state, which it cannot work out
	// for itself — the consumer's namespace is precisely what this side cannot
	// see.
	MountPropagationShared
)

// valid reports whether the policy is one this package defines.
//
// It exists because MountPropagationPolicy is an exported integer type: a
// caller building Options by hand can write MountPropagationPolicy(2), and
// every comparison in this file is against MountPropagationShared, so an
// unknown value would behave exactly like "off". That is a fail-open response
// to malformed security configuration — the guard silently absent because the
// value asking for it was not one of the two. The settings path already
// refuses a misspelling; the struct path has to refuse a wrong number.
func (p MountPropagationPolicy) valid() bool {
	return p == MountPropagationUnchecked || p == MountPropagationShared
}

// String renders the policy in its settings spelling, so an error about one
// says what the caller would have to write.
func (p MountPropagationPolicy) String() string {
	for spelling, policy := range mountPropagationNames {
		if policy == p {
			return spelling
		}
	}
	return "unknown(" + strconv.Itoa(int(p)) + ")"
}

// mountPropagationNames maps the policy onto its settings spelling, so the
// parser and the documentation cannot drift.
var mountPropagationNames = map[string]MountPropagationPolicy{
	"unchecked": MountPropagationUnchecked,
	"shared":    MountPropagationShared,
}

// mountPropagationSpellings returns the accepted settings values in a stable
// order, for the error a misspelling produces.
func mountPropagationSpellings() []string {
	spellings := make([]string, 0, len(mountPropagationNames))
	for spelling := range mountPropagationNames {
		spellings = append(spellings, spelling)
	}
	sort.Strings(spellings)
	return spellings
}

// verifyMountPropagation checks that the mount at target propagates, and is
// what turns the silent failure into a refusal.
//
// It runs AFTER the mount rather than before, because propagation is a property
// of the mount itself: it is inherited from the parent at the moment mount(2)
// is called, and there is nothing to inspect until then. That is also why this
// capability has no startup probe next to the other three — at startup there is
// no mount to ask about.
//
// It fails closed in both directions. A mount that is private is refused, and a
// check that could not run — /proc unreadable, the table unparseable, nothing
// mounted at the target at all — is ALSO refused, as CauseIndeterminate. A
// guard that reports success when its own check breaks is worse than no guard:
// it converts an unknown into a green light, and it does so exactly where
// somebody is relying on it.
func (p *Provider) verifyMountPropagation(ctx context.Context, device, target string) (uint32, error) {
	if p.mountPropagation != MountPropagationShared {
		return 0, nil
	}

	// The seam's propagation half is optional, so a caller that injected its own
	// mount table is not forced to implement a method for a guard it may never
	// turn on. Having turned it on and injected a table that cannot answer is a
	// different matter: it is refused rather than skipped, because a guard that
	// passes when it cannot check is the thing this exists to remove.
	reader, ok := p.mountTable.(MountPropagationReader)
	if !ok {
		return 0, &preflight.CapabilityError{
			Capability: preflight.CapabilityMountPropagation,
			Cause:      preflight.CauseIndeterminate,
			Probe:      "asking the configured mount table for the propagation of " + target,
			Err:        errMountTableCannotReportPropagation,
		}
	}

	// The lookup runs on a context detached from the caller's, and the caller's
	// is checked afterwards. Once mount(2) has returned, verifying and — if the
	// verification refuses — unwinding are COMPLETION work: a caller whose
	// deadline passed in that instant would otherwise leave a mount that was
	// never verified and never cleaned up, because the read that would identify
	// it fails first. So the read happens, and then the caller is told they
	// gave up, which is the same order ZeroOut uses for the same reason.
	lookupCtx, cancel := unwindContext(ctx)
	defer cancel()

	// Asked about THIS DEVICE at the path, not about whatever is at the path.
	// Between mount(2) returning and this lookup, another process can mount over
	// the target — and reading "the propagation at this path" would then read
	// the interloper's. A SHARED thing landing on top of our private mount would
	// make the guard pass, which is the fail-open it exists to prevent.
	id, propagates, spelling, err := reader.PropagationOf(lookupCtx, device, target)
	if err != nil {
		return 0, &preflight.CapabilityError{
			Capability: preflight.CapabilityMountPropagation,
			Cause:      preflight.CauseIndeterminate,
			Probe:      "reading the propagation of " + device + " at " + target + " from the kernel's mount table",
			Err:        err,
		}
	}
	if !propagates {
		return id, &preflight.CapabilityError{
			Capability: preflight.CapabilityMountPropagation,
			Cause:      preflight.CauseMountNotPropagated,
			Probe:      "the mount at " + target + " is " + spelling + ", which no other mount namespace can see",
		}
	}

	// The mount is verified. A caller who gave up while that was happening is
	// told so — and told it with the identity in hand, so the mount they no
	// longer want is one the rollback can still recognize as theirs.
	if err := ctx.Err(); err != nil {
		return id, &preflight.CapabilityError{
			Capability: preflight.CapabilityMountPropagation,
			Cause:      preflight.CauseIndeterminate,
			Probe:      "verifying the propagation of " + device + " at " + target,
			Err:        err,
		}
	}
	return id, nil
}

// unwindTimeout bounds a rollback so a cleanup cannot hang forever either. It
// covers a mount-table read and an unmount, both of which are fast when they
// work at all.
const unwindTimeout = 30 * time.Second

// unwindContext detaches from the caller's context for a compensating action.
//
// The most likely reason to be unwinding is that the caller's context died
// partway through the operation being compensated — and the propagation guard
// itself reports a canceled context as a refusal, which is precisely a path
// that arrives here with ctx already dead. Reusing it makes the mount-table
// read fail instantly and leaves behind exactly the mount this exists to
// remove, while the code reads as though it had been removed.
//
// pkg/drbd's cleanupContext is the same decision for the same reason; the two
// are separate because their timeouts are: that one waits on drbdadm and this
// one on a syscall.
func unwindContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), unwindTimeout)
}

// errUnwindTargetTakenOver reports a rollback that did not happen because the
// mount at the target stopped being the one this call made.
//
// It covers both shapes, because umount(2) cannot tell them apart either:
// another DEVICE mounted over the target, and a second mount of the SAME
// device stacked on it. In both, the thing that would be detached is somebody
// else's, and the refused mount stays underneath it.
var errUnwindTargetTakenOver = errors.New(
	"the refused mount was left in place: the mount visible at the target is no longer the one this call made, and unmounting the path would detach that one instead")

// unwindUnverifiedMount removes a mount the propagation guard refused.
//
// A Mount that returns an error must not leave a filesystem mounted: the caller
// has been told the operation failed, and a mount it does not know about is one
// nothing will ever unmount — the same orphan this provider's rollback paths
// exist to avoid.
//
// It unmounts by PATH, which is the only thing umount(2) takes, so it first
// confirms this volume is what is VISIBLE at that path. The gap between the
// mount succeeding and the guard refusing it is small and it is not closed by
// this provider's lock: anything on the host can mount over the target in it,
// and umount(2) would then detach that filesystem instead — somebody else's,
// over a rollback of our own. Unmount already refuses that case; a rollback
// that reached past the same check would be the hazard reintroduced by the
// path that exists to tidy up.
//
// The guard's finding is what the caller gets back either way. A failure to
// unwind — the check, the unmount, or a target that is no longer ours — is
// joined onto it rather than replacing it: the reason the mount is there is the
// finding, and what happened to the cleanup is a second fact about the same
// event, and an operator needs both.
func (p *Provider) unwindUnverifiedMount(ctx context.Context, device, target string, id uint32, finding error) error {
	ctx, cancel := unwindContext(ctx)
	defer cancel()

	reader, ok := p.mountTable.(MountPropagationReader)
	if !ok {
		return errors.Join(finding, errMountTableCannotReportPropagation)
	}

	// The mount is identified by the kernel's own identity for it, not by
	// (device, path). Those are the same thing only until somebody stacks a
	// SECOND mount of the same device on the same path, and then unmounting by
	// path detaches theirs while the refused mount stays underneath. An id that
	// still matches is the evidence that the mount here is the one this call
	// made rather than a replacement made since.
	current, _, _, err := reader.PropagationOf(ctx, device, target)
	if err != nil {
		return errors.Join(finding, err)
	}
	if current != id {
		return errors.Join(finding, errUnwindTargetTakenOver)
	}
	if err := p.umount(ctx, target); err != nil {
		return errors.Join(finding, err)
	}
	return finding
}
