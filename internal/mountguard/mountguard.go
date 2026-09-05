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

// Package mountguard verifies that a mount just made is visible outside the
// mount namespace that made it, and unwinds one that is not.
//
// It is shared rather than per-provider for the reason internal/mount and
// internal/mountinfo are: the question is about the kernel's mount table, not
// about LVM or DRBD, and the answer has to be the same whichever provider
// asked. It was pkg/local's alone until pkg/drbd needed it (#40), and the two
// subtleties below are what made copying it the wrong move — both were review
// findings on #34 rather than obvious first cuts, and a second copy is a second
// chance to lose them:
//
//   - the rollback runs on a context of its own, because the most likely reason
//     to be rolling back is that the caller's context died;
//   - the rollback refuses a target that is no longer the mount this call made,
//     because umount(2) takes a path and would detach whatever is visible there.
//
// Wrong mount propagation is the quietest failure in the deployment model this
// library was built for. mount(2) succeeds, the provider reports success, and
// the workload in its own namespace walks to the path and finds the directory
// exactly as it was before anything was mounted on it. There is no error, no log
// line and no non-zero exit anywhere; the first evidence is a workload writing
// to its own filesystem, and the second is somebody wondering where the data
// went.
package mountguard

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// ErrTableCannotReport reports a mount table injected by the caller that cannot
// answer the propagation question, in a provider configured to require an
// answer.
var ErrTableCannotReport = errors.New(
	"the configured mount table does not implement PropagationOf, so propagation cannot be established")

// ErrTargetTakenOver reports a rollback that did not happen because the mount at
// the target stopped being the one this call made.
//
// It covers both shapes, because umount(2) cannot tell them apart either:
// another DEVICE mounted over the target, and a second mount of the SAME device
// stacked on it. In both, the thing that would be detached is somebody else's,
// and the refused mount stays underneath it.
var ErrTargetTakenOver = errors.New(
	"the refused mount was left in place: the mount visible at the target is no longer the one this call made, and unmounting the path would detach that one instead")

// Policy selects whether a provider verifies that the mount it just made can be
// seen outside this mount namespace.
type Policy int

const (
	// Unchecked does not verify propagation after mounting.
	//
	// It is the zero value, and deliberately so: a mount is PRIVATE by default
	// on an ordinary host, which is correct there and is what every
	// non-containerized caller of this library has. Requiring propagation by
	// default would refuse those deployments for a property they have no reason
	// to want — the guard would be rejecting a correct environment, which is
	// the failure mode a guard is least forgiven for.
	Unchecked Policy = iota

	// Shared requires each mount to be SHARED, and refuses with a typed error
	// naming the required setting when it is not.
	//
	// This is the setting for the deployment this library was built for: a
	// storage component that mounts on behalf of a workload living in another
	// mount namespace. Declaring it is how the provider learns that a private
	// mount is a failure rather than the normal state, which it cannot work out
	// for itself — the consumer's namespace is precisely what this side cannot
	// see.
	Shared
)

// Valid reports whether the policy is one this package defines.
//
// It exists because the providers export this as an integer type: a caller
// building options by hand can write MountPropagationPolicy(2), and every
// comparison in this package is against Shared, so an unknown value would
// behave exactly like "off". That is a fail-open response to malformed security
// configuration — the guard silently absent because the value asking for it was
// not one of the two. The settings path already refuses a misspelling; the
// struct path has to refuse a wrong number.
func (p Policy) Valid() bool {
	return p == Unchecked || p == Shared
}

// String renders the policy in its settings spelling, so an error about one says
// what the caller would have to write.
func (p Policy) String() string {
	for spelling, policy := range policyNames {
		if policy == p {
			return spelling
		}
	}
	return "unknown(" + strconv.Itoa(int(p)) + ")"
}

// policyNames maps the policy onto its settings spelling, so the parser and the
// documentation cannot drift.
var policyNames = map[string]Policy{
	"unchecked": Unchecked,
	"shared":    Shared,
}

// Parse reads a policy from its settings spelling, reporting whether the
// spelling is one this package knows. A caller that ignored the second result
// would turn a misspelling into the default, which is "off".
func Parse(raw string) (Policy, bool) {
	policy, known := policyNames[raw]
	return policy, known
}

// Spellings returns the accepted settings values in a stable order, for the
// error a misspelling produces.
func Spellings() []string {
	spellings := make([]string, 0, len(policyNames))
	for spelling := range policyNames {
		spellings = append(spellings, spelling)
	}
	sort.Strings(spellings)
	return spellings
}

// Guard is a policy over one provider's mount table.
//
// It is a value built at the call site from the provider's two fields rather
// than a thing a provider holds, so there is no second copy of the policy to
// fall out of step with the one Posture reports.
type Guard struct {
	// Policy is what this provider was configured to require.
	Policy Policy

	// Table is the provider's mount-table seam. The propagation half of it is
	// optional, so this is asserted to a mountinfo.PropagationReader rather
	// than declared as one.
	Table mountinfo.Table
}

// CanReport reports whether the table can answer the propagation question at
// all.
//
// A provider told to require propagation, over a mount table that cannot report
// it, is a configuration that cannot work — and discovering it after the first
// mount is worse than useless: the mount has already happened, the guard cannot
// judge it, and the rollback cannot identify it either, so Mount would return an
// error over a filesystem it left mounted. Providers ask this at construction so
// it is a startup refusal instead.
func (g Guard) CanReport() bool {
	if g.Table == nil {
		return false
	}
	_, ok := g.Table.(mountinfo.PropagationReader)
	return ok
}

// Verify checks that the mount of device at target propagates, and is what turns
// the silent failure into a refusal. It returns the kernel's identity for the
// mount, which Unwind needs.
//
// It runs AFTER the mount rather than before, because propagation is a property
// of the mount itself: it is inherited from the parent at the moment mount(2) is
// called, and there is nothing to inspect until then. That is also why this
// capability has no startup probe next to the privilege checks — at startup
// there is no mount to ask about.
//
// It fails closed in both directions. A mount that is private is refused, and a
// check that could not run — /proc unreadable, the table unparseable, nothing
// mounted at the target at all — is ALSO refused, as CauseIndeterminate. A guard
// that reports success when its own check breaks is worse than no guard: it
// converts an unknown into a green light, and it does so exactly where somebody
// is relying on it.
func (g Guard) Verify(ctx context.Context, device, target string) (uint32, error) {
	if g.Policy != Shared {
		return 0, nil
	}

	// The seam's propagation half is optional, so a caller that injected its own
	// mount table is not forced to implement a method for a guard it may never
	// turn on. Having turned it on and injected a table that cannot answer is a
	// different matter: it is refused rather than skipped, because a guard that
	// passes when it cannot check is the thing this exists to remove.
	reader, ok := g.reader()
	if !ok {
		return 0, &preflight.CapabilityError{
			Capability: preflight.CapabilityMountPropagation,
			Cause:      preflight.CauseIndeterminate,
			Probe:      "asking the configured mount table for the propagation of " + target,
			Err:        ErrTableCannotReport,
		}
	}

	// The lookup runs on a context detached from the caller's, and the caller's
	// is checked afterwards. Once mount(2) has returned, verifying and — if the
	// verification refuses — unwinding are COMPLETION work: a caller whose
	// deadline passed in that instant would otherwise leave a mount that was
	// never verified and never cleaned up, because the read that would identify
	// it fails first. So the read happens, and then the caller is told they gave
	// up, which is the same order the providers' zeroing paths use for the same
	// reason.
	lookupCtx, cancel := UnwindContext(ctx)
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

// Unwind removes a mount the propagation guard refused.
//
// A Mount that returns an error must not leave a filesystem mounted: the caller
// has been told the operation failed, and a mount it does not know about is one
// nothing will ever unmount — the same orphan the providers' rollback paths
// exist to avoid.
//
// It unmounts by PATH, which is the only thing umount(2) takes, so it first
// confirms this volume is what is VISIBLE at that path. The gap between the
// mount succeeding and the guard refusing it is small and it is not closed by a
// provider's lock: anything on the host can mount over the target in it, and
// umount(2) would then detach that filesystem instead — somebody else's, over a
// rollback of our own. Unmount already refuses that case; a rollback that
// reached past the same check would be the hazard reintroduced by the path that
// exists to tidy up.
//
// The guard's finding is what the caller gets back either way. A failure to
// unwind — the check, the unmount, or a target that is no longer ours — is
// joined onto it rather than replacing it: the reason the mount is there is the
// finding, and what happened to the cleanup is a second fact about the same
// event, and an operator needs both.
func (g Guard) Unwind(ctx context.Context, device, target string, id uint32, finding error, umount func(context.Context, string) error) error {
	ctx, cancel := UnwindContext(ctx)
	defer cancel()

	reader, ok := g.reader()
	if !ok {
		return errors.Join(finding, ErrTableCannotReport)
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
		return errors.Join(finding, ErrTargetTakenOver)
	}
	if err := umount(ctx, target); err != nil {
		return errors.Join(finding, err)
	}
	return finding
}

// reader narrows the table to its optional propagation half.
func (g Guard) reader() (mountinfo.PropagationReader, bool) {
	if g.Table == nil {
		return nil, false
	}
	reader, ok := g.Table.(mountinfo.PropagationReader)
	return reader, ok
}

// unwindTimeout bounds a rollback so a cleanup cannot hang forever either. It
// covers a mount-table read and an unmount, both of which are fast when they
// work at all.
//
// It is not a provider's own cleanup timeout and must not be conflated with one:
// pkg/drbd's cleanupContext waits on drbdadm and lvremove, which are minutes;
// this waits on a syscall.
const unwindTimeout = 30 * time.Second

// UnwindContext detaches from the caller's context for a compensating action.
//
// The most likely reason to be unwinding is that the caller's context died
// partway through the operation being compensated — and the propagation guard
// itself reports a canceled context as a refusal, which is precisely a path that
// arrives here with ctx already dead. Reusing it makes the mount-table read fail
// instantly and leaves behind exactly the mount this exists to remove, while the
// code reads as though it had been removed.
func UnwindContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), unwindTimeout)
}
