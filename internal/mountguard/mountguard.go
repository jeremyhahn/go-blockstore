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

// Package mountguard verifies a new mount propagates out of its namespace and unwinds one that does not.
// The rollback runs on its own context and refuses a target that is no longer this call's mount.
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

// ErrTargetTakenOver reports a rollback skipped because another mount now sits at the target.
var ErrTargetTakenOver = errors.New(
	"the refused mount was left in place: the mount visible at the target is no longer the one this call made, and unmounting the path would detach that one instead")

// Policy selects whether a provider verifies that the mount it just made can be
// seen outside this mount namespace.
type Policy int

const (
	// Unchecked does not verify propagation; it is the zero value, right for ordinary hosts.
	Unchecked Policy = iota

	// Shared requires each mount to be shared and refuses with a typed error when it is not.
	Shared
)

// Valid reports whether the policy is one this package defines, so an unknown number is refused rather than read as off.
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

// Guard is a policy over one provider's mount table, built at the call site.
type Guard struct {
	// Policy is what this provider was configured to require.
	Policy Policy

	// Table is the provider's mount-table seam. The propagation half of it is
	// optional, so this is asserted to a mountinfo.PropagationReader rather
	// than declared as one.
	Table mountinfo.Table
}

// CanReport reports whether the table can answer the propagation question; providers ask at construction.
func (g Guard) CanReport() bool {
	if g.Table == nil {
		return false
	}
	_, ok := g.Table.(mountinfo.PropagationReader)
	return ok
}

// Verify checks after mounting that device at target propagates and returns the mount ID Unwind needs; a check that cannot run also refuses.
func (g Guard) Verify(ctx context.Context, device, target string) (uint32, error) {
	if g.Policy != Shared {
		return 0, nil
	}

	// A table without propagation support is refused when the guard is on.
	reader, ok := g.reader()
	if !ok {
		return 0, &preflight.CapabilityError{
			Capability: preflight.CapabilityMountPropagation,
			Cause:      preflight.CauseIndeterminate,
			Probe:      "asking the configured mount table for the propagation of " + target,
			Err:        ErrTableCannotReport,
		}
	}

	// Read on a detached context, then check the caller's, so a refused mount can still be unwound.
	lookupCtx, cancel := UnwindContext(ctx)
	defer cancel()

	// Ask about this device at the path, so a mount landing on top cannot make the guard pass.
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

// Unwind unmounts a refused mount after confirming it is still the visible one; any unwind failure is joined to the guard's finding.
func (g Guard) Unwind(ctx context.Context, device, target string, id uint32, finding error, umount func(context.Context, string) error) error {
	ctx, cancel := UnwindContext(ctx)
	defer cancel()

	reader, ok := g.reader()
	if !ok {
		return errors.Join(finding, ErrTableCannotReport)
	}

	// Identify the mount by its kernel ID, which tells this mount from a second mount of the same device at the path.
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

// unwindTimeout bounds a rollback's mount-table read and unmount.
const unwindTimeout = 30 * time.Second

// UnwindContext detaches from the caller's context, which is often already dead when unwinding.
func UnwindContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), unwindTimeout)
}
