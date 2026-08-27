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

package ha

import (
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// volume is one managed volume's state.
//
// The mutators below are called by ONE goroutine at a time. Almost always that
// is the volume's own manager goroutine; the single exception is a fence
// recorded while a shutdown demote blocks, where the manager is parked inside
// the provider and writes nothing until the goroutine that noticed the lease
// end has returned. The mutex is therefore not protecting the state machine
// from itself — the one-writer-at-a-time rule already does that — but from
// [Controller.Status], which any caller may invoke at any moment.
type volume struct {
	ctrl  *Controller
	volID string
	key   string

	mu     sync.Mutex
	status Status
}

// snapshot returns a copy of the current status.
func (v *volume) snapshot() Status {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.status
}

// epoch returns the current lease epoch.
func (v *volume) epoch() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.status.Epoch
}

// deadline returns the end of the last acknowledged lease.
func (v *volume) deadline() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.status.LeaseDeadline
}

// update applies fn to the status and notifies the observer if the transition
// is one an observer acts on.
//
// The observer is called with the lock released, and from the manager
// goroutine, which is what makes the notifications ordered without making them
// re-entrant: an observer may call Status without deadlocking.
func (v *volume) update(fn func(*Status)) {
	v.mu.Lock()
	before := v.status
	fn(&v.status)
	v.status.UpdatedAt = v.ctrl.cfg.Clock.Now()
	after := v.status
	v.mu.Unlock()

	if v.ctrl.cfg.Observer == nil || !transition(&before, &after) {
		return
	}
	v.ctrl.cfg.Observer(after)
}

// transition reports whether the change from before to after is one worth
// waking an observer for.
//
// Phase, the primary claim and the reason are the three facts an orchestrator
// mounts and unmounts on. A renewal that only moves the deadline is not one of
// them, and neither is the same refusal restated at the next reconcile, so
// errors are compared by their text rather than by identity — otherwise a
// volume parked on one unchanging refusal would notify on every cadence tick
// forever.
func transition(before, after *Status) bool {
	return before.Phase != after.Phase ||
		before.Primary != after.Primary ||
		errText(before.Err) != errText(after.Err)
}

// errText renders an error for comparison, mapping nil to the empty string.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// campaigning records that this controller does not hold the lease. err says
// why — a contended key, or a Coordinator that could not answer — and the
// announcement is dropped either way, because both mean the same thing about
// what this node may write.
//
// It does NOT overwrite an unresolved fence. A fence whose demote failed says
// this node may still be writable with no lease behind it, and going back to
// campaigning does not fix that — it is the same hazard, now with a contender's
// error on top of it. Replacing it would make the status stop reporting the
// unsafe condition the moment the controller got on with its retry loop, which
// is exactly when nobody is looking. The phase and the log carry the campaign
// outcome; Err carries the thing that still needs a human.
//
// A fence whose demote SUCCEEDED carries no such hazard — the role is back — so
// this reports the campaign error normally. [ErrRoleNotYielded] is what marks
// the difference.
func (v *volume) campaigning(err error) {
	v.update(func(s *Status) {
		s.Phase = PhaseCampaigning
		s.Primary = false
		if !errors.Is(s.Err, ErrRoleNotYielded) {
			s.Err = err
		}
	})
}

// leading records a fresh acquisition: a new epoch, a new acknowledged
// deadline, and no primary claim until a reconcile establishes one.
func (v *volume) leading(deadline time.Time, key string) {
	v.update(func(s *Status) {
		s.Phase = PhaseLeading
		s.Epoch++
		s.LeaseKey = key
		s.LeaseDeadline = deadline
		s.Primary = false
		s.Err = nil
	})
}

// acknowledged moves the deadline after a renewal the backend confirmed. Only
// an acknowledged renewal moves it: that is the whole point of tracking it.
//
// It clears ONLY a renewal error. A renewal succeeding says the Coordinator is
// reachable; it says nothing about the volume, so a refusal standing from the
// last reconcile keeps applying until a reconcile finds otherwise. Clearing it
// here would publish a healthy status for a volume that is still refused — and
// would do it on every cadence tick, producing exactly the clear/re-set churn
// that comparing errors by text in transition exists to avoid.
func (v *volume) acknowledged(deadline time.Time) {
	v.update(func(s *Status) {
		s.LeaseDeadline = deadline
		if errors.Is(s.Err, ErrRenewFailed) {
			s.Err = nil
		}
	})
}

// renewFailed records a renewal error WITHOUT moving the deadline and without
// fencing. Done decides whether the lease still exists; this is a warning that
// it might not, and the one thing a later successful renewal is allowed to
// clear.
func (v *volume) renewFailed(err error) {
	v.update(func(s *Status) { s.Err = err })
}

// observed records the replication state read during a reconcile.
func (v *volume) observed(repl common.ReplState) {
	v.update(func(s *Status) { s.Repl = repl })
}

// promoted records that the local copy holds primary under the current epoch.
//
// The recorded replication role moves with it. Either the provider just made
// this node primary and said so, or the read that got us here already found it
// primary; leaving Repl.Role at the value read BEFORE a promotion would have
// Status announce Primary alongside a role of secondary, and a caller reading
// the two together would have to guess which one to believe.
func (v *volume) promoted() {
	v.update(func(s *Status) {
		s.Primary = true
		s.Repl.Role = common.ReplRolePrimary
		s.Err = nil
	})
}

// demoted records that the local copy no longer holds the primary role, because
// this controller just gave it back and the provider said so.
//
// It is the mirror of promoted's role update, and it exists for the same
// reason: Status.Repl.Role is documented as the device's actual role, so a
// controller that moves the role and does not move the field turns that
// documentation into a lie in the one direction that matters — reporting
// primary for a node it has just demoted.
//
// The announcement goes with it, and must. A demote that succeeded means the
// provider has already made this node secondary, so continuing to advertise it
// as the authorized primary would contradict the very role this call recorded —
// and it would do so for as long as whatever follows takes, which on the
// shutdown path is a release that may retry for the whole ActionTimeout.
//
// Only a demote that SUCCEEDED calls this. One that failed leaves both alone,
// because it does not know where the role ended up and guessing would report as
// safe the exact case that is not.
func (v *volume) demoted() {
	v.update(func(s *Status) {
		s.Primary = false
		s.Repl.Role = common.ReplRoleSecondary
	})
}

// refused records something this controller declined to do — a promotion it
// would not attempt, or an announcement it would not make for a copy that is
// already primary. Both withdraw the announcement, which is the whole content
// of a refusal here.
//
// The volume is intact and the lease is still held, so the phase does not
// change; the next reconcile asks again, and a volume that finishes a resync
// answers differently.
func (v *volume) refused(err error) {
	v.update(func(s *Status) {
		s.Primary = false
		s.Err = err
	})
}

// failed records an operation that errored while leading WITHOUT knowing what
// the device's role now is.
//
// It deliberately does not touch the announcement. Its one caller is a failed
// read of the replication state, which changes nothing about the device and
// tells us nothing new about it either, so the last thing this controller
// actually established stands and the error says it is now unverified.
//
// A failure that DOES establish something uses promotionFailed instead.
func (v *volume) failed(err error) {
	v.update(func(s *Status) { s.Err = err })
}

// promotionFailed records a promotion attempt that did not take, and withdraws
// the announcement.
//
// Unlike failed, this outcome is informative: the reconcile had just read the
// local role as NOT primary, and the call to make it primary failed. Whatever
// this controller announced earlier is now known to be wrong, so leaving it
// standing would keep an orchestrator mounted on an authorization that has been
// disproven.
func (v *volume) promotionFailed(err error) {
	v.update(func(s *Status) {
		s.Primary = false
		s.Err = err
	})
}

// fenced records the loss of the lease. The primary claim goes first and
// unconditionally: it expired with the lease, whether or not the device can be
// demoted afterwards.
//
// A volume already fenced keeps the reason it has. The only way to reach this
// while fenced is that a promotion was voided a moment earlier, and that reason
// is the sharper of the two — it says a promotion was in flight, which the
// generic one does not.
func (v *volume) fenced(err error) {
	v.update(func(s *Status) {
		if s.Phase == PhaseFenced {
			return
		}
		s.Phase = PhaseFenced
		s.Primary = false
		s.Err = err
	})
}

// fencedWith fences the volume and takes err even if it is already fenced.
//
// It is the counterpart to fenced, which keeps whatever reason is standing. Its
// two callers both hold the fuller account of the same event — a promotion that
// was in flight when the lease died, or a shutdown that now also knows how the
// demote went — so here the newer reason is the better one.
func (v *volume) fencedWith(err error) {
	v.update(func(s *Status) {
		s.Phase = PhaseFenced
		s.Primary = false
		s.Err = err
	})
}

// demoteFailed records that the demote following a fence did not take. The
// phase stays where it was — this controller is still fenced and still
// initiating nothing — but the error says the local copy may remain writable,
// which is the difference between a fenced controller and a fenced node.
func (v *volume) demoteFailed(err error) {
	v.update(func(s *Status) { s.Err = err })
}

// stopped records the manager's exit.
//
// Two rules keep the final status honest, and both exist because it is the LAST
// record: Manage unregisters the volume as it returns, so Controller.Status can
// no longer answer for it and what the observer saw last is all that is left.
//
// The FIRST stop reason wins. A shutdown that failed to demote or release has
// already said the useful thing, and the loop unwinding afterwards would
// otherwise replace it with nil.
//
// A NIL stop reason keeps only what OUTLIVES the shutdown. Nil means the
// shutdown itself had nothing to report, which is not the same as saying
// everything before it is resolved — but most of what came before it is.
//
// Stopping resolves a refusal to promote and a renewal warning: the controller
// is no longer trying, so neither is actionable and carrying them into the
// final status would make a clean stop read like a failed one. It does not
// resolve a fence, which says the lease was lost and — when the demote after it
// failed — that this node may still be writable with no lease behind it. That
// condition survives the manager, and [ErrFenced] is what marks it, so that is
// the one reason a nil stop keeps.
//
// The distinction matters because this is the LAST record: Manage unregisters
// the volume as it returns, so Controller.Status can no longer answer for it and
// what the observer saw last is all that is left.
func (v *volume) stopped(err error) {
	v.mu.Lock()
	already := v.status.Phase == PhaseStopped
	v.mu.Unlock()
	if already {
		return
	}
	v.update(func(s *Status) {
		s.Phase = PhaseStopped
		s.Primary = false
		switch {
		case err != nil:
			s.Err = err
		case errors.Is(s.Err, ErrFenced):
			// Kept: the node may still be writable without a lease.
		default:
			s.Err = nil
		}
	})
}
