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

// volume is one managed volume's state; one writer at a time, with the mutex guarding reads by Controller.Status.
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

// update applies fn and notifies the observer of a relevant transition, with the lock released.
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

// transition reports whether phase, the primary claim or the error text changed.
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

// campaigning records that the lease is not held and drops the announcement; an unresolved fence keeps its error.
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

// acknowledged moves the deadline after a confirmed renewal and clears only a renewal error.
func (v *volume) acknowledged(deadline time.Time) {
	v.update(func(s *Status) {
		s.LeaseDeadline = deadline
		if errors.Is(s.Err, ErrRenewFailed) {
			s.Err = nil
		}
	})
}

// renewFailed records a renewal error without moving the deadline or fencing.
func (v *volume) renewFailed(err error) {
	v.update(func(s *Status) { s.Err = err })
}

// observed records the replication state read during a reconcile.
func (v *volume) observed(repl common.ReplState) {
	v.update(func(s *Status) { s.Repl = repl })
}

// promoted records primary under the current epoch and sets Repl.Role to match.
func (v *volume) promoted() {
	v.update(func(s *Status) {
		s.Primary = true
		s.Repl.Role = common.ReplRolePrimary
		s.Err = nil
	})
}

// demoted records a successful demote: role secondary and announcement dropped.
func (v *volume) demoted() {
	v.update(func(s *Status) {
		s.Primary = false
		s.Repl.Role = common.ReplRoleSecondary
	})
}

// refused records a declined promotion or announcement and withdraws the announcement; the phase is unchanged.
func (v *volume) refused(err error) {
	v.update(func(s *Status) {
		s.Primary = false
		s.Err = err
	})
}

// failed records a failed replication-state read without changing the announcement.
func (v *volume) failed(err error) {
	v.update(func(s *Status) { s.Err = err })
}

// promotionFailed records a failed promotion and withdraws the announcement.
func (v *volume) promotionFailed(err error) {
	v.update(func(s *Status) {
		s.Primary = false
		s.Err = err
	})
}

// fenced records the lease loss and drops the primary claim; an existing fence keeps its reason.
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

// fencedWith fences the volume and replaces the reason even if already fenced.
func (v *volume) fencedWith(err error) {
	v.update(func(s *Status) {
		s.Phase = PhaseFenced
		s.Primary = false
		s.Err = err
	})
}

// demoteFailed records that the demote after a fence did not take, so the copy may remain writable.
func (v *volume) demoteFailed(err error) {
	v.update(func(s *Status) { s.Err = err })
}

// stopped records the manager's exit; the first stop reason wins, and a nil reason keeps only a fence.
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
