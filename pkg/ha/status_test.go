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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// The promote-eligibility table is the safety property this package exists to
// enforce, so it is tested as a total function over the enum rather than
// through the states a controller test happens to walk through. Exactly one
// connection state is eligible; everything else, including a value this package
// has never been taught, is refused with a reason.
func TestPromoteEligibility(t *testing.T) {
	tests := []struct {
		name    string
		conn    common.ReplConnState
		want    bool
		because string
	}{
		{
			name: "uptodate is the only eligible state",
			conn: common.ReplStateUpToDate,
			want: true,
		},
		{
			name:    "sync-source is refused: the bucket says the peer is behind, not that this disk is current",
			conn:    common.ReplStateSyncSource,
			because: "resync",
		},
		{
			name:    "sync-target is refused: this copy is the one behind",
			conn:    common.ReplStateSyncTarget,
			because: "behind the peer",
		},
		{
			name:    "inconsistent is refused: a definite fact, and the fact is bad",
			conn:    common.ReplStateInconsistent,
			because: "not to be current",
		},
		{
			name:    "standalone is refused: the copies cannot be compared",
			conn:    common.ReplStateStandalone,
			because: "cannot be compared",
		},
		{
			name:    "connecting is refused: the peer is not known yet",
			conn:    common.ReplStateConnecting,
			because: "still being established",
		},
		{
			name:    "down is refused: replication is not running",
			conn:    common.ReplStateDown,
			because: "not running",
		},
		{
			name:    "unknown is refused: refusing on 'we do not know' is the discipline",
			conn:    common.ReplStateUnknown,
			because: "could not be determined",
		},
		{
			name:    "an unrecognized state is refused, so a grown enum cannot open the gate",
			conn:    common.ReplConnState("a-state-from-the-future"),
			because: "unrecognized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The role is varied deliberately: eligibility answers "is this
			// copy current", which a role cannot change.
			for _, role := range []common.ReplRole{
				common.ReplRoleUnknown, common.ReplRolePrimary, common.ReplRoleSecondary,
			} {
				ok, reason := promoteEligibility(common.ReplState{Conn: tt.conn, Role: role})
				if ok != tt.want {
					t.Fatalf("promoteEligibility(%q, role %q) = %v, want %v", tt.conn, role, ok, tt.want)
				}
				if tt.want {
					if reason != "" {
						t.Fatalf("an eligible state carried the reason %q", reason)
					}
					continue
				}
				if reason == "" {
					t.Fatalf("%q was refused with no reason", tt.conn)
				}
				if !strings.Contains(reason, tt.because) {
					t.Fatalf("%q was refused because %q, which does not mention %q", tt.conn, reason, tt.because)
				}
			}
		})
	}
}

// Every state in the enum must be covered by the table above. A state added to
// pkg/common without a decision here would otherwise fall into the default
// branch silently, and "we refused it because we had never heard of it" is a
// worse answer than a considered one.
func TestPromoteEligibilityCoversEveryDeclaredState(t *testing.T) {
	declared := []common.ReplConnState{
		common.ReplStateUnknown,
		common.ReplStateStandalone,
		common.ReplStateConnecting,
		common.ReplStateSyncSource,
		common.ReplStateSyncTarget,
		common.ReplStateUpToDate,
		common.ReplStateInconsistent,
		common.ReplStateDown,
	}
	for _, conn := range declared {
		_, reason := promoteEligibility(common.ReplState{Conn: conn})
		if reason == "unrecognized replication state" {
			t.Fatalf("%q reaches the default branch; give it an explicit case and a reason", conn)
		}
	}
}

func TestTransitionWakesAnObserverOnlyForActionableChanges(t *testing.T) {
	base := Status{Phase: PhaseLeading, Primary: true}
	boom := errors.New("boom")

	tests := []struct {
		name   string
		before Status
		after  Status
		want   bool
	}{
		{
			name:   "an unchanged status is not a transition",
			before: base,
			after:  base,
		},
		{
			name:   "a renewal that only moves the deadline is not a transition",
			before: base,
			after:  Status{Phase: PhaseLeading, Primary: true, LeaseDeadline: base.LeaseDeadline.Add(1)},
		},
		{
			name:   "a phase change is",
			before: base,
			after:  Status{Phase: PhaseFenced, Primary: true},
			want:   true,
		},
		{
			name:   "gaining or losing the primary claim is",
			before: base,
			after:  Status{Phase: PhaseLeading},
			want:   true,
		},
		{
			name:   "a new reason is",
			before: base,
			after:  Status{Phase: PhaseLeading, Primary: true, Err: boom},
			want:   true,
		},
		{
			name:   "the same reason restated is not, so a parked refusal does not notify forever",
			before: Status{Phase: PhaseLeading, Err: errors.New("same text")},
			after:  Status{Phase: PhaseLeading, Err: errors.New("same text")},
		},
		{
			name:   "clearing a reason is",
			before: Status{Phase: PhaseLeading, Err: boom},
			after:  Status{Phase: PhaseLeading},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := transition(&tt.before, &tt.after); got != tt.want {
				t.Fatalf("transition = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrTextMapsNilToEmpty(t *testing.T) {
	if got := errText(nil); got != "" {
		t.Fatalf("errText(nil) = %q, want the empty string", got)
	}
	if got := errText(errors.New("x")); got != "x" {
		t.Fatalf("errText = %q, want %q", got, "x")
	}
}

// The adoption gate is deliberately broader than the promotion gate, and the
// asymmetry is load-bearing in both directions: too narrow and a surviving
// Primary whose peer died gets its announcement withdrawn; too broad and a
// possible split-brain survivor is announced as serving.
func TestAdoptEligibility(t *testing.T) {
	tests := []struct {
		name    string
		conn    common.ReplConnState
		want    bool
		because string
	}{
		{
			name: "uptodate serves",
			conn: common.ReplStateUpToDate,
			want: true,
		},
		{
			name: "sync-source serves: the local copy is feeding the peer",
			conn: common.ReplStateSyncSource,
			want: true,
		},
		{
			name: "connecting serves: an established Primary surviving a dead peer is what HA is for",
			conn: common.ReplStateConnecting,
			want: true,
		},
		{
			name:    "standalone is refused: a Primary that stopped talking may be either side of a divergence",
			conn:    common.ReplStateStandalone,
			because: "either side of a divergence",
		},
		{
			name:    "sync-target is refused: the local copy is being overwritten",
			conn:    common.ReplStateSyncTarget,
			because: "overwritten",
		},
		{
			name:    "inconsistent is refused",
			conn:    common.ReplStateInconsistent,
			because: "not to be current",
		},
		{
			name:    "down is refused",
			conn:    common.ReplStateDown,
			because: "not running",
		},
		{
			name:    "unknown is refused",
			conn:    common.ReplStateUnknown,
			because: "could not be determined",
		},
		{
			name:    "an unrecognized state is refused",
			conn:    common.ReplConnState("a-state-from-the-future"),
			because: "unrecognized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := adoptEligibility(common.ReplState{Conn: tt.conn, Role: common.ReplRolePrimary})
			if ok != tt.want {
				t.Fatalf("adoptEligibility(%q) = %v, want %v", tt.conn, ok, tt.want)
			}
			if tt.want {
				if reason != "" {
					t.Fatalf("a serviceable state carried the reason %q", reason)
				}
				return
			}
			if !strings.Contains(reason, tt.because) {
				t.Fatalf("%q was refused because %q, which does not mention %q", tt.conn, reason, tt.because)
			}
		})
	}
}

// Whatever the adoption gate allows, the promotion gate must too — the reverse
// is what makes them different, but a state safe to bring INTO service and not
// safe to keep serving would be incoherent.
func TestAdoptionIsNoNarrowerThanPromotion(t *testing.T) {
	for _, conn := range []common.ReplConnState{
		common.ReplStateUnknown,
		common.ReplStateStandalone,
		common.ReplStateConnecting,
		common.ReplStateSyncSource,
		common.ReplStateSyncTarget,
		common.ReplStateUpToDate,
		common.ReplStateInconsistent,
		common.ReplStateDown,
	} {
		s := common.ReplState{Conn: conn}
		promotable, _ := promoteEligibility(s)
		serviceable, _ := adoptEligibility(s)
		if promotable && !serviceable {
			t.Fatalf("%q may be promoted but not served, which cannot be right", conn)
		}
	}
}
