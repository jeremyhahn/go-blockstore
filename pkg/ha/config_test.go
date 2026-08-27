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
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

func TestConfigDefaults(t *testing.T) {
	got := Config{NodeID: testNode}.withDefaults()

	if got.LeaseTTL != DefaultLeaseTTL {
		t.Fatalf("LeaseTTL = %s, want %s", got.LeaseTTL, DefaultLeaseTTL)
	}
	// The cadence has to leave room for two more attempts before the hard
	// deadline, which is what a third of the TTL buys.
	if got.RenewInterval != DefaultLeaseTTL/3 {
		t.Fatalf("RenewInterval = %s, want %s", got.RenewInterval, DefaultLeaseTTL/3)
	}
	if got.RetryInterval != got.RenewInterval {
		t.Fatalf("RetryInterval = %s, want the renewal cadence %s", got.RetryInterval, got.RenewInterval)
	}
	if got.PromoteGuard != got.RenewInterval {
		t.Fatalf("PromoteGuard = %s, want %s", got.PromoteGuard, got.RenewInterval)
	}
	if got.KeyPrefix != DefaultKeyPrefix {
		t.Fatalf("KeyPrefix = %q, want %q", got.KeyPrefix, DefaultKeyPrefix)
	}
	if got.ActionTimeout != DefaultActionTimeout {
		t.Fatalf("ActionTimeout = %s, want %s", got.ActionTimeout, DefaultActionTimeout)
	}
	if got.ReleaseAttempts != DefaultReleaseAttempts {
		t.Fatalf("ReleaseAttempts = %d, want %d", got.ReleaseAttempts, DefaultReleaseAttempts)
	}
	if _, ok := got.Clock.(SystemClock); !ok {
		t.Fatalf("Clock = %T, want SystemClock", got.Clock)
	}
	if got.Logger == nil {
		t.Fatal("Logger must default to a discarding logger, not nil")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("the defaults must validate: %v", err)
	}
}

func TestConfigDefaultsDoNotOverrideExplicitValues(t *testing.T) {
	clock := newTestClock()
	in := Config{
		NodeID:          testNode,
		LeaseTTL:        30 * time.Second,
		RenewInterval:   2 * time.Second,
		RetryInterval:   7 * time.Second,
		PromoteGuard:    3 * time.Second,
		KeyPrefix:       "custom/",
		ActionTimeout:   time.Minute,
		ReleaseAttempts: 9,
		Clock:           clock,
	}
	got := in.withDefaults()

	if got.LeaseTTL != 30*time.Second || got.RenewInterval != 2*time.Second ||
		got.RetryInterval != 7*time.Second || got.PromoteGuard != 3*time.Second ||
		got.KeyPrefix != "custom/" || got.ActionTimeout != time.Minute || got.ReleaseAttempts != 9 {
		t.Fatalf("withDefaults overwrote an explicit value: %+v", got)
	}
	if got.Clock != Clock(clock) {
		t.Fatal("withDefaults replaced an explicit Clock")
	}
}

func TestConfigReleaseAttemptsFloor(t *testing.T) {
	// One attempt is not enough — a revoke the backend did not acknowledge is
	// not a release — so a caller asking for fewer gets the default rather than
	// a controller that gives up on the first refusal.
	for _, n := range []int{0, -1, math.MinInt} {
		if got := (Config{NodeID: testNode, ReleaseAttempts: n}).withDefaults().ReleaseAttempts; got != DefaultReleaseAttempts {
			t.Fatalf("ReleaseAttempts %d became %d, want %d", n, got, DefaultReleaseAttempts)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
		// contains is a fragment the message must carry, so a rejection tells
		// whoever typed the value which one was wrong.
		contains string
	}{
		{
			name: "the defaults are valid",
			cfg:  Config{NodeID: testNode}.withDefaults(),
		},
		{
			name:     "a controller must be able to name its node",
			cfg:      Config{}.withDefaults(),
			wantErr:  true,
			contains: "NodeID is required",
		},
		{
			name: "a sub-second TTL is below the coordinator's granularity",
			cfg: Config{NodeID: testNode, LeaseTTL: 500 * time.Millisecond,
				RenewInterval: 100 * time.Millisecond}.withDefaults(),
			wantErr:  true,
			contains: "one-second lease granularity",
		},
		{
			name: "a cadence with no room to retry is rejected",
			cfg: Config{NodeID: testNode, LeaseTTL: 9 * time.Second,
				RenewInterval: 4 * time.Second}.withDefaults(),
			wantErr:  true,
			contains: "RenewInterval*3 <= LeaseTTL",
		},
		{
			name: "a cadence of exactly a third is accepted",
			cfg: Config{NodeID: testNode, LeaseTTL: 9 * time.Second,
				RenewInterval: 3 * time.Second}.withDefaults(),
		},
		{
			name: "an overflowing cadence is still rejected",
			// RenewInterval*3 wraps NEGATIVE at this magnitude, which is why
			// the check is spelled as a division. A multiplication would let
			// this through.
			cfg: Config{NodeID: testNode, LeaseTTL: time.Hour,
				RenewInterval: time.Duration(math.MaxInt64 / 2)}.withDefaults(),
			wantErr:  true,
			contains: "RenewInterval*3 <= LeaseTTL",
		},
		{
			name: "a guard that spans the whole TTL would refuse every promotion",
			cfg: Config{NodeID: testNode, LeaseTTL: 15 * time.Second,
				RenewInterval: 5 * time.Second, PromoteGuard: 15 * time.Second}.withDefaults(),
			wantErr:  true,
			contains: "no promotion could ever be initiated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate accepted a configuration it must reject")
			}
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Fatalf("Validate: got %v, want errors.Is common.ErrInvalidArgument", err)
			}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("Validate: %q does not mention %q", err, tt.contains)
			}
		})
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	cfg := Config{NodeID: testNode}

	if _, err := New(nil, newFakeCoordinator(), cfg); !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New with a nil provider: got %v, want common.ErrInvalidArgument", err)
	}
	if _, err := New(newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary), nil, cfg); !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New with a nil coordinator: got %v, want common.ErrInvalidArgument", err)
	}
}

func TestNewValidatesTheSettledConfig(t *testing.T) {
	prov := newFakeProvider(common.ReplStateUpToDate, common.ReplRoleSecondary)

	// The rejection has to judge the values the controller will run with, not
	// the ones passed in: a bad LeaseTTL is only visible after the cadence has
	// been derived from it.
	if _, err := New(prov, newFakeCoordinator(), Config{NodeID: testNode, LeaseTTL: time.Millisecond}); !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New with a sub-second TTL: got %v, want common.ErrInvalidArgument", err)
	}

	ctrl, err := New(prov, newFakeCoordinator(), Config{NodeID: testNode})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := ctrl.Config().LeaseTTL; got != DefaultLeaseTTL {
		t.Fatalf("Config().LeaseTTL = %s, want the applied default %s", got, DefaultLeaseTTL)
	}
}

func TestSystemClockTracksWallTime(t *testing.T) {
	var c Clock = SystemClock{}
	before := time.Now()
	got := c.Now()
	if got.Before(before) || got.After(time.Now()) {
		t.Fatalf("SystemClock.Now() = %s, outside [%s, now]", got, before)
	}
	select {
	case <-c.After(time.Millisecond):
	case <-time.After(waitTimeout):
		t.Fatal("SystemClock.After never fired")
	}
}
