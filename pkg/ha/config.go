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
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// Defaults applied by [Config.withDefaults] to a zero-valued field.
const (
	// DefaultLeaseTTL is the primary lease duration and the floor on failover latency.
	DefaultLeaseTTL = 15 * time.Second

	// DefaultKeyPrefix namespaces the per-volume primary lease keys.
	DefaultKeyPrefix = "blockstore/ha/primary/"

	// DefaultActionTimeout bounds an out-of-band provider call, such as the demote after the lease ended.
	DefaultActionTimeout = 30 * time.Second

	// DefaultReleaseAttempts is how many times a release is retried before the lease is left to expire.
	DefaultReleaseAttempts = 3
)

// minRenewDelay floors the wait between renewal attempts so a conservative deadline cannot cause a spin; a wait never extends past a live deadline.
const minRenewDelay = 20 * time.Millisecond

// Clock is the controller's view of time. It exists so the renewal cadence and
// the acknowledged-deadline arithmetic can be driven deterministically in
// tests instead of being waited out; production uses [SystemClock].
type Clock interface {
	// Now returns the current time.
	Now() time.Time

	// After returns a channel that delivers one value after d elapses.
	After(d time.Duration) <-chan time.Time
}

// SystemClock is the [Clock] backed by the time package.
type SystemClock struct{}

// Now returns the current wall time.
func (SystemClock) Now() time.Time { return time.Now() }

// After returns time.After(d).
func (SystemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Observer is called synchronously, one goroutine at a time, on every Status transition; a blocking observer stalls renewal, so hand slow work off.
type Observer func(Status)

// Config configures a Controller; zero durations take their defaults and NodeID is required.
type Config struct {
	// NodeID names this node in every error and log line; it does not address the provider.
	NodeID common.NodeID

	// LeaseTTL is the primary lease duration, default DefaultLeaseTTL, at least one second.
	LeaseTTL time.Duration

	// RenewInterval is the renewal cadence, default LeaseTTL/3, and must satisfy RenewInterval*3 <= LeaseTTL.
	RenewInterval time.Duration

	// RetryInterval is how long a follower waits before campaigning again; defaults to RenewInterval.
	RetryInterval time.Duration

	// PromoteGuard is the acknowledged lease that must remain to start a promotion; defaults to RenewInterval and must be below LeaseTTL.
	PromoteGuard time.Duration

	// KeyPrefix namespaces the per-volume lease keys, which are KeyPrefix +
	// volume id. Defaults to DefaultKeyPrefix.
	KeyPrefix string

	// ActionTimeout bounds each out-of-band provider call — the demotes on the
	// fenced and stopping paths. Defaults to DefaultActionTimeout.
	ActionTimeout time.Duration

	// ReleaseAttempts is how many times a lease release is attempted before the
	// controller stops and lets the deadline expire it. Defaults to
	// DefaultReleaseAttempts; a value below one is raised to one.
	ReleaseAttempts int

	// Clock is the controller's time source. Defaults to SystemClock{}.
	Clock Clock

	// Observer, when non-nil, is called on every status transition. See
	// [Observer] for the blocking rule.
	Observer Observer

	// Logger receives the controller's structured log. A nil Logger discards.
	Logger *slog.Logger
}

// withDefaults returns cfg with every unset field filled in. It is called once,
// by [New], so the running controller reads settled values rather than
// re-deriving a default at each use.
func (c Config) withDefaults() Config {
	if c.LeaseTTL <= 0 {
		c.LeaseTTL = DefaultLeaseTTL
	}
	if c.RenewInterval <= 0 {
		c.RenewInterval = c.LeaseTTL / 3
	}
	if c.RetryInterval <= 0 {
		c.RetryInterval = c.RenewInterval
	}
	if c.PromoteGuard <= 0 {
		c.PromoteGuard = c.RenewInterval
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = DefaultKeyPrefix
	}
	if c.ActionTimeout <= 0 {
		c.ActionTimeout = DefaultActionTimeout
	}
	if c.ReleaseAttempts < 1 {
		c.ReleaseAttempts = DefaultReleaseAttempts
	}
	if c.Clock == nil {
		c.Clock = SystemClock{}
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return c
}

// Validate reports whether the defaulted configuration can hold a lease safely; rejections wrap common.ErrInvalidArgument.
func (c Config) Validate() error {
	if c.NodeID == "" {
		return fmt.Errorf("%w: NodeID is required", common.ErrInvalidArgument)
	}
	if c.LeaseTTL < time.Second {
		return fmt.Errorf("%w: LeaseTTL %s is below the Coordinator's one-second lease granularity",
			common.ErrInvalidArgument, c.LeaseTTL)
	}
	// A division, because RenewInterval*3 can overflow.
	if c.RenewInterval > c.LeaseTTL/3 {
		return fmt.Errorf("%w: RenewInterval %s leaves no room to retry before LeaseTTL %s: need RenewInterval*3 <= LeaseTTL",
			common.ErrInvalidArgument, c.RenewInterval, c.LeaseTTL)
	}
	if c.PromoteGuard >= c.LeaseTTL {
		return fmt.Errorf("%w: PromoteGuard %s is not less than LeaseTTL %s, so no promotion could ever be initiated",
			common.ErrInvalidArgument, c.PromoteGuard, c.LeaseTTL)
	}
	return nil
}
