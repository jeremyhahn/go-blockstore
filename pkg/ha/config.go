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
	// DefaultLeaseTTL is the lease duration a volume's primary key is held
	// for. It is also the worst-case time a dead holder's key stays bound, so
	// it is the floor on failover latency; shortening it makes takeover faster
	// and makes a transient coordinator stall likelier to fence a healthy
	// leader.
	DefaultLeaseTTL = 15 * time.Second

	// DefaultKeyPrefix namespaces the per-volume primary lease keys.
	DefaultKeyPrefix = "blockstore/ha/primary/"

	// DefaultActionTimeout bounds a provider call the controller makes OUT OF
	// BAND — the demote on the fenced and stopping paths, which cannot use the
	// lease context because the lease is what just ended.
	DefaultActionTimeout = 30 * time.Second

	// DefaultReleaseAttempts is how many times a release is retried before the
	// controller gives up and lets the deadline expire the lease. A revoke the
	// backend did not acknowledge is not a release, so one attempt is not
	// enough; retrying forever on a dead backend is not better than the
	// deadline.
	DefaultReleaseAttempts = 3
)

// minRenewDelay is the floor on the wait between renewal attempts.
//
// It exists for one window. The controller's tracked deadline is deliberately
// conservative — computed from the CONFIGURED TTL, which the Coordinator rounds
// up — so it can pass while the backend's actual lease is still alive. That
// daylight is under a second and appears only when LeaseTTL is not a whole
// number of them, but inside it the remaining lease reads as negative, Done has
// not closed, and an unfloored wait would retry as fast as the scheduler
// allows: CPU burned and a log filled, for the rest of the second, exactly
// while the Coordinator is already in trouble.
//
// It is not a tuning knob, which is why it is not in Config. It is small enough
// that a renewal which could still save the lease gets many attempts inside
// that window, and large enough that "many" is not "as many as possible".
//
// It floors, it does not extend: a wait is still capped at the lease actually
// remaining, so the floor can never push an attempt past a deadline that was
// still live. Stopping a spin is worth twenty milliseconds of CPU; it is not
// worth forfeiting leadership.
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

// Observer is notified of every transition in a managed volume's [Status].
//
// It is called SYNCHRONOUSLY, and by exactly one goroutine at a time, which is
// what makes the notifications ordered: an observer sees "leading" before it
// sees "fenced" for the same epoch, so an orchestrator can mount and unmount
// against them. Almost always that is the volume's own manager goroutine; the
// one exception is a lease lost while a shutdown demote blocks, where the
// manager is parked inside the provider and writes nothing until the goroutine
// that noticed has finished — so there is still one writer, and the fence does
// not have to wait out a stuck demote to be announced.
//
// An observer that blocks therefore stalls that volume's renewal loop. That is a real hazard, and the direction it fails in is the safe one —
// a stalled loop stops renewing, the lease expires, and the controller fences
// itself — but it is still a bug in the observer. Hand slow work to a
// goroutine or a queue.
type Observer func(Status)

// Config configures a [Controller].
//
// The zero value of every duration field takes the documented default; the
// only field with no default is NodeID.
type Config struct {
	// NodeID names the node this controller runs on. It is required: it
	// appears in every error and log line the controller produces, and a
	// controller that cannot say which node refused a promotion is not worth
	// reading. It is NOT used to address the provider — a provider drives the
	// local node and no other.
	NodeID common.NodeID

	// LeaseTTL is the duration each primary lease is acquired and renewed for.
	// Defaults to DefaultLeaseTTL. It must be at least one second, which is the
	// Coordinator's lease granularity: anything shorter is rounded up to a
	// second by the backend, leaving a renewal cadence derived from the
	// configured value churning against a deadline that does not move with it.
	LeaseTTL time.Duration

	// RenewInterval is how often the holder renews. Defaults to LeaseTTL/3.
	//
	// It must satisfy RenewInterval*3 <= LeaseTTL. The acknowledged deadline is
	// hard and an unacknowledged renewal does not extend it, so a cadence is
	// only a cadence if a renewal can fail and still be retried before the
	// deadline arrives.
	//
	// At the default third of the TTL, attempts land at T/3, 2T/3 and T: two
	// strictly before the deadline, so one failure is survivable. Set it lower
	// for more retries; the rule is a floor on safety, not a target.
	RenewInterval time.Duration

	// RetryInterval is how long a follower waits before campaigning again,
	// after a refused acquisition or a Coordinator that could not answer.
	// Defaults to RenewInterval.
	RetryInterval time.Duration

	// PromoteGuard is the minimum acknowledged lease that must remain before
	// the controller will INITIATE a promotion. Defaults to RenewInterval.
	//
	// It is defense in depth and not the fencing mechanism: what actually
	// aborts a promotion whose lease died is the lease context, which is
	// canceled the moment Done closes. This only avoids starting one that is
	// already unlikely to finish inside the lease it was authorized by. It must
	// be less than LeaseTTL, or no promotion would ever be initiated.
	//
	// It bites when an acquisition or renewal took most of the TTL to be
	// acknowledged, because the deadline is measured from when that request was
	// ISSUED. In a healthy loop nearly the whole TTL remains at each reconcile
	// and the guard is silent.
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

// Validate reports whether the configuration describes a controller that can
// hold a lease safely. It is called by [New] AFTER defaults are applied, so it
// judges the values the controller will actually run with.
//
// Every rejection is common.ErrInvalidArgument wrapped with the offending
// value, because these are settings someone typed and someone has to correct.
func (c Config) Validate() error {
	if c.NodeID == "" {
		return fmt.Errorf("%w: NodeID is required", common.ErrInvalidArgument)
	}
	if c.LeaseTTL < time.Second {
		return fmt.Errorf("%w: LeaseTTL %s is below the Coordinator's one-second lease granularity",
			common.ErrInvalidArgument, c.LeaseTTL)
	}
	// Spelled as a division rather than RenewInterval*3 > LeaseTTL: the
	// multiplication overflows int64 for an absurd interval and wraps
	// NEGATIVE, which would pass the check it exists to fail.
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
