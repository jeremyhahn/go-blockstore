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
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// Controller campaigns for per-volume primary leases and drives the local
// copy's replication role to match what it holds.
//
// One Controller runs per node. It manages any number of volumes, each with its
// own lease and its own goroutine, and it refuses to manage the same volume
// twice — see [ErrAlreadyManaged] for why that refusal is the serialization
// this package relies on.
type Controller struct {
	provider common.ReplicatedProvider
	coord    common.Coordinator
	cfg      Config

	mu      sync.Mutex
	managed map[string]*volume
}

// New returns a Controller driving provider, coordinating through coord.
//
// Both dependencies are passed explicitly rather than resolved from
// pkg/factory. The factory builds providers, which are mechanical and need no
// Coordinator; this controller is the library's only Coordinator consumer, so a
// Coordinator seam in the factory would put a lease behind a name lookup and
// give every provider a dependency exactly one caller uses.
//
// It returns common.ErrInvalidArgument, wrapped, for a missing dependency or a
// configuration that could not hold a lease safely.
func New(provider common.ReplicatedProvider, coord common.Coordinator, cfg Config) (*Controller, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: a common.ReplicatedProvider is required", common.ErrInvalidArgument)
	}
	if coord == nil {
		return nil, fmt.Errorf("%w: a common.Coordinator is required", common.ErrInvalidArgument)
	}
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Controller{
		provider: provider,
		coord:    coord,
		cfg:      cfg,
		managed:  make(map[string]*volume),
	}, nil
}

// Config returns the controller's settled configuration — the values passed to
// [New] with defaults applied.
func (c *Controller) Config() Config { return c.cfg }

// Managed returns the volume ids this controller currently manages, sorted.
func (c *Controller) Managed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.managed))
	for id := range c.managed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Status reports the current state of a managed volume. It returns
// [ErrNotManaged] for a volume with no manager, which includes one whose
// Manage has already returned.
func (c *Controller) Status(volID string) (Status, error) {
	c.mu.Lock()
	v, ok := c.managed[volID]
	c.mu.Unlock()
	if !ok {
		return Status{}, fmt.Errorf("%w: %q", ErrNotManaged, volID)
	}
	return v.snapshot(), nil
}

// Manage campaigns for volID's primary lease and keeps the local replication
// role in step with it until ctx is canceled. It BLOCKS; run it in its own
// goroutine, one per volume.
//
// Canceling ctx starts a shutdown; it does not return at once. A manager that
// holds the lease gives the role back first, and that work runs on its own
// budget — up to Config.ActionTimeout — because the context asking it to stop
// is the same one it would otherwise be using to stop safely. Callers with
// their own deadline should size it above ActionTimeout.
//
// It returns nil for a clean stop, and an error only for a request it would not
// start: an invalid volume id, or a volume this controller already manages
// ([ErrAlreadyManaged]). A stop that could not complete cleanly — a demote or a
// release the backend refused — is reported through the final [Status] and the
// logger, not through this return value, because by then the caller has already
// asked for a shutdown and there is nothing left for it to decide.
func (c *Controller) Manage(ctx context.Context, volID string) error {
	if err := validateVolumeID(volID); err != nil {
		return err
	}
	v, err := c.register(volID)
	if err != nil {
		return err
	}
	defer c.unregister(volID)

	c.campaign(ctx, v)
	return nil
}

// register claims volID for a single manager.
func (c *Controller) register(volID string) (*volume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.managed[volID]; exists {
		return nil, fmt.Errorf("%w: %q", ErrAlreadyManaged, volID)
	}
	v := &volume{
		ctrl:  c,
		volID: volID,
		key:   c.cfg.KeyPrefix + volID,
	}
	v.status = Status{
		VolumeID:  volID,
		NodeID:    c.cfg.NodeID,
		Phase:     PhaseIdle,
		LeaseKey:  v.key,
		UpdatedAt: c.cfg.Clock.Now(),
	}
	c.managed[volID] = v
	return v, nil
}

// unregister releases the claim so the volume can be managed again later.
func (c *Controller) unregister(volID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.managed, volID)
}

// campaign runs the acquire, lead and retry loop until ctx is done, promoting nothing while not leading.
func (c *Controller) campaign(ctx context.Context, v *volume) {
	for {
		if ctx.Err() != nil {
			v.stopped(nil)
			return
		}

		// The deadline runs from when the request was issued.
		issued := c.cfg.Clock.Now()
		lease, err := c.coord.AcquireLease(ctx, v.key, c.cfg.LeaseTTL)
		switch {
		case err == nil:
			c.serve(ctx, v, lease, issued)
		case errors.Is(err, common.ErrLeaseHeld):
			c.cfg.Logger.Debug("primary lease held elsewhere",
				"node", c.cfg.NodeID, "volume", v.volID, "key", v.key, "err", err)
			v.campaigning(err)
		default:
			// The Coordinator could not answer: promote nothing, as when the election is lost.
			if ctx.Err() != nil {
				v.stopped(nil)
				return
			}
			c.cfg.Logger.Error("coordinator could not answer an acquisition",
				"node", c.cfg.NodeID, "volume", v.volID, "key", v.key, "err", err)
			// A Coordinator without lease support also lands here; this controller requires one that leases.
			v.campaigning(fmt.Errorf("acquiring the primary lease for %q: %w", v.volID, err))
		}

		if !c.wait(ctx, c.cfg.RetryInterval) {
			v.stopped(nil)
			return
		}
	}
}

// serve holds the lease: reconcile once, then renew on a cadence until the
// lease ends or the caller stops.
func (c *Controller) serve(ctx context.Context, v *volume, lease common.Lease, issued time.Time) {
	// Provider calls run under leaseCtx, so losing the lease reaches work in flight.
	leaseCtx, cancel := context.WithCancel(ctx)

	watching := make(chan struct{})
	go func() {
		defer close(watching)
		select {
		case <-lease.Done():
			cancel()
		case <-leaseCtx.Done():
		}
	}()
	defer func() {
		cancel()
		<-watching
	}()

	v.leading(issued.Add(c.cfg.LeaseTTL), lease.Key())
	c.cfg.Logger.Info("holding the primary lease",
		"node", c.cfg.NodeID, "volume", v.volID, "key", lease.Key(), "epoch", v.epoch())
	c.reconcile(leaseCtx, v, lease)

	for {
		// Fencing wins a tie with cancellation, so the fence is always recorded.
		select {
		case <-lease.Done():
			c.fence(v, cancel)
			return
		default:
		}

		select {
		case <-lease.Done():
			c.fence(v, cancel)
			return

		case <-ctx.Done():
			c.stopLeading(v, lease)
			return

		case <-c.cfg.Clock.After(c.renewDelay(v.deadline())):
			renewIssued := c.cfg.Clock.Now()
			if err := lease.Renew(leaseCtx); err != nil {
				// A failed renewal neither extends the deadline nor fences; Done decides.
				c.cfg.Logger.Warn("lease renewal failed",
					"node", c.cfg.NodeID, "volume", v.volID, "key", lease.Key(), "err", err)
				v.renewFailed(fmt.Errorf("%w: renewing the primary lease for %q: %w",
					ErrRenewFailed, v.volID, err))
				continue
			}
			v.acknowledged(renewIssued.Add(c.cfg.LeaseTTL))
			c.reconcile(leaseCtx, v, lease)
		}
	}
}

// reconcile drives the local role toward the held lease, only from the volume's own goroutine.
func (c *Controller) reconcile(leaseCtx context.Context, v *volume, lease common.Lease) {
	if c.authorityEnded(leaseCtx, lease) {
		return
	}

	// Decline to start a promotion without enough acknowledged lease, independent of goroutine scheduling.
	if err := c.guardRemaining(v); err != nil {
		v.refused(err)
		return
	}

	repl, err := c.provider.ReplicationState(leaseCtx, v.volID)
	if err != nil {
		if c.authorityEnded(leaseCtx, lease) {
			return
		}
		c.cfg.Logger.Error("reading replication state failed",
			"node", c.cfg.NodeID, "volume", v.volID, "err", err)
		v.failed(fmt.Errorf("reading the replication state of %q: %w", v.volID, err))
		return
	}
	v.observed(repl)

	// Neither announce nor promote once authority has ended.
	if c.authorityEnded(leaseCtx, lease) {
		return
	}

	if repl.Role == common.ReplRolePrimary {
		// Already primary: announce under adoptEligibility, not promoteEligibility, so a Primary whose peer died stays announced.
		if ok, reason := adoptEligibility(repl); !ok {
			c.cfg.Logger.Warn("the local copy is primary but will not be announced as serving",
				"node", c.cfg.NodeID, "volume", v.volID, "conn", string(repl.Conn), "reason", reason)
			v.refused(fmt.Errorf("%w: %q is primary and %s: %s", ErrNotServiceable, v.volID, repl.Conn, reason))
			return
		}
		v.promoted()
		return
	}

	if ok, reason := promoteEligibility(repl); !ok {
		c.cfg.Logger.Info("declining to promote",
			"node", c.cfg.NodeID, "volume", v.volID, "conn", string(repl.Conn), "reason", reason)
		v.refused(fmt.Errorf("%w: %q is %s: %s", ErrNotPromotable, v.volID, repl.Conn, reason))
		return
	}

	// The authoritative guard, checked after the slow replication-state read and just before the promotion.
	if err := c.guardRemaining(v); err != nil {
		v.refused(err)
		return
	}

	promoteErr := c.provider.Promote(leaseCtx, v.volID)

	if c.authorityEnded(leaseCtx, lease) {
		// Authority ended during the promotion: void it, even if it succeeded.
		c.voidPromotion(v, lease, promoteErr)
		return
	}
	if promoteErr != nil {
		// A provider refusal is surfaced, never worked around: DRBD declines a
		// promotion precisely when promoting would be unsafe, and forcing past
		// that is a data-loss decision belonging to an operator.
		c.cfg.Logger.Error("promotion failed",
			"node", c.cfg.NodeID, "volume", v.volID, "err", promoteErr)
		// The promotion failed, so drop any standing primary announcement.
		v.promotionFailed(fmt.Errorf("promoting %q: %w", v.volID, promoteErr))
		return
	}

	c.cfg.Logger.Info("promoted",
		"node", c.cfg.NodeID, "volume", v.volID, "epoch", v.epoch())
	v.promoted()
}

// voidPromotion drops the primary claim and records whether the lease ended or the manager stopped; the caller's exit path demotes.
func (c *Controller) voidPromotion(v *volume, lease common.Lease, promoteErr error) {
	reason := fmt.Errorf("the promotion of %q is void, the manager was stopped while it was in flight", v.volID)
	if leaseEnded(lease) {
		reason = fmt.Errorf("%w: the promotion of %q is void, the lease ended while it was in flight",
			ErrFenced, v.volID)
	}
	if promoteErr != nil {
		reason = fmt.Errorf("%w (the promotion itself reported: %w)", reason, promoteErr)
	}
	c.cfg.Logger.Error("promotion voided",
		"node", c.cfg.NodeID, "volume", v.volID, "err", reason)
	v.fencedWith(reason)
}

// fence marks the volume fenced and gives the role back; cancel runs first to reach work in flight.
func (c *Controller) fence(v *volume, cancel context.CancelFunc) {
	cancel()
	reason := fmt.Errorf("%w: %q", ErrFenced, v.volID)
	c.cfg.Logger.Warn("fenced: primary lease lost",
		"node", c.cfg.NodeID, "volume", v.volID, "key", v.key, "epoch", v.epoch())
	v.fenced(reason)
	c.yieldRole(v, reason)
}

// yieldRole demotes on a fresh bounded context after a fence and records any failure.
func (c *Controller) yieldRole(v *volume, reason error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.ActionTimeout)
	defer cancel()

	if err := c.provider.Demote(ctx, v.volID); err != nil {
		c.cfg.Logger.Error("demote after losing the lease failed; the local copy may still be writable",
			"node", c.cfg.NodeID, "volume", v.volID, "err", err)
		v.demoteFailed(fmt.Errorf("%w; %w: demoting %q afterwards failed: %w",
			reason, ErrRoleNotYielded, v.volID, err))
		return
	}
	c.cfg.Logger.Info("demoted after losing the lease", "node", c.cfg.NodeID, "volume", v.volID)
	v.demoted()
}

// stopLeading holds the lease while demoting, releases only if the demote succeeded, all within ActionTimeout.
func (c *Controller) stopLeading(v *volume, lease common.Lease) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.ActionTimeout)
	defer cancel()

	// Keep renewing across the demote; renewals log here and never change the status.
	stopRenewing := make(chan struct{})
	renewing := make(chan struct{})
	go func() {
		defer close(renewing)
		// Tracked locally: this loop deliberately writes no status, so it
		// cannot read the deadline back from one either.
		deadline := v.deadline()
		for {
			select {
			case <-stopRenewing:
				return
			case <-ctx.Done():
				return
			case <-lease.Done():
				// Announce the fence now, from this goroutine, while the manager is blocked in Demote.
				c.cfg.Logger.Warn("fenced during shutdown: the lease ended before the demote finished",
					"node", c.cfg.NodeID, "volume", v.volID, "key", lease.Key())
				v.fenced(fmt.Errorf("%w: %q, the lease ended during the shutdown demote",
					ErrFenced, v.volID))
				return
			case <-c.cfg.Clock.After(c.renewDelay(deadline)):
				issued := c.cfg.Clock.Now()
				if err := lease.Renew(ctx); err != nil {
					c.cfg.Logger.Warn("renewal during shutdown failed; the lease may lapse before the demote finishes",
						"node", c.cfg.NodeID, "volume", v.volID, "key", lease.Key(), "err", err)
				} else {
					// Only an acknowledged renewal moves the deadline.
					deadline = issued.Add(c.cfg.LeaseTTL)
				}
			}
		}
	}()

	demoteErr := c.provider.Demote(ctx, v.volID)
	close(stopRenewing)
	<-renewing

	// A lease that ended during the demote makes this a fence, recorded on the manager goroutine.
	if leaseEnded(lease) {
		// Complete the fence record with the demote's outcome, which takes precedence.
		reason := fmt.Errorf("%w: %q, the lease ended during the shutdown demote", ErrFenced, v.volID)
		if demoteErr != nil {
			reason = fmt.Errorf("%w; %w: the demote did not complete either: %w",
				reason, ErrRoleNotYielded, demoteErr)
		}
		c.cfg.Logger.Warn("shutdown ended fenced",
			"node", c.cfg.NodeID, "volume", v.volID, "key", lease.Key(), "err", reason)
		v.fencedWith(reason)
		// No release: the key the lease was bound to is already free, so there
		// is nothing to give back and an attempt would only add a confusing
		// error to a status that has already said the important thing.
		v.stopped(nil)
		return
	}

	if demoteErr != nil {
		c.cfg.Logger.Warn("stopping while still primary: the lease will be left to expire",
			"node", c.cfg.NodeID, "volume", v.volID, "err", demoteErr)
		v.stopped(fmt.Errorf("stopping %q while still primary: demote failed, leaving the lease to expire: %w",
			v.volID, demoteErr))
		return
	}

	// A lease ending just before this release only mislabels the status; the key ends up free either way.
	v.demoted()

	if err := c.releaseLease(ctx, lease); err != nil {
		c.cfg.Logger.Warn("could not release the primary lease; leaving it to expire",
			"node", c.cfg.NodeID, "volume", v.volID, "key", lease.Key(), "err", err)
		v.stopped(fmt.Errorf("releasing the primary lease for %q: %w", v.volID, err))
		return
	}
	c.cfg.Logger.Info("released the primary lease", "node", c.cfg.NodeID, "volume", v.volID, "key", lease.Key())
	v.stopped(nil)
}

// releaseLease retries an unacknowledged release every RenewInterval until ReleaseAttempts or ActionTimeout, then leaves the key to the deadline.
func (c *Controller) releaseLease(ctx context.Context, lease common.Lease) error {
	var err error
	for attempt := 1; attempt <= c.cfg.ReleaseAttempts; attempt++ {
		if err = lease.Release(ctx); err == nil {
			return nil
		}
		// Stop at the timeout, not only the attempt count.
		if ctx.Err() != nil {
			break
		}
		if attempt < c.cfg.ReleaseAttempts {
			select {
			case <-ctx.Done():
			case <-c.cfg.Clock.After(c.cfg.RenewInterval):
			}
		}
	}
	return fmt.Errorf("after %d attempts: %w", c.cfg.ReleaseAttempts, err)
}

// guardRemaining refuses when too little acknowledged lease remains to start a promotion.
func (c *Controller) guardRemaining(v *volume) error {
	remaining := v.deadline().Sub(c.cfg.Clock.Now())
	if remaining < c.cfg.PromoteGuard {
		return fmt.Errorf("%w: %q has %s left, guard is %s",
			ErrLeaseTooShort, v.volID, remaining, c.cfg.PromoteGuard)
	}
	return nil
}

// renewDelay is RenewInterval, or half the remaining lease when less, floored at minRenewDelay.
func (c *Controller) renewDelay(deadline time.Time) time.Duration {
	remaining := deadline.Sub(c.cfg.Clock.Now())
	if remaining <= 0 {
		return minRenewDelay
	}
	delay := min(c.cfg.RenewInterval, remaining/2)
	delay = max(delay, minRenewDelay)
	// Never sleep past a deadline that is still live.
	return min(delay, remaining)
}

// authorityEnded reports whether the lease's Done has closed or the context is done.
func (c *Controller) authorityEnded(leaseCtx context.Context, lease common.Lease) bool {
	return leaseCtx.Err() != nil || leaseEnded(lease)
}

// leaseEnded reports, without blocking, whether the lease's Done has closed.
func leaseEnded(lease common.Lease) bool {
	select {
	case <-lease.Done():
		return true
	default:
		return false
	}
}

// wait sleeps for d, reporting false if ctx ended first.
func (c *Controller) wait(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-c.cfg.Clock.After(d):
		return true
	}
}

// validateVolumeID rejects separators and control characters, since the id is appended to Config.KeyPrefix.
func validateVolumeID(volID string) error {
	if volID == "" {
		return fmt.Errorf("%w: volume id is empty", common.ErrInvalidArgument)
	}
	if strings.ContainsRune(volID, '/') {
		return fmt.Errorf("%w: volume id %q contains %q, which would place its lease key outside the configured prefix",
			common.ErrInvalidArgument, volID, "/")
	}
	for _, r := range volID {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: volume id %q contains the control character %U", common.ErrInvalidArgument, volID, r)
		}
	}
	return nil
}
