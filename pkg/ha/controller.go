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

// campaign runs the acquire/lead/retry loop until ctx is done.
//
// Every branch that is not a successful acquisition leads to the same place:
// wait, try again, and promote nothing in the meantime. A refused acquisition
// and a Coordinator that could not answer are different facts — Status.Err
// keeps them apart — but they authorize the same amount of writing, which is
// none.
func (c *Controller) campaign(ctx context.Context, v *volume) {
	for {
		if ctx.Err() != nil {
			v.stopped(nil)
			return
		}

		// The deadline is measured from when the request was ISSUED, not from
		// when it returned. The backend grants the TTL at some point between
		// those two instants, and the issue is the conservative end: a slow
		// round trip then shows up as less lease remaining rather than as the
		// same lease starting later. It is the same discipline as computing
		// the deadline from the configured TTL, which the backend rounds up.
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
			// Not a contended key: the Coordinator itself could not answer.
			// A substrate that cannot say whether this node owns the volume is
			// not permission to write to it, so this is the fail-STOPPED
			// branch and looks exactly like losing the election.
			if ctx.Err() != nil {
				v.stopped(nil)
				return
			}
			c.cfg.Logger.Error("coordinator could not answer an acquisition",
				"node", c.cfg.NodeID, "volume", v.volID, "key", v.key, "err", err)
			// A Coordinator that does not support leases at all reports here
			// too, and looks exactly like an outage. See the package doc: this
			// controller requires a lease-capable Coordinator in every
			// deployment, and a volume that never leaves campaigning is the
			// symptom of one that is not.
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
	// Every provider call made while leading runs under leaseCtx, so losing
	// the lease reaches work already in flight and not merely the next
	// iteration of this loop. That is what makes "fenced immediately" true of
	// a promotion that is halfway through drbdadm rather than only of one that
	// has not started.
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
		// Fencing wins a tie. A select over several ready cases picks at
		// random, so a lease that ended in the same instant the manager was
		// canceled would report a clean stop half the time — hiding a fencing
		// event on a node that was fenced. Both paths demote; only this one
		// says why, and on a fencing-critical component the record of having
		// been fenced is the part worth being deterministic about.
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
				// A failed renewal does NOT extend the acknowledged deadline
				// and does NOT fence. Done is the authority on whether the
				// lease still exists — the contract lets a late renewal report
				// its loss in more than one spelling — so this is recorded and
				// the loop goes back to a select that watches Done. The
				// cadence is what makes that safe: at the default third of the
				// TTL a failure here still has one more attempt landing
				// strictly before the deadline.
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

// reconcile drives the local role toward the lease this controller holds.
//
// It runs only from the volume's own goroutine, which is what makes its
// check-then-act sequences safe: read the remaining lease then decide, read the
// replication state then promote. Nothing else in this package touches a
// volume's provider calls, and [ErrAlreadyManaged] is what keeps a second
// goroutine from appearing.
func (c *Controller) reconcile(leaseCtx context.Context, v *volume, lease common.Lease) {
	if c.authorityEnded(leaseCtx, lease) {
		return
	}

	// Enough acknowledged lease to cover the operation? Defense in depth: what
	// actually aborts a promotion whose lease died is leaseCtx. This only
	// declines to start one already unlikely to finish inside its authority.
	//
	// It is also what makes an acquisition that took longer than the TTL it
	// granted safe DETERMINISTICALLY. In that case the lease is over before it
	// is ever used, and whether leaseCtx has been canceled yet depends on the
	// watcher goroutine having been scheduled — which Go does not promise. The
	// arithmetic does not need scheduling: the deadline runs from the issue, so
	// the remaining lease is already negative here.
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

	// One guard, placed to cover everything the read leads to — the primary
	// ANNOUNCEMENT below as much as the promotion after it. A read can complete
	// honestly a moment after the lease died, and announcing "this node is
	// primary" on the strength of it would have an orchestrator mount a volume
	// this controller no longer owns. Recording what was read is fine; acting
	// or announcing on it is not.
	//
	// It does not close the window — leaseCtx, threaded into Promote itself,
	// does that. It stops this reconcile from speaking past its authority.
	if c.authorityEnded(leaseCtx, lease) {
		return
	}

	if repl.Role == common.ReplRolePrimary {
		// Already primary: there is nothing to promote, so the question becomes
		// whether this copy may be ANNOUNCED as serving. That is a different
		// question with a broader answer — see adoptEligibility.
		//
		// Do not "simplify" this to promoteEligibility. Announcing changes
		// nothing the promotion gate exists to prevent, and the narrow gate
		// applied here would refuse an established Primary whose peer merely
		// died — DRBD reports that as connecting, not uptodate — so an
		// orchestrator acting on the withdrawn announcement would unmount the
		// last surviving copy. That is the failure high availability exists to
		// prevent, not one to cause.
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

	// The guard again, and THIS is the authoritative one. The check at the top
	// of this function is a cheap early-out; the replication-state read between
	// them can take arbitrary time, and what the guard is about is how much
	// acknowledged lease remains when the promotion STARTS. A guard checked
	// before a slow read is a guard checked against a world that has moved.
	//
	// The announcement path above is deliberately not guarded this way. It
	// authorizes nothing that has to finish, so there is no operation that could
	// outlive the lease; the renewal loop is what keeps an announcement honest,
	// and Done is what withdraws it.
	if err := c.guardRemaining(v); err != nil {
		v.refused(err)
		return
	}

	promoteErr := c.provider.Promote(leaseCtx, v.volID)

	if c.authorityEnded(leaseCtx, lease) {
		// The promotion's authority ended while it was in flight. Whatever
		// Promote returned, this node is not the elected owner any more, so
		// the promotion is void — including the case where it SUCCEEDED, which
		// is the dangerous one and the reason this branch exists at all.
		c.voidPromotion(v, lease, promoteErr)
		return
	}
	if promoteErr != nil {
		// A provider refusal is surfaced, never worked around: DRBD declines a
		// promotion precisely when promoting would be unsafe, and forcing past
		// that is a data-loss decision belonging to an operator.
		c.cfg.Logger.Error("promotion failed",
			"node", c.cfg.NodeID, "volume", v.volID, "err", promoteErr)
		// The claim is dropped, not merely annotated. Reaching this line means
		// the read said the local role was NOT primary and the attempt to make
		// it so failed, so an announcement standing from an earlier reconcile is
		// now known to be wrong — and an orchestrator holding a mount on the
		// strength of it would be holding it on nothing.
		v.promotionFailed(fmt.Errorf("promoting %q: %w", v.volID, promoteErr))
		return
	}

	c.cfg.Logger.Info("promoted",
		"node", c.cfg.NodeID, "volume", v.volID, "epoch", v.epoch())
	v.promoted()
}

// voidPromotion records a promotion whose authority ended while it was running.
//
// The primary claim is dropped unconditionally: it expired with the lease, and
// whether the device can actually be demoted is a separate question with a
// separate answer.
//
// It does NOT demote. The loop this returns into is about to take one of two
// exits — fence, because the lease died, or stopLeading, because the manager
// was canceled — and each of those owns exactly one demote. Giving the role
// back here as well would call Demote twice for one event, on a path where a
// second call is either redundant or racing the release the shutdown is about
// to do.
//
// The lease is consulted to say WHICH of the two happened, because the reason
// is what an operator reads, and "the lease was lost" and "you stopped me" are
// not the same incident.
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

// fence marks the volume fenced and gives the role back if it can.
//
// cancel is called first, not last: the fence must reach work in flight, and
// the loop reaching this line does not by itself mean the watcher goroutine has
// already observed Done.
func (c *Controller) fence(v *volume, cancel context.CancelFunc) {
	cancel()
	reason := fmt.Errorf("%w: %q", ErrFenced, v.volID)
	c.cfg.Logger.Warn("fenced: primary lease lost",
		"node", c.cfg.NodeID, "volume", v.volID, "key", v.key, "epoch", v.epoch())
	v.fenced(reason)
	c.yieldRole(v, reason)
}

// yieldRole attempts the best-effort demote that follows a fence.
//
// It runs on a fresh bounded context because the lease context is exactly what
// just ended. A failure is recorded and logged, never swallowed: DRBD refuses
// to demote an open device, so "still mounted by the workload" is the expected
// failure here, and a fenced controller that could not demote must not read as
// one that did.
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

// stopLeading runs the graceful shutdown of a holder: hold the lease, demote,
// and release only if the demote succeeded.
//
// Releasing while still Primary would hand the peer permission to promote
// against a node that is still writing; leaving the lease to expire instead
// makes the takeover TTL-gated, which is what a crash would have produced
// anyway and is the outcome the peer is already built to handle.
//
// The whole sequence is bounded by Config.ActionTimeout, renewals included, so
// a demote that is never going to return ends the shutdown rather than holding
// the key forever.
func (c *Controller) stopLeading(v *volume, lease common.Lease) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.ActionTimeout)
	defer cancel()

	// The lease is held ACROSS the demote, not dropped before it.
	//
	// Demoting can take longer than the lease has left — ActionTimeout is
	// larger than a typical LeaseTTL, and a demote blocked on an open device is
	// exactly the slow case. Letting the lease lapse there would invite the
	// peer to promote against a node that is still Primary, and it would be a
	// window this path CHOSE rather than one it inherited. A crash cannot help
	// leaving that window; a planned shutdown can.
	//
	// Renewals here report through the log and never through the status: status
	// transitions stay on the manager goroutine, which is what makes the
	// observer's ordering guarantee true.
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
				// The announcement goes NOW, not when the demote returns. A
				// demote blocked on an open device holds the manager for up to
				// ActionTimeout, and for all of that time the lease is gone and
				// a peer may already have acquired it; going on advertising
				// this node as the authorized primary is the one thing a
				// fencing controller must never do. Waiting for the demote
				// would make the fence as slow as the slowest failure.
				//
				// This is the only status write not made by the manager
				// goroutine, and it is safe for the reason the ordering
				// guarantee actually rests on: that goroutine is blocked inside
				// Demote and writes nothing until this one has returned, so
				// there is still exactly one writer at a time.
				//
				// Renewing on would also produce a stream of failures that read
				// like the shutdown breaking, when what happened is the thing
				// this loop was protecting against.
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
					// Only an acknowledged renewal moves it — the same rule the
					// leading loop follows, spelled with an else rather than a
					// break because a break inside a select leaves the select,
					// not the loop, and that reads as a bug even when it is not.
					deadline = issued.Add(c.cfg.LeaseTTL)
				}
			}
		}
	}()

	demoteErr := c.provider.Demote(ctx, v.volID)
	close(stopRenewing)
	<-renewing

	// The renewals above narrow the window in which the lease can end during
	// the demote; they do not close it. If it ended anyway this is not a clean
	// stop, whatever the demote returned: the authorization is gone, a peer may
	// already hold the key, and reporting a tidy shutdown would hide both.
	//
	// It is recorded HERE, on the manager goroutine, rather than in the renewal
	// loop that noticed it — status transitions stay on one goroutine, and that
	// is what makes the observer's ordering guarantee true.
	if leaseEnded(lease) {
		// The renewal loop above may already have fenced this volume the moment
		// Done closed, which is the point of it doing so. What it could not know
		// then is how the demote went, so the account is completed here and
		// takes precedence — including the hazard sentinel, because a lease that
		// is gone while the demote failed is precisely a node that may still be
		// writable with nothing authorizing it.
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

	// A lease that ends between the check above and this release is a window
	// that cannot be closed by checking again afterwards: a SUCCESSFUL release
	// closes Done itself, so a second look could never tell the two apart. What
	// it costs is a status labeled "released" for a lease that had already
	// expired — a reporting difference, not an unsafe act, since the key ends
	// up free either way and the demote has already happened.
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

// releaseLease retries a release, because a revoke the backend did not
// acknowledge is not a release: the key may well still be bound, and reporting
// it as freed would tell the peer to expect an acquisition that keeps failing.
// A release that cannot be acknowledged at all is returned, and the caller
// leaves the deadline to do the work.
//
// Attempts are spaced by the renewal interval — the cadence this controller
// already talks to the Coordinator on, rather than one more timing knob — and
// the sequence ends at whichever comes first, the attempt count or
// Config.ActionTimeout. A deployment with a long cadence runs out of time
// rather than out of attempts, and one with a high attempt count still stops at
// the timeout instead of spinning through the rest against a context that is
// already done. Either way it ends, and the outcome of ending is the same: the
// deadline frees the key.
func (c *Controller) releaseLease(ctx context.Context, lease common.Lease) error {
	var err error
	for attempt := 1; attempt <= c.cfg.ReleaseAttempts; attempt++ {
		if err = lease.Release(ctx); err == nil {
			return nil
		}
		// The bound is the timeout, not the attempt count. Once ctx is done
		// every remaining attempt would be an immediate failure against a dead
		// deadline, so a high ReleaseAttempts would spin instead of stopping —
		// and a shutdown that says it is bounded by ActionTimeout has to be.
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

// guardRemaining returns a refusal when too little acknowledged lease remains to
// INITIATE a promotion, and nil when there is enough.
//
// It exists as one function because it is asked twice in a single reconcile —
// once cheaply before the replication-state read, once authoritatively after it
// — and two spellings of the same rule would eventually stop agreeing.
func (c *Controller) guardRemaining(v *volume) error {
	remaining := v.deadline().Sub(c.cfg.Clock.Now())
	if remaining < c.cfg.PromoteGuard {
		return fmt.Errorf("%w: %q has %s left, guard is %s",
			ErrLeaseTooShort, v.volID, remaining, c.cfg.PromoteGuard)
	}
	return nil
}

// renewDelay returns how long to wait before the next renewal attempt.
//
// It is Config.RenewInterval in a healthy loop and LESS when the lease has
// less than that much life in it, because the cadence has to be measured
// against the acknowledged DEADLINE rather than against the moment the last
// call happened to return. An acquire or renew that consumed most of the TTL
// leaves the controller with a deadline much nearer than a full interval away;
// waiting one anyway would let the lease expire without a single attempt to
// keep it, which is the failure the cadence exists to prevent.
//
// Halving what remains rather than clamping to some fixed lead time is what
// keeps a struggling lease from turning into a busy loop: each attempt still
// leaves as much room as it consumed, so the delays shrink toward the deadline
// instead of collapsing to zero and hammering a backend that is already slow.
//
// Every wait is floored at [minRenewDelay], including the one past a deadline
// that has already gone by. That case is not the same as "the lease is over":
// the tracked deadline is deliberately conservative, so it can pass while the
// backend's rounded-up lease is still alive, and in that window Done has NOT
// closed and the loop's fence check does not fire. Returning zero there would
// retry as fast as the scheduler allows for the rest of the second.
func (c *Controller) renewDelay(deadline time.Time) time.Duration {
	remaining := deadline.Sub(c.cfg.Clock.Now())
	if remaining <= 0 {
		return minRenewDelay
	}
	if half := remaining / 2; half < c.cfg.RenewInterval {
		return max(half, minRenewDelay)
	}
	return c.cfg.RenewInterval
}

// authorityEnded reports whether this reconcile may still act or speak.
//
// It asks BOTH the lease and the context, and the lease is the reason it exists.
// leaseCtx is canceled by a watcher goroutine when Done closes, and Go does not
// promise that goroutine has run yet — so there is a scheduling window in which
// the lease is provably over and leaseCtx.Err() is still nil. A check that
// consulted only the context would, in that window, let a completed promotion
// be accepted and ANNOUNCED for a node that no longer owns the volume.
//
// Done is closed synchronously by whatever ended the lease and needs nothing
// scheduled to be true, which is the same reason the promote guard is computed
// from arithmetic rather than from a cancellation. The context still earns its
// place: it is what carries a caller's shutdown, which the lease knows nothing
// about, and it is what reaches INSIDE a provider call already running.
func (c *Controller) authorityEnded(leaseCtx context.Context, lease common.Lease) bool {
	return leaseCtx.Err() != nil || leaseEnded(lease)
}

// leaseEnded reports, without blocking, whether the lease is over.
//
// It is how the two places that must tell "the lease was lost" from "the caller
// stopped us" ask the question. Done is the authority on that, not the spelling
// of whatever error a call happened to return.
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

// validateVolumeID rejects an id that cannot become a coordination key.
//
// Providers already constrain the names they hand out to a far narrower
// allowlist, so this rejects nothing a provider produces. It is here because
// the id is CONCATENATED onto Config.KeyPrefix: a separator would place the
// volume's lease outside the namespace the prefix defines, where it could
// collide with another one, and a control character would corrupt every log
// line and key dump the lease appears in.
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
