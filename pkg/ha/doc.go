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

// Package ha implements the high-availability controller for replicated
// volumes: one node campaigns for a per-volume primary lease on the injected
// common.Coordinator, promotes the local copy while it holds that lease, and
// stops acting the instant the lease is lost.
//
// The controller is the only consumer of the Coordinator in this library.
// Providers are mechanical — they create backing devices, generate resource
// configuration and expose Promote, Demote and ReplicationState — and they
// hold no leases. Keeping coordination here means the promotion path has
// exactly one gatekeeper, and it is why [New] takes the provider and the
// Coordinator explicitly rather than reaching for either through
// pkg/factory: the factory builds providers, which need no Coordinator, and
// adding a Coordinator seam to it would put a lease behind a name lookup.
//
// # The two mechanisms, and why there is no third
//
// A replicated volume is guarded by two mechanisms that compose, at different
// scopes:
//
//   - The providers' per-volume flock is HOST-LOCAL lifecycle serialization.
//     It keeps two processes on the same machine from running overlapping
//     lifecycle operations against one volume. It says nothing about any other
//     host.
//   - The Coordinator lease is CROSS-NODE ownership. It says which node of the
//     pair may hold the primary role. It says nothing about what else is
//     running on that node.
//
// Neither substitutes for the other, and this package adds no third. In
// particular it publishes no "current owner" key alongside the lease: a second
// key would have to be deleted by whoever wrote it, so it would outlive the
// lease that justified it exactly in the case that matters — the holder dying
// — and a stale owner record is worse than none. Who holds the role is
// answered by the lease itself and by the provider's ReplicationState.
//
// # What this controller requires of a Coordinator
//
// A LEASE-CAPABLE one, in every deployment, clustered or not.
//
// The Coordinator contract allows an implementation without consensus to reject
// AcquireLease and Watch as "not supported" while still serving Get, Put,
// Delete and CompareAndSwap identically, and go-qrdb is such an
// implementation: its lease and watch families are raft-only, its key/value
// family is not. CompareAndSwap is therefore the portable verb and a lease is
// not, which raises a fair question — should this controller carry a
// CAS-based arbitration path for backends that cannot lease?
//
// It does not, and the reason is the one that keeps it from publishing an owner
// key: the promotion path has exactly one gatekeeper. A second arbitration
// mechanism would be a second thing to be correct about on the path where being
// wrong means two nodes writing to one device, and it would be chosen by
// configuration — which means it could be chosen wrongly, by someone who did
// not know which guarantees they had just traded away.
//
// So the deployment supplies a Coordinator that leases, rather than the
// controller growing a mode that does not. Two ways to do that, and what each
// one actually guarantees:
//
//   - CLUSTERED: a consensus-backed Coordinator — go-qrdb in raft mode. The
//     lease means what this package's fencing assumes it means: cross-node
//     ownership, arbitrated by a quorum that survives the loss of any single
//     node. This is the only configuration in which a replicated pair managed
//     from BOTH of its nodes is safe.
//   - SINGLE-NODE: an in-process Coordinator serving the whole contract without
//     raft. go-trusted-platform's pkg/storage/coordination.Local is exactly
//     this — a mutex-guarded map, TTL leases on timers, watch fan-out — and it
//     exists because qrdb's run modes are asymmetric in precisely this way.
//
// What the single-node one guarantees, precisely: arbitration among the
// goroutines of ONE process. Its guarantees stop at the process boundary, and
// that is the point rather than a limitation. What it does NOT protect against
// is the case it is easiest to misuse it for — a replicated pair whose two
// nodes each run their own control plane. There is no arbiter between two
// processes that share neither the map nor the leases, so both controllers
// would acquire "the" lease and both would promote. A replicated volume managed
// from more than one process needs the clustered Coordinator. A genuinely
// single-node deployment is safe with the in-process one because there is no
// second writer for an arbiter to arbitrate against.
//
// A Coordinator that rejects AcquireLease is not detected and specially
// reported, because "not supported" is implementation-defined and this package
// cannot recognize every spelling of it. It arrives at the fail-stopped branch
// like any other operational failure: the controller promotes nothing and
// retries, which is the safe direction and also indistinguishable from an
// outage. So the first thing to check when a volume never leaves campaigning is
// whether the Coordinator that was injected can lease at all.
//
// # Election
//
// Each managed volume gets its own goroutine and its own lease key,
// Config.KeyPrefix + volume id. The loop is:
//
//  1. AcquireLease on the volume's key. Acquisition is fail-fast, so a
//     contender does not queue behind the holder; it is refused.
//  2. common.ErrLeaseHeld means another node leads. The controller becomes a
//     follower and retries after Config.RetryInterval. It promotes nothing.
//  3. Any other error means the Coordinator could not answer. The controller
//     also promotes nothing, and retries. This is the fail-STOPPED direction:
//     a coordination substrate that cannot tell us whether we own the volume
//     is not permission to write to it.
//  4. On success the controller leads: it reconciles once immediately, then
//     renews on a cadence until the lease ends.
//
// Contenders poll rather than watch. A watch on the lease key reports that the
// key was deleted, which is not the same question as whether this node may now
// acquire it, and on an embedded go-qrdb backend the delete never fires at all
// (see the deployment caveat below). Retrying AcquireLease asks the question
// whose answer the controller actually acts on.
//
// Takeover latency after a holder stops renewing is therefore bounded by the
// lease TTL — the interval before the backend can free the key — plus at most
// one Config.RetryInterval.
//
// # Renewal cadence
//
// The acknowledged deadline is HARD. Done closes at it, an unacknowledged
// renewal never extends it, and a renewal that resolves after Done has closed
// reports a lease-lost error rather than success. A cadence therefore has to
// leave room for a renewal to fail and be retried before the deadline arrives,
// which is why [Config.Validate] requires RenewInterval*3 <= LeaseTTL and why
// the default is LeaseTTL/3.
//
// What that buys, counted exactly: renewals are attempted at T/3, 2T/3 and T
// for a deadline at T, so TWO of them land strictly before the deadline — a
// first attempt and one retry. The third is already at the deadline and is the
// one the contract says will report the lease as lost rather than extend it. A
// deployment that wants more than one retry sets RenewInterval below LeaseTTL/3
// rather than assuming the default provides it.
//
// The cadence is measured against the DEADLINE, not against the moment the last
// call returned, and the two differ exactly when it matters. An acquire or renew
// that consumed most of the TTL leaves the controller with far less than a full
// interval of lease; waiting one anyway would let it expire without a single
// attempt to keep it. So the wait is the interval or HALF of what remains,
// whichever is smaller. Halving rather than clamping to a fixed lead time is
// what keeps a struggling lease from becoming a busy loop: every attempt leaves
// as much room as it consumed, so the delays shrink toward the deadline instead
// of collapsing to zero against a backend that is already slow.
//
// The controller tracks the deadline itself, as the moment the last
// ACKNOWLEDGED acquire or renew was ISSUED plus Config.LeaseTTL. Two choices
// there both err in the same direction, toward believing the lease ends sooner
// than it does:
//
//   - The configured TTL is used, not the effective one. The Coordinator rounds
//     a TTL UP to whole seconds, so the real deadline is never earlier than the
//     computed one.
//   - The clock starts when the request was issued, not when it returned. The
//     backend grants the TTL somewhere between those two instants, so a slow
//     round trip shows up as less lease remaining rather than as the same lease
//     starting later.
//
// Config.PromoteGuard is what that arithmetic feeds: a promotion is not
// INITIATED unless that much acknowledged lease remains. In a healthy loop
// almost the whole TTL does, and the guard never fires; it fires when a renewal
// took most of the TTL to be acknowledged, or when the replication-state read
// before the promotion did — which is exactly when a promotion started under it
// would outlive it.
//
// It is checked twice per reconcile for that second reason. The guard is itself
// a check-then-act, and the act is the promotion, so the authoritative check is
// the one immediately before it; the earlier one only avoids issuing a read
// whose answer could not be acted on anyway.
//
// A failed renewal does not fence. Done is the authority on whether the lease
// still exists, not the spelling of an error, so a renewal error is recorded
// and the loop keeps going; if the lease really is gone, Done closes and the
// fencing path runs.
//
// # Fencing
//
// When Done closes the controller is FENCED for that volume, immediately and
// without qualification: it initiates no promotion until it is elected again.
//
// "Immediately" has to reach work already in flight, not just the next
// iteration of a loop, so every provider call the controller makes while
// leading is issued with a context that is canceled the moment Done closes.
// A promotion in progress when the lease dies is aborted rather than allowed
// to complete, and if it completed anyway the controller treats it as void:
// it drops its primary announcement, whatever the call reported.
//
// The role is then handed back — a Demote on a fresh bounded context, because
// the lease context is exactly what just ended. Exactly one place does that per
// event: the fencing path, or the shutdown path, never both. Voiding a
// promotion records the reason and demotes nothing, because the loop it returns
// into is about to take one of those two exits anyway.
//
// That demote is best-effort and is REPORTED, never assumed. DRBD refuses to
// demote a device that is open, which is the provider refusing to pull a live
// device out from under its user; a fenced controller whose demote failed says
// so in its Status rather than claiming the node was fenced.
//
// When a lease ends in the same instant the manager is stopped, fencing wins
// the tie deliberately. Both exits demote, so nothing unsafe turns on it, but
// only one of them records that this node was fenced — and on a node that was,
// that is the fact the incident turns on.
//
// # This is a control-plane fence, not a data-plane fence
//
// The distinction is the most important thing in this package.
//
// Losing the lease makes this CONTROLLER stop acting. It does not make the
// kernel stop accepting writes to a device that is already Primary and already
// mounted. If the node is partitioned rather than dead, its workload keeps
// writing while the peer's controller acquires the freed key and promotes.
// DRBD refuses a second Primary while it can see the first, so a partition
// that DRBD can also see is safe; a partition that severs the replication link
// too is exactly the case where nothing here can help.
//
// Closing that gap needs a mechanism outside this library: DRBD's own
// "fencing resource-and-stonith" with a fence agent that powers off or isolates
// the loser, or quorum configured so a minority node stops serving I/O on its
// own. A lease is coordination. A fence is a power switch. Deploy both.
//
// # Promote eligibility
//
// The controller promotes only a local copy whose replication state proves it
// is current. common.ReplState.Conn decides, and exactly one value is
// eligible:
//
//	uptodate      ELIGIBLE     connected, replicating, local copy current.
//	sync-source   refused      the bucket means "the PEER is behind", not "the
//	                           local disk is UpToDate". The provider collapses
//	                           SyncSource, PausedSyncS, WFBitMapS,
//	                           StartingSyncS and Ahead into it and carries no
//	                           local disk state alongside, so the controller
//	                           cannot tell the members apart. The cost of
//	                           refusing is a failover window that ends when the
//	                           resync does; the cost of a wrong promotion is
//	                           data.
//	sync-target   refused      the LOCAL copy is the one behind.
//	inconsistent  refused      connected, local copy known not current. A
//	                           definite fact, and the fact is that promoting
//	                           would publish stale or unreadable data.
//	standalone    refused      up, and not talking to its peer. The local copy
//	                           may well be fine, but nothing here can compare
//	                           it with the peer's, and promoting the wrong side
//	                           of a severed link is how a split brain is made.
//	connecting    refused      the peer's state is not yet known.
//	down          refused      replication is configured and not running.
//	unknown       refused      the state could not be determined. Refusing on
//	                           "we do not know" is the whole discipline.
//
// A freshly provisioned volume is Inconsistent by design — the drbd provider
// performs no initial sync — so it is not promotable until an operator makes
// one side authoritative out of band. That is the same class of decision as a
// force-promotion and it is deliberately not automated here.
//
// # Adopting a copy that is already primary is a different question
//
// A controller can find the local copy ALREADY Primary — it restarted, or the
// node was promoted before it started managing the volume. There is nothing to
// promote, so what it decides is whether to ANNOUNCE that copy as serving, and
// that gate is deliberately broader:
//
//	uptodate      SERVICEABLE  connected and current.
//	sync-source   SERVICEABLE  the local copy is feeding the peer.
//	connecting    SERVICEABLE  the peer is unreachable and this node is the
//	                           established Primary.
//	standalone    refused      it has stopped talking to its peer, which is what
//	                           DRBD reports once a split brain is detected and
//	                           not auto-resolved. Either side may be the one to
//	                           keep, and that is an operator's call.
//	sync-target   refused      the local copy is being overwritten from the peer.
//	inconsistent  refused      the local copy is known not to be current.
//	down          refused      replication is not running.
//	unknown       refused      the state could not be determined.
//
// The asymmetry is the point. Promotion brings a copy INTO service and is where
// a stale side of a divergence gets made authoritative, so its gate is as
// narrow as it can be. Adoption changes nothing: the copy is already Primary,
// already possibly mounted and already being written, and refusing does not
// undo any of it. Applying the promotion gate here would withdraw the
// announcement from an established Primary whose peer merely died — DRBD
// reports that as connecting, not uptodate — and an orchestrator acting on the
// withdrawal would unmount the last surviving copy. That is the failure high
// availability exists to prevent, not one to cause.
//
// A refusal here never demotes. Announcing is this controller's business;
// tearing a live device out from under a running workload is not, and is not
// something a controller that owns roles and not filesystems could finish.
//
// The controller never forces. "drbdadm primary --force" overrides precisely
// the check that makes a refusal safe, and which copy to keep after a
// divergence depends on facts this library cannot see. DRBD's refusal of a
// stale promotion is a feature the controller surfaces, not an obstacle it
// works around — and it is a backstop rather than the gate: the eligibility
// table above is what decides, so the controller's safety does not depend on
// the provider underneath happening to be DRBD.
//
// # Roles, not filesystems: the settled composition
//
// The controller drives Promote and Demote. It does not Mount, Unmount,
// format, or open a LUKS mapping, and it will not grow those. Mounting is the
// workload orchestrator's step, taken after the controller reports that this
// node is primary.
//
// Four reasons, in the order they bite:
//
//  1. Role and namespace have different owners and different lifetimes. The
//     lease decides which node may write. What is written, and where it appears
//     in a filesystem namespace, belongs to whoever runs the workload.
//  2. Unmounting is what makes demotion possible — DRBD refuses to demote an
//     open device — and the controller does not own the processes holding the
//     mount. A controller that mounted would still be unable to unmount
//     reliably, so it would own an operation it could not complete, which is
//     the worst arrangement available.
//  3. It keeps the fenced path cheap and total. On lease loss the controller
//     has a single role to hand back, not a stack to unwind under a deadline
//     that has already passed.
//  4. It decides issue #13 in advance. When the drbd provider grows LUKS
//     layering there is no open question about where luksOpen goes: a LUKS
//     mapping is a namespace object with the mount's lifetime, not the role's,
//     so it belongs with Mount on the workload side. Promote stays the one
//     operation whose success means "this node may write".
//
// The seam that makes this usable is Config.Observer: the controller reports
// every phase transition, so an orchestrator mounts when it is told the node
// became primary and unmounts when it is told the node was fenced.
//
// This is a deliberate DEVIATION from issue #4's body, which asked that the
// lease holder "Promotes + Mounts". That text predates issue #13, which
// surfaced the question the boundary turns on — does Promote open the LUKS
// mapping, or does Mount? — and forced it to be decided rather than assumed.
// Once it was, the mount could not stay on this side of it, and reason 2 above
// is what settles it: the controller would own an operation it could not
// complete, because the demote it owes on the way back out is blocked by a
// mount held by processes it does not control.
//
// The issue's actual requirement is unchanged and is met: exactly one node may
// write, and the lease is what decides which. What moved is which component
// performs the step that makes the writing visible.
//
// # Graceful stop
//
// Canceling the context passed to [Controller.Manage] stops the loop. While
// leading, the controller HOLDS the lease across the demote — renewing it until
// the demote returns, the lease ends, or Config.ActionTimeout elapses — and
// releases it only if the demote succeeded, so the peer takes over at once.
//
// The alternative, when the demote fails, is to leave the lease to expire, and
// it is worth knowing what that costs. The peer waits out whatever remains of
// the last acknowledged lease, which at a ttl/3 cadence is between two thirds
// of the TTL and all of it — 10 to 15 seconds for the defaults, averaging about
// 12.5 — plus up to one Config.RetryInterval before it tries again. Releasing
// cleanly costs none of that, which is why the demote is attempted first.
//
// Holding it is the difference between the planned case and the crash. A demote
// can take longer than the lease has left, and letting it lapse mid-demote
// would invite the peer to promote against a node that is still Primary. That
// window is unavoidable after a crash and avoidable here, so it is avoided.
// When the lease ends anyway the shutdown is recorded as a FENCE rather than a
// clean stop, because the authorization is gone and a peer may already hold the
// key; a demote that then happens to succeed does not make that untrue. If the demote failed —
// the workload still holds the mount — the lease is NOT released: the
// controller stops renewing and lets the deadline expire it, which makes the
// takeover TTL-gated exactly as it would be after a crash. Releasing a lease
// while still Primary would hand the peer permission to promote against a node
// that is still writing.
//
// A release the backend did not acknowledge is not a release, so it is
// retried; a release that cannot be acknowledged is reported and left to the
// deadline.
//
// # What has and has not been exercised
//
// Everything here is verified against fakes and against the contracts its
// dependencies publish: an in-process Coordinator written to pkg/common's rules
// rather than to what these tests needed, with its own conformance suite, and a
// provider that answers the three replication calls and panics on every other
// method.
//
// None of it has been run against real DRBD, or against a real two-node pair.
// The drbd provider's own fixtures are hand-built and its real-cluster suite
// has never been executed, so nothing in this package should be read as
// hardware-validated failover. What is validated is that the controller behaves
// correctly GIVEN the contracts its dependencies promise. Whether the provider
// keeps those promises on real hardware is a separate question with its own
// acceptance work, and two DRBD behaviors this composition leans on — what a
// repeated "drbdadm up" does, and what a failed "down" leaves attached — are
// among the things still unverified there.
//
// # Deployment caveat: lease reaping on embedded go-qrdb
//
// go-qrdb #174: an EMBEDDED qrdb node (sdk/go/node) never reaps an expired
// lease's bound key, because the leader-side expiry sweeper is started only by
// cmd/qrdbd. Done still closes on the deadline, so FENCING works — the holder
// stops acting — but the key stays present, every contender's AcquireLease
// keeps returning common.ErrLeaseHeld, and the volume is never re-elected.
//
// The controller is written against the contract, which says the key is freed;
// it is correct as soon as the backend reaps. Until go-qrdb #174 is fixed, a
// clustered HA deployment must run its coordinator against a qrdb backend that
// runs the sweeper, and an embedded one fences without failing over.
package ha
