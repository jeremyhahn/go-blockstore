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
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// Package error sentinels. They classify outcomes a caller branches on; the
// wrapped detail says which volume and why.
var (
	// ErrAlreadyManaged is returned by Manage when the volume already has a
	// manager on this controller.
	//
	// One goroutine per volume is not a convenience, it is the serialization:
	// the controller's check-then-act sequences — read the replication state,
	// then promote; check the remaining lease, then act — are safe because
	// exactly one goroutine per volume performs them. A second manager would
	// interleave two of those sequences against one device, and the lease
	// cannot prevent it, because both would be running under the same node's
	// single lease.
	ErrAlreadyManaged = errors.New("volume already managed by this controller")

	// ErrNotManaged is returned by Status for a volume with no manager.
	ErrNotManaged = errors.New("volume not managed by this controller")

	// ErrNotPromotable reports that the local replication state is not one the
	// controller will promote. It is wrapped with the state and the reason.
	// It is a refusal, not a failure: the volume is intact and the controller
	// retries on the next reconcile.
	ErrNotPromotable = errors.New("replication state is not safe to promote")

	// ErrNotServiceable reports that the local copy ALREADY holds the primary
	// role, and is in a state this controller will not announce as serving.
	//
	// It is the counterpart to ErrNotPromotable and asks a different question —
	// see [adoptEligibility]. The controller does not demote in this case: the
	// copy is already in service, and pulling it out from under a running
	// workload is not a decision a refusal to announce should make.
	ErrNotServiceable = errors.New("the local copy is primary but not in a state safe to serve")

	// ErrLeaseTooShort reports that too little of the acknowledged lease
	// remained for the controller to initiate a promotion under it.
	ErrLeaseTooShort = errors.New("insufficient acknowledged lease remaining to promote")

	// ErrRenewFailed reports a renewal the backend did not acknowledge. The
	// lease is NOT lost — Done decides that, not this — but the deadline did
	// not move, so the controller has less of it left than the cadence assumes.
	//
	// It is a sentinel rather than a bare wrap because a renewal succeeding is
	// allowed to clear exactly this and nothing else: a refusal standing from
	// the last reconcile is a fact about the VOLUME, and no amount of talking
	// to the Coordinator resolves it.
	ErrRenewFailed = errors.New("lease renewal was not acknowledged")

	// ErrFenced reports that the lease was lost. Once it is set the controller
	// initiates no promotion for that volume until it is elected again.
	ErrFenced = errors.New("fenced: primary lease lost")

	// ErrRoleNotYielded reports that the best-effort demote after a fence did
	// not take, so the local copy may still be writable with no lease behind
	// it. It is always wrapped alongside [ErrFenced].
	//
	// It is a separate sentinel because it marks an UNRESOLVED hazard, and that
	// is a different thing from the fence itself. A fence is an event and stays
	// in the record; this is a condition that persists until somebody acts on
	// it, so it survives the controller moving on — a retry loop that replaced
	// it with a contender's error would stop reporting the unsafe state exactly
	// when nobody is watching.
	ErrRoleNotYielded = errors.New("the local copy could not be demoted after the lease was lost")
)

// Phase is the controller's relationship to one volume's primary lease.
type Phase string

const (
	// PhaseIdle is the phase before the first acquisition attempt.
	PhaseIdle Phase = "idle"

	// PhaseCampaigning means this controller does not hold the volume's lease.
	// It covers both reasons — another node holds it, or the Coordinator could
	// not answer — because the controller's behavior is identical in each: it
	// promotes nothing and retries. Status.Err says which.
	PhaseCampaigning Phase = "campaigning"

	// PhaseLeading means this controller holds the volume's lease.
	PhaseLeading Phase = "leading"

	// PhaseFenced means the lease was lost. The controller initiates no
	// promotion in this phase; it moves back to PhaseCampaigning only by
	// starting a new acquisition.
	PhaseFenced Phase = "fenced"

	// PhaseStopped means the manager returned; the volume is no longer managed.
	PhaseStopped Phase = "stopped"
)

// Status is a point-in-time report on one managed volume.
type Status struct {
	// VolumeID is the volume this status describes.
	VolumeID string

	// NodeID is the node the reporting controller runs on.
	NodeID common.NodeID

	// Phase is the controller's relationship to the volume's lease.
	Phase Phase

	// LeaseKey is the Coordinator key the volume's primary lease binds to.
	LeaseKey string

	// Epoch counts acquisitions of the lease by this manager, starting at one.
	// It is what distinguishes "still leading" from "led, was fenced, and was
	// elected again": a promotion belongs to the epoch it was issued under.
	Epoch uint64

	// Primary is the controller's ANNOUNCEMENT that this node holds the primary
	// role for the volume under the current epoch and its copy is safe to
	// serve. Because Config.Observer is what an orchestrator mounts on, this is
	// an authorization and not merely an observation, and the two eligibility
	// tables in the package documentation are what stand behind it — one for
	// promoting a copy into service, a broader one for announcing a copy that
	// is already primary.
	//
	// It is not the same as "the device is Primary". A node whose copy is
	// Primary but not safe to serve reports Primary false with
	// [ErrNotServiceable], and Repl below still carries the role the provider
	// actually reported. A consumer that wants the device's role rather than
	// this controller's authorization reads Repl.Role.
	//
	// It is dropped on fencing, before any demote is attempted, because the
	// authorization expires with the lease whether or not the device could be
	// demoted.
	Primary bool

	// Repl is the replication state observed at the last reconcile. The zero
	// value means none has been observed yet.
	Repl common.ReplState

	// LeaseDeadline is when the last ACKNOWLEDGED acquire or renew expires. It
	// is computed from the configured LeaseTTL, which the Coordinator rounds
	// up, so the real deadline is never earlier than this one.
	LeaseDeadline time.Time

	// Err is the reason for the current phase, or the most recent refusal or
	// failure. A nil Err in PhaseLeading with Primary set is the healthy state.
	//
	// In PhaseStopped it carries the reason the shutdown itself had, when it
	// had one, and otherwise only a condition that OUTLIVES the shutdown — a
	// fence, which is how "the lease was lost and the demote afterwards failed,
	// so this node may still be writable" survives into the last status anyone
	// will see for the volume. A refusal or a renewal warning is resolved by no
	// longer trying, so a clean stop reports nil rather than making itself look
	// like a failed one.
	Err error

	// UpdatedAt is when this status was last written.
	UpdatedAt time.Time
}

// promoteEligibility decides whether a local replication state is safe to
// promote, and says why when it is not.
//
// Exactly one connection state is eligible: uptodate. The reasoning for each
// refusal is in the package doc's eligibility table, and the reason strings
// here are the short form of it — they are what an operator reads in a log
// line, so they say what is true of the volume rather than naming the constant
// again.
//
// The role is deliberately not consulted. A node already Primary is handled by
// the caller before it gets here, and a node's role says nothing about whether
// its data is current, which is the only question this function answers.
func promoteEligibility(s common.ReplState) (bool, string) {
	switch s.Conn {
	case common.ReplStateUpToDate:
		return true, ""
	case common.ReplStateSyncSource:
		return false, "a resync is in progress and the local disk state is not reported alongside it"
	case common.ReplStateSyncTarget:
		return false, "the local copy is the target of an in-progress resync and is behind the peer"
	case common.ReplStateInconsistent:
		return false, "the local copy is connected but known not to be current"
	case common.ReplStateStandalone:
		return false, "the volume is up but not talking to its peer, so the two copies cannot be compared"
	case common.ReplStateConnecting:
		return false, "the peer connection is still being established"
	case common.ReplStateDown:
		return false, "replication is configured but not running"
	case common.ReplStateUnknown:
		return false, "the replication state could not be determined"
	default:
		// A state this package has not been taught. Refusing an unrecognized
		// value is the same discipline as refusing unknown: a promotion gate
		// whose default is "allow" stops being a gate the moment the enum
		// grows.
		return false, "unrecognized replication state"
	}
}

// adoptEligibility decides whether a copy that ALREADY holds the primary role
// may be announced as serving, and says why when it may not.
//
// It is deliberately broader than [promoteEligibility], and the asymmetry is
// the point rather than an oversight.
//
// Promotion brings a copy INTO service. It is a state change, it is the moment
// a stale side of a divergence can be made authoritative, and the controller
// chooses it — so the gate is as narrow as it can be: uptodate only.
//
// Adoption changes nothing. The copy is already Primary, already possibly
// mounted, already being written; the controller did not choose it and refusing
// does not undo it. Applying the promotion gate here would refuse the exact
// case high availability exists for — an established Primary whose peer just
// died, which DRBD reports as connecting, not uptodate — and an orchestrator
// acting on the withdrawn announcement would unmount the last surviving copy.
//
// So this refuses only the states that say this copy may be the WRONG one, or
// is not current:
//
//	uptodate      SERVICEABLE  connected and current.
//	sync-source   SERVICEABLE  the local copy is feeding the peer, so it is the
//	                           more current of the two.
//	connecting    SERVICEABLE  the peer is unreachable and this node is the
//	                           established Primary. This is a peer failure, and
//	                           surviving one is the entire point.
//	standalone    refused      up, and it has STOPPED talking to its peer —
//	                           which is what DRBD reports once a split brain is
//	                           detected and not auto-resolved. A Primary here
//	                           may be either side of a divergence, and which one
//	                           to keep is an operator's decision, not a
//	                           controller's.
//	sync-target   refused      the local copy is being overwritten from the
//	                           peer, so it is not the copy anyone should read.
//	inconsistent  refused      the local copy is known not to be current.
//	down          refused      replication is not running.
//	unknown       refused      the state could not be determined.
//
// A refusal here does NOT demote. Announcing is this controller's business;
// tearing a live device out from under a running workload is not, and it is not
// something a controller that owns roles and not filesystems could complete
// anyway.
func adoptEligibility(s common.ReplState) (bool, string) {
	switch s.Conn {
	case common.ReplStateUpToDate:
		return true, ""
	case common.ReplStateSyncSource:
		return true, ""
	case common.ReplStateConnecting:
		return true, ""
	case common.ReplStateStandalone:
		return false, "it has stopped talking to its peer, so it may be either side of a divergence"
	case common.ReplStateSyncTarget:
		return false, "the local copy is being overwritten by a resync from the peer"
	case common.ReplStateInconsistent:
		return false, "the local copy is known not to be current"
	case common.ReplStateDown:
		return false, "replication is configured but not running"
	case common.ReplStateUnknown:
		return false, "the replication state could not be determined"
	default:
		return false, "unrecognized replication state"
	}
}
