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
	// ErrAlreadyManaged is returned by Manage when the volume already has a manager; one goroutine per volume is the serialization.
	ErrAlreadyManaged = errors.New("volume already managed by this controller")

	// ErrNotManaged is returned by Status for a volume with no manager.
	ErrNotManaged = errors.New("volume not managed by this controller")

	// ErrNotPromotable reports a local replication state the controller will not promote; it retries next reconcile.
	ErrNotPromotable = errors.New("replication state is not safe to promote")

	// ErrNotServiceable reports an already-Primary copy in a state the controller will not announce; it does not demote.
	ErrNotServiceable = errors.New("the local copy is primary but not in a state safe to serve")

	// ErrLeaseTooShort reports that too little of the acknowledged lease
	// remained for the controller to initiate a promotion under it.
	ErrLeaseTooShort = errors.New("insufficient acknowledged lease remaining to promote")

	// ErrRenewFailed reports an unacknowledged renewal; the lease is not lost, and a later successful renewal clears it.
	ErrRenewFailed = errors.New("lease renewal was not acknowledged")

	// ErrFenced reports that the lease was lost. Once it is set the controller
	// initiates no promotion for that volume until it is elected again.
	ErrFenced = errors.New("fenced: primary lease lost")

	// ErrRoleNotYielded reports a failed demote after a fence, so the copy may still be writable; always wrapped with ErrFenced.
	ErrRoleNotYielded = errors.New("the local copy could not be demoted after the lease was lost")
)

// Phase is the controller's relationship to one volume's primary lease.
type Phase string

const (
	// PhaseIdle is the phase before the first acquisition attempt.
	PhaseIdle Phase = "idle"

	// PhaseCampaigning means this controller does not hold the lease; Status.Err says why.
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

	// Primary is the controller's announcement that this node may serve the volume under the current epoch; Repl.Role is the device's actual role.
	Primary bool

	// Repl is the replication state observed at the last reconcile. The zero
	// value means none has been observed yet.
	Repl common.ReplState

	// LeaseDeadline is when the last acknowledged acquire or renew expires, never later than the real deadline.
	LeaseDeadline time.Time

	// Err is the reason for the current phase; in PhaseStopped only the shutdown's own reason or a fence survives.
	Err error

	// UpdatedAt is when this status was last written.
	UpdatedAt time.Time
}

// promoteEligibility allows only uptodate and gives the reason otherwise; the role is not consulted.
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
		// An unrecognized state is refused.
		return false, "unrecognized replication state"
	}
}

// adoptEligibility allows announcing an already-Primary copy when uptodate, sync-source or connecting; it never demotes.
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
