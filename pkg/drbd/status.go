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

//go:build drbd

package drbd

import (
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// This file models the output of "drbdsetup status --json" and maps it onto
// common.ReplState.
//
// drbdsetup is used rather than "drbdadm status --json" even though drbd-utils
// 9 accepts both: drbdadm re-parses the configuration files and then shells out
// to drbdsetup anyway, so going straight to drbdsetup removes a failure mode
// (an unrelated resource file with a syntax error) from every status read.
//
// The whole-node form is used — "drbdsetup status --json" with no resource
// argument — so that a resource which is simply not up is an absent entry in a
// successful reply rather than a non-zero exit whose code has to be
// interpreted.

// The volume number this provider gives every resource. One resource holds
// exactly one volume, so the mapping between a go-blockstore volume and a DRBD
// resource stays one-to-one.
const resourceVolume = 0

// resourceStatus is one element of the drbdsetup status array.
type resourceStatus struct {
	Name          string             `json:"name"`
	NodeID        int                `json:"node-id"`
	Role          string             `json:"role"`
	Suspended     bool               `json:"suspended"`
	WriteOrdering string             `json:"write-ordering"`
	Devices       []deviceStatus     `json:"devices"`
	Connections   []connectionStatus `json:"connections"`
}

// deviceStatus is one local volume of a resource.
type deviceStatus struct {
	Volume    int    `json:"volume"`
	Minor     int    `json:"minor"`
	DiskState string `json:"disk-state"`
	Client    bool   `json:"client"`
	Quorum    bool   `json:"quorum"`
	Size      int64  `json:"size"` // KiB, as drbdsetup reports it.
}

// connectionStatus is one peer connection of a resource.
type connectionStatus struct {
	PeerNodeID int    `json:"peer-node-id"`
	Name       string `json:"name"`
	Connection string `json:"connection"`
	Congested  bool   `json:"congested"`
	PeerRole   string `json:"peer-role"`

	// drbdsetup spells this key with an underscore while every neighboring key
	// is hyphenated. The hyphenated alternative is accepted too so that a
	// drbd-utils build which normalises the key does not silently produce a
	// connection with no peer devices — which would read as "volume missing"
	// rather than as a parse problem. See UnmarshalJSON.
	PeerDevices []peerDeviceStatus `json:"-"`
}

// peerDeviceStatus is one volume as seen across one connection.
type peerDeviceStatus struct {
	Volume        int     `json:"volume"`
	Replication   string  `json:"replication"`
	PeerDiskState string  `json:"peer-disk-state"`
	PeerClient    bool    `json:"peer-client"`
	ResyncSusp    string  `json:"resync-suspended"`
	OutOfSync     int64   `json:"out-of-sync"`
	PercentInSync float64 `json:"percent-in-sync"`
}

// UnmarshalJSON accepts either spelling of the peer-devices key.
func (c *connectionStatus) UnmarshalJSON(data []byte) error {
	type alias connectionStatus // Shed this method to avoid recursing.
	var raw struct {
		alias
		Underscore []peerDeviceStatus `json:"peer_devices"`
		Hyphen     []peerDeviceStatus `json:"peer-devices"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = connectionStatus(raw.alias)
	switch {
	case len(raw.Underscore) > 0:
		c.PeerDevices = raw.Underscore
	default:
		c.PeerDevices = raw.Hyphen
	}
	return nil
}

// parseStatus decodes a drbdsetup status --json document.
func parseStatus(data []byte) ([]resourceStatus, error) {
	var out []resourceStatus
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parsing drbdsetup status --json: %w", err)
	}
	return out, nil
}

// findResource returns the status of the named resource, and whether it was
// present. An absent resource means it is not up on this node.
func findResource(all []resourceStatus, name string) (resourceStatus, bool) {
	for _, r := range all {
		if r.Name == name {
			return r, true
		}
	}
	return resourceStatus{}, false
}

// device returns the resource's volume-0 device.
func (r *resourceStatus) device() (deviceStatus, bool) {
	for _, d := range r.Devices {
		if d.Volume == resourceVolume {
			return d, true
		}
	}
	return deviceStatus{}, false
}

// peerDevice returns a connection's volume-0 peer device.
func (c *connectionStatus) peerDevice() (peerDeviceStatus, bool) {
	for _, pd := range c.PeerDevices {
		if pd.Volume == resourceVolume {
			return pd, true
		}
	}
	return peerDeviceStatus{}, false
}

// -----------------------------------------------------------------------------
// DRBD 9 state names
//
// Each family below lists every name the kernel can report, so that an
// unrecognized name is distinguishable from a recognized one this provider has
// nothing better to say about. Parsing returns ok=false for anything off the
// list and the caller reports common.ReplStateUnknown; nothing is inferred from
// the shape of an unknown name.
// -----------------------------------------------------------------------------

// drbdRole is the "role" / "peer-role" field.
type drbdRole string

const (
	rolePrimary   drbdRole = "Primary"
	roleSecondary drbdRole = "Secondary"
	roleUnknown   drbdRole = "Unknown"
)

var roleNames = map[string]drbdRole{
	"Primary":   rolePrimary,
	"Secondary": roleSecondary,
	"Unknown":   roleUnknown,
}

func parseRole(s string) (drbdRole, bool) {
	r, ok := roleNames[s]
	return r, ok
}

func (r drbdRole) common() common.ReplRole {
	switch r {
	case rolePrimary:
		return common.ReplRolePrimary
	case roleSecondary:
		return common.ReplRoleSecondary
	default:
		return common.ReplRoleUnknown
	}
}

// drbdConn is the "connection" field: the state of the TCP connection to one
// peer, independent of what is being replicated over it.
type drbdConn string

const (
	connStandAlone     drbdConn = "StandAlone"
	connDisconnecting  drbdConn = "Disconnecting"
	connUnconnected    drbdConn = "Unconnected"
	connTimeout        drbdConn = "Timeout"
	connBrokenPipe     drbdConn = "BrokenPipe"
	connNetworkFailure drbdConn = "NetworkFailure"
	connProtocolError  drbdConn = "ProtocolError"
	connTearDown       drbdConn = "TearDown"
	connConnecting     drbdConn = "Connecting"
	connConnected      drbdConn = "Connected"
)

var connNames = map[string]drbdConn{
	"StandAlone":     connStandAlone,
	"Disconnecting":  connDisconnecting,
	"Unconnected":    connUnconnected,
	"Timeout":        connTimeout,
	"BrokenPipe":     connBrokenPipe,
	"NetworkFailure": connNetworkFailure,
	"ProtocolError":  connProtocolError,
	"TearDown":       connTearDown,
	"Connecting":     connConnecting,
	"Connected":      connConnected,
}

func parseConn(s string) (drbdConn, bool) {
	c, ok := connNames[s]
	return c, ok
}

// drbdRepl is the "replication" field of a peer device: what is flowing over a
// connection that is up.
type drbdRepl string

const (
	replOff           drbdRepl = "Off"
	replEstablished   drbdRepl = "Established"
	replStartingSyncS drbdRepl = "StartingSyncS"
	replStartingSyncT drbdRepl = "StartingSyncT"
	replWFBitMapS     drbdRepl = "WFBitMapS"
	replWFBitMapT     drbdRepl = "WFBitMapT"
	replWFSyncUUID    drbdRepl = "WFSyncUUID"
	replSyncSource    drbdRepl = "SyncSource"
	replSyncTarget    drbdRepl = "SyncTarget"
	replVerifyS       drbdRepl = "VerifyS"
	replVerifyT       drbdRepl = "VerifyT"
	replPausedSyncS   drbdRepl = "PausedSyncS"
	replPausedSyncT   drbdRepl = "PausedSyncT"
	replAhead         drbdRepl = "Ahead"
	replBehind        drbdRepl = "Behind"
)

var replNames = map[string]drbdRepl{
	"Off":           replOff,
	"Established":   replEstablished,
	"StartingSyncS": replStartingSyncS,
	"StartingSyncT": replStartingSyncT,
	"WFBitMapS":     replWFBitMapS,
	"WFBitMapT":     replWFBitMapT,
	"WFSyncUUID":    replWFSyncUUID,
	"SyncSource":    replSyncSource,
	"SyncTarget":    replSyncTarget,
	"VerifyS":       replVerifyS,
	"VerifyT":       replVerifyT,
	"PausedSyncS":   replPausedSyncS,
	"PausedSyncT":   replPausedSyncT,
	"Ahead":         replAhead,
	"Behind":        replBehind,
}

func parseRepl(s string) (drbdRepl, bool) {
	r, ok := replNames[s]
	return r, ok
}

// drbdDisk is the "disk-state" / "peer-disk-state" field.
type drbdDisk string

const (
	diskDiskless     drbdDisk = "Diskless"
	diskAttaching    drbdDisk = "Attaching"
	diskDetaching    drbdDisk = "Detaching"
	diskFailed       drbdDisk = "Failed"
	diskNegotiating  drbdDisk = "Negotiating"
	diskInconsistent drbdDisk = "Inconsistent"
	diskOutdated     drbdDisk = "Outdated"
	diskDUnknown     drbdDisk = "DUnknown"
	diskConsistent   drbdDisk = "Consistent"
	diskUpToDate     drbdDisk = "UpToDate"
)

var diskNames = map[string]drbdDisk{
	"Diskless":     diskDiskless,
	"Attaching":    diskAttaching,
	"Detaching":    diskDetaching,
	"Failed":       diskFailed,
	"Negotiating":  diskNegotiating,
	"Inconsistent": diskInconsistent,
	"Outdated":     diskOutdated,
	"DUnknown":     diskDUnknown,
	"Consistent":   diskConsistent,
	"UpToDate":     diskUpToDate,
}

func parseDisk(s string) (drbdDisk, bool) {
	d, ok := diskNames[s]
	return d, ok
}

// -----------------------------------------------------------------------------
// Mapping onto common.ReplConnState
// -----------------------------------------------------------------------------

// connMapping maps every DRBD connection state onto the common model.
//
// Connected is absent: it is not an answer on its own, and is resolved from the
// peer device's replication state instead. See toCommonConn.
//
// The seven names between StandAlone and Connecting — Disconnecting, Timeout,
// BrokenPipe, NetworkFailure, ProtocolError, TearDown, Unconnected — are the
// ways a connection breaks or is torn down. DRBD re-enters Connecting from all
// of them on its own, so ReplStateConnecting describes where the resource is
// heading and, more to the point, keeps them out of ReplStateStandalone.
// StandAlone means the node has stopped trying, which is an operator-visible
// condition; a flapping link is not.
var connMapping = map[drbdConn]common.ReplConnState{
	connStandAlone:     common.ReplStateStandalone,
	connDisconnecting:  common.ReplStateConnecting,
	connUnconnected:    common.ReplStateConnecting,
	connTimeout:        common.ReplStateConnecting,
	connBrokenPipe:     common.ReplStateConnecting,
	connNetworkFailure: common.ReplStateConnecting,
	connProtocolError:  common.ReplStateConnecting,
	connTearDown:       common.ReplStateConnecting,
	connConnecting:     common.ReplStateConnecting,
}

// replResolution is how one replication state resolves.
type replResolution struct {
	// state is the common state to report, when deferToDisk is false.
	state common.ReplConnState

	// deferToDisk says the replication state carries no divergence of its own,
	// so the answer comes from the local disk state instead.
	deferToDisk bool
}

// replMapping maps every DRBD replication state onto the common model.
//
// The question the HA controller asks of this value is "is my local copy safe
// to promote", so the direction of a divergence is what matters and the sync
// states are bucketed by which side is behind:
//
//	source side — StartingSyncS, WFBitMapS, SyncSource, PausedSyncS, Ahead
//	target side — StartingSyncT, WFBitMapT, WFSyncUUID, SyncTarget,
//	              PausedSyncT, Behind
//
// WFSyncUUID has no S/T pair because it exists only on the target, waiting for
// the source's sync UUID before the resync begins.
//
// Ahead and Behind are not resyncs — they are protocol-A congestion, where
// replication is temporarily suspended and the peer is allowed to fall behind.
// They land in the sync buckets anyway because they answer the same question
// the same way: Behind means the local copy is the stale one and must not be
// promoted, Ahead means it is the good one.
//
// VerifyS and VerifyT defer to the disk state. Online verification compares two
// UpToDate copies block by block; it changes no data and, until it finds a
// mismatch, says nothing about which copy is current.
//
// Off means this volume is not replicated over this connection. It is
// self-contradictory here, because it is only consulted once the connection has
// reported Connected, so it resolves to unknown rather than to a guess.
var replMapping = map[drbdRepl]replResolution{
	replOff:           {state: common.ReplStateUnknown},
	replEstablished:   {deferToDisk: true},
	replStartingSyncS: {state: common.ReplStateSyncSource},
	replStartingSyncT: {state: common.ReplStateSyncTarget},
	replWFBitMapS:     {state: common.ReplStateSyncSource},
	replWFBitMapT:     {state: common.ReplStateSyncTarget},
	replWFSyncUUID:    {state: common.ReplStateSyncTarget},
	replSyncSource:    {state: common.ReplStateSyncSource},
	replSyncTarget:    {state: common.ReplStateSyncTarget},
	replVerifyS:       {deferToDisk: true},
	replVerifyT:       {deferToDisk: true},
	replPausedSyncS:   {state: common.ReplStateSyncSource},
	replPausedSyncT:   {state: common.ReplStateSyncTarget},
	replAhead:         {state: common.ReplStateSyncSource},
	replBehind:        {state: common.ReplStateSyncTarget},
}

// diskMapping resolves a local disk state for a connection that is Connected
// and replicating normally.
//
// Only UpToDate becomes ReplStateUpToDate. Every other disk state describes a
// local copy that is not current, and they all become ReplStateInconsistent —
// a definite fact about the volume, as distinct from ReplStateUnknown, which
// means the state could not be determined. A controller must refuse to promote
// on either, but only one of them is an answer.
//
// The nine are not all the same underneath. Consistent, Outdated and
// Inconsistent describe data that is present and not current; Diskless and
// Failed describe a device that cannot serve reads at all; Attaching,
// Detaching and Negotiating are transient; DUnknown is DRBD's own ignorance.
// They collapse here because the question this value answers is binary — is
// the local copy safe to promote, and for all nine the answer is no — and
// because nothing is lost by collapsing them: Status reports Failed and
// Diskless as VolumeStateError, so the distinction that matters for diagnosis
// survives one level up.
var diskMapping = map[drbdDisk]common.ReplConnState{
	diskUpToDate:     common.ReplStateUpToDate,
	diskConsistent:   common.ReplStateInconsistent,
	diskOutdated:     common.ReplStateInconsistent,
	diskInconsistent: common.ReplStateInconsistent,
	diskDiskless:     common.ReplStateInconsistent,
	diskAttaching:    common.ReplStateInconsistent,
	diskDetaching:    common.ReplStateInconsistent,
	diskFailed:       common.ReplStateInconsistent,
	diskNegotiating:  common.ReplStateInconsistent,
	diskDUnknown:     common.ReplStateInconsistent,
}

// toCommonConn resolves one connection into a common connection state.
//
// connRaw is the connection field, replRaw and diskRaw the peer device's
// replication state and the local device's disk state. Any name that is not a
// known DRBD state yields ReplStateUnknown.
func toCommonConn(connRaw, replRaw, diskRaw string) common.ReplConnState {
	conn, ok := parseConn(connRaw)
	if !ok {
		return common.ReplStateUnknown
	}
	if conn != connConnected {
		if state, mapped := connMapping[conn]; mapped {
			return state
		}
		return common.ReplStateUnknown
	}

	repl, ok := parseRepl(replRaw)
	if !ok {
		return common.ReplStateUnknown
	}
	res, ok := replMapping[repl]
	if !ok {
		return common.ReplStateUnknown
	}
	if !res.deferToDisk {
		return res.state
	}

	disk, ok := parseDisk(diskRaw)
	if !ok {
		return common.ReplStateUnknown
	}
	if state, ok := diskMapping[disk]; ok {
		return state
	}
	return common.ReplStateUnknown
}

// safetyRank orders connection states from least to most safe, where "safe"
// means "the local copy can be trusted". It exists so that a resource with more
// than one peer reports its worst connection: this provider configures exactly
// one, but a resource that has grown a second must not be reported as UpToDate
// while that second peer is resyncing.
func safetyRank(s common.ReplConnState) int {
	switch s {
	case common.ReplStateUnknown:
		return 0
	case common.ReplStateDown:
		// Never reached by this reduction — down is a property of the whole
		// resource, not of one connection — but ranked so the function is total
		// over the enum rather than falling through to the unknown default.
		return 1
	case common.ReplStateStandalone:
		return 2
	case common.ReplStateInconsistent:
		// Below the sync states: a resync at least ends with a current copy,
		// while an inconsistent one is not on its way anywhere.
		return 3
	case common.ReplStateConnecting:
		return 4
	case common.ReplStateSyncTarget:
		return 5
	case common.ReplStateSyncSource:
		return 6
	case common.ReplStateUpToDate:
		return 7
	default:
		return 0
	}
}

// replState builds the common.ReplState for a resource.
//
// It returns ok=false when the resource has no connections at all, which is the
// one shape that genuinely means "this volume is not replicated": a resource
// with a peer that is merely unreachable still reports a connection, in
// StandAlone or one of the failure states. The caller turns that into
// common.ErrNotReplicated.
func (r *resourceStatus) replState() (common.ReplState, bool) {
	if len(r.Connections) == 0 {
		return common.ReplState{}, false
	}

	role := common.ReplRoleUnknown
	if parsed, ok := parseRole(r.Role); ok {
		role = parsed.common()
	}

	diskRaw := ""
	if dev, ok := r.device(); ok {
		diskRaw = dev.DiskState
	}

	worst := common.ReplStateUpToDate
	worstRank := safetyRank(worst) + 1
	peer := common.NodeID("")

	for i := range r.Connections {
		c := &r.Connections[i]
		replRaw := ""
		if pd, ok := c.peerDevice(); ok {
			replRaw = pd.Replication
		}
		state := toCommonConn(c.Connection, replRaw, diskRaw)
		if rank := safetyRank(state); rank < worstRank {
			worst, worstRank = state, rank
			peer = common.NodeID(c.Name)
		}
	}

	return common.ReplState{Conn: worst, Role: role, Peer: peer}, true
}
