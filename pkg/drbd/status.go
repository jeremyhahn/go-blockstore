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

// This file models "drbdsetup status --json" for the whole node and maps it onto common.ReplState; a resource not up is an absent entry.

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

	// drbdsetup spells this key with an underscore; the hyphenated form is accepted too. See UnmarshalJSON.
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

// DRBD 9 state names: each family lists every name the kernel reports; an unknown name maps to common.ReplStateUnknown.

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

// connMapping maps every DRBD connection state; Connected resolves through toCommonConn, and the broken-link states map to ReplStateConnecting.
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

// replMapping maps every DRBD replication state by which side is behind; Verify defers to the disk state and Off resolves to unknown.
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

// diskMapping: UpToDate is ReplStateUpToDate, every other disk state ReplStateInconsistent.
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

// toCommonConn resolves a connection, peer replication and local disk state into a common state; unknown names yield ReplStateUnknown.
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

// safetyRank orders connection states from least to most safe, so a resource reports its worst connection.
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

// replState builds the common.ReplState for a resource, ok=false when it has no connections at all.
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
