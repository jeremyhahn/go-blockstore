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
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// The three tables below are the point of this file: every DRBD 9 state name
// must have a mapping, and a name added to the parser without one must fail the
// build's tests rather than quietly resolve to unknown at runtime.

func TestConnMappingCoversEveryConnectionState(t *testing.T) {
	for name, conn := range connNames {
		if conn == connConnected {
			// Connected is resolved from the replication state instead; it
			// deliberately has no entry.
			if _, ok := connMapping[conn]; ok {
				t.Errorf("connMapping has an entry for %q, which must resolve from the replication state", name)
			}
			continue
		}
		if _, ok := connMapping[conn]; !ok {
			t.Errorf("connection state %q has no mapping", name)
		}
	}
}

func TestReplMappingCoversEveryReplicationState(t *testing.T) {
	for name, repl := range replNames {
		if _, ok := replMapping[repl]; !ok {
			t.Errorf("replication state %q has no mapping", name)
		}
	}
}

func TestDiskMappingCoversEveryDiskState(t *testing.T) {
	for name, disk := range diskNames {
		if _, ok := diskMapping[disk]; !ok {
			t.Errorf("disk state %q has no mapping", name)
		}
	}
}

func TestToCommonConn(t *testing.T) {
	tests := []struct {
		name string
		conn string
		repl string
		disk string
		want common.ReplConnState
	}{
		// Every connection state, with a healthy peer device underneath so the
		// connection field is what decides.
		{"standalone", "StandAlone", "Off", "UpToDate", common.ReplStateStandalone},
		{"disconnecting", "Disconnecting", "Off", "UpToDate", common.ReplStateConnecting},
		{"unconnected", "Unconnected", "Off", "UpToDate", common.ReplStateConnecting},
		{"timeout", "Timeout", "Off", "UpToDate", common.ReplStateConnecting},
		{"broken pipe", "BrokenPipe", "Off", "UpToDate", common.ReplStateConnecting},
		{"network failure", "NetworkFailure", "Off", "UpToDate", common.ReplStateConnecting},
		{"protocol error", "ProtocolError", "Off", "UpToDate", common.ReplStateConnecting},
		{"tear down", "TearDown", "Off", "UpToDate", common.ReplStateConnecting},
		{"connecting", "Connecting", "Off", "UpToDate", common.ReplStateConnecting},
		{"connected established uptodate", "Connected", "Established", "UpToDate", common.ReplStateUpToDate},

		// Every replication state, over a Connected connection with an UpToDate
		// local disk.
		{"repl off", "Connected", "Off", "UpToDate", common.ReplStateUnknown},
		{"repl starting sync source", "Connected", "StartingSyncS", "UpToDate", common.ReplStateSyncSource},
		{"repl starting sync target", "Connected", "StartingSyncT", "UpToDate", common.ReplStateSyncTarget},
		{"repl wf bitmap source", "Connected", "WFBitMapS", "UpToDate", common.ReplStateSyncSource},
		{"repl wf bitmap target", "Connected", "WFBitMapT", "UpToDate", common.ReplStateSyncTarget},
		{"repl wf sync uuid is target side", "Connected", "WFSyncUUID", "UpToDate", common.ReplStateSyncTarget},
		{"repl sync source", "Connected", "SyncSource", "UpToDate", common.ReplStateSyncSource},
		{"repl sync target", "Connected", "SyncTarget", "UpToDate", common.ReplStateSyncTarget},
		{"repl verify source defers to disk", "Connected", "VerifyS", "UpToDate", common.ReplStateUpToDate},
		{"repl verify target defers to disk", "Connected", "VerifyT", "UpToDate", common.ReplStateUpToDate},
		{"repl paused sync source", "Connected", "PausedSyncS", "UpToDate", common.ReplStateSyncSource},
		{"repl paused sync target", "Connected", "PausedSyncT", "UpToDate", common.ReplStateSyncTarget},
		{"repl ahead is the good copy", "Connected", "Ahead", "UpToDate", common.ReplStateSyncSource},
		{"repl behind is the stale copy", "Connected", "Behind", "UpToDate", common.ReplStateSyncTarget},

		// Every local disk state, over an established connection. Only UpToDate
		// is current; the rest are a definite "not current", which is
		// inconsistent rather than unknown — the controller must be able to
		// tell a bad copy from an unreadable status.
		{"disk uptodate", "Connected", "Established", "UpToDate", common.ReplStateUpToDate},
		{"disk consistent", "Connected", "Established", "Consistent", common.ReplStateInconsistent},
		{"disk outdated", "Connected", "Established", "Outdated", common.ReplStateInconsistent},
		{"disk inconsistent", "Connected", "Established", "Inconsistent", common.ReplStateInconsistent},
		{"disk diskless", "Connected", "Established", "Diskless", common.ReplStateInconsistent},
		{"disk attaching", "Connected", "Established", "Attaching", common.ReplStateInconsistent},
		{"disk detaching", "Connected", "Established", "Detaching", common.ReplStateInconsistent},
		{"disk failed", "Connected", "Established", "Failed", common.ReplStateInconsistent},
		{"disk negotiating", "Connected", "Established", "Negotiating", common.ReplStateInconsistent},
		{"disk unknown", "Connected", "Established", "DUnknown", common.ReplStateInconsistent},

		// A name from none of the three families resolves to unknown rather
		// than to whichever bucket it superficially resembles.
		{"unrecognized connection", "Teleporting", "Established", "UpToDate", common.ReplStateUnknown},
		{"unrecognized replication", "Connected", "SyncSideways", "UpToDate", common.ReplStateUnknown},
		{"unrecognized disk", "Connected", "Established", "Excellent", common.ReplStateUnknown},
		{"empty connection", "", "Established", "UpToDate", common.ReplStateUnknown},
		{"empty replication", "Connected", "", "UpToDate", common.ReplStateUnknown},
		{"empty disk", "Connected", "Established", "", common.ReplStateUnknown},

		// A name that differs only in case is not the same name.
		{"lowercased connection", "connected", "Established", "UpToDate", common.ReplStateUnknown},
		{"lowercased replication", "Connected", "established", "UpToDate", common.ReplStateUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := toCommonConn(tc.conn, tc.repl, tc.disk); got != tc.want {
				t.Errorf("toCommonConn(%q, %q, %q) = %q, want %q", tc.conn, tc.repl, tc.disk, got, tc.want)
			}
		})
	}
}

func TestParseRoleIsExhaustive(t *testing.T) {
	tests := []struct {
		raw    string
		want   common.ReplRole
		wantOK bool
	}{
		{"Primary", common.ReplRolePrimary, true},
		{"Secondary", common.ReplRoleSecondary, true},
		{"Unknown", common.ReplRoleUnknown, true},
		{"primary", common.ReplRoleUnknown, false},
		{"", common.ReplRoleUnknown, false},
		{"Tertiary", common.ReplRoleUnknown, false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			role, ok := parseRole(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("parseRole(%q) ok = %v, want %v", tc.raw, ok, tc.wantOK)
			}
			if got := role.common(); ok && got != tc.want {
				t.Errorf("parseRole(%q).common() = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestReplStateFromFixtures drives the mapping from whole drbdsetup documents,
// so the field names the parser reads are exercised alongside the state table.
func TestReplStateFromFixtures(t *testing.T) {
	tests := []struct {
		fixture      string
		resource     string
		wantOK       bool
		wantConn     common.ReplConnState
		wantRole     common.ReplRole
		wantPeer     common.NodeID
		wantMinor    int
		wantDiskName string
	}{
		{
			fixture: "status-connected-primary.json", resource: "vol1", wantOK: true,
			wantConn: common.ReplStateUpToDate, wantRole: common.ReplRolePrimary,
			wantPeer: "node-b", wantMinor: 0, wantDiskName: "UpToDate",
		},
		{
			fixture: "status-sync-target.json", resource: "vol1", wantOK: true,
			wantConn: common.ReplStateSyncTarget, wantRole: common.ReplRoleSecondary,
			wantPeer: "node-a", wantMinor: 3, wantDiskName: "Inconsistent",
		},
		{
			fixture: "status-sync-source.json", resource: "vol1", wantOK: true,
			wantConn: common.ReplStateSyncSource, wantRole: common.ReplRolePrimary,
			wantPeer: "node-b", wantMinor: 0, wantDiskName: "UpToDate",
		},
		{
			fixture: "status-standalone.json", resource: "vol1", wantOK: true,
			wantConn: common.ReplStateStandalone, wantRole: common.ReplRolePrimary,
			wantPeer: "node-b", wantMinor: 0, wantDiskName: "UpToDate",
		},
		{
			fixture: "status-connecting.json", resource: "vol1", wantOK: true,
			wantConn: common.ReplStateConnecting, wantRole: common.ReplRoleSecondary,
			wantPeer: "node-b", wantMinor: 0, wantDiskName: "Outdated",
		},
		{
			// A resource with no connection at all is the one shape that means
			// "not replicated".
			fixture: "status-no-peer.json", resource: "vol1", wantOK: false,
			wantMinor: 0, wantDiskName: "UpToDate",
		},
		{
			// Two peers, one healthy and one resyncing: the least safe wins, so
			// the caller is never told UpToDate while a copy is behind.
			fixture: "status-two-peers.json", resource: "vol1", wantOK: true,
			wantConn: common.ReplStateSyncSource, wantRole: common.ReplRolePrimary,
			wantPeer: "node-c", wantMinor: 0, wantDiskName: "UpToDate",
		},
		{
			fixture: "status-hyphenated-peer-devices.json", resource: "vol1", wantOK: true,
			wantConn: common.ReplStateUpToDate, wantRole: common.ReplRoleSecondary,
			wantPeer: "node-b", wantMinor: 0, wantDiskName: "UpToDate",
		},
		{
			fixture: "status-multi-resource.json", resource: "vol2", wantOK: true,
			wantConn: common.ReplStateConnecting, wantRole: common.ReplRoleSecondary,
			wantPeer: "node-b", wantMinor: 1, wantDiskName: "Inconsistent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.fixture+"/"+tc.resource, func(t *testing.T) {
			all, err := parseStatus([]byte(fixture(t, tc.fixture)))
			if err != nil {
				t.Fatalf("parseStatus: %v", err)
			}
			rs, found := findResource(all, tc.resource)
			if !found {
				t.Fatalf("resource %q not found in fixture", tc.resource)
			}

			dev, ok := rs.device()
			if !ok {
				t.Fatalf("resource %q has no volume-%d device", tc.resource, resourceVolume)
			}
			if dev.Minor != tc.wantMinor {
				t.Errorf("minor = %d, want %d", dev.Minor, tc.wantMinor)
			}
			if dev.DiskState != tc.wantDiskName {
				t.Errorf("disk-state = %q, want %q", dev.DiskState, tc.wantDiskName)
			}

			state, ok := rs.replState()
			if ok != tc.wantOK {
				t.Fatalf("replState ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if state.Conn != tc.wantConn {
				t.Errorf("Conn = %q, want %q", state.Conn, tc.wantConn)
			}
			if state.Role != tc.wantRole {
				t.Errorf("Role = %q, want %q", state.Role, tc.wantRole)
			}
			if state.Peer != tc.wantPeer {
				t.Errorf("Peer = %q, want %q", state.Peer, tc.wantPeer)
			}
		})
	}
}

// TestPeerDevicesKeySpellings proves both spellings decode, since drbdsetup
// emits the underscore one next to hyphenated neighbors.
func TestPeerDevicesKeySpellings(t *testing.T) {
	for _, f := range []string{"status-connected-primary.json", "status-hyphenated-peer-devices.json"} {
		t.Run(f, func(t *testing.T) {
			all, err := parseStatus([]byte(fixture(t, f)))
			if err != nil {
				t.Fatalf("parseStatus: %v", err)
			}
			rs := all[0]
			if len(rs.Connections) != 1 {
				t.Fatalf("connections = %d, want 1", len(rs.Connections))
			}
			pd, ok := rs.Connections[0].peerDevice()
			if !ok {
				t.Fatalf("volume-%d peer device not decoded", resourceVolume)
			}
			if pd.Replication != "Established" {
				t.Errorf("replication = %q, want %q", pd.Replication, "Established")
			}
			if pd.PeerDiskState != "UpToDate" {
				t.Errorf("peer-disk-state = %q, want %q", pd.PeerDiskState, "UpToDate")
			}
		})
	}
}

func TestParseStatusRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not json", "{}", `{"name":"vol1"}`} {
		if _, err := parseStatus([]byte(in)); err == nil {
			t.Errorf("parseStatus(%q) succeeded, want an error", in)
		}
	}
}

func TestParseStatusEmptyNode(t *testing.T) {
	all, err := parseStatus([]byte(emptyStatus))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("resources = %d, want 0", len(all))
	}
	if _, ok := findResource(all, testVolume); ok {
		t.Error("findResource found a resource on an empty node")
	}
}

// TestSafetyRankOrdering pins the order the multi-peer reduction relies on: a
// state must never be considered safer than one that is genuinely worse.
func TestSafetyRankOrdering(t *testing.T) {
	order := []common.ReplConnState{
		common.ReplStateUnknown,
		common.ReplStateDown,
		common.ReplStateStandalone,
		common.ReplStateInconsistent,
		common.ReplStateConnecting,
		common.ReplStateSyncTarget,
		common.ReplStateSyncSource,
		common.ReplStateUpToDate,
	}
	for i := 1; i < len(order); i++ {
		if safetyRank(order[i-1]) >= safetyRank(order[i]) {
			t.Errorf("safetyRank(%q) = %d is not below safetyRank(%q) = %d",
				order[i-1], safetyRank(order[i-1]), order[i], safetyRank(order[i]))
		}
	}
	if safetyRank(common.ReplConnState("invented")) != safetyRank(common.ReplStateUnknown) {
		t.Error("an unrecognized state must rank as low as unknown")
	}
}

// TestDeviceLookupIgnoresOtherVolumes proves the volume-0 lookup is by number
// and not by position, so a resource that grew a second volume cannot have its
// state read off the wrong one.
func TestDeviceLookupIgnoresOtherVolumes(t *testing.T) {
	rs := resourceStatus{
		Devices: []deviceStatus{
			{Volume: 1, Minor: 9, DiskState: "Inconsistent"},
			{Volume: 0, Minor: 4, DiskState: "UpToDate"},
		},
	}
	dev, ok := rs.device()
	if !ok {
		t.Fatal("volume-0 device not found")
	}
	if dev.Minor != 4 || dev.DiskState != "UpToDate" {
		t.Errorf("device = %+v, want minor 4 UpToDate", dev)
	}

	missing := resourceStatus{Devices: []deviceStatus{{Volume: 1, Minor: 9}}}
	if _, ok := missing.device(); ok {
		t.Error("device() found a volume-0 device that is not there")
	}
}
