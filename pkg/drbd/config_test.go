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
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig(map[string]string{
		SettingVolumeGroup: testVG,
		SettingNodeName:    testNode,
		SettingNodeAddress: "10.10.0.1",
		SettingPeerNode:    testPeer,
		SettingPeerAddress: "10.10.0.2",
	})
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.ConfigDir != defaultConfigDir {
		t.Errorf("ConfigDir = %q, want %q", cfg.ConfigDir, defaultConfigDir)
	}
	if cfg.StateDir != defaultStateDir {
		t.Errorf("StateDir = %q, want %q", cfg.StateDir, defaultStateDir)
	}
	// node-a sorts before node-b, so the local node takes 0.
	if cfg.NodeID != 0 || cfg.PeerNodeID != 1 {
		t.Errorf("node ids = %d/%d, want 0/1", cfg.NodeID, cfg.PeerNodeID)
	}
	if cfg.PortBase != defaultPortBase || cfg.MinorBase != defaultMinorBase {
		t.Errorf("bases = %d/%d, want %d/%d", cfg.PortBase, cfg.MinorBase, defaultPortBase, defaultMinorBase)
	}
	if cfg.SnapshotSizePercent != defaultSnapshotSizePercent {
		t.Errorf("SnapshotSizePercent = %d, want %d", cfg.SnapshotSizePercent, defaultSnapshotSizePercent)
	}
}

func TestParseConfigRejections(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{
			SettingVolumeGroup: testVG,
			SettingNodeName:    testNode,
			SettingNodeAddress: "10.10.0.1",
			SettingPeerNode:    testPeer,
			SettingPeerAddress: "10.10.0.2",
		}
	}

	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"missing volume group", func(s map[string]string) { delete(s, SettingVolumeGroup) }},
		{"missing peer node", func(s map[string]string) { delete(s, SettingPeerNode) }},
		{"missing node address", func(s map[string]string) { delete(s, SettingNodeAddress) }},
		{"missing peer address", func(s map[string]string) { delete(s, SettingPeerAddress) }},
		{"unknown setting", func(s map[string]string) { s["protocol"] = "A" }},
		{"volume group fails the name allowlist", func(s map[string]string) { s[SettingVolumeGroup] = "vg0;rm -rf /" }},
		{"node address is not an IP", func(s map[string]string) { s[SettingNodeAddress] = "node-a.internal" }},
		{"node address is unspecified", func(s map[string]string) { s[SettingNodeAddress] = "0.0.0.0" }},
		{"peer address is multicast", func(s map[string]string) { s[SettingPeerAddress] = "224.0.0.1" }},
		{"addresses collide", func(s map[string]string) { s[SettingPeerAddress] = "10.10.0.1" }},
		{"address families differ", func(s map[string]string) { s[SettingPeerAddress] = "fd00::2" }},
		{"peer is the local node", func(s map[string]string) { s[SettingPeerNode] = testNode }},
		{"node ids collide", func(s map[string]string) { s[SettingNodeID] = "1"; s[SettingPeerNodeID] = "1" }},
		{"node id above the drbd ceiling", func(s map[string]string) { s[SettingNodeID] = "32"; s[SettingPeerNodeID] = "1" }},
		{"node id is negative", func(s map[string]string) { s[SettingNodeID] = "-1"; s[SettingPeerNodeID] = "1" }},
		{"node id is not a number", func(s map[string]string) { s[SettingNodeID] = "one"; s[SettingPeerNodeID] = "1" }},
		{"peer node id above the ceiling", func(s map[string]string) { s[SettingNodeID] = "0"; s[SettingPeerNodeID] = "99" }},
		{"only the local node id is given", func(s map[string]string) { s[SettingNodeID] = "0" }},
		{"only the peer node id is given", func(s map[string]string) { s[SettingPeerNodeID] = "1" }},
		{"port base is zero", func(s map[string]string) { s[SettingPortBase] = "0" }},
		{"port base above 65535", func(s map[string]string) { s[SettingPortBase] = "65536" }},
		{"snapshot percent is zero", func(s map[string]string) { s[SettingSnapshotSizePercent] = "0" }},
		{"snapshot percent above 100", func(s map[string]string) { s[SettingSnapshotSizePercent] = "101" }},
		{"config dir is relative", func(s map[string]string) { s[SettingConfigDir] = "etc/drbd.d" }},
		{"state dir is uncleaned", func(s map[string]string) { s[SettingStateDir] = "/var/lib/../lib/bs" }},
		{"node name is not a hostname", func(s map[string]string) { s[SettingNodeName] = "node a" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mutate(s)
			_, err := ParseConfig(s)
			if err == nil {
				t.Fatalf("ParseConfig(%v) = nil, want an error", s)
			}
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Errorf("error is not common.ErrInvalidArgument: %v", err)
			}
		})
	}
}

func TestParseConfigIPv6(t *testing.T) {
	cfg, err := ParseConfig(map[string]string{
		SettingVolumeGroup: testVG,
		SettingNodeName:    testNode,
		SettingNodeAddress: "fd00::1",
		SettingPeerNode:    testPeer,
		SettingPeerAddress: "fd00::2",
	})
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if got, want := formatAddress(cfg.NodeAddress, 7789), "ipv6 [fd00::1]:7789"; got != want {
		t.Errorf("formatAddress = %q, want %q", got, want)
	}
	if got, want := formatAddress(cfg.PeerAddress, 7789), "ipv6 [fd00::2]:7789"; got != want {
		t.Errorf("formatAddress = %q, want %q", got, want)
	}
}

func TestNewRejectsBadSettings(t *testing.T) {
	if _, err := New(map[string]string{}, WithRunner(newFakeRunner(t))); err == nil {
		t.Fatal("New with empty settings succeeded, want an error")
	}
}

func TestNewCreatesDirectories(t *testing.T) {
	settings := testSettings(t)
	p, err := New(settings, WithRunner(newFakeRunner(t)), WithSecretProvider(testSecretProvider))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, dir := range []string{p.Config().ConfigDir, p.Config().StateDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("directory %q was not created: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%q is not a directory", dir)
		}
	}
}

// TestNodeIDsAgreeAcrossThePair is the interop property behind deriving node
// ids from the node names: a pair where both hosts take the defaults must still
// agree on which name holds which id, or the two copies of a resource file
// describe different clusters and never connect.
func TestNodeIDsAgreeAcrossThePair(t *testing.T) {
	pairs := [][2]string{
		{"node-a", "node-b"},
		{"node-b", "node-a"},
		{"ci-node-1", "ci-node-2"},
		{"zeta.storage.internal", "alpha.storage.internal"},
	}

	for _, pair := range pairs {
		local, peer := pair[0], pair[1]
		t.Run(local+"/"+peer, func(t *testing.T) {
			here, err := ParseConfig(map[string]string{
				SettingVolumeGroup: testVG, SettingNodeName: local, SettingNodeAddress: "10.10.0.1",
				SettingPeerNode: peer, SettingPeerAddress: "10.10.0.2",
			})
			if err != nil {
				t.Fatalf("ParseConfig on %q: %v", local, err)
			}
			// The same deployment, parsed on the other host: the names swap.
			there, err := ParseConfig(map[string]string{
				SettingVolumeGroup: testVG, SettingNodeName: peer, SettingNodeAddress: "10.10.0.2",
				SettingPeerNode: local, SettingPeerAddress: "10.10.0.1",
			})
			if err != nil {
				t.Fatalf("ParseConfig on %q: %v", peer, err)
			}

			if here.NodeID != there.PeerNodeID {
				t.Errorf("%q calls itself %d but %q calls it %d", local, here.NodeID, peer, there.PeerNodeID)
			}
			if here.PeerNodeID != there.NodeID {
				t.Errorf("%q calls %q %d but it calls itself %d", local, peer, here.PeerNodeID, there.NodeID)
			}
			if here.NodeID == here.PeerNodeID {
				t.Errorf("both halves were given node id %d", here.NodeID)
			}
		})
	}
}

// TestExplicitNodeIDsAreKept checks the override still works, for a deployment
// whose ids were assigned before this provider existed.
func TestExplicitNodeIDsAreKept(t *testing.T) {
	cfg, err := ParseConfig(map[string]string{
		SettingVolumeGroup: testVG, SettingNodeName: testNode, SettingNodeAddress: "10.10.0.1",
		SettingPeerNode: testPeer, SettingPeerAddress: "10.10.0.2",
		SettingNodeID: "7", SettingPeerNodeID: "3",
	})
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.NodeID != 7 || cfg.PeerNodeID != 3 {
		t.Errorf("node ids = %d/%d, want 7/3", cfg.NodeID, cfg.PeerNodeID)
	}
}

// TestConfigIsNotAWindowIntoTheProvider covers a leak the struct copy hides.
//
// Config returns a value, which looks like a copy — but net.IP is a slice, so
// the returned struct shares the provider's backing arrays. A caller that
// inspects its configuration and then writes to the address it got back is
// editing the provider's validated state, and every resource file generated
// afterwards carries the change, having gone nowhere near ParseConfig.
func TestConfigIsNotAWindowIntoTheProvider(t *testing.T) {
	p, _ := newTestProvider(t)

	before := p.Config().NodeAddress.String()
	peerBefore := p.Config().PeerAddress.String()

	// What an ordinary caller might do with a value it believes is its own.
	cfg := p.Config()
	for i := range cfg.NodeAddress {
		cfg.NodeAddress[i] = 0
	}
	for i := range cfg.PeerAddress {
		cfg.PeerAddress[i] = 0
	}

	if got := p.Config().NodeAddress.String(); got != before {
		t.Errorf("the provider's node address changed to %q from outside; was %q", got, before)
	}
	if got := p.Config().PeerAddress.String(); got != peerBefore {
		t.Errorf("the provider's peer address changed to %q from outside; was %q", got, peerBefore)
	}

	// And the resource file it generates is still the configured one.
	meta := resourceMeta{Name: testVolume, LV: testVolume, VG: testVG, Minor: 0, Port: 7789}
	out, err := renderToFile(t, p, &meta)
	if err != nil {
		t.Fatalf("writeResourceFile: %v", err)
	}
	if !strings.Contains(string(out), before) {
		t.Errorf("the generated resource no longer carries %q:\n%s", before, out)
	}
}
