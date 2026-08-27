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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// Setting keys accepted by New.
//
// They are snake_case, which is the convention across every go-blockstore
// provider and is inherited from go-objstore (access_key_id,
// secret_access_key, encryption_kms_path). The LVM volume group is
// volume_group rather than the terser vg because pkg/local names the same
// concept that way and the two must agree — a caller configuring either
// provider should not have to remember which spelling this one wants.
//
// Any other key is rejected rather than ignored: a mistyped setting that
// silently does nothing is a configuration bug that only shows up as wrong
// behavior much later, on the node it was meant to fix.
const (
	SettingVolumeGroup         = "volume_group"
	SettingConfigDir           = "config_dir"
	SettingStateDir            = "state_dir"
	SettingNodeName            = "node_name"
	SettingNodeAddress         = "node_address"
	SettingNodeID              = "node_id"
	SettingPeerNode            = "peer_node"
	SettingPeerAddress         = "peer_address"
	SettingPeerNodeID          = "peer_node_id"
	SettingMinorBase           = "minor_base"
	SettingPortBase            = "port_base"
	SettingSnapshotSizePercent = "snapshot_size_percent"

	// SettingReplicationSecretFile points at the file holding the shared secret
	// DRBD authenticates the peer with. Both nodes of a pair need the same
	// secret for a resource.
	// #nosec G101 -- this is the NAME of a setting key, not a credential; the
	// value it names is a path, and the secret itself never appears in source.
	SettingReplicationSecretFile = "replication_secret_file"

	// SettingAllowUnauthenticatedPeers ("true") provisions resources with no
	// peer authentication at all.
	//
	// It exists for lab bring-up and is named so that nobody sets it by
	// accident or mistakes it for a tuning knob. Absent — the default — a
	// resource cannot be provisioned without a secret.
	SettingAllowUnauthenticatedPeers = "allow_unauthenticated_peers"
)

// Defaults for the optional settings.
const (
	defaultConfigDir           = "/etc/drbd.d"
	defaultStateDir            = "/var/lib/go-blockstore/drbd"
	defaultMinorBase           = 0
	defaultPortBase            = 7789
	defaultSnapshotSizePercent = 20
)

// Limits imposed by DRBD itself.
const (
	maxNodeID = 31      // DRBD 9 addresses at most 32 nodes per resource.
	maxMinor  = 1048575 // Kernel device-minor ceiling.
	maxPort   = 65535
)

// Config is the validated, typed form of the settings map handed to New.
type Config struct {
	// VG is the LVM volume group backing devices are carved from.
	VG string

	// ConfigDir is where per-resource .res files are installed. It must be a
	// directory the node's drbd.conf includes, conventionally /etc/drbd.d.
	ConfigDir string

	// StateDir is where this provider records what it has provisioned. It is
	// kept out of ConfigDir so that nothing but .res files lands in a directory
	// DRBD globs over.
	StateDir string

	// NodeName is the local node's name. It must equal the node's uname -n,
	// because that is what DRBD matches an "on" section against.
	NodeName string

	// NodeAddress is the local replication address — the storage-VLAN IP, not
	// the management one. The per-resource port is appended to it.
	NodeAddress net.IP

	// NodeID is the local DRBD node id. Left unset, it and PeerNodeID are
	// derived from the two node names so that both hosts reach the same
	// assignment; see resolveNodeIDs.
	NodeID int

	// PeerNode, PeerAddress and PeerNodeID are the same three values for the
	// other half of the pair.
	PeerNode    string
	PeerAddress net.IP
	PeerNodeID  int

	// MinorBase and PortBase are the low ends of the device-minor and TCP-port
	// ranges this provider allocates from. Minors and ports below them, or
	// belonging to resources outside StateDir, are the operator's to keep clear
	// of the range.
	MinorBase int
	PortBase  int

	// SnapshotSizePercent is the copy-on-write space an LVM snapshot is given,
	// as a percentage of the origin volume.
	SnapshotSizePercent int

	// ReplicationSecretFile is where the shared secret is read from. Empty
	// means no file-backed provider; a caller may inject one through
	// WithSecretProvider instead.
	ReplicationSecretFile string

	// AllowUnauthenticatedPeers provisions resources with no peer
	// authentication. It is off unless explicitly set.
	AllowUnauthenticatedPeers bool
}

// ParseConfig validates a settings map and fills in defaults.
//
// Required: vg, node-address, peer-node, peer-address. node-name defaults to
// the host's name, which is what DRBD will match anyway; every other setting
// has a default above.
func ParseConfig(settings map[string]string) (Config, error) {
	known := map[string]struct{}{
		SettingVolumeGroup: {}, SettingConfigDir: {}, SettingStateDir: {},
		SettingNodeName: {}, SettingNodeAddress: {}, SettingNodeID: {},
		SettingPeerNode: {}, SettingPeerAddress: {}, SettingPeerNodeID: {},
		SettingMinorBase: {}, SettingPortBase: {}, SettingSnapshotSizePercent: {},
		SettingReplicationSecretFile: {}, SettingAllowUnauthenticatedPeers: {},
	}
	for k := range settings {
		if _, ok := known[k]; !ok {
			return Config{}, fmt.Errorf("%w: unknown setting %q (known: %s)", common.ErrInvalidArgument, k, sortedKeys(known))
		}
	}

	cfg := Config{
		ConfigDir:           defaultConfigDir,
		StateDir:            defaultStateDir,
		MinorBase:           defaultMinorBase,
		PortBase:            defaultPortBase,
		SnapshotSizePercent: defaultSnapshotSizePercent,
	}

	var err error

	if cfg.VG, err = requiredName(settings, SettingVolumeGroup, "volume group"); err != nil {
		return Config{}, err
	}

	if v := settings[SettingConfigDir]; v != "" {
		cfg.ConfigDir = v
	}
	if v := settings[SettingStateDir]; v != "" {
		cfg.StateDir = v
	}
	for key, dir := range map[string]string{SettingConfigDir: cfg.ConfigDir, SettingStateDir: cfg.StateDir} {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			return Config{}, fmt.Errorf("%w: %s %q must be an absolute path in cleaned form", common.ErrInvalidArgument, key, dir)
		}
	}

	if v := settings[SettingNodeName]; v != "" {
		cfg.NodeName = v
	} else if cfg.NodeName, err = os.Hostname(); err != nil {
		return Config{}, fmt.Errorf("%w: %s not given and the local hostname is unavailable: %w", common.ErrInvalidArgument, SettingNodeName, err)
	}
	if hostErr := validateHostname(SettingNodeName, cfg.NodeName); hostErr != nil {
		return Config{}, hostErr
	}

	if cfg.PeerNode, err = requiredValue(settings, SettingPeerNode); err != nil {
		return Config{}, err
	}
	if hostErr := validateHostname(SettingPeerNode, cfg.PeerNode); hostErr != nil {
		return Config{}, hostErr
	}
	if cfg.PeerNode == cfg.NodeName {
		return Config{}, fmt.Errorf("%w: %s %q is the local node: a resource needs two distinct hosts", common.ErrInvalidArgument, SettingPeerNode, cfg.PeerNode)
	}

	if cfg.NodeAddress, err = requiredIP(settings, SettingNodeAddress); err != nil {
		return Config{}, err
	}
	if cfg.PeerAddress, err = requiredIP(settings, SettingPeerAddress); err != nil {
		return Config{}, err
	}
	if cfg.NodeAddress.Equal(cfg.PeerAddress) {
		return Config{}, fmt.Errorf("%w: %s and %s are the same address %s", common.ErrInvalidArgument, SettingNodeAddress, SettingPeerAddress, cfg.NodeAddress)
	}
	// A resource writes both addresses into one config file, and DRBD cannot
	// span address families within a connection.
	if (cfg.NodeAddress.To4() == nil) != (cfg.PeerAddress.To4() == nil) {
		return Config{}, fmt.Errorf("%w: %s and %s must be the same address family", common.ErrInvalidArgument, SettingNodeAddress, SettingPeerAddress)
	}

	if cfg.NodeID, cfg.PeerNodeID, err = resolveNodeIDs(settings, cfg.NodeName, cfg.PeerNode); err != nil {
		return Config{}, err
	}

	if cfg.MinorBase, err = optionalInt(settings, SettingMinorBase, cfg.MinorBase, 0, maxMinor); err != nil {
		return Config{}, err
	}
	if cfg.PortBase, err = optionalInt(settings, SettingPortBase, cfg.PortBase, 1, maxPort); err != nil {
		return Config{}, err
	}
	if cfg.SnapshotSizePercent, err = optionalInt(settings, SettingSnapshotSizePercent, cfg.SnapshotSizePercent, 1, 100); err != nil {
		return Config{}, err
	}

	if v := settings[SettingReplicationSecretFile]; v != "" {
		if !filepath.IsAbs(v) || filepath.Clean(v) != v {
			return Config{}, fmt.Errorf("%w: %s %q must be an absolute path in cleaned form", common.ErrInvalidArgument, SettingReplicationSecretFile, v)
		}
		cfg.ReplicationSecretFile = v
	}
	if cfg.AllowUnauthenticatedPeers, err = optionalBool(settings, SettingAllowUnauthenticatedPeers); err != nil {
		return Config{}, err
	}
	// Setting both says two contradictory things about the same resource. The
	// secret would win, since it is what gets written, so the override would be
	// a line in a config file asserting something untrue about the deployment.
	if cfg.ReplicationSecretFile != "" && cfg.AllowUnauthenticatedPeers {
		return Config{}, fmt.Errorf("%w: %s and %s contradict each other; remove one",
			common.ErrInvalidArgument, SettingReplicationSecretFile, SettingAllowUnauthenticatedPeers)
	}

	return cfg, nil
}

// resolveNodeIDs decides which DRBD node id each half of the pair carries.
//
// This is the one setting a two-node deployment cannot get wrong quietly. DRBD
// identifies a node by its id, and both copies of a resource file must agree on
// which name holds which: if node-a's copy says a=0/b=1 while node-b's copy
// says b=0/a=1, the two never connect. A fixed default of "local 0, peer 1"
// would produce exactly that on a pair where both sides took the default, so
// there is none.
//
// With neither id given, they are derived from the two node names by sorting
// them: the lexicographically smaller name takes 0. Both hosts compare the same
// pair of names and so reach the same assignment without coordinating, which
// makes the minimal configuration correct rather than merely convenient.
//
// Giving one id and not the other is refused. It would mix an explicit choice
// on one side with a derived one on the other, which is how a pair ends up
// disagreeing after somebody "fixed" a single node.
func resolveNodeIDs(settings map[string]string, nodeName, peerNode string) (nodeID, peerNodeID int, err error) {
	_, haveNode := settings[SettingNodeID]
	_, havePeer := settings[SettingPeerNodeID]

	switch {
	case haveNode != havePeer:
		return 0, 0, fmt.Errorf("%w: %s and %s must be set together or not at all: a node id given on one side of a pair and derived on the other is how the two copies of a resource end up disagreeing",
			common.ErrInvalidArgument, SettingNodeID, SettingPeerNodeID)

	case !haveNode:
		// Derived: the smaller name takes 0, on both hosts.
		if nodeName < peerNode {
			return 0, 1, nil
		}
		return 1, 0, nil
	}

	// Both keys are present in this branch, so the default passed here is never
	// the value that comes back. There is deliberately no default node id; see
	// the doc above.
	if nodeID, err = optionalInt(settings, SettingNodeID, 0, 0, maxNodeID); err != nil {
		return 0, 0, err
	}
	if peerNodeID, err = optionalInt(settings, SettingPeerNodeID, 0, 0, maxNodeID); err != nil {
		return 0, 0, err
	}
	if nodeID == peerNodeID {
		return 0, 0, fmt.Errorf("%w: %s and %s are both %d", common.ErrInvalidArgument, SettingNodeID, SettingPeerNodeID, nodeID)
	}
	return nodeID, peerNodeID, nil
}

func requiredValue(settings map[string]string, key string) (string, error) {
	v := settings[key]
	if v == "" {
		return "", fmt.Errorf("%w: setting %q is required", common.ErrInvalidArgument, key)
	}
	return v, nil
}

func requiredName(settings map[string]string, key, kind string) (string, error) {
	v, err := requiredValue(settings, key)
	if err != nil {
		return "", err
	}
	if err := validateName(kind, v); err != nil {
		return "", err
	}
	return v, nil
}

func requiredIP(settings map[string]string, key string) (net.IP, error) {
	v, err := requiredValue(settings, key)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return nil, fmt.Errorf("%w: setting %q is not an IP address: %q", common.ErrInvalidArgument, key, v)
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return nil, fmt.Errorf("%w: setting %q must be a unicast address, got %q", common.ErrInvalidArgument, key, v)
	}
	return ip, nil
}

// optionalBool reads a boolean setting. Only "true" and "false" are accepted:
// a setting that turns off peer authentication is not one to reach through a
// permissive parser that would take "yes", "1" or "TRUE" and leave an operator
// unsure which spellings count.
func optionalBool(settings map[string]string, key string) (bool, error) {
	raw, ok := settings[key]
	if !ok || raw == "" {
		return false, nil
	}
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%w: setting %q must be \"true\" or \"false\", got %q", common.ErrInvalidArgument, key, raw)
	}
}

func optionalInt(settings map[string]string, key string, def, min, max int) (int, error) {
	raw, ok := settings[key]
	if !ok || raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: setting %q is not an integer: %q", common.ErrInvalidArgument, key, raw)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%w: setting %q must be in [%d,%d], got %d", common.ErrInvalidArgument, key, min, max, n)
	}
	return n, nil
}
