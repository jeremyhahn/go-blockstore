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
	"strings"

	"github.com/jeremyhahn/go-blockstore/internal/mountguard"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// Setting keys accepted by New, snake_case and shared with pkg/local; any other key is rejected.
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

	// SettingReplicationSecretFile names the file holding the peer authentication secret; both nodes need the same secret.
	// #nosec G101 -- the name of a setting key, not a credential.
	SettingReplicationSecretFile = "replication_secret_file"

	// SettingAllowUnauthenticatedPeers ("true") provisions resources with no peer authentication; by default a secret is required.
	SettingAllowUnauthenticatedPeers = "allow_unauthenticated_peers"

	// SettingWipeOnDelete ("true"/"false", default false) zero-fills a volume's backing device before removing it; see Config.WipeOnDelete.
	SettingWipeOnDelete = "wipe_on_delete"

	// SettingEncrypted ("true"/"false", default false) puts a LUKS2 container above each replicated device; needs SettingLUKSKeyFile or a KeyProvider.
	SettingEncrypted = "encrypted"

	// SettingLUKSKeyFile is the absolute, cleaned path of the LUKS passphrase file, re-read on each use; it must differ from the replication secret file.
	SettingLUKSKeyFile = "luks_key_file"

	// SettingPreflight selects the startup privilege checks: "configured" (default), "all" or "off".
	SettingPreflight = "preflight"

	// SettingMountPropagation is "unchecked" (default) or "shared"; use shared where a workload in another mount namespace consumes the mounts.
	SettingMountPropagation = "mount_propagation"
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

	// NodeAddress is the local replication address (storage network); the per-resource port is appended.
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

	// MinorBase and PortBase are the low ends of the minor and port ranges this provider allocates from.
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

	// WipeOnDelete zero-fills a volume's backing LV before removing it; default false.
	// Without it, an unencrypted volume on non-discarding media leaves readable data in freed extents, on both nodes; encryption is the better mitigation.
	WipeOnDelete bool

	// Encrypted puts a LUKS2 container above each replicated device, so the wire and both backing volumes hold ciphertext.
	// The 16 MiB header is added on top of SizeBytes. The mapping is sized at open, so Resize refuses with ErrMappingStale until a demote/promote reopens it.
	Encrypted bool

	// LUKSKeyFile is the path to a file holding the LUKS passphrase. Empty
	// means no file-backed provider; a caller may inject one through
	// WithKeyProvider instead.
	LUKSKeyFile string

	// Preflight selects which startup privilege checks New performs; default PreflightConfigured.
	Preflight PreflightMode

	// MountPropagation selects whether Mount verifies the mount is visible outside this namespace; default MountPropagationUnchecked.
	MountPropagation MountPropagationPolicy
}

// ParseConfig validates a settings map and fills in defaults; vg, node-address, peer-node and peer-address are required.
func ParseConfig(settings map[string]string) (Config, error) {
	known := map[string]struct{}{
		SettingVolumeGroup: {}, SettingConfigDir: {}, SettingStateDir: {},
		SettingNodeName: {}, SettingNodeAddress: {}, SettingNodeID: {},
		SettingPeerNode: {}, SettingPeerAddress: {}, SettingPeerNodeID: {},
		SettingMinorBase: {}, SettingPortBase: {}, SettingSnapshotSizePercent: {},
		SettingReplicationSecretFile: {}, SettingAllowUnauthenticatedPeers: {},
		SettingWipeOnDelete: {}, SettingPreflight: {},
		SettingMountPropagation: {},
		SettingEncrypted:        {}, SettingLUKSKeyFile: {},
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
	if raw, ok := settings[SettingPreflight]; ok && raw != "" {
		mode, known := preflightModeNames[raw]
		if !known {
			return Config{}, fmt.Errorf("%w: %s=%q is not one of %s",
				common.ErrInvalidArgument, SettingPreflight, raw, strings.Join(preflightModeSpellings(), ", "))
		}
		cfg.Preflight = mode
	}
	if raw, ok := settings[SettingMountPropagation]; ok && raw != "" {
		policy, known := mountguard.Parse(raw)
		if !known {
			return Config{}, fmt.Errorf("%w: %s=%q is not one of %s",
				common.ErrInvalidArgument, SettingMountPropagation, raw, strings.Join(mountguard.Spellings(), ", "))
		}
		cfg.MountPropagation = policy
	}

	if cfg.WipeOnDelete, err = optionalBool(settings, SettingWipeOnDelete); err != nil {
		return Config{}, err
	}
	if cfg.Encrypted, err = optionalBool(settings, SettingEncrypted); err != nil {
		return Config{}, err
	}
	if v := settings[SettingLUKSKeyFile]; v != "" {
		if !filepath.IsAbs(v) || filepath.Clean(v) != v {
			return Config{}, fmt.Errorf("%w: %s %q must be an absolute path in cleaned form", common.ErrInvalidArgument, SettingLUKSKeyFile, v)
		}
		cfg.LUKSKeyFile = v
	}
	// One file cannot hold both secrets: the replication secret is shared with the peer.
	if cfg.LUKSKeyFile != "" && cfg.LUKSKeyFile == cfg.ReplicationSecretFile {
		return Config{}, fmt.Errorf("%w: %s and %s name the same file %q: the peer-authentication secret must not also be the volume passphrase",
			common.ErrInvalidArgument, SettingLUKSKeyFile, SettingReplicationSecretFile, cfg.LUKSKeyFile)
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

// resolveNodeIDs assigns DRBD node IDs; with neither given, the lexicographically smaller name takes 0, and giving only one is refused.
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

// optionalBool reads a boolean setting; only "true" and "false" are accepted.
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
