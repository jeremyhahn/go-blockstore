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

	// SettingWipeOnDelete ("true"/"false") zero-fills a volume's backing device
	// before removing it, so its contents do not survive in the volume group's
	// free extents. It defaults to false.
	//
	// Read Config.WipeOnDelete before leaving it at that default: it documents
	// what an unwiped delete leaves behind, and what this option does and does
	// not reach.
	SettingWipeOnDelete = "wipe_on_delete"

	// SettingPreflight selects which startup privilege checks New performs:
	// "configured" (the default), "all", or "off".
	//
	// It is spelled out in configuration rather than inferred because "off" is
	// the value that re-enables the silent failure the checks removed — a
	// provider that constructs happily on a node that cannot bring a resource
	// up — and a choice with that consequence belongs where a reviewer sees it.
	SettingPreflight = "preflight"

	// SettingMountPropagation selects whether Mount verifies that the mount it
	// made is visible outside this mount namespace: "unchecked" (the default)
	// or "shared".
	//
	// Set it to "shared" where a workload in ANOTHER mount namespace consumes
	// these mounts — a container handed a replicated volume by a storage
	// component. Left unchecked there, a wrong propagation setting is the
	// quietest failure in that model: the mount succeeds on this node, the
	// workload finds an empty directory, and nothing anywhere reports an error.
	//
	// It is not the default because a mount is private on an ordinary host and
	// that is correct there — a replicated cluster whose mounts nobody consumes
	// from another namespace is not broken, and requiring propagation of it
	// would refuse a working deployment on upgrade. See MountPropagationPolicy.
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

	// WipeOnDelete zero-fills a volume's backing logical volume before removing
	// it, so its contents do not survive in the volume group's free extents.
	//
	// Read this before leaving it at its default: AN UNENCRYPTED VOLUME ON
	// NON-DISCARDING MEDIA RETAINS READABLE DATA AFTER Delete UNLESS
	// WipeOnDelete IS SET. Its extents go back to the volume group holding
	// whatever was written to them, and the next volume to be allocated those
	// extents can read it — lvcreate zeroes only the first few kilobytes of a
	// new volume, enough that a stale filesystem signature is not detected, not
	// enough that the last tenant's data is gone. The extents lvextend adds to a
	// growing volume come from the same pool. Replication does not change this:
	// what DRBD wrote to the backing device is plain data on both nodes, so the
	// exposure exists once per copy.
	//
	// ENCRYPTION IS THE BETTER MITIGATION, and this provider does not offer it
	// yet. What survives in a freed extent is then ciphertext whose key went
	// away with the LUKS header, at none of the cost: a wipe writes the whole
	// volume, which is minutes per terabyte on rotating disks, while encryption
	// costs nothing at delete time. pkg/local has it today as Options.Encrypted;
	// the LUKS-above-DRBD work that brings it here is tracked separately. Until
	// then this option is the mitigation available on this provider, and the
	// choice is between paying for it and accepting the remanence.
	//
	// How much the exposure bites depends on the storage. With LVM's
	// devices/issue_discards set to 1 over a backing device that supports
	// discard, lvremove discards the freed extents and they read back as zeroes
	// whatever this option says. The LVM default is 0, and rotating disks do not
	// discard at all, which is the case the option is for. Do not infer from a
	// host where the data happens to be gone that it will be gone on the next
	// one.
	//
	// What it does NOT reach is a snapshot's copy-on-write extents, which hold
	// the pre-snapshot copies of everything the origin has overwritten since.
	// Delete cannot encounter that here — it refuses a volume that still has
	// snapshots, with common.ErrHasSnapshots — so on this provider the hazard is
	// unreachable rather than merely unlikely; see Delete. A caller that removes
	// the snapshots first and then deletes the origin has still had those CoW
	// extents freed unwiped by the snapshot removal, and encryption is the only
	// complete answer for a volume that has ever been snapshotted.
	//
	// It defaults to false, matching LVM's own behavior rather than imposing a
	// full-volume zero-fill on every deletion in every deployment.
	WipeOnDelete bool

	// Preflight selects which startup privilege checks New performs. It
	// defaults to PreflightConfigured, which checks exactly the capabilities
	// this configuration will exercise — a set that is NOT the local
	// provider's; see requiredCapabilities.
	Preflight PreflightMode

	// MountPropagation selects whether Mount verifies that the mount it made is
	// visible outside this mount namespace. It defaults to
	// MountPropagationUnchecked; a deployment that hands these mounts to a
	// workload in another namespace wants MountPropagationShared. See
	// MountPropagationPolicy for why the default is off, and why off is still
	// reported by Posture rather than being invisible.
	MountPropagation MountPropagationPolicy
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
		SettingWipeOnDelete: {}, SettingPreflight: {},
		SettingMountPropagation: {},
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
