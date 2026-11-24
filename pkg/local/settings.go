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

package local

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-blockstore/internal/mountguard"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// Settings keys accepted by NewFromSettings.
const (
	// SettingVolumeGroup names the LVM volume group. Required.
	SettingVolumeGroup = "volume_group"

	// SettingNodeID overrides the node identity, which otherwise comes from
	// the system hostname.
	SettingNodeID = "node_id"

	// SettingEncrypted ("true"/"false") provisions new volumes as LUKS2
	// containers. It requires SettingLUKSKeyFile.
	SettingEncrypted = "encrypted"

	// SettingLUKSKeyFile is the path to a file holding the LUKS passphrase, never the passphrase itself.
	SettingLUKSKeyFile = "luks_key_file"

	// SettingSnapshotCoWPercent sizes a snapshot's copy-on-write area as a
	// percentage of its origin.
	SettingSnapshotCoWPercent = "snapshot_cow_percent"

	// SettingWipeOnDelete ("true"/"false", default false) zero-fills a volume before removing it; see Options.WipeOnDelete.
	SettingWipeOnDelete = "wipe_on_delete"

	// SettingLockDir holds the per-volume lock files, default DefaultLockDir; every provider over one volume group must share it.
	SettingLockDir = "lock_dir"

	// SettingPreflight selects New's startup privilege checks: "configured" (default), "all" or "off". See PreflightMode.
	SettingPreflight = "preflight"

	// SettingMountPropagation selects whether Mount verifies visibility outside this namespace: "unchecked" (default) or "shared". See MountPropagationPolicy.
	SettingMountPropagation = "mount_propagation"
)

// knownSettings is every key NewFromSettings understands.
var knownSettings = map[string]struct{}{
	SettingVolumeGroup:        {},
	SettingNodeID:             {},
	SettingEncrypted:          {},
	SettingLUKSKeyFile:        {},
	SettingSnapshotCoWPercent: {},
	SettingWipeOnDelete:       {},
	SettingLockDir:            {},
	SettingPreflight:          {},
	SettingMountPropagation:   {},
}

// NewFromSettings builds a Provider from the factory's settings map; an unrecognized key is an error.
func NewFromSettings(settings map[string]string) (*Provider, error) {
	var unknown []string
	for key := range settings {
		if _, ok := knownSettings[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("%w: unrecognized setting(s) %s", common.ErrInvalidArgument, strings.Join(unknown, ", "))
	}

	opts := Options{
		VolumeGroup: settings[SettingVolumeGroup],
		NodeID:      common.NodeID(settings[SettingNodeID]),
		LockDir:     settings[SettingLockDir],
	}

	if raw, ok := settings[SettingEncrypted]; ok && raw != "" {
		encrypted, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s=%q is not a boolean", common.ErrInvalidArgument, SettingEncrypted, raw)
		}
		opts.Encrypted = encrypted
	}

	if raw, ok := settings[SettingWipeOnDelete]; ok && raw != "" {
		wipe, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s=%q is not a boolean", common.ErrInvalidArgument, SettingWipeOnDelete, raw)
		}
		opts.WipeOnDelete = wipe
	}

	if raw, ok := settings[SettingPreflight]; ok && raw != "" {
		mode, known := preflightModeNames[raw]
		if !known {
			return nil, fmt.Errorf("%w: %s=%q is not one of %s",
				common.ErrInvalidArgument, SettingPreflight, raw, strings.Join(preflightModeSpellings(), ", "))
		}
		opts.Preflight = mode
	}

	if raw, ok := settings[SettingMountPropagation]; ok && raw != "" {
		policy, known := mountguard.Parse(raw)
		if !known {
			return nil, fmt.Errorf("%w: %s=%q is not one of %s",
				common.ErrInvalidArgument, SettingMountPropagation, raw, strings.Join(mountPropagationSpellings(), ", "))
		}
		opts.MountPropagation = policy
	}

	if path := settings[SettingLUKSKeyFile]; path != "" {
		opts.KeyProvider = FileKeyProvider(path)
		// Kept so the provider can prove the key file is outside the paths it
		// hands to a workload. The KeyProvider closes over the path and cannot
		// be asked for it afterwards.
		opts.luksKeyFile = path
	}

	if raw, ok := settings[SettingSnapshotCoWPercent]; ok && raw != "" {
		pct, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s=%q is not an integer", common.ErrInvalidArgument, SettingSnapshotCoWPercent, raw)
		}
		// An explicit 0 is out of range here; in Options zero means the default.
		if pct < 1 || pct > 100 {
			return nil, fmt.Errorf("%w: %s=%d is outside 1-100", common.ErrInvalidArgument, SettingSnapshotCoWPercent, pct)
		}
		opts.SnapshotCoWPercent = pct
	}

	return New(opts)
}
