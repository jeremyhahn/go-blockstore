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

	// SettingLUKSKeyFile is the path to a file holding the LUKS passphrase.
	//
	// The setting is a path, never the passphrase itself. Settings come from
	// configuration files and process environments that get logged, copied into
	// support bundles and printed by diagnostic endpoints; a key in that map is
	// a key in all of those. A deployment whose keys live somewhere a file path
	// cannot reach — sealed to a TPM, say — builds the provider with New and an
	// Options.KeyProvider of its own rather than going through settings.
	SettingLUKSKeyFile = "luks_key_file"

	// SettingSnapshotCoWPercent sizes a snapshot's copy-on-write area as a
	// percentage of its origin.
	SettingSnapshotCoWPercent = "snapshot_cow_percent"

	// SettingWipeOnDelete ("true"/"false") zero-fills a volume before removing
	// it.
	//
	// It defaults to false, and an unencrypted volume on non-discarding media
	// retains readable data after deletion unless it is set. Setting
	// SettingEncrypted is the recommended answer to that and costs far less;
	// see Options.WipeOnDelete for the whole picture.
	//
	// It covers the volume's current contents only. A snapshot's exception
	// store holds the origin's overwritten history and is freed unwiped, by a
	// measured impossibility rather than an omission — see the package doc.
	SettingWipeOnDelete = "wipe_on_delete"

	// SettingLockDir holds the per-volume lock files that serialize
	// state-changing operations. It defaults to DefaultLockDir.
	//
	// Every provider over one volume group must be given the SAME directory —
	// on one host, and on a local filesystem. That is what the serialization
	// rests on, and two providers pointed at different directories do not
	// serialize against each other at all.
	SettingLockDir = "lock_dir"
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
}

// NewFromSettings builds a Provider from the string map the factory passes to a
// registered provider creator.
//
// An unrecognized key is an error rather than something ignored: a misspelled
// "encrypted" that silently provisions plaintext volumes is the kind of
// misconfiguration nobody discovers until the disk is in someone else's hands.
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

	if path := settings[SettingLUKSKeyFile]; path != "" {
		opts.KeyProvider = FileKeyProvider(path)
	}

	if raw, ok := settings[SettingSnapshotCoWPercent]; ok && raw != "" {
		pct, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s=%q is not an integer", common.ErrInvalidArgument, SettingSnapshotCoWPercent, raw)
		}
		// The range is checked here as well as in New because Options treats a
		// zero SnapshotCoWPercent as "use the default", which is right for a
		// struct literal that simply omits the field and wrong for an operator
		// who wrote 0 and meant it. Leaving it to New would turn that 0 into
		// 20 without a word.
		if pct < 1 || pct > 100 {
			return nil, fmt.Errorf("%w: %s=%d is outside 1-100", common.ErrInvalidArgument, SettingSnapshotCoWPercent, pct)
		}
		opts.SnapshotCoWPercent = pct
	}

	return New(opts)
}
