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
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-blockstore/pkg/common"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
)

// maxNameLen bounds a volume or snapshot name so "<volume>_snap_<snapshot>" fits LVM's 127-character limit.
const maxNameLen = 56

// snapSeparator joins volume and snapshot names into the SnapshotID; validateName forbids underscores, so the join splits back unambiguously.
const snapSeparator = "_snap_"

// reservedNamePrefixes are the leading words LVM refuses in a logical volume
// name. Rejecting them here turns an obscure lvcreate failure into a clear
// error at the API boundary.
var reservedNamePrefixes = []string{"snapshot", "pvmove"}

// validateName accepts an ASCII letter or digit followed by letters, digits and hyphens: safe as an LVM argument, dm name and path element.
func validateName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%w: %s name is empty", common.ErrInvalidArgument, kind)
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: %s name %q exceeds %d characters", common.ErrInvalidArgument, kind, name, maxNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return fmt.Errorf("%w: %s name %q contains %q; permitted: letters, digits and hyphen, not leading", common.ErrInvalidArgument, kind, name, string(c))
		}
	}
	for _, p := range reservedNamePrefixes {
		if strings.HasPrefix(name, p) {
			return fmt.Errorf("%w: %s name %q starts with LVM-reserved word %q", common.ErrInvalidArgument, kind, name, p)
		}
	}
	return nil
}

// mkfsBinaries maps an accepted filesystem type to its binary; it is the allowlist.
var mkfsBinaries = map[string]string{
	"ext2": "mkfs.ext2",
	"ext3": "mkfs.ext3",
	"ext4": "mkfs.ext4",
	"xfs":  "mkfs.xfs",
}

// validateFSType checks a requested filesystem type. The empty string is valid
// and means a raw, unformatted device, per VolumeSpec.FSType.
func validateFSType(fsType string) error {
	if fsType == "" {
		return nil
	}
	if _, ok := mkfsBinaries[fsType]; !ok {
		return fmt.Errorf("%w: filesystem type %q is not supported; permitted: %s", common.ErrInvalidArgument, fsType, strings.Join(sortedFSTypes(), ", "))
	}
	return nil
}

// sortedFSTypes returns the supported filesystem types in a stable order for
// error messages.
func sortedFSTypes() []string {
	return []string{"ext2", "ext3", "ext4", "xfs"}
}

// validateMountFlags checks every flag against the allowlist and rejects "rw" alongside a read-only request.
func validateMountFlags(readOnly bool, flags []string) error {
	for _, f := range flags {
		if _, ok := mount.Lookup(f); !ok {
			return fmt.Errorf("%w: mount flag %q is not permitted", common.ErrInvalidArgument, f)
		}
		if readOnly && f == "rw" {
			return fmt.Errorf("%w: mount flag %q contradicts MountOptions.ReadOnly", common.ErrInvalidArgument, f)
		}
	}
	return nil
}

// validateTarget requires an absolute, already-clean mount target path.
func validateTarget(target string) error {
	return validateAbsPath("mount target", target)
}

// validateAbsPath applies the path rules shared by every filesystem path this
// provider accepts from configuration or from a caller.
func validateAbsPath(kind, target string) error {
	if target == "" {
		return fmt.Errorf("%w: %s is empty", common.ErrInvalidArgument, kind)
	}
	// Control characters are refused; a space is allowed and round-trips through mountinfo.
	for i := 0; i < len(target); i++ {
		if c := target[i]; c < 0x20 || c == 0x7f {
			return fmt.Errorf("%w: %s %q contains control character %#x", common.ErrInvalidArgument, kind, target, c)
		}
	}
	if !filepath.IsAbs(target) {
		return fmt.Errorf("%w: %s %q is not absolute", common.ErrInvalidArgument, kind, target)
	}
	if filepath.Clean(target) != target {
		return fmt.Errorf("%w: %s %q is not a clean path", common.ErrInvalidArgument, kind, target)
	}
	// Leading or trailing whitespace is refused: it cannot be matched against the mount table afterwards.
	if strings.TrimSpace(target) != target {
		return fmt.Errorf("%w: %s %q has leading or trailing whitespace", common.ErrInvalidArgument, kind, target)
	}
	if target == "/" {
		return fmt.Errorf("%w: %s %q is the root filesystem", common.ErrInvalidArgument, kind, target)
	}
	return nil
}

// splitSnapshotID splits a snapshot's logical volume name back into the volume
// it was taken from and the name it was created with. ok is false when the id
// is not one this provider composed.
func splitSnapshotID(id string) (volID, name string, ok bool) {
	volID, name, found := strings.Cut(id, snapSeparator)
	if !found || volID == "" || name == "" {
		return "", "", false
	}
	return volID, name, true
}
