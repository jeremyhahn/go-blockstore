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

// maxNameLen bounds a caller-supplied volume or snapshot name.
//
// LVM caps a logical volume name at 127 characters and this provider composes
// snapshot LV names as "<volume>_snap_<snapshot>", so two names plus the
// six-character separator have to fit. 56 leaves that composition at 118 with
// room to spare, and no realistic volume name comes close.
const maxNameLen = 56

// snapSeparator joins a volume name and a snapshot name into the snapshot's
// logical volume name, which is also its SnapshotID.
//
// The underscore is what makes the join reversible: validateName rejects it in
// caller-supplied names, so "<volume>_snap_<snapshot>" splits back into its two
// halves unambiguously no matter what hyphens or digits either half contains.
const snapSeparator = "_snap_"

// reservedNamePrefixes are the leading words LVM refuses in a logical volume
// name. Rejecting them here turns an obscure lvcreate failure into a clear
// error at the API boundary.
var reservedNamePrefixes = []string{"snapshot", "pvmove"}

// validateName checks a caller-supplied volume, snapshot or volume-group name.
//
// The permitted set is deliberately narrower than what LVM itself accepts:
// an ASCII letter or digit, then letters, digits and hyphens. Every accepted
// name is therefore safe as an lvcreate argument, as a device-mapper name, and
// as a path element, with no escaping anywhere. Names that LVM would take but
// this rejects are a small price for a rule that is auditable by reading it.
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

// mkfsBinaries maps an accepted filesystem type to the binary that creates it.
//
// The map is the allowlist. Nothing derives a binary name from caller input by
// concatenating "mkfs." onto it, because that turns FSType into a choice of
// which program to execute; a type absent from this table is rejected, never
// guessed at.
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

// validateMountFlags checks every flag against the allowlist, and rejects a
// flag that contradicts an explicit read-only request.
//
// mount(8) resolves a conflicting -o ro,rw by taking the last option, so an
// "rw" arriving in Flags would quietly win over MountOptions.ReadOnly and mount
// the volume writable. That is exactly the case where ReadOnly is being used as
// a guard and Flags are coming from somewhere less trusted, so the contradiction
// is refused rather than silently resolved either way.
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

// validateTarget checks a mount target path.
//
// The path must be absolute and already clean, so "/mnt/data/../../etc" is
// rejected rather than quietly resolved to somewhere else. Requiring the
// caller's path to equal its own cleaned form also means the string handed to
// mount(8) is the string the caller passed, which is what makes an audit log of
// the request meaningful.
func validateTarget(target string) error {
	return validateAbsPath("mount target", target)
}

// validateAbsPath applies the path rules shared by every filesystem path this
// provider accepts from configuration or from a caller.
func validateAbsPath(kind, target string) error {
	if target == "" {
		return fmt.Errorf("%w: %s is empty", common.ErrInvalidArgument, kind)
	}
	// Control characters are rejected, newline above all. The kernel's mount
	// table is a line-oriented file, and while the parser now undoes the octal
	// escaping the kernel applies to a newline (\012), a target carrying one is
	// still a target nothing else in the system handles well — and this
	// provider passes it to tools that are line-oriented in their own right.
	// Linux permits any byte but NUL and '/' in a path, so this has to be
	// refused here rather than assumed away.
	//
	// A space is deliberately still allowed, and it round-trips: the kernel
	// escapes it as \040 in /proc/self/mountinfo and internal/mountinfo unescapes
	// it, which TestParseUnescapesPaths and the integration test that mounts at
	// a path with a space both pin.
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
	// Leading or trailing whitespace is refused because the kernel's own record
	// would not carry it back the way it went in: the mount table is
	// whitespace-separated, and a target padded with a space is a target this
	// provider cannot match against its own record afterwards. Unmount would
	// then report the convergent "not mounted there" over a volume that is
	// still mounted, which is the fail-open the mount lookups exist to avoid.
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
