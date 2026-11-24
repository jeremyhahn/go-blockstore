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
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// nameRe allows lowercase alphanumerics, underscore and hyphen, leading alphanumeric, at most 48 bytes; no dot, so "<volume>.snap.<name>" splits unambiguously.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)

// digitsRe matches a name made entirely of digits.
var digitsRe = regexp.MustCompile(`^[0-9]+$`)

// hostnameRe is the allowlist for the node names written into an "on" section.
// DRBD matches them against uname -n, so they are hostnames: RFC 1123 labels,
// optionally dotted.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// reservedNames are words drbdadm interprets rather than treats as a resource.
// "all" is drbdadm's every-resource keyword; a purely numeric name and the
// "minor-" prefix collide with the minor-number spellings drbdsetup accepts.
var reservedNames = map[string]struct{}{
	"all": {},
}

// LVM's reserved name prefixes and substrings, which lvcreate refuses.
var reservedLVMPrefixes = []string{"snapshot", "pvmove"}

var reservedLVMSubstrings = []string{
	"_cdata", "_cmeta", "_corig", "_mimage", "_mlog", "_pmspare",
	"_rimage", "_rmeta", "_tdata", "_tmeta", "_vorigin",
}

// validateName checks a volume or snapshot name against the allowlist. kind
// names the thing being validated so the error says which argument was wrong.
func validateName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%w: %s is empty", common.ErrInvalidArgument, kind)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%w: %s %q must match %s", common.ErrInvalidArgument, kind, name, nameRe)
	}
	if _, bad := reservedNames[name]; bad {
		return fmt.Errorf("%w: %s %q is reserved by drbdadm", common.ErrInvalidArgument, kind, name)
	}
	if digitsRe.MatchString(name) {
		return fmt.Errorf("%w: %s %q must not be all digits: drbdsetup would read it as a minor number", common.ErrInvalidArgument, kind, name)
	}
	if strings.HasPrefix(name, "minor-") {
		return fmt.Errorf("%w: %s %q must not start with %q: drbdsetup reserves that spelling", common.ErrInvalidArgument, kind, name, "minor-")
	}
	for _, prefix := range reservedLVMPrefixes {
		if strings.HasPrefix(name, prefix) {
			return fmt.Errorf("%w: %s %q starts with %q, which LVM reserves; lvcreate would refuse it",
				common.ErrInvalidArgument, kind, name, prefix)
		}
	}
	for _, sub := range reservedLVMSubstrings {
		if strings.Contains(name, sub) {
			return fmt.Errorf("%w: %s %q contains %q, which LVM reserves; lvcreate would refuse it",
				common.ErrInvalidArgument, kind, name, sub)
		}
	}
	return nil
}

// validateHostname checks a node name destined for an "on" section.
func validateHostname(kind, host string) error {
	if host == "" {
		return fmt.Errorf("%w: %s is empty", common.ErrInvalidArgument, kind)
	}
	if len(host) > 253 {
		return fmt.Errorf("%w: %s %q exceeds 253 bytes", common.ErrInvalidArgument, kind, host)
	}
	if !hostnameRe.MatchString(host) {
		return fmt.Errorf("%w: %s %q is not a valid hostname", common.ErrInvalidArgument, kind, host)
	}
	return nil
}

// supportedFilesystems are the filesystem types this provider will create and
// mount. The list is short on purpose: each entry means a mkfs.<type> binary
// this package is willing to exec, so growing it is a deliberate act.
var supportedFilesystems = map[string]struct{}{
	"ext4": {},
	"xfs":  {},
}

// validateFSType checks a filesystem type. The empty string is valid and means
// a raw block device, per the VolumeSpec contract.
func validateFSType(fsType string) error {
	if fsType == "" {
		return nil
	}
	if _, ok := supportedFilesystems[fsType]; !ok {
		return fmt.Errorf("%w: filesystem type %q is not supported (want one of %s)", common.ErrInvalidArgument, fsType, sortedKeys(supportedFilesystems))
	}
	return nil
}

// allowedMountFlags are the MountOptions.Flags a caller may set, a subset of internal/mount's table; ro and rw go through ReadOnly.
var allowedMountFlags = map[string]struct{}{
	"acl":               {},
	"async":             {},
	"barrier":           {},
	"data=journal":      {},
	"data=ordered":      {},
	"data=writeback":    {},
	"discard":           {},
	"errors=continue":   {},
	"errors=panic":      {},
	"errors=remount-ro": {},
	"lazytime":          {},
	"noacl":             {},
	"noatime":           {},
	"nobarrier":         {},
	"nodev":             {},
	"nodiratime":        {},
	"nodiscard":         {},
	"noexec":            {},
	"nolazytime":        {},
	"noquota":           {},

	// nouuid lets a restored XFS volume mount beside its source.
	"nouuid":       {},
	"nosuid":       {},
	"nouser_xattr": {},
	"relatime":     {},
	"strictatime":  {},
	"sync":         {},
	"user_xattr":   {},
}

// validateMountFlags checks every flag against the allowlist.
func validateMountFlags(flags []string) error {
	for _, f := range flags {
		if _, ok := allowedMountFlags[f]; !ok {
			return fmt.Errorf("%w: mount flag %q is not allowed", common.ErrInvalidArgument, f)
		}
	}
	return nil
}

// mountFlagsAreClassified reports the first allowed flag the shared table does not classify.
func mountFlagsAreClassified() (string, bool) {
	for f := range allowedMountFlags {
		if _, ok := mount.Lookup(f); !ok {
			return f, false
		}
	}
	return "", true
}

// validateMountTarget requires an absolute, clean path with no control characters and no whitespace at a component edge.
func validateMountTarget(target string) error {
	if target == "" {
		return fmt.Errorf("%w: mount target is empty", common.ErrInvalidArgument)
	}
	for _, r := range target {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: mount target %q contains a control character (%#U)", common.ErrInvalidArgument, target, r)
		}
	}
	if !filepath.IsAbs(target) {
		return fmt.Errorf("%w: mount target %q must be an absolute path", common.ErrInvalidArgument, target)
	}
	if filepath.Clean(target) != target {
		return fmt.Errorf("%w: mount target %q must be in cleaned form (%q)", common.ErrInvalidArgument, target, filepath.Clean(target))
	}
	if target == "/" {
		return fmt.Errorf("%w: mount target must not be the root filesystem", common.ErrInvalidArgument)
	}
	for _, component := range strings.Split(strings.TrimPrefix(target, "/"), "/") {
		if component != strings.TrimSpace(component) {
			return fmt.Errorf("%w: mount target %q has leading or trailing whitespace in component %q", common.ErrInvalidArgument, target, component)
		}
	}
	return nil
}

// sortedKeys renders a set as a stable, comma-separated list for error text.
func sortedKeys[T any](m map[string]T) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Small, fixed sets; an insertion sort keeps this dependency-free.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return strings.Join(keys, ", ")
}
