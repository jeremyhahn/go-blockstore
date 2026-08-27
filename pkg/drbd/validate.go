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

// nameRe is the allowlist for volume and snapshot names.
//
// The intersection of three namespaces has to hold: a DRBD resource name, an
// LVM logical-volume name, and a path component under the state directory.
// Lowercase alphanumerics, underscore and hyphen satisfy all three. A leading
// alphanumeric keeps a name from being read as an option by any of the tools,
// and the 48-byte cap leaves room for the ".snap.<name>" suffix inside LVM's
// 127-byte limit.
//
// The dot is deliberately excluded even though LVM permits it: it is what makes
// "<volume>.snap.<name>" an unambiguous decomposition back into its two halves.
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

// LVM's own reserved names, which matter because a volume's name IS its logical
// volume's name and is handed straight to lvcreate.
//
// Measured against LVM 2.03.16 rather than taken from documentation: lvcreate
// answers "Names starting \"snapshot\" are reserved" for the prefixes and
// "Names including \"_tmeta\" are reserved" for the substrings, and refuses.
// Catching them here turns an obscure failure partway through provisioning —
// after a state record, after allocation, into the rollback path — into a clear
// refusal at the API boundary.
//
// The SUBSTRING list matters more here than it does in pkg/local, whose names
// cannot contain an underscore at all. This provider's do, so "vol_tmeta" is a
// name a caller can reach and LVM will not take.
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

// allowedMountFlags are the mount options a caller may put in
// MountOptions.Flags. Everything reaching mount(8) comes from this set, so a
// caller cannot smuggle in an option that changes what is mounted or from
// where.
//
// "ro" and "rw" are absent by design: read-only is MountOptions.ReadOnly, and
// accepting both spellings would let a caller set ReadOnly and then contradict
// it in Flags, with the winner decided by argument order.
//
// This is a SUBSET of internal/mount's table, which is the classification every
// provider shares. A provider may accept less than that table and never more:
// an option outside it has no classification, and applying one unclassified is
// how a security option like nosuid gets passed as data and quietly not
// applied. Everything here is checked against Lookup below for exactly that.
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

	// XFS refuses to mount a filesystem whose UUID matches one already mounted.
	// A restore is a byte-for-byte copy, so a restored XFS volume carries its
	// source's UUID exactly — and mounting the copy beside the original, which
	// is most of the reason to restore one, needs this. Without it the API
	// supports XFS and supports restores and cannot combine them.
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

// mountFlagsAreClassified reports the first flag this provider allows that the
// shared table does not classify. Such a flag would reach mount(2) as neither a
// kernel bit nor a data option — silently dropped rather than applied — so the
// test that calls this is the one keeping the two lists in step.
func mountFlagsAreClassified() (string, bool) {
	for f := range allowedMountFlags {
		if _, ok := mount.Lookup(f); !ok {
			return f, false
		}
	}
	return "", true
}

// validateMountTarget checks a mount point path.
//
// It must be absolute and already in cleaned form, so the string handed to
// mount(8) is the path the caller named and not one that resolves elsewhere
// through "..".
//
// It must also carry no control character and no leading or trailing
// whitespace on any component. A space INSIDE a component is fine — mount
// points with spaces in them are legal and this provider passes every path as
// its own argv element, so nothing has to quote or escape one — but whitespace
// at an edge is the shape that goes wrong quietly. A target that differs from
// the caller's by a trailing space is a different path to the kernel and the
// same path to a human reading a log, and anything that trims it turns
// "mounted somewhere else" into "not mounted" and a teardown into a silent
// no-op. A newline is worse: it makes one path look like two in every
// line-oriented tool an operator will reach for.
//
// This provider reads findmnt as JSON (see mountTarget) precisely so that
// parsing never depends on how a path is spelled. The check here is the other
// half: what reaches the tools is a path with no room for that ambiguity.
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
