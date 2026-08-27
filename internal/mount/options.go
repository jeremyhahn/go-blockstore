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

// Package mount performs the two filesystem operations a storage provider
// cannot route through an exec'd binary: mounting and unmounting.
//
// It is internal and shared rather than per-provider because the reason it
// exists is the same for every backend that mounts. Validating a path and then
// handing the STRING to mount(8) — or to mount(2) — leaves a window in which
// the path can become a symlink, and the mount that follows is privileged: it
// lands wherever the link points, including over /. Closing that window means
// resolving the path to a descriptor with symlink resolution refused and then
// operating on the descriptor, which no amount of argument checking around an
// exec'd binary reproduces.
//
// One copy, because a security-relevant mechanism duplicated per provider is
// one that drifts per provider. pkg/local and pkg/drbd both consume this, and
// pkg/cephrbd will make three.
package mount

import "strings"

// Option says how one allowed mount option reaches the kernel.
//
// mount(2) takes the generic options as bits in its flags argument and the
// filesystem-specific ones as a comma-separated data string, and getting the
// split wrong is silent: a security option like nosuid handed over as data is
// simply not applied. Classifying every option here rather than at the call site
// makes an unclassified one impossible — the allowlist and the classification
// are the same table, so a token cannot be permitted without saying where it
// goes.
type Option struct {
	// Flag is the MS_* bit this option sets, or 0 for a data option and for the
	// options that name a kernel default and therefore set nothing.
	Flag uintptr

	// Data marks an option the filesystem parses rather than the kernel.
	Data bool
}

// flagTable is the exact set of mount options that may be applied.
//
// Matching is on the whole token, which is what makes the allowlist hold: the
// data options are joined with commas into one string, so a token containing a
// comma would smuggle in options nobody vetted. "noatime,exec" is not on this
// list and is rejected rather than split, and so is anything beginning with a
// hyphen.
//
// nofail is deliberately absent. It directs mount(8) and fstab, means nothing to
// mount(2), and would reach a filesystem as an unrecognized data option — so it
// is refused with the rest rather than accepted and quietly dropped.
var flagTable = map[string]Option{
	// Generic options the kernel applies.
	"ro":          {Flag: msRDONLY},
	"nosuid":      {Flag: msNOSUID},
	"nodev":       {Flag: msNODEV},
	"noexec":      {Flag: msNOEXEC},
	"sync":        {Flag: msSYNCHRONOUS},
	"dirsync":     {Flag: msDIRSYNC},
	"noatime":     {Flag: msNOATIME},
	"nodiratime":  {Flag: msNODIRATIME},
	"relatime":    {Flag: msRELATIME},
	"strictatime": {Flag: msSTRICTATIME},
	"lazytime":    {Flag: msLAZYTIME},
	"nosymfollow": {Flag: msNOSYMFOLLOW},

	// The kernel defaults. Flags are built up from zero, so naming one sets
	// nothing — they are accepted because a caller may state them for clarity.
	"rw":         {},
	"suid":       {},
	"dev":        {},
	"exec":       {},
	"async":      {},
	"atime":      {},
	"diratime":   {},
	"nolazytime": {},

	// Filesystem-specific options, passed through as data.
	"barrier":            {Data: true},
	"nobarrier":          {Data: true},
	"discard":            {Data: true},
	"nodiscard":          {Data: true},
	"data=journal":       {Data: true},
	"data=ordered":       {Data: true},
	"data=writeback":     {Data: true},
	"errors=continue":    {Data: true},
	"errors=panic":       {Data: true},
	"errors=remount-ro":  {Data: true},
	"nouuid":             {Data: true},
	"user_xattr":         {Data: true},
	"nouser_xattr":       {Data: true},
	"acl":                {Data: true},
	"noacl":              {Data: true},
	"journal_checksum":   {Data: true},
	"nojournal_checksum": {Data: true},
	"grpquota":           {Data: true},
	"usrquota":           {Data: true},
	"noquota":            {Data: true},
	"norecovery":         {Data: true},
	"inode64":            {Data: true},
	"largeio":            {Data: true},
	"swalloc":            {Data: true},
}

// Arguments turns validated options into the two things mount(2) takes.
//
// A read-only request becomes MS_RDONLY here rather than a "ro" token, so it
// cannot be lost among the data options; a caller's validation has already
// refused an "rw" alongside it.
//
// An option absent from the table contributes nothing, which is safe only
// because every caller validates against Lookup first — an unvetted token
// reaching here would be silently dropped rather than applied.
func Arguments(readOnly bool, flags []string) (uintptr, string) {
	var out uintptr
	if readOnly {
		out |= msRDONLY
	}
	var dataOpts []string
	for _, f := range flags {
		option := flagTable[f]
		if option.Data {
			dataOpts = append(dataOpts, f)
			continue
		}
		out |= option.Flag
	}
	return out, strings.Join(dataOpts, ",")
}

// Lookup reports how an option reaches the kernel, and whether it is permitted
// at all. A provider may accept a subset of these — it validates with Lookup
// and refuses what it does not want — but never a superset: an option outside
// the table has no classification, and applying one unclassified is how a
// security option like nosuid gets passed as data and quietly not applied.
func Lookup(name string) (Option, bool) {
	option, ok := flagTable[name]
	return option, ok
}
