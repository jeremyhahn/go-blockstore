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

// Package mount mounts and unmounts through a descriptor opened with symlinks refused, closing the window a path string leaves.
package mount

import "strings"

// Option says whether an allowed mount option is a mount(2) flag bit or a data-string token.
type Option struct {
	// Flag is the MS_* bit this option sets, or 0 for a data option and for the
	// options that name a kernel default and therefore set nothing.
	Flag uintptr

	// Data marks an option the filesystem parses rather than the kernel.
	Data bool
}

// flagTable is the exact set of mount options that may be applied, matched on the whole token; nofail is not one.
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

// Arguments turns validated options into mount(2) flags and data; read-only becomes MS_RDONLY. Callers validate with Lookup first.
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

// Lookup reports how an option reaches the kernel and whether it is permitted; providers may accept a subset, never more.
func Lookup(name string) (Option, bool) {
	option, ok := flagTable[name]
	return option, ok
}
