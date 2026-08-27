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

//go:build !linux

package local

import (
	"context"
	"errors"
)

// The MS_* bits have no meaning off Linux; the option table still needs the
// names to compile.
const (
	msRDONLY      = 0
	msNOSUID      = 0
	msNODEV       = 0
	msNOEXEC      = 0
	msSYNCHRONOUS = 0
	msDIRSYNC     = 0
	msNOATIME     = 0
	msNODIRATIME  = 0
	msRELATIME    = 0
	msSTRICTATIME = 0
	msLAZYTIME    = 0
	msNOSYMFOLLOW = 0
)

// errNoMounter reports that safe mounting is unavailable here.
//
// Pinning a target needs openat2, which is Linux-only, and the whole provider is
// Linux-only in practice — it drives LVM and device-mapper. The package still
// COMPILES elsewhere, and refusing here is what keeps that from quietly becoming
// an unpinned mount somewhere it cannot be done safely.
var errNoMounter = errors.New("go-blockstore/local: mounting requires Linux, where a target can be pinned against symlink substitution")

type systemMounter struct{}

func (systemMounter) Mount(context.Context, string, string, string, uintptr, string) error {
	return errNoMounter
}

func (systemMounter) Unmount(context.Context, string) error { return errNoMounter }
