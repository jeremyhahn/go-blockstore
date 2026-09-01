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

package blkdev

import (
	"errors"
	"os"
)

// errUnsupportedPlatform is what the operations report where they have no
// implementation. It lives here rather than beside them because here is the
// only place it is used.
var errUnsupportedPlatform = errors.New("blkdev: block-device ioctls require Linux")

// deviceSize has no implementation off Linux.
func deviceSize(*os.File) (int64, error) { return 0, errUnsupportedPlatform }

// zeroRange has no implementation off Linux.
//
// Refusing rather than falling back to writing zeroes by hand: the callers use
// this to destroy a former tenant's data, and a silent substitution with
// different durability is not the kind of thing to do behind a build tag.
func zeroRange(*os.File, uint64, uint64) error { return errUnsupportedPlatform }
