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

//go:build !unix || aix

package local

import (
	"errors"
	"os"
)

// tryLockFile has no implementation off unix and returns an error.
func tryLockFile(*os.File) (bool, error) {
	return false, errors.New("advisory file locking is not available on this platform")
}
