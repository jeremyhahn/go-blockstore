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

// tryLockFile has no implementation off unix.
//
// The provider cannot run there anyway — it drives LVM and device-mapper — but
// the package still COMPILES for other platforms, and it should
// keep doing so rather than break a cross-build. Refusing here is what keeps the
// serialization guarantee honest: a platform without flock gets an error, never
// an unlocked operation that looks locked.
func tryLockFile(*os.File) (bool, error) {
	return false, errors.New("advisory file locking is not available on this platform")
}
