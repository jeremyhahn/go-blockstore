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

// AIX is excluded because x/sys does not provide Flock there — measured, a
// GOOS=aix build fails on it. Every other unix has it.
//go:build unix && !aix

package local

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// tryLockFile takes a non-blocking exclusive flock on the open file description, released on close or exit; x/sys/unix because syscall.Flock is missing on some targets.
func tryLockFile(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EWOULDBLOCK):
		return false, nil
	default:
		return false, err
	}
}
