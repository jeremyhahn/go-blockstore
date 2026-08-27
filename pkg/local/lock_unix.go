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

// tryLockFile takes an exclusive advisory lock without blocking, reporting
// whether it got one.
//
// The lock belongs to the open file description, not to the process, which is
// what makes it work in both directions this provider needs: two Provider values
// in one process hold separate descriptions and conflict, and so do two separate
// daemons. Closing the file releases it, including when the process dies, so a
// crash mid-operation does not leave a volume locked forever.
// x/sys/unix rather than the syscall package: syscall.Flock is missing on some
// unix targets — measured, a GOOS=solaris build fails on it — and this package
// compiles for every platform even though it can only RUN on Linux. x/sys/unix
// provides it uniformly, and it is already in the module graph.
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
