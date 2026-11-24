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

package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// DefaultLockDir is where the per-volume lock files live unless configured
// otherwise. /run/lock is tmpfs on a systemd host, so the files do not survive a
// reboot — which is right for a lock whose only meaning is "an operation is in
// flight in some live process".
const DefaultLockDir = "/run/lock/go-blockstore"

// lockRetryInterval is how long a blocked acquisition waits before trying again; polling never acquires after the context is done.
const lockRetryInterval = 25 * time.Millisecond

// lockVolumes flocks one file per named volume, sorted and deduplicated, and returns the release function.
// Every state-changing operation holds it for its whole read-decide-act sequence; it serializes across Providers and processes.
func (p *Provider) lockVolumes(ctx context.Context, volIDs ...string) (func(), error) {
	keys := sortedUnique(volIDs)

	held := make([]*os.File, 0, len(keys))
	release := func() {
		// Reverse order, mirroring acquisition. Closing the descriptor releases
		// the flock; the file itself stays, and is meant to.
		for i := len(held) - 1; i >= 0; i-- {
			_ = held[i].Close()
		}
	}

	for _, volID := range keys {
		f, err := p.acquireVolumeLock(ctx, volID)
		if err != nil {
			release()
			return nil, err
		}
		held = append(held, f)
	}
	return release, nil
}

// acquireVolumeLock blocks until it holds one volume's lock, or until ctx says
// to stop.
func (p *Provider) acquireVolumeLock(ctx context.Context, volID string) (*os.File, error) {
	if err := os.MkdirAll(p.lockDir, 0o700); err != nil {
		return nil, fmt.Errorf("go-blockstore/local: preparing the lock directory %q: %w", p.lockDir, err)
	}

	path := filepath.Join(p.lockDir, p.lockFileName(volID))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- lockDir is operator configuration and volID is allowlist-validated
	if err != nil {
		return nil, fmt.Errorf("go-blockstore/local: opening the lock for %s: %w", p.lvRef(volID), err)
	}

	for {
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("go-blockstore/local: waiting for the lock on %s: %w", p.lvRef(volID), err)
		}

		locked, err := tryLockFile(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("go-blockstore/local: locking %s: %w", p.lvRef(volID), err)
		}
		if locked {
			return f, nil
		}

		timer := time.NewTimer(lockRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = f.Close()
			return nil, fmt.Errorf("go-blockstore/local: waiting for the lock on %s: %w", p.lvRef(volID), ctx.Err())
		case <-timer.C:
		}
	}
}

// lockFileName is the lock file for one volume: group and volume joined by an underscore, which neither may contain.
func (p *Provider) lockFileName(volID string) string {
	return p.volumeGroup + "_" + volID + ".lock"
}

// sortedUnique returns the input sorted with duplicates removed.
func sortedUnique(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)

	deduped := out[:0]
	for i, v := range out {
		if i == 0 || v != out[i-1] {
			deduped = append(deduped, v)
		}
	}
	return deduped
}
