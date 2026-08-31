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

// lockRetryInterval is how long a blocked acquisition waits before trying again.
//
// The wait is a polling one because the alternative — a goroutine parked in a
// blocking flock — can acquire the lock AFTER its caller has given up on the
// context, leaving a lock held on behalf of an operation that is no longer
// running. Nothing would release it until the process exits. Polling has no such
// window: every attempt is non-blocking, so the only way this function holds a
// lock is by returning it.
//
// 25ms is immaterial against what these operations do. The cheapest of them
// forks lvs; the expensive ones run a LUKS key derivation, which is a hundred
// thousand PBKDF2 rounds.
const lockRetryInterval = 25 * time.Millisecond

// lockVolumes takes the per-volume lock for each named volume and returns the
// function that releases them.
//
// EVERY state-changing operation holds these for its whole read-decide-act
// sequence, rollback included. The provider keeps no state of its own — it reads
// the volume group, decides, and acts across several commands — so without a
// lock two operations interleave inside that gap and act on a world that has
// moved underneath them. Resize reads a volume as detached and begins growing
// it; Attach completes in between; Resize's deferred deactivation then detaches
// a volume the other caller was just told it could use.
//
// The lock is an flock on a file per volume, which gets both properties needed
// at once. Two acquisitions in one process use separate open file descriptions
// and therefore conflict, so two Provider values over one volume group serialize
// correctly. And flock is held by the file description rather than the process,
// so two DAEMONS over one volume group serialize too — which is not a
// hypothetical: nothing in this design stops an operator running a second one.
//
// The keys are sorted and deduplicated, which is what makes multiple locks safe.
// Every caller acquires in the same order, so two operations wanting the same
// pair cannot each hold one and wait for the other. Deduplication matters for
// the restore that names the volume it is restoring into and the volume that
// owns the snapshot: when those coincide, one lock is taken rather than a second
// acquisition on a file description this call already holds, which would block
// forever against itself.
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

// lockFileName is the lock file for one volume.
//
// The volume group is part of it because one lock directory can serve several
// groups, and the separator is an underscore because validateName refuses one in
// either half — so no group and volume pair can collide with another by moving a
// hyphen, the same reasoning that names the device-mapper entries.
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
