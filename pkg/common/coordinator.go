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

package common

import (
	"context"
	"time"
)

// Coordinator provides leader election, metadata storage and change notification; lease and watch need a clustered backend, the key/value family works in both modes.
type Coordinator interface {
	// AcquireLease takes an exclusive lease on key for ttl (rounded up to whole seconds, minimum one), returning ErrLeaseHeld if another holder owns it.
	AcquireLease(ctx context.Context, key string, ttl time.Duration) (Lease, error)

	// CompareAndSwap sets key to set if it equals expect (nil expect means absent) and reports whether it swapped; an error means an operational failure.
	CompareAndSwap(ctx context.Context, key string, expect, set []byte) (bool, error)

	// Delete removes key; deleting an absent key returns nil.
	Delete(ctx context.Context, key string) error

	// Get returns the value at key, or (nil, nil) when absent; an empty value is a non-nil zero-length slice.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put stores val at key, creating or overwriting it.
	Put(ctx context.Context, key string, val []byte) error

	// Watch delivers Events for keys under prefix until ctx is done or the backend ends the watch, then closes the channel; setup errors are returned here.
	Watch(ctx context.Context, prefix string) (<-chan Event, error)
}

// Lease is a time-bounded lease bound to a key that exists while the lease is held; renew it before its ttl elapses.
type Lease interface {
	// Renew extends the lease for another ttl. It returns an error if the lease
	// has already expired or been released.
	Renew(ctx context.Context) error

	// Release deletes the bound key and closes Done; after a success further calls return nil, and a failed revoke returns an error.
	Release(ctx context.Context) error

	// Done returns a channel that is closed when the lease is lost, whether by
	// expiry or release.
	Done() <-chan struct{}

	// Key returns the key the lease is held on.
	Key() string
}
