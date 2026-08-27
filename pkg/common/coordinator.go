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

// Coordinator is the distributed-coordination primitive the library depends on
// for leader election, metadata storage and change notification when managing
// highly available volumes.
//
// It is declared here, rather than imported from a concrete consensus store
// (such as go-qrdb or go-quicraft), so go-blockstore never takes a dependency
// on a specific backend. Callers inject an implementation — dependency
// inversion keeps the coordination substrate a deployment choice.
//
// Not every implementation supports the full interface in every deployment.
// The lease and watch families require a clustered, consensus-backed backend;
// an implementation running single-node/non-replicated may reject AcquireLease
// and Watch with an implementation-defined "not supported" error while still
// serving the key/value family — Get, Put, Delete and CompareAndSwap —
// identically to the clustered case. A
// control plane that needs lease- or watch-based coordination must therefore
// run its coordinator backend in clustered mode; CompareAndSwap-based
// coordination works in both.
type Coordinator interface {
	// AcquireLease acquires an exclusive lease on key for the given ttl and
	// returns a Lease that must be renewed to retain it. Acquisition is
	// fail-fast, not blocking: the lease binds to key only if no live lease
	// currently holds it, and if another holder owns key the call returns
	// ErrLeaseHeld rather than waiting. It therefore behaves as a TTL-scoped
	// distributed lock, suitable for leader election; a caller wanting to wait
	// for the key builds that from retry plus Watch. The returned Lease's Done
	// channel fires on release or expiry. Implementations without consensus
	// support (see the interface doc) may reject this call with a "not
	// supported" error.
	//
	// ttl is rounded UP to whole seconds, with a floor of one second: whole-
	// second granularity is what the underlying lease grant offers, so a
	// sub-second ttl becomes one second and 1500ms becomes two. Callers must
	// Renew on an interval shorter than the effective ttl to retain the key.
	AcquireLease(ctx context.Context, key string, ttl time.Duration) (Lease, error)

	// CompareAndSwap atomically sets key to set, conditional on the current
	// value, and reports whether the swap occurred. A nil expect requires key to
	// be currently absent (create-only). A non-nil expect — including a
	// zero-length slice — requires key to already exist and its current value to
	// equal expect; an absent key never matches a non-nil expect. On a
	// precondition miss it returns (false, nil); a non-nil error is returned
	// only on an operational failure.
	CompareAndSwap(ctx context.Context, key string, expect, set []byte) (bool, error)

	// Delete removes key. Deleting a key that is not present is not an error:
	// the call returns nil, matching Get's treatment of absence as a normal
	// outcome rather than a failure, so a caller unwinding state converges
	// without first probing for existence. A non-nil error means the delete
	// itself failed and the key may still be present. The clustered
	// implementation backs this with go-qrdb's KV delete.
	Delete(ctx context.Context, key string) error

	// Get returns the value stored at key. A key that does not exist yields
	// (nil, nil); a key that exists with an empty value yields a non-nil,
	// zero-length slice, so callers can distinguish absent from empty. Callers
	// must nil-check the returned slice rather than rely on a sentinel error.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put stores val at key, creating or overwriting it.
	Put(ctx context.Context, key string, val []byte) error

	// Watch returns a channel that delivers Events for every change to keys
	// under prefix. The channel is closed when ctx is done and also when the
	// backend terminates the watch on its own — a terminal cancellation
	// carries no event, so the close is the only signal. A closed channel
	// therefore means "this watch is over", never "the system is shutting
	// down"; a caller that still needs notifications and did not cancel ctx
	// re-establishes the watch.
	//
	// Errors surface from this call, not on the channel: a watch that cannot
	// be established returns a non-nil error here, and the channel carries
	// Events only. Implementations without consensus support (see the
	// interface doc) may reject this call with a "not supported" error.
	Watch(ctx context.Context, prefix string) (<-chan Event, error)
}

// Lease represents a held, time-bounded lease acquired from a Coordinator. It
// must be renewed before its ttl elapses to retain ownership, and released when
// no longer needed.
//
// A lease is bound to a key: the Coordinator creates that key when the lease is
// acquired and deletes it when the lease is released or expires. The key's
// existence is the ownership signal — that is what makes a contender's
// AcquireLease fail with ErrLeaseHeld while this lease lives, and what frees
// the key for the next holder once it does not.
type Lease interface {
	// Renew extends the lease for another ttl. It returns an error if the lease
	// has already expired or been released.
	Renew(ctx context.Context) error

	// Release relinquishes the lease, deleting the bound key and closing Done.
	//
	// It is idempotent only once it has SUCCEEDED: after a successful release a
	// second call returns nil without touching the backend. A revoke the
	// backend did not acknowledge is NOT a release — the error is returned,
	// Done stays open, the lease may well still be held, and the caller should
	// retry. Reporting such a failure as success would tell the caller the key
	// was freed while contenders still saw ErrLeaseHeld until expiry.
	Release(ctx context.Context) error

	// Done returns a channel that is closed when the lease is lost, whether by
	// expiry or release.
	Done() <-chan struct{}

	// Key returns the key the lease is held on.
	Key() string
}
