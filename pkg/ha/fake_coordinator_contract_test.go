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

package ha

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// The controller's correctness rests entirely on the Coordinator contract, so a
// fake that answers a little differently would let the controller pass tests it
// would fail in production. This is the fixture proving itself against
// pkg/common/coordinator.go, rule by rule.
//
// It is not a test of the controller. It is the reason the controller's tests
// are worth anything.

func TestFakeCoordinatorLeaseIsExclusiveAndFailFast(t *testing.T) {
	ctx := context.Background()
	c := newFakeCoordinator()

	first, err := c.AcquireLease(ctx, "k", 10*time.Second)
	if err != nil {
		t.Fatalf("first acquisition: %v", err)
	}
	if first.Key() != "k" {
		t.Fatalf("Key() = %q, want %q", first.Key(), "k")
	}

	// Fail-fast, not blocking: the second caller is refused immediately.
	done := make(chan error, 1)
	go func() {
		_, contendErr := c.AcquireLease(ctx, "k", 10*time.Second)
		done <- contendErr
	}()
	select {
	case contendErr := <-done:
		if !errors.Is(contendErr, common.ErrLeaseHeld) {
			t.Fatalf("contended acquisition: got %v, want errors.Is common.ErrLeaseHeld", contendErr)
		}
		var held *fakeLeaseHeldError
		if !errors.As(contendErr, &held) {
			t.Fatalf("contended acquisition: got %v, want errors.As *fakeLeaseHeldError", contendErr)
		}
		if held.Key != "k" {
			t.Fatalf("contended key = %q, want %q", held.Key, "k")
		}
	case <-time.After(waitTimeout):
		t.Fatal("contended acquisition blocked; AcquireLease must be fail-fast")
	}

	// The key is free again once released, and the next holder gets it.
	if releaseErr := first.Release(ctx); releaseErr != nil {
		t.Fatalf("release: %v", releaseErr)
	}
	second, err := c.AcquireLease(ctx, "k", 10*time.Second)
	if err != nil {
		t.Fatalf("acquisition after release: %v", err)
	}
	if releaseErr := second.Release(ctx); releaseErr != nil {
		t.Fatalf("second release: %v", releaseErr)
	}
}

func TestFakeCoordinatorRoundsTTLUpToWholeSeconds(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"sub-second takes the floor", 250 * time.Millisecond, time.Second},
		{"zero takes the floor", 0, time.Second},
		{"negative takes the floor", -5 * time.Second, time.Second},
		{"one second is exact", time.Second, time.Second},
		{"1500ms rounds up to two", 1500 * time.Millisecond, 2 * time.Second},
		{"whole seconds are unchanged", 15 * time.Second, 15 * time.Second},
		{"a nanosecond over rounds up", 15*time.Second + time.Nanosecond, 16 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeTTL(tt.in); got != tt.want {
				t.Fatalf("normalizeTTL(%s) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestFakeCoordinatorExpiryClosesDoneAndFreesTheKey(t *testing.T) {
	ctx := context.Background()
	c := newFakeCoordinator()

	// A REAL one-second TTL, elapsed by the wall clock. This is the one test
	// that waits, and it exists so the deterministic expireNow hook used
	// everywhere else is known to share the timer path's behavior rather than
	// merely to resemble it.
	lease, err := c.AcquireLease(ctx, "k", time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !c.held("k") {
		t.Fatal("the key must be bound while the lease lives")
	}

	select {
	case <-lease.Done():
	case <-time.After(waitTimeout):
		t.Fatal("Done did not close at the deadline")
	}
	if c.held("k") {
		t.Fatal("the key must be freed when the lease expires")
	}

	// A renewal resolving after Done closed reports the loss and never nil.
	if renewErr := lease.Renew(ctx); renewErr == nil {
		t.Fatal("Renew after expiry returned nil; it must report the lease as lost")
	} else if !errors.Is(renewErr, errFakeLeaseLost) {
		t.Fatalf("Renew after expiry: got %v, want errFakeLeaseLost", renewErr)
	}

	// And a contender can now take it.
	next, err := c.AcquireLease(ctx, "k", 10*time.Second)
	if err != nil {
		t.Fatalf("acquisition after expiry: %v", err)
	}
	if err := next.Release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}
}

func TestFakeCoordinatorExpireNowMatchesTheTimerPath(t *testing.T) {
	ctx := context.Background()
	c := newFakeCoordinator()

	lease, err := c.AcquireLease(ctx, "k", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !c.expireNow("k") {
		t.Fatal("expireNow found no lease on a key it had just bound")
	}

	select {
	case <-lease.Done():
	case <-time.After(waitTimeout):
		t.Fatal("expireNow did not close Done")
	}
	if c.held("k") {
		t.Fatal("expireNow did not free the key")
	}
	if err := lease.Renew(ctx); !errors.Is(err, errFakeLeaseLost) {
		t.Fatalf("Renew after expireNow: got %v, want errFakeLeaseLost", err)
	}
	if c.expireNow("k") {
		t.Fatal("expireNow reported success on a key with no lease")
	}
}

func TestFakeCoordinatorReleaseIsIdempotentOnlyAfterSuccess(t *testing.T) {
	ctx := context.Background()
	c := newFakeCoordinator()

	lease, err := c.AcquireLease(ctx, "k", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// A refused release is NOT a release: Done stays open, the key stays bound.
	refused := errors.New("backend refused the revoke")
	c.setReleaseErr(refused)
	if err := lease.Release(ctx); !errors.Is(err, refused) {
		t.Fatalf("refused release: got %v, want %v", err, refused)
	}
	select {
	case <-lease.Done():
		t.Fatal("a refused release must not close Done")
	default:
	}
	if !c.held("k") {
		t.Fatal("a refused release must leave the key bound")
	}

	// Once it succeeds, a second call returns nil without touching the backend.
	c.setReleaseErr(nil)
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("second release must be nil, got %v", err)
	}
	if c.held("k") {
		t.Fatal("release must free the key")
	}
}

func TestFakeCoordinatorUnacknowledgedRenewalDoesNotExtend(t *testing.T) {
	ctx := context.Background()
	c := newFakeCoordinator()

	lease, err := c.AcquireLease(ctx, "k", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	boom := errors.New("coordinator unreachable")
	c.setRenewErr(boom)
	if err := lease.Renew(ctx); !errors.Is(err, boom) {
		t.Fatalf("failed renewal: got %v, want %v", err, boom)
	}
	// The deadline is untouched by a failed renewal, so expiry still ends it.
	if !c.expireNow("k") {
		t.Fatal("the lease should still exist after a failed renewal")
	}
	select {
	case <-lease.Done():
	case <-time.After(waitTimeout):
		t.Fatal("Done did not close")
	}
}

func TestFakeCoordinatorKeyValueFamily(t *testing.T) {
	ctx := context.Background()
	c := newFakeCoordinator()

	// Absent reads as (nil, nil).
	val, err := c.Get(ctx, "absent")
	if err != nil {
		t.Fatalf("Get on an absent key: %v", err)
	}
	if val != nil {
		t.Fatalf("Get on an absent key = %v, want nil", val)
	}

	// Present-but-empty reads as a non-nil zero-length slice.
	if putErr := c.Put(ctx, "empty", nil); putErr != nil {
		t.Fatalf("Put: %v", putErr)
	}
	val, err = c.Get(ctx, "empty")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val == nil || len(val) != 0 {
		t.Fatalf("Get on a present empty key = %v, want a non-nil zero-length slice", val)
	}

	// Deleting an absent key is not an error.
	if err := c.Delete(ctx, "absent"); err != nil {
		t.Fatalf("Delete on an absent key: %v", err)
	}
}

func TestFakeCoordinatorCompareAndSwapExistenceRules(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		seed    func(*fakeCoordinator)
		expect  []byte
		set     []byte
		wantOK  bool
		wantVal []byte
	}{
		{
			name:    "nil expect creates an absent key",
			seed:    func(*fakeCoordinator) {},
			expect:  nil,
			set:     []byte("v1"),
			wantOK:  true,
			wantVal: []byte("v1"),
		},
		{
			name:    "nil expect refuses a present key",
			seed:    func(c *fakeCoordinator) { c.store["k"] = []byte("old") },
			expect:  nil,
			set:     []byte("v1"),
			wantOK:  false,
			wantVal: []byte("old"),
		},
		{
			name:    "empty expect refuses an ABSENT key",
			seed:    func(*fakeCoordinator) {},
			expect:  []byte{},
			set:     []byte("v1"),
			wantOK:  false,
			wantVal: nil,
		},
		{
			name:    "empty expect matches a present empty value",
			seed:    func(c *fakeCoordinator) { c.store["k"] = []byte{} },
			expect:  []byte{},
			set:     []byte("v1"),
			wantOK:  true,
			wantVal: []byte("v1"),
		},
		{
			name:    "a matching value swaps",
			seed:    func(c *fakeCoordinator) { c.store["k"] = []byte("old") },
			expect:  []byte("old"),
			set:     []byte("new"),
			wantOK:  true,
			wantVal: []byte("new"),
		},
		{
			name:    "a mismatched value does not",
			seed:    func(c *fakeCoordinator) { c.store["k"] = []byte("old") },
			expect:  []byte("other"),
			set:     []byte("new"),
			wantOK:  false,
			wantVal: []byte("old"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeCoordinator()
			tt.seed(c)
			ok, err := c.CompareAndSwap(ctx, "k", tt.expect, tt.set)
			if err != nil {
				t.Fatalf("CompareAndSwap: %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("CompareAndSwap ok = %v, want %v", ok, tt.wantOK)
			}
			got, err := c.Get(ctx, "k")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(got, tt.wantVal) || (got == nil) != (tt.wantVal == nil) {
				t.Fatalf("value after CompareAndSwap = %v, want %v", got, tt.wantVal)
			}
		})
	}
}

func TestFakeCoordinatorWatchFansOutAndClosesOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeCoordinator()

	first, err := c.Watch(ctx, "a/")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	second, err := c.Watch(ctx, "a/")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	other, err := c.Watch(ctx, "b/")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	if err := c.Put(ctx, "a/one", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	for i, ch := range []<-chan common.Event{first, second} {
		select {
		case ev := <-ch:
			if ev.Type != common.EventTypePut || ev.Key != "a/one" || string(ev.Value) != "v" {
				t.Fatalf("watcher %d got %+v", i, ev)
			}
		case <-time.After(waitTimeout):
			t.Fatalf("watcher %d never received the put", i)
		}
	}

	if err := c.Delete(ctx, "a/one"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	select {
	case ev := <-first:
		if ev.Type != common.EventTypeDelete || ev.Key != "a/one" || ev.Value != nil {
			t.Fatalf("delete event = %+v", ev)
		}
	case <-time.After(waitTimeout):
		t.Fatal("the delete never reached the watcher")
	}

	// The b/ watcher saw nothing: prefixes are respected.
	select {
	case ev, open := <-other:
		if open {
			t.Fatalf("the b/ watcher received %+v for an a/ key", ev)
		}
	default:
	}

	// Canceling ends every watch, and the close is the only signal.
	cancel()
	for i, ch := range []<-chan common.Event{first, second, other} {
		deadline := time.After(waitTimeout)
		for {
			select {
			case _, open := <-ch:
				if !open {
					goto next
				}
			case <-deadline:
				t.Fatalf("watcher %d never closed after cancellation", i)
			}
		}
	next:
	}
}

func TestFakeCoordinatorDeleteDoesNotRevokeALease(t *testing.T) {
	ctx := context.Background()
	c := newFakeCoordinator()

	lease, err := c.AcquireLease(ctx, "k", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Deleting a leased key removes the ownership signal without ending the
	// lease — the behavior go-qrdb has, and the reason callers unwind a lease
	// with Release rather than Delete.
	if deleteErr := c.Delete(ctx, "k"); deleteErr != nil {
		t.Fatalf("Delete: %v", deleteErr)
	}
	select {
	case <-lease.Done():
		t.Fatal("deleting the bound key must not close Done")
	default:
	}
	// And the freed key is acquirable, which is exactly why callers must not do
	// this.
	other, err := c.AcquireLease(ctx, "k", time.Hour)
	if err != nil {
		t.Fatalf("acquiring the deleted key: %v", err)
	}

	// The original lease expiring must not delete the NEW holder's key. It is
	// expired through the lease itself rather than through expireNow, which
	// addresses by key and would now find the new holder.
	orphan, ok := lease.(*fakeLease)
	if !ok {
		t.Fatalf("lease is %T, want *fakeLease", lease)
	}
	orphan.expire()
	select {
	case <-orphan.Done():
	case <-time.After(waitTimeout):
		t.Fatal("the orphaned lease's Done did not close")
	}
	select {
	case <-other.Done():
		t.Fatal("the new holder's lease was ended by the old one expiring")
	default:
	}
	if !c.held("k") {
		t.Fatal("the new holder's key was deleted by the old lease expiring")
	}
}

func TestFakeCoordinatorHonorsACanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := newFakeCoordinator()

	if _, err := c.AcquireLease(ctx, "k", time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("AcquireLease: got %v, want context.Canceled", err)
	}
	if _, err := c.Get(ctx, "k"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get: got %v, want context.Canceled", err)
	}
	if err := c.Put(ctx, "k", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put: got %v, want context.Canceled", err)
	}
	if err := c.Delete(ctx, "k"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete: got %v, want context.Canceled", err)
	}
	if _, err := c.CompareAndSwap(ctx, "k", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("CompareAndSwap: got %v, want context.Canceled", err)
	}
	if _, err := c.Watch(ctx, "k"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Watch: got %v, want context.Canceled", err)
	}

	live := newFakeCoordinator()
	lease, err := live.AcquireLease(context.Background(), "k", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := lease.Renew(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Renew: got %v, want context.Canceled", err)
	}
	if err := lease.Release(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Release: got %v, want context.Canceled", err)
	}
}
