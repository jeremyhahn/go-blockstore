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

package common_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// fakeProvider is a no-op implementation used to assert that the interface
// contracts compile as declared.
type fakeProvider struct{}

func (fakeProvider) Provision(context.Context, common.VolumeSpec) (common.Volume, error) {
	return common.Volume{}, nil
}
func (fakeProvider) Attach(context.Context, string, common.NodeID) (common.AttachInfo, error) {
	return common.AttachInfo{}, nil
}
func (fakeProvider) Detach(context.Context, string, common.NodeID) error { return nil }
func (fakeProvider) Mount(context.Context, string, string, common.MountOptions) error {
	return nil
}
func (fakeProvider) Unmount(context.Context, string, string) error { return nil }
func (fakeProvider) Resize(context.Context, string, int64) error   { return nil }
func (fakeProvider) Snapshot(context.Context, string, string) (common.SnapshotID, error) {
	return "", nil
}
func (fakeProvider) ListSnapshots(context.Context, string) ([]common.SnapshotInfo, error) {
	return nil, nil
}
func (fakeProvider) DeleteSnapshot(context.Context, common.SnapshotID) error { return nil }
func (fakeProvider) Delete(context.Context, string) error                    { return nil }
func (fakeProvider) Status(context.Context, string) (common.VolumeStatus, error) {
	return common.VolumeStatus{}, nil
}

// fakeReplicatedProvider extends fakeProvider with the replication operations.
type fakeReplicatedProvider struct {
	fakeProvider
}

func (fakeReplicatedProvider) Promote(context.Context, string) error { return nil }
func (fakeReplicatedProvider) Demote(context.Context, string) error  { return nil }
func (fakeReplicatedProvider) ReplicationState(context.Context, string) (common.ReplState, error) {
	return common.ReplState{}, nil
}

// fakeLease and fakeCoordinator assert the coordination contracts compile.
type fakeLease struct{}

func (fakeLease) Renew(context.Context) error   { return nil }
func (fakeLease) Release(context.Context) error { return nil }
func (fakeLease) Done() <-chan struct{}         { return nil }
func (fakeLease) Key() string                   { return "" }

type fakeCoordinator struct{}

func (fakeCoordinator) AcquireLease(context.Context, string, time.Duration) (common.Lease, error) {
	return fakeLease{}, nil
}
func (fakeCoordinator) CompareAndSwap(context.Context, string, []byte, []byte) (bool, error) {
	return false, nil
}
func (fakeCoordinator) Delete(context.Context, string) error        { return nil }
func (fakeCoordinator) Get(context.Context, string) ([]byte, error) { return nil, nil }
func (fakeCoordinator) Put(context.Context, string, []byte) error   { return nil }
func (fakeCoordinator) Watch(context.Context, string) (<-chan common.Event, error) {
	return nil, nil
}

// Compile-time assertions that the fakes satisfy the declared interfaces.
var (
	_ common.VolumeProvider     = (*fakeProvider)(nil)
	_ common.ReplicatedProvider = (*fakeReplicatedProvider)(nil)
	_ common.Coordinator        = (*fakeCoordinator)(nil)
	_ common.Lease              = (*fakeLease)(nil)
)

// TestFakesSatisfyInterfaces exercises the fakes through the interfaces at run
// time. The var block above already fails the build if a contract drifts; this
// keeps the whole snapshot and coordination surface reachable from a test, so a
// method added to an interface has to be answered here rather than only in a
// type assertion.
func TestFakesSatisfyInterfaces(t *testing.T) {
	ctx := context.Background()

	var p common.VolumeProvider = fakeProvider{}
	if _, err := p.ListSnapshots(ctx, "vol-1"); err != nil {
		t.Errorf("ListSnapshots returned error: %v", err)
	}
	if err := p.DeleteSnapshot(ctx, common.SnapshotID("snap-1")); err != nil {
		t.Errorf("DeleteSnapshot returned error: %v", err)
	}

	var rp common.ReplicatedProvider = fakeReplicatedProvider{}
	if _, err := rp.ReplicationState(ctx, "vol-1"); err != nil {
		t.Errorf("ReplicationState returned error: %v", err)
	}

	var c common.Coordinator = fakeCoordinator{}
	if err := c.Delete(ctx, "key"); err != nil {
		t.Errorf("Delete returned error: %v", err)
	}

	l, err := c.AcquireLease(ctx, "key", time.Second)
	if err != nil {
		t.Fatalf("AcquireLease returned error: %v", err)
	}
	if err := l.Release(ctx); err != nil {
		t.Errorf("Release returned error: %v", err)
	}
}

// TestSentinelErrorsAreDistinct guards the identities callers branch on. The
// sentinels only earn their keep if errors.Is separates them — a sentinel
// aliased to another would send a caller down the wrong recovery path.
func TestSentinelErrorsAreDistinct(t *testing.T) {
	sentinels := map[string]error{
		"ErrNotFound":              common.ErrNotFound,
		"ErrAlreadyExists":         common.ErrAlreadyExists,
		"ErrSnapshotNotFound":      common.ErrSnapshotNotFound,
		"ErrNotAttached":           common.ErrNotAttached,
		"ErrUnsupported":           common.ErrUnsupported,
		"ErrNotReplicated":         common.ErrNotReplicated,
		"ErrProviderNotRegistered": common.ErrProviderNotRegistered,
		"ErrLeaseHeld":             common.ErrLeaseHeld,
	}

	for name, err := range sentinels {
		if err == nil {
			t.Errorf("%s is nil", name)
			continue
		}
		if err.Error() == "" {
			t.Errorf("%s has an empty message", name)
		}
		for otherName, other := range sentinels {
			if name == otherName {
				continue
			}
			if errors.Is(err, other) {
				t.Errorf("errors.Is(%s, %s) = true, want false: sentinels must be distinct", name, otherName)
			}
		}
	}
}

// TestSnapshotNotFoundIsNotNotFound pins the distinction the two sentinels
// exist for: a missing snapshot must not be mistaken for a missing volume, or a
// restore of a pruned snapshot looks like the source volume vanished.
func TestSnapshotNotFoundIsNotNotFound(t *testing.T) {
	err := fmt.Errorf("provision from snapshot %q: %w", "snap-1", common.ErrSnapshotNotFound)

	if !errors.Is(err, common.ErrSnapshotNotFound) {
		t.Error("errors.Is(err, ErrSnapshotNotFound) = false, want true")
	}
	if errors.Is(err, common.ErrNotFound) {
		t.Error("errors.Is(err, ErrNotFound) = true, want false: a missing snapshot is not a missing volume")
	}
}

// leaseHeldError stands in for a backend's typed lease-held error — go-qrdb's
// *sdk.LeaseHeldError, in the deployment go-blockstore targets — which carries
// the contended key.
type leaseHeldError struct {
	Key string
}

func (e *leaseHeldError) Error() string { return "lease key already held: " + e.Key }

// TestErrLeaseHeldWrappingPreservesBackendError encodes the contract documented
// on ErrLeaseHeld: an implementation wraps its backend error rather than
// returning the bare sentinel, so the portable errors.Is branch works AND the
// key the backend error carries is still recoverable with errors.As.
func TestErrLeaseHeldWrappingPreservesBackendError(t *testing.T) {
	backendErr := &leaseHeldError{Key: "cluster/leader"}
	err := fmt.Errorf("%w: %w", common.ErrLeaseHeld, backendErr)

	if !errors.Is(err, common.ErrLeaseHeld) {
		t.Fatal("errors.Is(err, ErrLeaseHeld) = false, want true: callers branch on the sentinel")
	}

	var held *leaseHeldError
	if !errors.As(err, &held) {
		t.Fatal("errors.As(err, *leaseHeldError) = false, want true: the backend error must survive wrapping")
	}
	if held.Key != "cluster/leader" {
		t.Errorf("recovered key = %q, want %q", held.Key, "cluster/leader")
	}

	// The bare sentinel is what the contract warns against: it matches, but the
	// contended key is gone.
	if errors.As(common.ErrLeaseHeld, &held) {
		t.Error("bare sentinel carries a backend error, want none")
	}
}

// TestSnapshotInfoZeroValue documents what an unpopulated SnapshotInfo means,
// so a provider filling one in cannot mistake a zero CreatedAt for a real
// timestamp.
func TestSnapshotInfoZeroValue(t *testing.T) {
	var info common.SnapshotInfo

	if info.ID != "" {
		t.Errorf("zero ID = %q, want empty", info.ID)
	}
	if info.VolumeID != "" {
		t.Errorf("zero VolumeID = %q, want empty", info.VolumeID)
	}
	if info.Name != "" {
		t.Errorf("zero Name = %q, want empty", info.Name)
	}
	if !info.CreatedAt.IsZero() {
		t.Errorf("zero CreatedAt = %v, want the zero time", info.CreatedAt)
	}
	if info.SizeBytes != 0 {
		t.Errorf("zero SizeBytes = %d, want 0", info.SizeBytes)
	}
}

// TestVolumeSpecSourceSnapshotID checks the field that selects between the two
// Provision modes: the zero value provisions empty, a non-empty value restores.
func TestVolumeSpecSourceSnapshotID(t *testing.T) {
	var empty common.VolumeSpec
	if empty.SourceSnapshotID != "" {
		t.Errorf("zero SourceSnapshotID = %q, want empty (provision an empty volume)", empty.SourceSnapshotID)
	}

	restore := common.VolumeSpec{
		Name:             "restored",
		SizeBytes:        1 << 30,
		SourceSnapshotID: common.SnapshotID("snap-1"),
	}
	if restore.SourceSnapshotID != common.SnapshotID("snap-1") {
		t.Errorf("SourceSnapshotID = %q, want %q", restore.SourceSnapshotID, "snap-1")
	}
}
