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
	"context"
	"sync"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// roleOnlyProvider implements every common.VolumeProvider method by panicking.
//
// It is the mechanical form of the settled composition in the package doc: the
// controller owns the replication ROLE and never the filesystem. Embedding this
// in the test provider means a controller that grew a Mount, an Unmount, a
// Provision or a Delete call would fail its tests with a panic naming the
// method, rather than quietly acquiring a responsibility it cannot discharge.
//
// The panics are the assertion. They are not a stub to be filled in later: if
// this package ever needs one of these operations, that is a design change to
// argue for, not a fixture to extend.
type roleOnlyProvider struct{}

func (roleOnlyProvider) Provision(context.Context, common.VolumeSpec) (common.Volume, error) {
	panic("ha controller must not call Provision: it owns the replication role, not the volume lifecycle")
}

func (roleOnlyProvider) Attach(context.Context, string, common.NodeID) (common.AttachInfo, error) {
	panic("ha controller must not call Attach: attaching is the orchestrator's step")
}

func (roleOnlyProvider) Detach(context.Context, string, common.NodeID) error {
	panic("ha controller must not call Detach: attaching is the orchestrator's step")
}

func (roleOnlyProvider) Mount(context.Context, string, string, common.MountOptions) error {
	panic("ha controller must not call Mount: mounting follows promotion and belongs to the workload")
}

func (roleOnlyProvider) Unmount(context.Context, string, string) error {
	panic("ha controller must not call Unmount: it does not own the processes holding the mount")
}

func (roleOnlyProvider) Resize(context.Context, string, int64) error {
	panic("ha controller must not call Resize")
}

func (roleOnlyProvider) Snapshot(context.Context, string, string) (common.SnapshotID, error) {
	panic("ha controller must not call Snapshot")
}

func (roleOnlyProvider) ListSnapshots(context.Context, string) ([]common.SnapshotInfo, error) {
	panic("ha controller must not call ListSnapshots")
}

func (roleOnlyProvider) DeleteSnapshot(context.Context, common.SnapshotID) error {
	panic("ha controller must not call DeleteSnapshot")
}

func (roleOnlyProvider) Delete(context.Context, string) error {
	panic("ha controller must not call Delete: deletion does not cascade and is not a failover step")
}

func (roleOnlyProvider) Status(context.Context, string) (common.VolumeStatus, error) {
	panic("ha controller must not call Status: ReplicationState is the narrower question it asks")
}

// replResult is the scripted answer ReplicationState gives.
type replResult struct {
	state common.ReplState
	err   error
}

// fakeProvider is a scriptable common.ReplicatedProvider for the three methods
// the controller is allowed to call. Everything else panics — see
// [roleOnlyProvider].
type fakeProvider struct {
	roleOnlyProvider

	mu sync.Mutex

	// repl is the answer ReplicationState gives, swappable mid-test so a
	// volume can change state between reconciles.
	repl replResult

	promoteErr error
	demoteErr  error

	// promoteHonorsCancel picks which of TWO real orderings Promote models when
	// its context is canceled while it runs.
	//
	// True — the default — is drbdadm killed mid-exec: the call fails, and the
	// node did not become Primary.
	//
	// False is the other one, and the dangerous one: the exec COMPLETED and the
	// cancellation landed a moment later, so the provider returns nil having
	// genuinely made this node Primary while the lease that authorized it was
	// already gone. A fixture that could not produce this would make the
	// void-promotion path untestable by pretending an ordering the real
	// provider produces cannot happen.
	promoteHonorsCancel bool

	calls    []string
	promotes int
	demotes  int

	// Hooks run INSIDE the call, before it returns, with no lock held. They are
	// the barriers race tests use to hold a provider call open while something
	// else happens.
	promoteHook func(ctx context.Context)
	demoteHook  func(ctx context.Context)
	replHook    func(ctx context.Context)
}

var _ common.ReplicatedProvider = (*fakeProvider)(nil)

// newFakeProvider returns a provider reporting conn with the given role.
func newFakeProvider(conn common.ReplConnState, role common.ReplRole) *fakeProvider {
	return &fakeProvider{
		repl:                replResult{state: common.ReplState{Conn: conn, Role: role}},
		promoteHonorsCancel: true,
	}
}

// setPromoteCompletesAfterCancel models the ordering where the promotion
// succeeded and the cancellation landed afterwards. See promoteHonorsCancel.
func (p *fakeProvider) setPromoteCompletesAfterCancel() {
	p.mu.Lock()
	p.promoteHonorsCancel = false
	p.mu.Unlock()
}

func (p *fakeProvider) setRepl(conn common.ReplConnState, role common.ReplRole) {
	p.mu.Lock()
	p.repl = replResult{state: common.ReplState{Conn: conn, Role: role}}
	p.mu.Unlock()
}

func (p *fakeProvider) setReplErr(err error) {
	p.mu.Lock()
	p.repl = replResult{err: err}
	p.mu.Unlock()
}

func (p *fakeProvider) setPromoteErr(err error) {
	p.mu.Lock()
	p.promoteErr = err
	p.mu.Unlock()
}

func (p *fakeProvider) setDemoteErr(err error) {
	p.mu.Lock()
	p.demoteErr = err
	p.mu.Unlock()
}

func (p *fakeProvider) setPromoteHook(fn func(ctx context.Context)) {
	p.mu.Lock()
	p.promoteHook = fn
	p.mu.Unlock()
}

func (p *fakeProvider) setDemoteHook(fn func(ctx context.Context)) {
	p.mu.Lock()
	p.demoteHook = fn
	p.mu.Unlock()
}

func (p *fakeProvider) setReplHook(fn func(ctx context.Context)) {
	p.mu.Lock()
	p.replHook = fn
	p.mu.Unlock()
}

func (p *fakeProvider) recorded() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func (p *fakeProvider) promoteCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.promotes
}

func (p *fakeProvider) demoteCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.demotes
}

// ReplicationState answers with its scripted result. The context is checked
// BEFORE the hook runs and not after, which models the read having completed:
// a cancellation landing while the caller is between drbdsetup returning and
// the provider returning is a real ordering, and it is the one that leaves a
// controller holding a state it may no longer act on.
func (p *fakeProvider) ReplicationState(ctx context.Context, volID string) (common.ReplState, error) {
	if err := ctx.Err(); err != nil {
		return common.ReplState{}, err
	}

	p.mu.Lock()
	p.calls = append(p.calls, "ReplicationState")
	hook := p.replHook
	res := p.repl
	p.mu.Unlock()

	if hook != nil {
		hook(ctx)
	}
	if res.err != nil {
		return common.ReplState{}, res.err
	}
	return res.state, nil
}

// Promote records the call, runs any barrier hook, and then honors the
// context: a real provider exec'ing drbdadm under a canceled context fails,
// so a fake that returned success after cancellation would be emitting an
// outcome the real one cannot.
func (p *fakeProvider) Promote(ctx context.Context, volID string) error {
	p.mu.Lock()
	p.calls = append(p.calls, "Promote")
	p.promotes++
	hook := p.promoteHook
	err := p.promoteErr
	honorsCancel := p.promoteHonorsCancel
	p.mu.Unlock()

	if hook != nil {
		hook(ctx)
	}
	if cerr := ctx.Err(); cerr != nil && honorsCancel {
		return cerr
	}
	return err
}

func (p *fakeProvider) Demote(ctx context.Context, volID string) error {
	p.mu.Lock()
	p.calls = append(p.calls, "Demote")
	p.demotes++
	hook := p.demoteHook
	err := p.demoteErr
	p.mu.Unlock()

	if hook != nil {
		hook(ctx)
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return err
}
