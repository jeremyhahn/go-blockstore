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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// gate blocks a fake command until a test releases it, which is how these tests
// hold one operation open inside its read-decide-act window while another one
// runs. Without it the two would simply finish in whatever order the scheduler
// picked and the race would go unobserved.
type gate struct {
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGate() *gate {
	return &gate{reached: make(chan struct{}), release: make(chan struct{})}
}

// wait is called from inside the fake runner: it announces that the operation
// has reached this point, then blocks until the test lets it continue.
func (g *gate) wait() {
	g.once.Do(func() { close(g.reached) })
	<-g.release
}

// awaitReached fails the test if the gated command is never run.
func (g *gate) awaitReached(t *testing.T) {
	t.Helper()
	select {
	case <-g.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the gated command was never reached")
	}
}

func (g *gate) open() { close(g.release) }

// blockedOn reports whether something is still waiting on the lock, by checking
// that a call has NOT completed within a short window. A false negative here
// makes the test pass for the wrong reason, so it is only used to assert that a
// call is blocked, never that it is not.
func blockedOn(done <-chan struct{}) bool {
	select {
	case <-done:
		return false
	case <-time.After(250 * time.Millisecond):
		return true
	}
}

// TestResizeAndAttachDoNotInterleave is the reported race, reproduced and then
// held closed.
//
// Resize on a DETACHED volume activates it, grows the filesystem, and
// deactivates it again on the way out. Without a lock, an Attach that completes
// inside that window hands its caller a device that Resize's deferred
// deactivation then pulls out from under them. The test holds Resize open at its
// filesystem grow, runs Attach, and requires that Attach could not have got in.
func TestResizeAndAttachDoNotInterleave(t *testing.T) {
	g := newGate()
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	runner.on("resize2fs", func([]string, []byte) ([]byte, error) {
		g.wait()
		return nil, nil
	})
	p := newTestProvider(t, runner)

	resizeDone := make(chan struct{})
	var resizeErr error
	go func() {
		defer close(resizeDone)
		resizeErr = p.Resize(context.Background(), "data", 2*gib)
	}()

	// Resize is now inside its window, holding the volume's lock.
	g.awaitReached(t)

	attachDone := make(chan struct{})
	var attachErr error
	go func() {
		defer close(attachDone)
		_, attachErr = p.Attach(context.Background(), "data", "node-a")
	}()

	if !blockedOn(attachDone) {
		t.Fatal("Attach completed while Resize held the volume; it could be detached out from under its caller")
	}

	g.open()
	<-resizeDone
	<-attachDone

	if resizeErr != nil {
		t.Fatalf("Resize: %v", resizeErr)
	}
	if attachErr != nil {
		t.Fatalf("Attach: %v", attachErr)
	}

	// The ordering that matters: Attach's activation is the LAST one, so the
	// device it returned survives rather than being deactivated behind it.
	lines := runner.lines()
	lastActivate, lastDeactivate := -1, -1
	for i, line := range lines {
		switch line {
		case "lvchange --activate y --yes vg0/data":
			lastActivate = i
		case "lvchange --activate n --yes vg0/data":
			lastDeactivate = i
		}
	}
	if lastActivate < lastDeactivate {
		t.Errorf("the volume ends deactivated after a successful Attach:\n  %v", lines)
	}
}

// TestOverlappingAttachesDoNotStealEachOthersRollback covers the other shape of
// the same hazard. A failing Attach rolls back by deactivating the volume it
// activated; a concurrent Attach that succeeded must not have that rollback
// applied to it.
func TestOverlappingAttachesDoNotStealEachOthersRollback(t *testing.T) {
	g := newGate()
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})

	// The first unlock fails and gates there; later ones succeed.
	var opens int
	var mu sync.Mutex
	runner.on(luksBinary, func(args []string, stdin []byte) ([]byte, error) {
		// Everything this test does not specifically stage goes to the fake's
		// own LUKS backend, so the operations Attach issues around the unlock —
		// the mapping lookup, and the header read that records the volume's
		// encryption — behave the way they do everywhere else. Answering them
		// ad hoc here silently changed what this test exercises the moment
		// Attach grew another LUKS call.
		if len(args) == 0 || args[0] != "open" {
			return runner.luks(args, stdin)
		}
		mu.Lock()
		opens++
		first := opens == 1
		mu.Unlock()
		if first {
			g.wait()
			return nil, errors.New("no key available with this passphrase")
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, withKey)

	failingDone := make(chan struct{})
	go func() {
		defer close(failingDone)
		_, _ = p.Attach(context.Background(), "data", "node-a")
	}()
	g.awaitReached(t)

	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		_, _ = p.Attach(context.Background(), "data", "node-a")
	}()

	if !blockedOn(secondDone) {
		t.Fatal("a second Attach ran inside the first one's rollback window")
	}

	g.open()
	<-failingDone
	<-secondDone

	// The failing Attach's rollback belongs to the failing Attach: its
	// deactivation must come before the second attempt's activation, never
	// after it.
	lines := runner.lines()
	lastActivate, lastDeactivate := -1, -1
	for i, line := range lines {
		switch line {
		case "lvchange --activate y --yes vg0/data":
			lastActivate = i
		case "lvchange --activate n --yes vg0/data":
			lastDeactivate = i
		}
	}
	if lastDeactivate > lastActivate {
		t.Errorf("a rollback landed after the succeeding attach's activation:\n  %v", lines)
	}
}

// TestLockExcludesASeparateProviderValue is the property that makes this an
// flock rather than a mutex. Two Provider values hold separate open file
// descriptions, so they conflict — which is the honest in-process proxy for the
// case that actually motivates it: two daemons over one volume group.
func TestLockExcludesASeparateProviderValue(t *testing.T) {
	lockDir := t.TempDir()
	withShared := func(o *Options) { o.LockDir = lockDir }

	g := newGate()
	firstRunner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	firstRunner.on("resize2fs", func([]string, []byte) ([]byte, error) {
		g.wait()
		return nil, nil
	})
	first := newTestProvider(t, firstRunner, withShared)

	secondRunner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	second := newTestProvider(t, secondRunner, withShared)

	if first == second {
		t.Fatal("the two providers are the same value; this test would prove nothing")
	}

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_ = first.Resize(context.Background(), "data", 2*gib)
	}()
	g.awaitReached(t)

	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		_ = second.Resize(context.Background(), "data", 2*gib)
	}()

	if !blockedOn(secondDone) {
		t.Fatal("a separate Provider value entered the locked window; the lock does not cross Provider instances")
	}

	g.open()
	<-firstDone
	<-secondDone
}

// TestSeparateVolumesDoNotBlockEachOther keeps the lock from being a volume
// group-wide mutex: it is per volume, and unrelated volumes proceed together.
func TestSeparateVolumesDoNotBlockEachOther(t *testing.T) {
	g := newGate()
	runner := newFakeRunner().
		withLVs(
			lvFixture{Name: "data", SizeBytes: gib, Active: false},
			lvFixture{Name: "other", SizeBytes: gib, Active: false},
		).
		withBlkid(map[string]string{
			"/dev/vg0/data":  "ext4",
			"/dev/vg0/other": "ext4",
		})
	runner.on("resize2fs", func(args []string, _ []byte) ([]byte, error) {
		if args[len(args)-1] == "/dev/vg0/data" {
			g.wait()
		}
		return nil, nil
	})
	p := newTestProvider(t, runner)

	heldDone := make(chan struct{})
	go func() {
		defer close(heldDone)
		_ = p.Resize(context.Background(), "data", 2*gib)
	}()
	g.awaitReached(t)

	otherDone := make(chan struct{})
	var otherErr error
	go func() {
		defer close(otherDone)
		otherErr = p.Resize(context.Background(), "other", 2*gib)
	}()

	select {
	case <-otherDone:
	case <-time.After(10 * time.Second):
		t.Fatal("an unrelated volume blocked behind another volume's lock")
	}
	if otherErr != nil {
		t.Fatalf("Resize of an unrelated volume: %v", otherErr)
	}

	g.open()
	<-heldDone
}

// TestLockAcquisitionHonorsContext keeps a blocked operation from waiting
// forever when its caller has given up.
func TestLockAcquisitionHonorsContext(t *testing.T) {
	g := newGate()
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: false}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	runner.on("resize2fs", func([]string, []byte) ([]byte, error) {
		g.wait()
		return nil, nil
	})
	p := newTestProvider(t, runner)

	heldDone := make(chan struct{})
	go func() {
		defer close(heldDone)
		_ = p.Resize(context.Background(), "data", 2*gib)
	}()
	g.awaitReached(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := p.Attach(ctx, "data", "node-a")
	if err == nil {
		t.Fatal("Attach acquired a lock that was held")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Attach = %v, want the context deadline", err)
	}

	g.open()
	<-heldDone
}

// TestRestoreLocksBothVolumes covers the one operation that holds two locks: it
// reads a snapshot, which activates that snapshot's origin, while creating a
// different volume.
func TestRestoreLocksBothVolumes(t *testing.T) {
	g := newGate()
	runner := newFakeRunner().withLVs(snapshotFixtures()...)
	runner.on("dd", func([]string, []byte) ([]byte, error) {
		g.wait()
		return nil, nil
	})
	p := newTestProvider(t, runner)

	restoreDone := make(chan struct{})
	go func() {
		defer close(restoreDone)
		_, _ = p.Provision(context.Background(), common.VolumeSpec{
			Name:             "restored",
			SizeBytes:        gib,
			SourceSnapshotID: common.SnapshotID("data" + snapSeparator + "nightly"),
		})
	}()
	g.awaitReached(t)

	// The ORIGIN is locked too, because reading its snapshot moves it.
	originDone := make(chan struct{})
	go func() {
		defer close(originDone)
		_, _ = p.Attach(context.Background(), "data", "node-a")
	}()
	if !blockedOn(originDone) {
		t.Error("the snapshot's origin was not locked during a restore")
	}

	g.open()
	<-restoreDone
	<-originDone
}

func TestSortedUnique(t *testing.T) {
	got := sortedUnique([]string{"b", "a", "b", "c", "a"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("sortedUnique = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedUnique = %v, want %v", got, want)
		}
	}
	// A restore into the origin's own name must collapse to one lock rather
	// than blocking on a file description it already holds.
	if single := sortedUnique([]string{"data", "data"}); len(single) != 1 {
		t.Fatalf("sortedUnique = %v, want one key", single)
	}
}
