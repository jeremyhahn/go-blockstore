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

package mount

import (
	"context"
	"sync"
)

// Fake is a Mounter that records what it was asked to do instead of doing it.
//
// It lives beside the seam rather than in each provider's test files for the
// same reason the seam itself does: two fakes for one interface drift, and a
// provider whose fake accepts a call the real Mounter would refuse is a
// provider whose tests pass for the wrong reason. pkg/local and pkg/drbd drive
// this one.
//
// It is in a non-test file because it is consumed across package boundaries,
// which a _test.go file cannot be. It is exported from an INTERNAL package, so
// it is still unreachable from outside this module.
//
// The zero value is ready to use, and it is safe for concurrent use — the
// providers' tests race their operations against each other deliberately.
type Fake struct {
	mu         sync.Mutex
	mounts     []Call
	unmounts   []string
	mountErr   error
	unmountErr error
}

// Call is one recorded Mount, in the terms mount(2) takes rather than the
// terms a caller wrote: the flags are already split from the data, so a test
// asserts on what the kernel would actually have been given.
type Call struct {
	Source string
	Target string
	FSType string
	Flags  uintptr
	Data   string
}

// Mount records a mount instead of performing one.
func (f *Fake) Mount(_ context.Context, source, target, fsType string, flags uintptr, data string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mounts = append(f.mounts, Call{Source: source, Target: target, FSType: fsType, Flags: flags, Data: data})
	return f.mountErr
}

// Unmount records an unmount instead of performing one.
func (f *Fake) Unmount(_ context.Context, target string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmounts = append(f.unmounts, target)
	return f.unmountErr
}

// MountCalls returns the mounts recorded so far.
func (f *Fake) MountCalls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.mounts...)
}

// UnmountCalls returns the unmount targets recorded so far.
func (f *Fake) UnmountCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.unmounts...)
}

// FailMount makes every subsequent Mount return err.
func (f *Fake) FailMount(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mountErr = err
}

// FailUnmount makes every subsequent Unmount return err.
func (f *Fake) FailUnmount(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmountErr = err
}

// Reset forgets what has been recorded, leaving any scripted failures in place.
func (f *Fake) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mounts, f.unmounts = nil, nil
}

// Compile-time proof that the fake and the real implementation stay
// interchangeable.
var _ Mounter = (*Fake)(nil)
