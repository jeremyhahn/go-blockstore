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

// Fake is a Mounter that records calls instead of mounting; its zero value is ready and safe for concurrent use.
type Fake struct {
	mu         sync.Mutex
	mounts     []Call
	unmounts   []string
	mountErr   error
	unmountErr error
	mountHook  func()
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
	f.mounts = append(f.mounts, Call{Source: source, Target: target, FSType: fsType, Flags: flags, Data: data})
	hook, err := f.mountHook, f.mountErr
	f.mu.Unlock()

	if hook != nil {
		hook()
	}
	return err
}

// OnMount registers a function to run after a mount is made, before the caller continues.
func (f *Fake) OnMount(hook func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mountHook = hook
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
