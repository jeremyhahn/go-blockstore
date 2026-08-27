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

package factory_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-blockstore/pkg/factory"
)

// fakeProvider is an in-test VolumeProvider double used to exercise the
// registry without depending on a real backend.
type fakeProvider struct {
	settings map[string]string
}

func (f *fakeProvider) Provision(context.Context, common.VolumeSpec) (common.Volume, error) {
	return common.Volume{}, nil
}
func (f *fakeProvider) Attach(context.Context, string, common.NodeID) (common.AttachInfo, error) {
	return common.AttachInfo{}, nil
}
func (f *fakeProvider) Detach(context.Context, string, common.NodeID) error { return nil }
func (f *fakeProvider) Mount(context.Context, string, string, common.MountOptions) error {
	return nil
}
func (f *fakeProvider) Unmount(context.Context, string, string) error { return nil }
func (f *fakeProvider) Resize(context.Context, string, int64) error   { return nil }
func (f *fakeProvider) Snapshot(context.Context, string, string) (common.SnapshotID, error) {
	return "", nil
}
func (f *fakeProvider) ListSnapshots(context.Context, string) ([]common.SnapshotInfo, error) {
	return nil, nil
}
func (f *fakeProvider) DeleteSnapshot(context.Context, common.SnapshotID) error { return nil }
func (f *fakeProvider) Delete(context.Context, string) error                    { return nil }
func (f *fakeProvider) Status(context.Context, string) (common.VolumeStatus, error) {
	return common.VolumeStatus{}, nil
}

// Ensure the double satisfies the interface at compile time.
var _ common.VolumeProvider = (*fakeProvider)(nil)

func newFake(settings map[string]string) (common.VolumeProvider, error) {
	return &fakeProvider{settings: settings}, nil
}

// register registers newFake under name and undoes it when the test ends.
// RegisterProvider panics on a duplicate, and the registry outlives the test, so
// without the cleanup a second pass over the suite in the same process (go test
// -count=2) would panic instead of re-running.
func register(t *testing.T, name string) {
	t.Helper()
	factory.RegisterProvider(name, newFake)
	t.Cleanup(func() { factory.UnregisterProviderForTest(name) })
}

func TestRegisterAndNewProvider(t *testing.T) {
	const name = "fake-register-new"
	register(t, name)

	if !factory.IsRegistered(name) {
		t.Fatalf("IsRegistered(%q) = false, want true after registration", name)
	}

	settings := map[string]string{"path": "/dev/loop0"}
	p, err := factory.NewProvider(name, settings)
	if err != nil {
		t.Fatalf("NewProvider(%q) returned error: %v", name, err)
	}
	if p == nil {
		t.Fatal("NewProvider returned a nil provider")
	}

	fp, ok := p.(*fakeProvider)
	if !ok {
		t.Fatalf("NewProvider returned %T, want *fakeProvider", p)
	}
	if fp.settings["path"] != "/dev/loop0" {
		t.Errorf("settings not passed through: got %q", fp.settings["path"])
	}
}

func TestRegisterProviderDuplicatePanics(t *testing.T) {
	const name = "fake-duplicate"
	register(t, name)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("RegisterProvider(duplicate) did not panic; a name claimed twice is a build-configuration bug")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value is %T, want string", r)
		}
		if !strings.Contains(msg, name) {
			t.Errorf("panic message %q does not name the duplicate provider %q", msg, name)
		}
	}()

	factory.RegisterProvider(name, newFake)
}

// TestRegisterProviderNilCreatorPanics pins the other init-time mistake the
// registry refuses to store: a name wired up without a constructor. Accepting
// it would defer the failure to a nil call inside NewProvider, far from the
// init that caused it, and leave the name reported as registered.
func TestRegisterProviderNilCreatorPanics(t *testing.T) {
	const name = "fake-nil-creator"

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("RegisterProvider(nil creator) did not panic")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value is %T, want string", r)
		}
		if !strings.Contains(msg, name) {
			t.Errorf("panic message %q does not name the provider %q", msg, name)
		}
		if factory.IsRegistered(name) {
			t.Errorf("IsRegistered(%q) = true after a rejected registration, want false", name)
		}
	}()

	factory.RegisterProvider(name, nil)
}

// TestRegisterProviderDistinctNamesCoexist guards the other half of the rule:
// the panic must fire on a repeated name only, not on registration generally.
func TestRegisterProviderDistinctNamesCoexist(t *testing.T) {
	names := []string{"fake-coexist-a", "fake-coexist-b"}
	for _, name := range names {
		register(t, name)
	}

	for _, name := range names {
		if !factory.IsRegistered(name) {
			t.Errorf("IsRegistered(%q) = false, want true", name)
		}
	}
}

func TestNewProviderUnknownReturnsError(t *testing.T) {
	_, err := factory.NewProvider("does-not-exist", nil)
	if !errors.Is(err, common.ErrProviderNotRegistered) {
		t.Fatalf("NewProvider(unknown) error = %v, want ErrProviderNotRegistered", err)
	}
}

func TestIsRegisteredUnknown(t *testing.T) {
	if factory.IsRegistered("never-registered") {
		t.Error("IsRegistered(unknown) = true, want false")
	}
}

func TestListProviders(t *testing.T) {
	const name = "fake-list"
	register(t, name)

	found := false
	for _, n := range factory.ListProviders() {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListProviders() = %v, want it to contain %q", factory.ListProviders(), name)
	}
}
