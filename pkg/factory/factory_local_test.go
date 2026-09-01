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
	"github.com/jeremyhahn/go-blockstore/pkg/local"
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// TestLocalProviderIsAlwaysRegistered is the point of the local provider
// carrying no build tag: a binary built with no tags at all still has a
// backend. Nothing in this test registers anything, so a pass means the
// registration came from importing the package.
func TestLocalProviderIsAlwaysRegistered(t *testing.T) {
	if !factory.IsRegistered("local") {
		t.Fatal(`IsRegistered("local") = false; the untagged local provider should self-register`)
	}

	found := false
	for _, name := range factory.ListProviders() {
		if name == "local" {
			found = true
		}
	}
	if !found {
		t.Errorf("ListProviders() = %v, want it to contain local", factory.ListProviders())
	}
}

func TestNewLocalProvider(t *testing.T) {
	// "preflight": "off" because this test is about REGISTRATION and the
	// returned type, not about whether this machine can attach a volume. The
	// checks that setting disables are exercised on their own in
	// TestNewLocalProviderRunsTheStartupPrivilegeChecks.
	provider, err := factory.NewProvider("local", map[string]string{
		"volume_group": "vg0",
		"node_id":      "node-a",
		"preflight":    "off",
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if provider == nil {
		t.Fatal("NewProvider returned a nil provider")
	}
	if _, ok := provider.(*local.Provider); !ok {
		t.Errorf("NewProvider returned %T, want *local.Provider", provider)
	}
}

// TestNewLocalProviderRunsTheStartupPrivilegeChecks is the guard on the path an
// operator's configuration actually takes.
//
// It asserts against the checker rather than against a fixed outcome, so it is
// meaningful on a privileged host and on an unprivileged one: where the machine
// can do the work the provider must be built, and where it cannot the factory
// must refuse with something that names the missing capability. Remove the
// check from local.New and the second half of this test fails.
func TestNewLocalProviderRunsTheStartupPrivilegeChecks(t *testing.T) {
	settings := map[string]string{"volume_group": "vg0"}

	oracle := preflight.Check(context.Background(),
		preflight.CapabilityDeviceMapper, preflight.CapabilityMount)

	provider, err := factory.NewProvider("local", settings)

	if oracle == nil {
		if err != nil {
			t.Fatalf("this machine can do the work and NewProvider refused anyway: %v", err)
		}
		if provider == nil {
			t.Fatal("NewProvider returned no provider and no error")
		}
		return
	}

	if err == nil {
		t.Fatalf("this machine cannot do the work (%v) and NewProvider returned a provider anyway", oracle)
	}
	if provider != nil {
		t.Error("NewProvider returned a provider alongside the refusal")
	}
	if !errors.Is(err, preflight.ErrUnavailable) {
		t.Errorf("NewProvider = %v, want a failure matching preflight.ErrUnavailable", err)
	}
	// The warning belongs to the refusals an operator could "fix" with
	// --privileged. A platform-unsupported refusal is not one of them: package
	// preflight compiles and refuses on darwin and windows, where there is no
	// container to make privileged, and asserting the warning there fails the
	// suite on a platform this repository explicitly supports building on.
	// Codex caught it; the remedy texts themselves are checked exhaustively in
	// preflight's own TestNoRemedyEverRecommendsPrivileged.
	if !errors.Is(err, preflight.ErrPlatformUnsupported) &&
		!strings.Contains(err.Error(), "Do NOT use --privileged") {
		t.Errorf("the refusal does not warn against the fix an operator will reach for:\n%v", err)
	}
}

// TestNewLocalProviderSurfacesConfigurationErrors checks that a bad settings
// map fails at construction rather than at the first volume operation.
func TestNewLocalProviderSurfacesConfigurationErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"no volume group": {},
		"hostile group":   {"volume_group": "vg0; rm -rf /"},
		//nolint:misspell // "encrpyted" is the point: this case proves a typo'd key is rejected rather than ignored.
		"misspelled key":   {"volume_group": "vg0", "encrpyted": "true"},
		"bad percent":      {"volume_group": "vg0", "snapshot_cow_percent": "500"},
		"encrypted no key": {"volume_group": "vg0", "encrypted": "true"},
	}

	for name, settings := range cases {
		t.Run(name, func(t *testing.T) {
			provider, err := factory.NewProvider("local", settings)
			if err == nil {
				t.Fatalf("NewProvider succeeded with %v", settings)
			}
			if provider != nil {
				t.Error("NewProvider returned a provider alongside an error")
			}
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Errorf("NewProvider = %v, want common.ErrInvalidArgument", err)
			}
			// A configuration mistake is not a missing registration.
			if errors.Is(err, common.ErrProviderNotRegistered) {
				t.Errorf("NewProvider = %v, want a configuration error", err)
			}
		})
	}
}
