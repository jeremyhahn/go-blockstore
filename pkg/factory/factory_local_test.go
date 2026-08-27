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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-blockstore/pkg/factory"
	"github.com/jeremyhahn/go-blockstore/pkg/local"
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
	provider, err := factory.NewProvider("local", map[string]string{
		"volume_group": "vg0",
		"node_id":      "node-a",
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
