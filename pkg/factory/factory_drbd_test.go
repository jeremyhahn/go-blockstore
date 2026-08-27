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

//go:build drbd

package factory_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-blockstore/pkg/factory"
)

func drbdSettings(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()

	// The factory builds from settings alone, so peer authentication has to be
	// reachable that way — there is no option to inject a provider through.
	// This is the settings-driven path an operator actually uses.
	secret := filepath.Join(dir, "drbd.secret")
	if err := os.WriteFile(secret, []byte("s3cr3t-replication-key-for-tests\n"), 0o600); err != nil {
		t.Fatalf("writing the replication secret: %v", err)
	}
	// Spelled out rather than taken from the drbd package's Setting constants:
	// this is the settings map a caller writes, and the test is worth failing
	// if a key is renamed without the callers being told.
	return map[string]string{
		"volume_group": "vg0",
		"config_dir":   filepath.Join(dir, "drbd.d"),
		"state_dir":    filepath.Join(dir, "state"),
		"node_name":    "node-a",
		"node_address": "10.10.0.1",
		"peer_node":    "node-b",
		"peer_address": "10.10.0.2",

		"replication_secret_file": secret,
	}
}

// TestDRBDIsRegistered proves the init in factory_drbd.go ran. Building without
// -tags drbd excludes this test along with the file it checks, which is the
// whole point of the tag: the untagged binary links no DRBD code and lists no
// "drbd" provider.
func TestDRBDIsRegistered(t *testing.T) {
	if !factory.IsRegistered(factory.ProviderNameDRBD) {
		t.Fatalf("%q is not registered under -tags drbd", factory.ProviderNameDRBD)
	}
	if !slices.Contains(factory.ListProviders(), factory.ProviderNameDRBD) {
		t.Errorf("ListProviders() = %v, want it to contain %q", factory.ListProviders(), factory.ProviderNameDRBD)
	}
}

func TestNewDRBDProvider(t *testing.T) {
	p, err := factory.NewProvider(factory.ProviderNameDRBD, drbdSettings(t))
	if err != nil {
		t.Fatalf("NewProvider(%q): %v", factory.ProviderNameDRBD, err)
	}
	// The factory hands back a VolumeProvider; the DRBD backend must also
	// satisfy the replicated contract, or the HA controller cannot drive it.
	if _, ok := p.(common.ReplicatedProvider); !ok {
		t.Fatalf("the %q provider does not satisfy common.ReplicatedProvider", factory.ProviderNameDRBD)
	}
}

// TestNewDRBDProviderRejectsBadSettings proves the constructor's validation is
// reachable through the factory, so a misconfigured deployment fails at
// construction rather than at the first drbdadm call.
func TestNewDRBDProviderRejectsBadSettings(t *testing.T) {
	settings := drbdSettings(t)
	delete(settings, "volume_group")

	_, err := factory.NewProvider(factory.ProviderNameDRBD, settings)
	if err == nil {
		t.Fatal("NewProvider with no volume group succeeded, want an error")
	}
	if errors.Is(err, common.ErrProviderNotRegistered) {
		t.Fatalf("got ErrProviderNotRegistered, want a settings error: %v", err)
	}
}

// TestFailedConstructionReturnsANilProvider guards a trap the compiler will not
// catch: returning a constructor's (*drbd.Provider, error) pair straight from a
// function typed (common.VolumeProvider, error) boxes a nil POINTER inside a
// non-nil INTERFACE, so a caller's `if provider != nil` is true for a
// construction that failed.
func TestFailedConstructionReturnsANilProvider(t *testing.T) {
	settings := drbdSettings(t)
	delete(settings, "volume_group")

	provider, err := factory.NewProvider(factory.ProviderNameDRBD, settings)
	if err == nil {
		t.Fatal("NewProvider with no volume group succeeded, want an error")
	}
	if provider != nil {
		t.Errorf("a failed construction returned a non-nil provider (%T), want nil", provider)
	}
}

// TestDRBDRefusesUnauthenticatedPeersByDefault checks that the refusal survives
// construction through the factory, which is how a deployment actually builds
// one. A provider that authenticated its peer only when built directly would
// leave the configured path unprotected.
func TestDRBDRefusesUnauthenticatedPeersByDefault(t *testing.T) {
	settings := drbdSettings(t)
	delete(settings, "replication_secret_file")

	provider, err := factory.NewProvider(factory.ProviderNameDRBD, settings)
	if err == nil {
		t.Fatal("NewProvider built a drbd provider with no peer authentication")
	}
	if provider != nil {
		t.Errorf("a failed construction returned a non-nil provider (%T)", provider)
	}
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("error = %v, want ErrInvalidArgument", err)
	}

	// And the acknowledged form builds, because a lab has to be able to.
	settings["allow_unauthenticated_peers"] = "true"
	if _, err := factory.NewProvider(factory.ProviderNameDRBD, settings); err != nil {
		t.Fatalf("NewProvider with the acknowledgement: %v", err)
	}
}
