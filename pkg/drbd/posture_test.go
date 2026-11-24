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

package drbd

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
)

// guardNamed finds one guard's line in a posture, so a test asserts on the guard
// it means rather than on a position in a slice.
func guardNamed(t *testing.T, p Posture, name string) GuardStatus {
	t.Helper()
	for _, g := range p.Guards {
		if g.Name == name {
			return g
		}
	}
	t.Fatalf("posture has no guard named %q; it has:\n%s", name, p)
	return GuardStatus{}
}

// TestPostureReportsTheGuardThatIsOff: the line reads NOT CHECKED and names the setting.
func TestPostureReportsTheGuardThatIsOff(t *testing.T) {
	p, _, _ := newTestProviderWith(t, nil)

	guard := guardNamed(t, p.Posture(), "mount propagation")
	if guard.Active {
		t.Fatal("mount propagation reads as checked in a provider that was not configured for it")
	}
	if !strings.Contains(guard.Detail, SettingMountPropagation) {
		t.Errorf("detail = %q, want it to name %s, which is what turns the guard on", guard.Detail, SettingMountPropagation)
	}

	rendered := p.Posture().String()
	if !strings.Contains(rendered, "mount propagation: NOT CHECKED") {
		t.Errorf("posture reads:\n%s\nwant a NOT CHECKED line for mount propagation", rendered)
	}
	if !strings.Contains(rendered, "go-blockstore/drbd") {
		t.Errorf("posture reads:\n%s\nwant it to name this provider, so two providers' postures are tellable apart", rendered)
	}
}

// TestPostureReportsTheGuardThatIsOn: the line follows the configuration.
func TestPostureReportsTheGuardThatIsOn(t *testing.T) {
	p, _, _ := newTestProviderWith(t, requirePropagation)

	guard := guardNamed(t, p.Posture(), "mount propagation")
	if !guard.Active {
		t.Fatalf("mount propagation reads as unchecked with %s=shared", SettingMountPropagation)
	}
	if !strings.Contains(p.Posture().String(), "mount propagation: checked") {
		t.Errorf("posture reads:\n%s\nwant a checked line for mount propagation", p.Posture())
	}
}

// TestPostureNamesEveryGuardWhicheverWayItIsSet is what makes the report
// readable: a guard is listed whether it is on or off, so an operator can tell a
// list of five guards from a list of four. Omitting the off ones would leave the
// absence to be inferred, which is exactly what nobody does.
func TestPostureNamesEveryGuardWhicheverWayItIsSet(t *testing.T) {
	want := []string{
		"device-mapper access",
		"mount(2) privilege",
		"net-admin privilege",
		"DRBD control interface",
		"kernel keyring",
		"mount propagation",
		"peer authentication",
		"delete-time wipe",
	}

	for _, tweak := range []func(map[string]string){
		nil,
		requirePropagation,
		func(s map[string]string) { s[SettingPreflight] = "off" },
		func(s map[string]string) { s[SettingWipeOnDelete] = "true" },
	} {
		p, _, _ := newTestProviderWith(t, tweak)
		posture := p.Posture()
		if len(posture.Guards) != len(want) {
			t.Fatalf("posture lists %d guards, want %d:\n%s", len(posture.Guards), len(want), posture)
		}
		for _, name := range want {
			guardNamed(t, posture, name)
		}
	}
}

// TestPostureDoesNotClaimAPreflightCheckThatDidNotRun: preflight off reports capabilities unchecked.
func TestPostureDoesNotClaimAPreflightCheckThatDidNotRun(t *testing.T) {
	p, _, _ := newTestProviderWith(t, func(s map[string]string) { s[SettingPreflight] = "off" })

	posture := p.Posture()
	for _, name := range []string{"device-mapper access", "mount(2) privilege", "net-admin privilege", "DRBD control interface"} {
		if guardNamed(t, posture, name).Active {
			t.Errorf("%q reads as checked with %s=off", name, SettingPreflight)
		}
	}
	// Unchecked() is what an operator scans, so it has to carry those four —
	// and only the guards that really are off, which peer authentication is
	// not in this fixture.
	off := map[string]struct{}{}
	for _, g := range posture.Unchecked() {
		off[g.Name] = struct{}{}
	}
	for _, name := range []string{"device-mapper access", "mount(2) privilege", "net-admin privilege", "DRBD control interface", "mount propagation", "delete-time wipe"} {
		if _, listed := off[name]; !listed {
			t.Errorf("Unchecked() omits %q, which is off in this provider", name)
		}
	}
	if _, listed := off["peer authentication"]; listed {
		t.Error("Unchecked() lists peer authentication, which this provider does have")
	}
}

// TestPostureReportsAPreflightCheckThatDidRun: the mode is set on the built provider so no real probes run.
func TestPostureReportsAPreflightCheckThatDidRun(t *testing.T) {
	p, _, _ := newTestProviderWith(t, nil)
	p.cfg.Preflight = PreflightAll

	posture := p.Posture()
	for _, name := range []string{"device-mapper access", "mount(2) privilege", "net-admin privilege", "DRBD control interface"} {
		guard := guardNamed(t, posture, name)
		if !guard.Active {
			t.Errorf("%q reads as unchecked with %s=all", name, SettingPreflight)
		}
		if !strings.Contains(guard.Detail, "startup") {
			t.Errorf("%q detail = %q, want it to say when the check ran", name, guard.Detail)
		}
	}
}

// TestPostureReportsThePeerAuthenticationTheProviderActuallyHas covers the guard
// an operator is most likely to have turned off deliberately and then forgotten.
func TestPostureReportsThePeerAuthenticationTheProviderActuallyHas(t *testing.T) {
	p, _, _ := newTestProviderWith(t, nil)
	if !guardNamed(t, p.Posture(), "peer authentication").Active {
		t.Error("peer authentication reads as absent in a provider given a SecretProvider")
	}

	// The same provider built the way a lab bring-up builds it: no secret, and
	// the exposure acknowledged in configuration.
	settings := testSettings(t)
	settings[SettingAllowUnauthenticatedPeers] = "true"
	unauthenticated, err := New(settings,
		WithRunner(newFakeRunner(t)),
		WithMounter(&mount.Fake{}),
		WithMountTable(newFakeRunner(t)),
		WithBlockDevices(newFakeRunner(t)),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	guard := guardNamed(t, unauthenticated.Posture(), "peer authentication")
	if guard.Active {
		t.Fatal("peer authentication reads as checked with no secret configured")
	}
	if !strings.Contains(guard.Detail, SettingAllowUnauthenticatedPeers) {
		t.Errorf("detail = %q, want it to name the setting that produced this state", guard.Detail)
	}
}

// TestPostureReportsTheKeyringCheckOnlyWhenItIsActuallyDerived: checked only when encrypting with the real LUKS backend.
func TestPostureReportsTheKeyringCheckOnlyWhenItIsActuallyDerived(t *testing.T) {
	const guard = "kernel keyring"

	active := func(t *testing.T, p *Provider, encrypted, luksInjected bool) bool {
		t.Helper()
		p.cfg.Preflight = PreflightConfigured
		p.cfg.Encrypted = encrypted
		p.injected.luks = luksInjected
		return guardNamed(t, p.Posture(), guard).Active
	}

	// Encrypting, on the real backend: New derives the check, so the report
	// must say so. This is the case the `false` mutation breaks.
	enc, _, _ := newEncryptedProvider(t)
	if !active(t, enc, true, false) {
		t.Error("an encrypting provider on the real backend does not report the kernel-keyring check, hiding a check New does make")
	}

	// Encrypting, but driven by an injected backend: nothing derives a key and
	// no mapping is created, so New does NOT check the keyring and the report
	// must not claim it did.
	enc2, _, _ := newEncryptedProvider(t)
	if active(t, enc2, true, true) {
		t.Error("a provider driven by an injected LUKS backend reports the kernel-keyring check, which New never makes")
	}

	// Not encrypting: the case that must not regress to the unconditional
	// demand, which would make a correctly configured node refuse to start.
	plain, _, _ := newTestProviderWith(t, nil)
	if active(t, plain, false, false) {
		t.Error("an unencrypted provider reports the kernel-keyring check; New never makes it")
	}
}
