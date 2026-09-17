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
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// capabilitySet renders a capability slice for comparison and for messages.
func capabilitySet(capabilities []preflight.Capability) string {
	names := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		names = append(names, string(capability))
	}
	return strings.Join(names, ",")
}

// TestRequiredCapabilitiesFollowsTheConfiguration is the derivation the default
// mode rests on: the checks cover exactly the operations this provider will
// perform, and no others.
func TestRequiredCapabilitiesFollowsTheConfiguration(t *testing.T) {
	cases := map[string]struct {
		seams     injectedSeams
		encrypted bool
		mode      PreflightMode
		want      string
	}{
		"a production provider needs all four": {
			want: "device-mapper,net-admin,drbd-control,mount",
		},
		"an injected runner removes the control-path requirements": {
			seams: injectedSeams{runner: true},
			want:  "mount",
		},
		"an injected mounter removes the mount requirement": {
			seams: injectedSeams{mounter: true},
			want:  "device-mapper,net-admin,drbd-control",
		},
		"every seam injected needs nothing": {
			seams: injectedSeams{runner: true, mounter: true, mountTable: true, blockDevices: true},
			want:  "",
		},
		// PreflightAll checks everything this provider CAN do, so the keyring
		// is in the set whether or not this deployment encrypts — the same
		// answer pkg/local's PreflightAll gives.
		"PreflightAll ignores the injected seams and the configuration": {
			seams: injectedSeams{runner: true, mounter: true, mountTable: true, blockDevices: true, luks: true},
			mode:  PreflightAll,
			want:  "device-mapper,net-admin,drbd-control,mount,kernel-keyring",
		},
		"PreflightOff derives nothing": {
			mode: PreflightOff,
			want: "",
		},
		"encryption adds the keyring requirement": {
			encrypted: true,
			want:      "device-mapper,net-admin,drbd-control,mount,kernel-keyring",
		},
		"an injected LUKS backend removes it again": {
			seams:     injectedSeams{luks: true},
			encrypted: true,
			want:      "device-mapper,net-admin,drbd-control,mount",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := capabilitySet(requiredCapabilities(tc.seams, tc.encrypted, tc.mode))
			if got != tc.want {
				t.Errorf("requiredCapabilities = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTheCapabilitySetIsNotTheLocalProvidersIsTheWholePoint pins the two
// differences that a copied list would have got wrong in both directions.
//
// This is the assertion the issue asked for. A guard assembled by copying
// pkg/local's capability set would pass its own tests and be wrong twice: it
// would omit the capability DRBD actually needs, and demand one it never uses.
func TestTheCapabilitySetIsNotTheLocalProvidersIsTheWholePoint(t *testing.T) {
	got := requiredCapabilities(injectedSeams{}, false, PreflightConfigured)

	has := func(c preflight.Capability) bool {
		for _, g := range got {
			if g == c {
				return true
			}
		}
		return false
	}

	// Required HERE and not by the local provider. DRBD's control path is
	// generic netlink to the drbd module, gated on CAP_NET_ADMIN — a different
	// bit from CAP_SYS_ADMIN, conferred by neither.
	if !has(preflight.CapabilityNetAdmin) {
		t.Error("net-admin is absent; a container with only the device-mapper privilege drives LVM and fails at the first resource up")
	}
	if !has(preflight.CapabilityDRBDControl) {
		t.Error("drbd-control is absent; a node without the module loaded would get no refusal until the first Provision")
	}

	// NOT required by an UNENCRYPTED deployment, which is what this case is,
	// though pkg/local needs it whenever it handles encrypted volumes. The DRBD
	// peer-authentication secret never enters the kernel keyring, so demanding
	// it here would make a correctly configured node refuse to start.
	//
	// The condition is the whole of the difference now: LUKS-above-DRBD does
	// derive keys and does create dm-crypt mappings, and the encrypted case
	// above asserts the capability appears there. What must not come back is
	// the unconditional demand.
	if has(preflight.CapabilityKernelKeyring) {
		t.Error("kernel-keyring is required of an unencrypted provider, which performs no LUKS operation, so a correct node would be refused")
	}

	// Genuinely shared: volumes are LVM logical volumes and the provider mounts.
	if !has(preflight.CapabilityDeviceMapper) || !has(preflight.CapabilityMount) {
		t.Errorf("the shared capabilities are missing: %v", got)
	}
}

// TestRunPreflightChecksNothingWhenThereIsNothingToCheck covers the one path
// that legitimately passes without probing.
func TestRunPreflightChecksNothingWhenThereIsNothingToCheck(t *testing.T) {
	all := injectedSeams{runner: true, mounter: true, mountTable: true, blockDevices: true}
	if err := runPreflight(all, false, PreflightConfigured); err != nil {
		t.Fatalf("runPreflight over a fully injected provider: %v", err)
	}
}

// TestRunPreflightAgreesWithTheChecker ties the wiring to the package that owns
// the probes: for the derived capabilities, this must reach the checker's own
// verdict on whatever machine the test runs.
//
// Two-sided by construction. On a node with DRBD and the capabilities it
// requires a PASS, so a guard that refused everything would fail it; on a node
// without, the refusal.
func TestRunPreflightAgreesWithTheChecker(t *testing.T) {
	capabilities := requiredCapabilities(injectedSeams{}, false, PreflightConfigured)
	if len(capabilities) == 0 {
		t.Fatal("the default configuration derived no capabilities, so this test would prove nothing")
	}

	oracle := preflight.Check(context.Background(), capabilities...)
	got := runPreflight(injectedSeams{}, false, PreflightConfigured)

	if (oracle == nil) != (got == nil) {
		t.Fatalf("the checker says %v and runPreflight says %v; they must agree", oracle, got)
	}
	if got != nil && !errors.Is(got, preflight.ErrUnavailable) {
		t.Errorf("runPreflight = %v, want a failure matching preflight.ErrUnavailable", got)
	}
}

// TestNewRunsTheStartupPrivilegeChecks is the guard at the point that matters.
// Delete the runPreflight call from New and this fails on any machine without a
// loaded drbd module.
func TestNewRunsTheStartupPrivilegeChecks(t *testing.T) {
	settings := testSettings(t)
	delete(settings, SettingPreflight) // the default mode is the subject here

	oracle := preflight.Check(context.Background(),
		requiredCapabilities(injectedSeams{}, false, PreflightConfigured)...)

	p, err := New(settings, WithSecretProvider(testSecretProvider))

	if oracle == nil {
		if err != nil {
			t.Fatalf("this machine can do the work and New refused anyway: %v", err)
		}
		if p == nil {
			t.Fatal("New returned no provider and no error")
		}
		return
	}

	if err == nil {
		t.Fatalf("this machine cannot do the work (%v) and New returned a provider anyway", oracle)
	}
	if p != nil {
		t.Error("New returned a provider alongside the refusal")
	}
	if !errors.Is(err, preflight.ErrUnavailable) {
		t.Errorf("New = %v, want a failure matching preflight.ErrUnavailable", err)
	}
}

// TestNewSucceedsWithEverySeamInjected is the other side, deterministic on every
// machine: a provider that will not touch the kernel is not refused for the
// kernel's sake.
func TestNewSucceedsWithEverySeamInjected(t *testing.T) {
	settings := testSettings(t)
	delete(settings, SettingPreflight)

	r := newFakeRunner(t)
	p, err := New(settings,
		WithRunner(r),
		WithMounter(&mount.Fake{}),
		WithMountTable(r),
		WithBlockDevices(r),
		WithSecretProvider(testSecretProvider),
	)
	if err != nil {
		t.Fatalf("New with every seam injected: %v", err)
	}
	if p == nil {
		t.Fatal("New returned no provider and no error")
	}
}

// TestNewValidatesBeforeItProbes keeps a configuration mistake reported as a
// configuration mistake. An operator who misspelled a volume group should not
// be told to load a kernel module.
func TestNewValidatesBeforeItProbes(t *testing.T) {
	settings := testSettings(t)
	delete(settings, SettingPreflight)
	settings[SettingVolumeGroup] = "vg0; rm -rf /"

	_, err := New(settings, WithSecretProvider(testSecretProvider))
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Fatalf("New = %v, want common.ErrInvalidArgument rather than a privilege refusal", err)
	}
	if errors.Is(err, preflight.ErrUnavailable) {
		t.Error("a bad configuration was reported as a missing capability")
	}
}

// TestPreflightSettingSpellings covers the parser in both directions, since
// "off" is the value that turns the guard back into the silent failure.
func TestPreflightSettingSpellings(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		for spelling, want := range preflightModeNames {
			t.Run(spelling, func(t *testing.T) {
				settings := testSettings(t)
				settings[SettingPreflight] = spelling

				cfg, err := ParseConfig(settings)
				if err != nil {
					t.Fatalf("ParseConfig(preflight=%q): %v", spelling, err)
				}
				if cfg.Preflight != want {
					t.Errorf("Preflight = %v, want %v", cfg.Preflight, want)
				}
			})
		}
	})

	t.Run("rejected", func(t *testing.T) {
		for _, spelling := range []string{"none", "false", "disabled", "OFF", "0"} {
			t.Run(spelling, func(t *testing.T) {
				settings := testSettings(t)
				settings[SettingPreflight] = spelling

				_, err := ParseConfig(settings)
				if !errors.Is(err, common.ErrInvalidArgument) {
					t.Fatalf("ParseConfig(preflight=%q) = %v, want common.ErrInvalidArgument", spelling, err)
				}
				if !strings.Contains(err.Error(), "configured") {
					t.Errorf("the rejection does not list the accepted spellings: %v", err)
				}
			})
		}
	})

	t.Run("an empty value is the default rather than off", func(t *testing.T) {
		settings := testSettings(t)
		settings[SettingPreflight] = ""

		cfg, err := ParseConfig(settings)
		if err != nil {
			t.Fatalf("ParseConfig: %v", err)
		}
		if cfg.Preflight != PreflightConfigured {
			t.Errorf("Preflight = %v, want PreflightConfigured", cfg.Preflight)
		}
	})
}

// TestPreflightModeSpellingsAreStableAndComplete keeps the error message that
// lists the accepted values honest.
func TestPreflightModeSpellingsAreStableAndComplete(t *testing.T) {
	spellings := preflightModeSpellings()
	if len(spellings) != len(preflightModeNames) {
		t.Fatalf("preflightModeSpellings has %d entries, want %d", len(spellings), len(preflightModeNames))
	}
	for i := 1; i < len(spellings); i++ {
		if spellings[i-1] >= spellings[i] {
			t.Fatalf("preflightModeSpellings is not sorted: %v", spellings)
		}
	}
	for _, spelling := range spellings {
		if _, ok := preflightModeNames[spelling]; !ok {
			t.Errorf("preflightModeSpellings names %q, which the parser does not accept", spelling)
		}
	}
}

// TestEverySeamOptionRecordsItsInjection keeps requiredCapabilities honest: a
// new With* option that forgets to record itself would silently widen the
// checked set and refuse a correctly configured node.
func TestEverySeamOptionRecordsItsInjection(t *testing.T) {
	r := newFakeRunner(t)

	cases := map[string]struct {
		opt   Option
		check func(injectedSeams) bool
	}{
		"WithRunner":       {WithRunner(r), func(s injectedSeams) bool { return s.runner }},
		"WithMounter":      {WithMounter(&mount.Fake{}), func(s injectedSeams) bool { return s.mounter }},
		"WithMountTable":   {WithMountTable(r), func(s injectedSeams) bool { return s.mountTable }},
		"WithBlockDevices": {WithBlockDevices(r), func(s injectedSeams) bool { return s.blockDevices }},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var p Provider
			tc.opt(&p)
			if !tc.check(p.injected) {
				t.Errorf("%s did not record that it replaced a seam", name)
			}
		})
	}
}
