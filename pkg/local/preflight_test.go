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
	"strings"
	"testing"

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
	runner := newFakeRunner()

	cases := map[string]struct {
		opts Options
		mode PreflightMode
		want string
	}{
		"a production provider needs all three": {
			opts: Options{VolumeGroup: "vg0", Encrypted: true, KeyProvider: FileKeyProvider("/k")},
			want: "mount,kernel-keyring,device-mapper",
		},
		"unencrypted still drives LVM and mounts": {
			opts: Options{VolumeGroup: "vg0"},
			want: "mount,device-mapper",
		},
		"a KeyProvider alone implies the keyring, because existing volumes are probed": {
			opts: Options{VolumeGroup: "vg0", KeyProvider: FileKeyProvider("/k")},
			want: "mount,kernel-keyring,device-mapper",
		},
		"an injected runner removes the device-mapper requirement": {
			opts: Options{VolumeGroup: "vg0", Runner: runner},
			want: "mount",
		},
		"an injected mounter removes the mount requirement": {
			opts: Options{VolumeGroup: "vg0", Mounter: runner},
			want: "device-mapper",
		},
		"an injected LUKS backend removes the keyring requirement": {
			opts: Options{VolumeGroup: "vg0", Encrypted: true, KeyProvider: FileKeyProvider("/k"), luks: runner},
			want: "mount,device-mapper",
		},
		"every seam injected needs nothing": {
			opts: Options{VolumeGroup: "vg0", Runner: runner, Mounter: runner, luks: runner},
			want: "",
		},
		"encryption implies device-mapper even with an injected runner": {
			opts: Options{VolumeGroup: "vg0", Encrypted: true, KeyProvider: FileKeyProvider("/k"), Runner: runner},
			want: "mount,kernel-keyring,device-mapper",
		},
		"PreflightAll ignores the injected seams": {
			opts: Options{VolumeGroup: "vg0", Runner: runner, Mounter: runner, luks: runner},
			mode: PreflightAll,
			want: "mount,kernel-keyring,device-mapper",
		},
		"PreflightOff derives nothing": {
			opts: Options{VolumeGroup: "vg0", Encrypted: true, KeyProvider: FileKeyProvider("/k")},
			mode: PreflightOff,
			want: "",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := capabilitySet(requiredCapabilities(tc.opts, tc.mode))
			if got != tc.want {
				t.Errorf("requiredCapabilities = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRunPreflightChecksNothingWhenThereIsNothingToCheck covers the one path
// that legitimately passes without probing: a provider driven entirely through
// injected seams performs no privileged operation of its own.
func TestRunPreflightChecksNothingWhenThereIsNothingToCheck(t *testing.T) {
	runner := newFakeRunner()
	opts := Options{VolumeGroup: "vg0", Runner: runner, Mounter: runner, luks: runner}

	if err := runPreflight(opts, PreflightConfigured); err != nil {
		t.Fatalf("runPreflight over a fully injected provider: %v", err)
	}
}

// TestRunPreflightAgreesWithTheChecker ties the wiring to the package that owns
// the probes: for the capabilities this configuration derives, New's answer must
// be the checker's answer on this machine, whatever that is.
//
// This is the two-sided form. On a machine that can do the work it requires a
// PASS, so a guard that refused everything would fail it; on a machine that
// cannot it requires the refusal.
func TestRunPreflightAgreesWithTheChecker(t *testing.T) {
	opts := Options{VolumeGroup: "vg0"}
	capabilities := requiredCapabilities(opts, PreflightConfigured)
	if len(capabilities) == 0 {
		t.Fatal("the default configuration derived no capabilities, so this test would prove nothing")
	}

	oracle := preflight.Check(context.Background(), capabilities...)
	got := runPreflight(opts, PreflightConfigured)

	if (oracle == nil) != (got == nil) {
		t.Fatalf("the checker says %v and runPreflight says %v; they must agree", oracle, got)
	}
	if got != nil && !errors.Is(got, preflight.ErrUnavailable) {
		t.Errorf("runPreflight = %v, want a failure matching preflight.ErrUnavailable", got)
	}
}

// TestNewRunsTheStartupPrivilegeChecks is the guard at the point that matters:
// a Provider must not be constructed in a deployment that cannot serve it.
//
// It is written against the checker rather than against a fixed expectation, so
// it asserts the real thing on a privileged host and on an unprivileged one.
// Delete the runPreflight call from New and this test fails on any machine that
// cannot do device-mapper.
func TestNewRunsTheStartupPrivilegeChecks(t *testing.T) {
	opts := Options{VolumeGroup: "vg0"}
	oracle := preflight.Check(context.Background(), requiredCapabilities(opts, PreflightConfigured)...)

	provider, err := New(opts)

	if oracle == nil {
		if err != nil {
			t.Fatalf("this machine can do the work and New refused anyway: %v", err)
		}
		if provider == nil {
			t.Fatal("New returned no provider and no error")
		}
		return
	}

	if err == nil {
		t.Fatalf("this machine cannot do the work (%v) and New returned a provider anyway", oracle)
	}
	if provider != nil {
		t.Error("New returned a provider alongside the refusal")
	}
	if !errors.Is(err, preflight.ErrUnavailable) {
		t.Errorf("New = %v, want a failure matching preflight.ErrUnavailable", err)
	}
}

// TestNewSucceedsWithEverySeamInjected is the other side of the guard, and it
// is deterministic on every machine: a provider that will not touch the kernel
// is not refused for the kernel's sake.
func TestNewSucceedsWithEverySeamInjected(t *testing.T) {
	runner := newFakeRunner()
	provider, err := New(Options{
		VolumeGroup: "vg0",
		Runner:      runner,
		Mounter:     runner,
		luks:        runner,
		LockDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New with every seam injected: %v", err)
	}
	if provider == nil {
		t.Fatal("New returned no provider and no error")
	}
}

// TestNewWithPreflightOffSkipsTheChecks covers the explicit opt-out, which has
// to work on a machine that would otherwise be refused — that is the whole
// reason it exists.
func TestNewWithPreflightOffSkipsTheChecks(t *testing.T) {
	provider, err := New(Options{VolumeGroup: "vg0", Preflight: PreflightOff, LockDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New with PreflightOff: %v", err)
	}
	if provider == nil {
		t.Fatal("New returned no provider and no error")
	}
}

// TestNewValidatesBeforeItProbes keeps a configuration mistake being reported
// as a configuration mistake. An operator who misspelled a volume group should
// not be told to grant CAP_SYS_ADMIN.
func TestNewValidatesBeforeItProbes(t *testing.T) {
	cases := map[string]Options{
		"a hostile volume group":     {VolumeGroup: "vg0; rm -rf /"},
		"encryption with no key":     {VolumeGroup: "vg0", Encrypted: true},
		"an out-of-range CoW factor": {VolumeGroup: "vg0", SnapshotCoWPercent: 500},
	}

	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(opts)
			if !errors.Is(err, common.ErrInvalidArgument) {
				t.Fatalf("New = %v, want common.ErrInvalidArgument rather than a privilege refusal", err)
			}
			if errors.Is(err, preflight.ErrUnavailable) {
				t.Error("a bad configuration was reported as a missing capability")
			}
		})
	}
}

// TestPreflightSettingSpellings covers the settings parser in both directions,
// since "off" is the value that turns the guard back into the silent failure it
// replaced and must not be reachable by accident.
func TestPreflightSettingSpellings(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		for spelling, want := range preflightModeNames {
			t.Run(spelling, func(t *testing.T) {
				// Every accepted spelling is exercised through NewFromSettings
				// with the seams left real, so only "off" can succeed on an
				// unprivileged machine. The mode itself is checked directly.
				if got := preflightModeNames[spelling]; got != want {
					t.Fatalf("mode for %q = %v, want %v", spelling, got, want)
				}
				_, err := NewFromSettings(map[string]string{
					SettingVolumeGroup: "vg0",
					SettingPreflight:   spelling,
				})
				if err != nil && !errors.Is(err, preflight.ErrUnavailable) {
					t.Fatalf("NewFromSettings(preflight=%q) = %v, want either success or a privilege refusal", spelling, err)
				}
				if want == PreflightOff && err != nil {
					t.Errorf(`NewFromSettings(preflight="off") = %v, want success`, err)
				}
			})
		}
	})

	t.Run("rejected", func(t *testing.T) {
		for _, spelling := range []string{"none", "false", "disabled", "OFF", "0"} {
			t.Run(spelling, func(t *testing.T) {
				_, err := NewFromSettings(map[string]string{
					SettingVolumeGroup: "vg0",
					SettingPreflight:   spelling,
				})
				if !errors.Is(err, common.ErrInvalidArgument) {
					t.Fatalf("NewFromSettings(preflight=%q) = %v, want common.ErrInvalidArgument", spelling, err)
				}
				if !strings.Contains(err.Error(), "configured") {
					t.Errorf("the rejection does not list the accepted spellings: %v", err)
				}
			})
		}
	})

	t.Run("an empty value is the default rather than off", func(t *testing.T) {
		// NewFromSettings ignores an empty value, so the zero mode applies.
		opts := Options{}
		if opts.Preflight != PreflightConfigured {
			t.Errorf("the zero PreflightMode is %v, want PreflightConfigured", opts.Preflight)
		}
		_, err := NewFromSettings(map[string]string{
			SettingVolumeGroup: "vg0",
			SettingPreflight:   "",
		})
		oracle := preflight.Check(context.Background(), requiredCapabilities(Options{VolumeGroup: "vg0"}, PreflightConfigured)...)
		if (oracle == nil) != (err == nil) {
			t.Errorf("an empty preflight setting behaved differently from the default: %v vs %v", err, oracle)
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

// TestNewFromSettingsRunsThePreflight is the factory-facing half: the checks
// reach the path an operator's configuration actually takes, not only the
// programmatic constructor.
func TestNewFromSettingsRunsThePreflight(t *testing.T) {
	oracle := preflight.Check(context.Background(),
		requiredCapabilities(Options{VolumeGroup: "vg0"}, PreflightConfigured)...)

	_, err := NewFromSettings(map[string]string{SettingVolumeGroup: "vg0"})

	if (oracle == nil) != (err == nil) {
		t.Fatalf("NewFromSettings says %v and the checker says %v; they must agree", err, oracle)
	}
	if err != nil && !errors.Is(err, preflight.ErrUnavailable) {
		t.Errorf("NewFromSettings = %v, want a failure matching preflight.ErrUnavailable", err)
	}
}
