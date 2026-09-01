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

//go:build !linux

package preflight

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestEveryProbeRefusesOnThisPlatform is the fail-closed rule where the kernel
// facilities do not exist at all.
//
// The package compiles on darwin and windows so the tree can be built and
// vetted there, matching pkg/local. What it must never do is answer "the
// capability is available" — a preflight that passes where device-mapper does
// not exist lies in the one direction that costs something.
func TestEveryProbeRefusesOnThisPlatform(t *testing.T) {
	for capability, probe := range platformProbes() {
		t.Run(string(capability), func(t *testing.T) {
			err := probe(context.Background())
			if err == nil {
				t.Fatalf("the %s probe passed on a platform with no such facility", capability)
			}
			if !errors.Is(err, ErrPlatformUnsupported) {
				t.Errorf("probe = %v, want ErrPlatformUnsupported", err)
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Error("the refusal does not match the root sentinel")
			}

			var typed *CapabilityError
			if !errors.As(err, &typed) {
				t.Fatalf("probe returned %T, want a *CapabilityError", err)
			}
			if typed.Capability != capability {
				t.Errorf("Capability = %q, want %q", typed.Capability, capability)
			}
			if !strings.Contains(typed.Probe, string(capability)) {
				t.Errorf("Probe does not name the capability: %q", typed.Probe)
			}
			if typed.Remedy() == "" {
				t.Error("the refusal carries no remedy")
			}
		})
	}
}

// TestCheckRefusesEverythingOnThisPlatform ties the package entry point to the
// same answer, so a caller that never touches a probe directly still cannot get
// a false pass here.
func TestCheckRefusesEverythingOnThisPlatform(t *testing.T) {
	err := Check(context.Background(),
		CapabilityDeviceMapper, CapabilityMount, CapabilityKernelKeyring)
	if err == nil {
		t.Fatal("Check passed on a platform with none of these facilities")
	}
	if !errors.Is(err, ErrPlatformUnsupported) {
		t.Errorf("Check = %v, want ErrPlatformUnsupported", err)
	}
}
