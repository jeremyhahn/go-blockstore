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
	"sort"

	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// PreflightMode selects which privilege checks New runs before it hands back a
// Provider. See pkg/local's PreflightMode: same three values, same reasoning,
// a DIFFERENT capability set.
type PreflightMode int

const (
	// PreflightConfigured checks the capabilities this provider's configuration
	// will exercise, for each seam left at its real implementation. Zero value.
	PreflightConfigured PreflightMode = iota

	// PreflightAll checks every capability this provider could need, whatever
	// seams were injected.
	PreflightAll

	// PreflightOff runs no checks. Explicit configuration, never a default.
	PreflightOff
)

// preflightModeNames maps the mode onto its settings spelling.
var preflightModeNames = map[string]PreflightMode{
	"configured": PreflightConfigured,
	"all":        PreflightAll,
	"off":        PreflightOff,
}

// preflightModeSpellings returns the accepted values in a stable order.
func preflightModeSpellings() []string {
	spellings := make([]string, 0, len(preflightModeNames))
	for spelling := range preflightModeNames {
		spellings = append(spellings, spelling)
	}
	sort.Strings(spellings)
	return spellings
}

// injectedSeams records which seams a caller replaced.
type injectedSeams struct {
	runner       bool
	mounter      bool
	mountTable   bool
	blockDevices bool
	luks         bool
}

// requiredCapabilities: NetAdmin, DRBDControl, DeviceMapper and Mount, plus KernelKeyring only when encrypting.
func requiredCapabilities(seams injectedSeams, encrypted bool, mode PreflightMode) []preflight.Capability {
	if mode == PreflightOff {
		return nil
	}
	all := mode == PreflightAll

	var capabilities []preflight.Capability

	// The real CommandRunner drives drbdadm, drbdsetup and the LVM tools. The
	// first two are the netlink control path; all of them are device-mapper
	// underneath.
	if all || !seams.runner {
		capabilities = append(capabilities,
			preflight.CapabilityDeviceMapper,
			preflight.CapabilityNetAdmin,
			preflight.CapabilityDRBDControl,
		)
	}

	// The real Mounter calls mount(2).
	if all || !seams.mounter {
		capabilities = append(capabilities, preflight.CapabilityMount)
	}

	// The kernel keyring is reached only when this provider handles encrypted
	// volumes, and only through the real LUKS backend — a test driving an
	// injected one derives no keys and creates no mappings.
	if all || (!seams.luks && encrypted) {
		capabilities = append(capabilities, preflight.CapabilityKernelKeyring)
	}

	return capabilities
}

// runPreflight verifies the node after configuration is validated and before New returns a Provider.
func runPreflight(seams injectedSeams, encrypted bool, mode PreflightMode) error {
	capabilities := requiredCapabilities(seams, encrypted, mode)
	if len(capabilities) == 0 {
		return nil
	}
	return preflight.Check(context.Background(), capabilities...)
}
