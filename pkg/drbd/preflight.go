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
}

// requiredCapabilities derives what this configuration will actually ask the
// kernel to do.
//
// # This set is MEASURED, not copied from pkg/local
//
// The two providers overlap and they are not the same, and taking the local
// provider's list would have been a guard that passes for the wrong reason.
// Measured 2026-09-02 against this package's own dispatch and the kernel:
//
//   - CapabilityNetAdmin is REQUIRED HERE AND NOT THERE. DRBD's control path is
//     drbdsetup speaking generic netlink to the drbd kernel module, whose
//     administrative operations are gated on CAP_NET_ADMIN. That is a different
//     bit from CAP_SYS_ADMIN and neither confers the other, so a container
//     granted only the device-mapper privilege drives LVM perfectly and fails at
//     the first resource up.
//   - CapabilityDRBDControl is required here and has no analog there. It is
//     not a privilege: the module has to be loaded on the node.
//   - CapabilityKernelKeyring is NOT required here, though pkg/local needs it
//     whenever it handles encrypted volumes. This package performs no LUKS
//     operations at all — grep the package: it has no key-derivation, no
//     dm-crypt mapping and no keyring use. Its secret is a DRBD shared secret
//     for peer authentication, which never enters the kernel keyring. Asking for
//     a capability this provider does not exercise would make a correctly
//     configured node refuse to start.
//   - CapabilityDeviceMapper and CapabilityMount ARE shared: volumes are LVM
//     logical volumes underneath, and the provider mounts filesystems.
func requiredCapabilities(seams injectedSeams, mode PreflightMode) []preflight.Capability {
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

	return capabilities
}

// runPreflight verifies the deployment before New returns a Provider.
//
// It runs after the configuration has been parsed and validated, so a caller
// who got the settings wrong hears about the settings rather than about the
// node's capabilities — and before any volume work, so a misconfigured
// deployment is a refusal to start rather than a failure at the first Provision.
func runPreflight(seams injectedSeams, mode PreflightMode) error {
	capabilities := requiredCapabilities(seams, mode)
	if len(capabilities) == 0 {
		return nil
	}
	return preflight.Check(context.Background(), capabilities...)
}
