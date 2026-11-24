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

import "context"

// DeviceMapperControl is the path the device-mapper control node has on Linux.
// It is declared here too so that documentation and error text compile
// everywhere, not because anything on this platform can open it.
const DeviceMapperControl = "/dev/mapper/control"

// platformProbes returns probes that refuse on platforms without device-mapper and kernel keyrings.
func platformProbes() map[Capability]Probe {
	probes := map[Capability]Probe{
		CapabilityDeviceMapper:  unsupportedProbe(CapabilityDeviceMapper, "device-mapper exists only in the Linux kernel"),
		CapabilityMount:         unsupportedProbe(CapabilityMount, "the mount(2) semantics this stack relies on exist only on Linux"),
		CapabilityKernelKeyring: unsupportedProbe(CapabilityKernelKeyring, "the kernel keyring syscalls exist only on Linux"),
	}
	for capability, why := range platformExtras {
		probes[capability] = unsupportedProbe(capability, why)
	}
	return probes
}

// unsupportedProbe builds a probe that always refuses, naming why.
func unsupportedProbe(capability Capability, why string) Probe {
	return func(context.Context) error {
		return &CapabilityError{
			Capability: capability,
			Cause:      CausePlatformUnsupported,
			Probe:      "checking " + string(capability) + " on this platform: " + why,
		}
	}
}

// The replicated backend's capabilities are Linux-only and refuse here too.
func init() {
	platformExtras = map[Capability]string{
		CapabilityNetAdmin:    "CAP_NET_ADMIN is a Linux capability",
		CapabilityDRBDControl: "DRBD is a Linux kernel module reached over generic netlink",
	}
}

// platformExtras is merged into platformProbes.
var platformExtras map[Capability]string
