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
	"sort"

	"github.com/jeremyhahn/go-blockstore/internal/posture"
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// Posture is what this provider checks and what it does not, by name; the type is shared with pkg/local.
type Posture = posture.Posture

// GuardStatus is one guard's configured state.
type GuardStatus = posture.GuardStatus

// guardNames maps a preflight capability to its report name; unmapped ones are reported under their own name. The keyring appears only when encrypting.
var guardNames = map[preflight.Capability]string{
	preflight.CapabilityDeviceMapper:  "device-mapper access",
	preflight.CapabilityMount:         "mount(2) privilege",
	preflight.CapabilityNetAdmin:      "net-admin privilege",
	preflight.CapabilityDRBDControl:   "DRBD control interface",
	preflight.CapabilityKernelKeyring: "kernel keyring",
}

// Posture reports what this provider checks and what it does not, derived from its configuration and New's own capability derivation.
func (p *Provider) Posture() Posture {
	report := Posture{Component: "drbd"}

	checked := make(map[preflight.Capability]struct{})
	// The same arguments New passes to runPreflight; keep them identical.
	for _, capability := range requiredCapabilities(p.injected, p.cfg.Encrypted, p.cfg.Preflight) {
		checked[capability] = struct{}{}
	}

	all := make([]preflight.Capability, 0, len(guardNames))
	for capability := range guardNames {
		all = append(all, capability)
	}
	sort.Slice(all, func(i, j int) bool { return guardNames[all[i]] < guardNames[all[j]] })

	for _, capability := range all {
		_, active := checked[capability]
		report.Guards = append(report.Guards, GuardStatus{
			Name:   guardNames[capability],
			Active: active,
			Detail: preflightDetail(active),
		})
	}

	report.Guards = append(report.Guards,
		GuardStatus{
			Name:   "mount propagation",
			Active: p.cfg.MountPropagation == MountPropagationShared,
			Detail: propagationDetail(p.cfg.MountPropagation),
		},
		GuardStatus{
			Name:   "peer authentication",
			Active: p.secrets != nil,
			Detail: peerAuthDetail(p.secrets != nil),
		},
		// A mitigation, on or off, not a check; see Config.WipeOnDelete.
		GuardStatus{
			Name:   "delete-time wipe",
			Active: p.cfg.WipeOnDelete,
			Detail: wipeDetail(p.cfg.WipeOnDelete),
		},
	)
	return report
}

// preflightDetail says why a startup check is or is not running.
func preflightDetail(active bool) string {
	if active {
		return "verified at startup"
	}
	return "not required by this configuration, or preflight is off (" + SettingPreflight + ")"
}

// propagationDetail says what the propagation guard will do, or what turns it
// on. The off case names the setting, because the operator who most needs to
// read this line is the one who did not know it existed.
func propagationDetail(policy MountPropagationPolicy) string {
	if policy == MountPropagationShared {
		return "each mount must be visible outside this namespace, or Mount refuses"
	}
	return "a mount invisible to another namespace will NOT be refused; set " +
		SettingMountPropagation + "=shared where a workload elsewhere consumes these mounts"
}

// peerAuthDetail says whether the replication link authenticates its peer.
func peerAuthDetail(haveSecret bool) string {
	if haveSecret {
		return "resources are provisioned with a shared secret DRBD authenticates the peer with"
	}
	return "NO PEER AUTHENTICATION — " + SettingAllowUnauthenticatedPeers +
		" is set, so anything that can reach the replication port can connect; set " +
		SettingReplicationSecretFile + " or inject a SecretProvider"
}

// wipeDetail says what a delete leaves behind.
func wipeDetail(wipe bool) string {
	if wipe {
		return "a volume's backing device is zero-filled before it is removed"
	}
	return "an unencrypted volume's data REMAINS READABLE in the volume group's free extents after Delete " +
		"on media that does not discard; set " + SettingWipeOnDelete + "=true to pay for the zero-fill"
}
