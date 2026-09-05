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

// Posture is what this provider checks and what it does not, by name.
//
// It is the type pkg/local reports, not a second one: a component that builds
// whichever provider a deployment configured prints one posture with one
// renderer, and a guard present in one provider and absent in the other shows up
// as a missing LINE rather than as a different type. See internal/posture.
type Posture = posture.Posture

// GuardStatus is one guard's configured state.
type GuardStatus = posture.GuardStatus

// guardNames maps a preflight capability onto the words this report uses for
// it. A capability absent from the map is reported under its own name rather
// than dropped: an unnamed guard is still a guard, and omitting it would be the
// silence this type exists to remove.
//
// The set is this provider's, not pkg/local's — net-admin and drbd-control are
// required here and have no analog there, and the kernel keyring is required
// there and never touched here. See requiredCapabilities, which measured it.
var guardNames = map[preflight.Capability]string{
	preflight.CapabilityDeviceMapper: "device-mapper access",
	preflight.CapabilityMount:        "mount(2) privilege",
	preflight.CapabilityNetAdmin:     "net-admin privilege",
	preflight.CapabilityDRBDControl:  "DRBD control interface",
}

// Posture reports what this provider checks and what it does not.
//
// It exists because an off guard is invisible. The startup capability checks
// announce themselves by refusing construction, so an operator learns about them
// the moment they are wrong; the mount-propagation guard added in #40 defaults
// to OFF, so without this an operator who never enabled it sees exactly what an
// operator whose cluster does not need it sees — nothing at all. Off-by-default
// with no way to see it is not a conservative default, it is a silently absent
// guard, which is the defect the guard was written to remove one level up.
//
// It is derived from the configuration the provider was built with and from
// which seams were injected, so it describes THIS Provider rather than what the
// package can do in general. The capability half is derived by the same function
// New runs, so the report cannot claim a check New did not make.
func (p *Provider) Posture() Posture {
	report := Posture{Component: "drbd"}

	checked := make(map[preflight.Capability]struct{})
	for _, capability := range requiredCapabilities(p.injected, p.cfg.Preflight) {
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
		// Reported as a mitigation that is on or off rather than as a check,
		// because that is what it is: nothing verifies afterwards that the
		// extents were wiped. Its absence is the one line here an operator is
		// most likely to want and least likely to go looking for — see
		// Config.WipeOnDelete for what an unwiped delete leaves behind.
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
//
// New already refuses to build a provider with neither a secret nor the explicit
// acknowledgement, so the off case here is always a deployment that ASKED for
// it — which is exactly the choice worth restating once at startup.
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
