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
	"sort"

	"github.com/jeremyhahn/go-blockstore/internal/posture"
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// Posture is what this provider checks and what it does not, by name.
//
// It exists because a guard that is off is invisible: an operator who never
// enabled the mount-propagation guard sees exactly what an operator whose
// deployment does not need it sees — nothing. Reporting a guard as CHECKED or
// as NOT CHECKED, both kinds in the same list, is what makes the third state
// sayable. See internal/posture, whose type this is: pkg/drbd reports the same
// shape, and a caller holding either provider should not need two renderers.
type Posture = posture.Posture

// GuardStatus is one guard's configured state.
type GuardStatus = posture.GuardStatus

// guardNames maps a preflight capability onto the words this report uses for
// it. A capability absent from the map is reported under its own name rather
// than dropped: an unnamed guard is still a guard, and omitting it would be the
// silence this type exists to remove.
var guardNames = map[preflight.Capability]string{
	preflight.CapabilityDeviceMapper:  "device-mapper access",
	preflight.CapabilityMount:         "mount(2) privilege",
	preflight.CapabilityKernelKeyring: "kernel keyring",
}

// Posture reports what this provider checks and what it does not.
//
// It is derived from the configuration the provider was built with, so it
// describes this Provider rather than what the package can do in general.
func (p *Provider) Posture() Posture {
	report := Posture{Component: "local"}

	// The startup checks, named individually: "preflight ran" says nothing
	// about WHICH capabilities it covered, and the mode makes that vary.
	checked := make(map[preflight.Capability]struct{}, len(p.preflightChecked))
	for _, capability := range p.preflightChecked {
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
			Active: p.mountPropagation == MountPropagationShared,
			Detail: propagationDetail(p.mountPropagation),
		},
		GuardStatus{
			Name:   "key-path containment",
			Active: p.keyFile != "",
			Detail: keyPathDetail(p.keyFile != "", p.keyProvider != nil),
		},
		// The orphan inspection is always available and never acts, so it is
		// reported as what it is rather than as on or off. Saying "checked"
		// would imply something watches continuously — it runs when a component
		// calls it — and omitting it would leave an operator to discover by
		// reading the code that nothing cleans up an abandoned mapping.
		GuardStatus{
			Name:   "orphaned dm-crypt mappings",
			Active: false,
			Detail: "REPORTED, NEVER REMOVED — InspectMappings names what this provider owns and " +
				"cannot account for; nothing here tears one down, and a component that acts on a finding owns that decision",
		},
		// Reported beside the inspection rather than inside it, because it is
		// what decides how much of the report is worth anything. The oracle is
		// injected and defaults to absent, which makes it the second guard in
		// this list that an operator can leave off without ever seeing a symptom
		// — and the symptom, when it comes, is a report full of "live" lines
		// over mappings nothing has held for weeks.
		GuardStatus{
			Name:   "attachment liveness",
			Active: p.liveness != nil,
			Detail: livenessDetail(p.liveness != nil),
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

// keyPathDetail says whether the key file can be checked against the paths this
// provider hands over, and why not when it cannot.
//
// The distinction is not on/off, it is KNOWABLE or not. A KeyProvider supplied
// as a func closes over whatever it reads, so this package cannot see a path to
// check — and reporting that as an unchecked guard would suggest a setting
// somebody could turn on, when the honest statement is that the check does not
// apply to how this provider was built.
func keyPathDetail(haveKeyPath, haveProvider bool) string {
	switch {
	case haveKeyPath:
		return "the key file is refused if it resolves inside any path handed to a workload, symlinks followed"
	case haveProvider:
		return "NOT APPLICABLE — the key comes from a KeyProvider this package cannot see a path in; " +
			"use " + SettingLUKSKeyFile + " to have the containment checked"
	default:
		return "no key material is configured"
	}
}

// livenessDetail says what the liveness oracle is asked, or what is not asked
// without one.
//
// The absent case spells out the CONSEQUENCE and not merely the configuration,
// because the operator who most needs this line is the one who does not know
// the question exists: "no oracle" reads as a feature nobody turned on, while
// "a mapping made on this boot is reported as live whether or not anything
// still holds it" reads as the report being partly blind, which is what it is.
func livenessDetail(configured bool) string {
	if configured {
		return "a mapping made on the boot that is still running is put to the injected LivenessOracle; " +
			"an oracle that cannot answer is reported as " + string(VerdictLivenessUnknown) +
			", never as live and never as an orphan"
	}
	return "NO ORACLE — a mapping made on this boot is reported as " + string(VerdictLive) +
		" whether or not whatever attached it still exists, so an init container that attached, " +
		"mounted and exited leaves a mapping nothing here can call abandoned; set Options.LivenessOracle " +
		"to have the question asked (issue #41)"
}
