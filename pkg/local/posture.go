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
	"strings"

	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// Posture is what this provider checks and what it does not, by name.
//
// It exists because a guard that is off is invisible. The startup privilege
// checks announce themselves by refusing construction, so an operator learns
// about them the moment they are wrong; the mount-propagation guard defaults to
// off, so an operator who never enabled it sees exactly what an operator whose
// deployment does not need it sees — nothing. That is the failure the guard was
// added to remove, one level up: not a wrong answer, an absent one.
//
// So the third state is made sayable. A guard is reported as CHECKED or as NOT
// CHECKED, always both kinds in the same list, rather than the unchecked ones
// being omitted and inferred. An operator reading
//
//	mount propagation: NOT CHECKED
//
// beside three that are checked can act on it. An operator reading a list of
// three cannot tell it from a list of four.
//
// This library writes nothing to a log — every other result it produces is a
// returned value — so this is returned too, and the component that builds a
// Provider is expected to print it once at startup, next to where it reports a
// preflight failure.
type Posture struct {
	// Guards is every guard this provider knows about, checked or not, in a
	// stable order.
	Guards []GuardStatus
}

// GuardStatus is one guard's configured state.
type GuardStatus struct {
	// Name is the guard, in the words an operator would use.
	Name string

	// Active is whether this provider will check it.
	Active bool

	// Detail says what turns it on, or what it will do, in one clause. It is
	// the part that makes the line actionable rather than merely informative.
	Detail string
}

// String renders the whole posture, one guard per line, for a component to
// print at startup.
//
// NOT CHECKED is upper case and CHECKED is not, deliberately: the eye finds the
// gaps in a list of a dozen lines, which is the reading this exists to support.
func (p Posture) String() string {
	var b strings.Builder
	b.WriteString("go-blockstore/local guards:")
	for _, g := range p.Guards {
		b.WriteString("\n  ")
		b.WriteString(g.Name)
		b.WriteString(": ")
		if g.Active {
			b.WriteString("checked")
		} else {
			b.WriteString("NOT CHECKED")
		}
		if g.Detail != "" {
			b.WriteString(" — ")
			b.WriteString(g.Detail)
		}
	}
	return b.String()
}

// Unchecked returns the guards that are off, which is the part worth acting on.
func (p Posture) Unchecked() []GuardStatus {
	var off []GuardStatus
	for _, g := range p.Guards {
		if !g.Active {
			off = append(off, g)
		}
	}
	return off
}

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
	posture := Posture{}

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
		posture.Guards = append(posture.Guards, GuardStatus{
			Name:   guardNames[capability],
			Active: active,
			Detail: preflightDetail(active),
		})
	}

	posture.Guards = append(posture.Guards, GuardStatus{
		Name:   "mount propagation",
		Active: p.mountPropagation == MountPropagationShared,
		Detail: propagationDetail(p.mountPropagation),
	})
	return posture
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
