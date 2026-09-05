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

// Package posture is what a provider checks and what it does not, by name.
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
//
// The type is shared across providers rather than declared in each, so a caller
// holding one of several providers can print or inspect its posture without
// knowing which it built. The provider is named in Component rather than in the
// type.
package posture

import "strings"

// Posture is one provider's guards, checked or not.
type Posture struct {
	// Component is the provider this describes, in the words the settings use
	// for it — "local", "drbd". It is what the rendering names, so two
	// providers' postures printed together are still tellable apart.
	Component string

	// Guards is every guard the provider knows about, checked or not, in a
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

// String renders the whole posture, one guard per line, for a component to print
// at startup.
//
// NOT CHECKED is upper case and CHECKED is not, deliberately: the eye finds the
// gaps in a list of a dozen lines, which is the reading this exists to support.
func (p Posture) String() string {
	var b strings.Builder
	b.WriteString("go-blockstore")
	if p.Component != "" {
		b.WriteString("/")
		b.WriteString(p.Component)
	}
	b.WriteString(" guards:")
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
