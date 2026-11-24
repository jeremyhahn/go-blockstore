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

// Package posture reports which guards a provider checks and which it does not, for the caller to print at startup.
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

// String renders the posture, one guard per line; NOT CHECKED is upper case so gaps stand out.
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
