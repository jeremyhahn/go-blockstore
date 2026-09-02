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
	"strings"
	"testing"
)

// TestPostureNamesTheGuardThatIsOff is the whole point: a guard that is off has
// to be SAID, not omitted. An operator reading a list of the guards that are on
// cannot tell it from a complete list.
func TestPostureNamesTheGuardThatIsOff(t *testing.T) {
	p := newTestProvider(t, newFakeRunner())

	posture := p.Posture()
	if len(posture.Guards) == 0 {
		t.Fatal("the posture names no guards at all")
	}

	rendered := posture.String()
	if !strings.Contains(rendered, "mount propagation: NOT CHECKED") {
		t.Errorf("the posture does not say the propagation guard is off:\n%s", rendered)
	}
	// And it says what to do about it, because the operator who most needs this
	// line is the one who did not know the setting existed.
	if !strings.Contains(rendered, SettingMountPropagation+"=shared") {
		t.Errorf("the posture does not name the setting that turns it on:\n%s", rendered)
	}
}

// TestPostureReportsAnEnabledGuardAsChecked is the other half — the report has
// to distinguish the states, or it is decoration.
func TestPostureReportsAnEnabledGuardAsChecked(t *testing.T) {
	p := newTestProvider(t, newFakeRunner(), requireShared)

	rendered := p.Posture().String()
	if !strings.Contains(rendered, "mount propagation: checked") {
		t.Errorf("an enabled guard is not reported as checked:\n%s", rendered)
	}
	if strings.Contains(rendered, "mount propagation: NOT CHECKED") {
		t.Errorf("an enabled guard is also reported as unchecked:\n%s", rendered)
	}
}

// TestPostureNamesEveryStartupCapability covers the other kind of silence:
// "preflight ran" says nothing about WHICH capabilities it covered, and the
// mode makes that vary.
func TestPostureNamesEveryStartupCapability(t *testing.T) {
	p := newTestProvider(t, newFakeRunner())

	rendered := p.Posture().String()
	for _, want := range []string{"device-mapper access", "mount(2) privilege", "kernel keyring"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the posture does not mention %q:\n%s", want, rendered)
		}
	}
}

// TestPostureReflectsTheConfiguration checks the report is derived rather than
// fixed. A provider driven entirely through injected seams performs no
// privileged operation, so its startup checks are correctly absent — and that
// absence has to show up as NOT CHECKED rather than as a shorter list.
func TestPostureReflectsTheConfiguration(t *testing.T) {
	injected := newTestProvider(t, newFakeRunner()).Posture()

	real, err := New(Options{VolumeGroup: "vg0", Preflight: PreflightOff, LockDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if len(injected.Guards) != len(real.Posture().Guards) {
		t.Errorf("the two postures name different numbers of guards (%d and %d); the list must be complete either way",
			len(injected.Guards), len(real.Posture().Guards))
	}
	if len(real.Posture().Unchecked()) != len(real.Posture().Guards) {
		t.Error("preflight off should leave every startup guard unchecked")
	}
}

// TestUncheckedIsTheActionablePart pins the accessor a component would use to
// decide whether to shout, rather than re-parsing the rendered string.
func TestUncheckedIsTheActionablePart(t *testing.T) {
	on := newTestProvider(t, newFakeRunner(), requireShared)
	for _, g := range on.Posture().Unchecked() {
		if g.Name == "mount propagation" {
			t.Error("an enabled guard is listed as unchecked")
		}
	}

	off := newTestProvider(t, newFakeRunner())
	var found bool
	for _, g := range off.Posture().Unchecked() {
		if g.Name == "mount propagation" {
			found = true
			if g.Detail == "" {
				t.Error("the unchecked guard carries no detail, so the report is not actionable")
			}
		}
	}
	if !found {
		t.Error("the disabled guard is not in Unchecked()")
	}
}

// TestPostureNamesTheOrphanInspection covers the guard that never acts.
//
// Reporting it as "checked" would imply something watches continuously, and
// omitting it would leave an operator to discover by reading the code that
// nothing cleans up an abandoned mapping. It is named, and the line says which
// of those it is.
func TestPostureNamesTheOrphanInspection(t *testing.T) {
	rendered := newTestProvider(t, newFakeRunner()).Posture().String()

	if !strings.Contains(rendered, "orphaned dm-crypt mappings") {
		t.Errorf("the posture does not mention the orphan inspection:\n%s", rendered)
	}
	for _, want := range []string{"REPORTED, NEVER REMOVED", "#41"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the posture does not say %q:\n%s", want, rendered)
		}
	}
}
