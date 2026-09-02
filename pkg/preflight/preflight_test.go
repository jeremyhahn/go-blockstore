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

package preflight

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// passingProbe is a probe that reports the capability available.
func passingProbe(calls *int) Probe {
	return func(context.Context) error {
		*calls++
		return nil
	}
}

// failingProbe is a probe that reports a typed failure.
func failingProbe(capability Capability, cause Cause) Probe {
	return func(context.Context) error {
		return &CapabilityError{
			Capability: capability,
			Cause:      cause,
			Probe:      "a probe that always refuses",
			Err:        errors.New("refused"),
		}
	}
}

// TestCheckPassesWhenEveryProbePasses is the happy path: the guard must not
// refuse a deployment that can do the work.
//
// It is half of the two-sided requirement. A guard tested only against broken
// environments passes by refusing everything, which is not a guard.
func TestCheckPassesWhenEveryProbePasses(t *testing.T) {
	deviceMapperCalls, mountCalls, keyringCalls := 0, 0, 0
	checker := New(
		WithProbe(CapabilityDeviceMapper, passingProbe(&deviceMapperCalls)),
		WithProbe(CapabilityMount, passingProbe(&mountCalls)),
		WithProbe(CapabilityKernelKeyring, passingProbe(&keyringCalls)),
	)

	if err := checker.Check(context.Background(),
		CapabilityDeviceMapper, CapabilityMount, CapabilityKernelKeyring); err != nil {
		t.Fatalf("Check over three passing probes: %v", err)
	}
	if deviceMapperCalls != 1 || mountCalls != 1 || keyringCalls != 1 {
		t.Errorf("probe call counts = %d/%d/%d, want 1/1/1", deviceMapperCalls, mountCalls, keyringCalls)
	}
}

// TestCheckReportsEveryFailureRatherThanTheFirst is why the failures are
// joined. A container missing two things is one configuration mistake, and
// reporting them one per restart makes an operator discover them serially.
func TestCheckReportsEveryFailureRatherThanTheFirst(t *testing.T) {
	keyringCalls := 0
	checker := New(
		WithProbe(CapabilityDeviceMapper, failingProbe(CapabilityDeviceMapper, CausePrivilegeMissing)),
		WithProbe(CapabilityMount, failingProbe(CapabilityMount, CauseLSMDenied)),
		WithProbe(CapabilityKernelKeyring, passingProbe(&keyringCalls)),
	)

	err := checker.Check(context.Background(),
		CapabilityDeviceMapper, CapabilityMount, CapabilityKernelKeyring)
	if err == nil {
		t.Fatal("Check succeeded with two failing probes")
	}
	if !errors.Is(err, ErrPrivilegeMissing) {
		t.Errorf("the joined error does not match ErrPrivilegeMissing: %v", err)
	}
	if !errors.Is(err, ErrLSMDenied) {
		t.Errorf("the joined error does not match ErrLSMDenied: %v", err)
	}
	if keyringCalls != 1 {
		t.Errorf("the keyring probe ran %d times, want 1: a failure must not stop the remaining probes", keyringCalls)
	}
}

// TestCheckOverNoCapabilitiesIsAFailure is the fail-closed direction for the
// emptiest possible mistake: a caller whose capability list came out empty must
// not be told its deployment is fine.
func TestCheckOverNoCapabilitiesIsAFailure(t *testing.T) {
	if err := New().Check(context.Background()); !errors.Is(err, ErrNoCapabilities) {
		t.Fatalf("Check with no capabilities = %v, want ErrNoCapabilities", err)
	}
}

// TestCheckRefusesAnUnknownCapability keeps a typo from silently checking
// nothing. It is the same reasoning as the provider rejecting an unrecognized
// settings key.
func TestCheckRefusesAnUnknownCapability(t *testing.T) {
	err := New().Check(context.Background(), Capability("device-maper"))
	if err == nil {
		t.Fatal("Check accepted a capability no probe is registered for")
	}

	var unknown *UnknownCapabilityError
	if !errors.As(err, &unknown) {
		t.Fatalf("Check error = %T (%v), want *UnknownCapabilityError", err, err)
	}
	if unknown.Capability != Capability("device-maper") {
		t.Errorf("Capability = %q, want the misspelling that was passed", unknown.Capability)
	}
	if len(unknown.Known) == 0 {
		t.Error("Known is empty; the error should list what a caller could have meant")
	}
}

// TestCheckCollapsesDuplicatesAndOrdersTheResult keeps the same
// misconfiguration producing the same message every time, which is what makes a
// refusal searchable in an operator's logs.
func TestCheckCollapsesDuplicatesAndOrdersTheResult(t *testing.T) {
	calls := 0
	checker := New(WithProbe(CapabilityMount, passingProbe(&calls)))

	if err := checker.Check(context.Background(), CapabilityMount, CapabilityMount, CapabilityMount); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if calls != 1 {
		t.Errorf("the probe ran %d times for three requests of one capability, want 1", calls)
	}

	failing := New(
		WithProbe(CapabilityMount, failingProbe(CapabilityMount, CauseLSMDenied)),
		WithProbe(CapabilityDeviceMapper, failingProbe(CapabilityDeviceMapper, CausePrivilegeMissing)),
	)
	first := failing.Check(context.Background(), CapabilityMount, CapabilityDeviceMapper)
	second := failing.Check(context.Background(), CapabilityDeviceMapper, CapabilityMount)
	if first.Error() != second.Error() {
		t.Errorf("the same two failures rendered differently depending on argument order:\n%v\n%v", first, second)
	}
	if !strings.HasPrefix(first.Error(), "go-blockstore/preflight: device-mapper") {
		t.Errorf("the joined error does not start with the alphabetically first capability: %v", first)
	}
}

// TestCheckClassifiesAnUnclassifiedProbeFailure is the fail-closed rule for a
// probe that returns a bare error: it must arrive at the caller classified,
// because an unclassified failure has no remedy and cannot be matched.
func TestCheckClassifiesAnUnclassifiedProbeFailure(t *testing.T) {
	sentinel := errors.New("something the probe did not classify")
	checker := New(WithProbe(CapabilityMount, func(context.Context) error { return sentinel }))

	err := checker.Check(context.Background(), CapabilityMount)
	var typed *CapabilityError
	if !errors.As(err, &typed) {
		t.Fatalf("Check error = %T (%v), want it wrapped in a *CapabilityError", err, err)
	}
	if typed.Cause != CauseIndeterminate {
		t.Errorf("Cause = %q, want %q", typed.Cause, CauseIndeterminate)
	}
	if !errors.Is(err, sentinel) {
		t.Error("the original error is not reachable through the wrapper")
	}
}

// TestCheckTreatsANilProbeAsAFailure covers the registration mistake. A
// capability wired up without a probe must not read as a capability that
// passed.
func TestCheckTreatsANilProbeAsAFailure(t *testing.T) {
	checker := New(WithProbe(CapabilityMount, nil))

	err := checker.Check(context.Background(), CapabilityMount)
	if !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("Check over a nil probe = %v, want ErrIndeterminate", err)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Error("the failure does not match the root sentinel ErrUnavailable")
	}
}

// TestCheckTreatsATypedNilProbeResultAsAFailure is a regression test for the
// interface trap: a probe returning a nil *CapabilityError produces a non-nil
// error holding a nil pointer, which is neither a pass nor renderable — it
// panics the first time anything prints it.
//
// It was a real defect in this package, found because the provider tests print
// the error they did not expect.
func TestCheckTreatsATypedNilProbeResultAsAFailure(t *testing.T) {
	checker := New(WithProbe(CapabilityMount, func(context.Context) error {
		var nilTyped *CapabilityError
		return nilTyped
	}))

	err := checker.Check(context.Background(), CapabilityMount)
	if err == nil {
		t.Fatal("Check read a nil *CapabilityError as a capability that passed")
	}
	if !errors.Is(err, ErrIndeterminate) {
		t.Errorf("Check = %v, want ErrIndeterminate", err)
	}
	// Rendering it must not panic, which is the failure the trap produces.
	if msg := err.Error(); msg == "" {
		t.Error("the failure renders as an empty string")
	}
}

// TestCheckPropagatesContextCancellation proves a canceled preflight is not a
// pass. The live probes check the context first for exactly this reason.
func TestCheckPropagatesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	checker := New(WithProbe(CapabilityMount, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return &CapabilityError{
				Capability: CapabilityMount,
				Cause:      CauseIndeterminate,
				Probe:      "starting",
				Err:        err,
			}
		}
		return nil
	}))

	err := checker.Check(ctx, CapabilityMount)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Check with a canceled context = %v, want it to carry context.Canceled", err)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Error("a canceled preflight does not match ErrUnavailable, so a caller's catch-all would miss it")
	}
}

// TestNewRegistersEveryKnownCapability checks the live constructor wires a
// probe for each capability this package documents. A capability with no probe
// would be an UnknownCapabilityError at the worst possible moment.
func TestNewRegistersEveryKnownCapability(t *testing.T) {
	known := New().Capabilities()
	want := []Capability{
		CapabilityDeviceMapper,
		CapabilityDRBDControl,
		CapabilityKernelKeyring,
		CapabilityMount,
		CapabilityNetAdmin,
	}

	if len(known) != len(want) {
		t.Fatalf("Capabilities() = %v, want %v", known, want)
	}
	for i := range want {
		if known[i] != want[i] {
			t.Fatalf("Capabilities() = %v, want %v (sorted)", known, want)
		}
	}

	// CapabilityMountPropagation is deliberately absent: it has no startup
	// probe, because there is no mount yet to inspect. Passing it to Check must
	// stay an UnknownCapabilityError rather than quietly checking nothing.
	for _, c := range known {
		if c == CapabilityMountPropagation {
			t.Error("mount-propagation has a registered probe; it cannot be established at startup")
		}
	}
}

// TestWithProbeReplacesRatherThanAdds checks the option overrides the live
// probe for a capability that already has one, which is what makes the refusal
// paths testable at all.
func TestWithProbeReplacesRatherThanAdds(t *testing.T) {
	calls := 0
	checker := New(WithProbe(CapabilityDeviceMapper, passingProbe(&calls)))

	if err := checker.Check(context.Background(), CapabilityDeviceMapper); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if calls != 1 {
		t.Fatalf("the replacement probe ran %d times, want 1 — the live probe was used instead", calls)
	}
	// Replacing must REPLACE, not add: the inventory is whatever the live
	// constructor registers, unchanged.
	if got, want := len(checker.Capabilities()), len(New().Capabilities()); got != want {
		t.Errorf("Capabilities() has %d entries, want %d: replacing must not add one", got, want)
	}
}

// TestPackageCheckUsesTheLiveProbes ties the package-level entry point to the
// live implementation, so a caller that never constructs a Checker gets the
// real checks.
//
// It asserts the SHAPE of the answer rather than a specific outcome, because
// the outcome legitimately depends on the machine. The outcome itself is
// asserted against the environment in probe_linux_test.go.
func TestPackageCheckUsesTheLiveProbes(t *testing.T) {
	err := Check(context.Background(), CapabilityDeviceMapper, CapabilityMount, CapabilityKernelKeyring)
	if err == nil {
		return // this machine can do all three; nothing further to assert here
	}

	var typed *CapabilityError
	if !errors.As(err, &typed) {
		t.Fatalf("Check returned %T (%v); every failure must be a *CapabilityError", err, err)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Error("the failure does not match the root sentinel, so a catch-all would miss it")
	}
}
