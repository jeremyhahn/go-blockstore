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

// TestCapabilityErrorRendersEverythingAnOperatorNeeds checks the message
// carries all four parts plus the remedy, because this string is very often the
// only artifact anybody sees of a crashed container.
func TestCapabilityErrorRendersEverythingAnOperatorNeeds(t *testing.T) {
	err := &CapabilityError{
		Capability: CapabilityKernelKeyring,
		Cause:      CauseSyscallBlocked,
		Probe:      "adding a throwaway key",
		Err:        errors.New("operation not permitted"),
	}

	msg := err.Error()
	for _, want := range []string{
		"kernel-keyring",
		"adding a throwaway key",
		"operation not permitted",
		"syscall-blocked",
		"CAP_SYS_ADMIN does NOT lift a seccomp denial",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message is missing %q:\n%s", want, msg)
		}
	}
}

// TestCapabilityErrorRendersWithoutAnUnderlyingError covers the structural
// refusals — an unsupported platform has no errno — which must not render as a
// dangling colon or panic.
func TestCapabilityErrorRendersWithoutAnUnderlyingError(t *testing.T) {
	err := &CapabilityError{
		Capability: CapabilityMount,
		Cause:      CausePlatformUnsupported,
		Probe:      "checking mount on this platform",
	}

	msg := err.Error()
	if strings.Contains(msg, ": [") {
		t.Errorf("the message has an empty error slot:\n%s", msg)
	}
	if !strings.Contains(msg, "platform-unsupported") {
		t.Errorf("the message does not name the cause:\n%s", msg)
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap returned something for an error with no cause underneath")
	}
}

// TestCapabilityErrorUnwrapsToTheKernelsAnswer keeps errno matching working
// through the wrapper.
func TestCapabilityErrorUnwrapsToTheKernelsAnswer(t *testing.T) {
	underlying := errors.New("the kernel said no")
	err := &CapabilityError{Capability: CapabilityMount, Cause: CausePrivilegeMissing, Probe: "p", Err: underlying}

	if !errors.Is(err, underlying) {
		t.Error("the underlying error is not reachable with errors.Is")
	}
	if !errors.Is(err.Unwrap(), underlying) {
		t.Error("Unwrap did not return the underlying error")
	}
}

// TestCapabilityErrorMatchesItsCauseSentinelAndTheRoot is the matching contract
// callers write branches against: one sentinel per cause, and one root that
// matches everything.
func TestCapabilityErrorMatchesItsCauseSentinelAndTheRoot(t *testing.T) {
	for cause, sentinel := range causeSentinels {
		t.Run(string(cause), func(t *testing.T) {
			err := &CapabilityError{Capability: CapabilityMount, Cause: cause, Probe: "p"}

			if !errors.Is(err, sentinel) {
				t.Errorf("a %s failure does not match its own sentinel", cause)
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Errorf("a %s failure does not match the root ErrUnavailable", cause)
			}
			for otherCause, other := range causeSentinels {
				if otherCause == cause {
					continue
				}
				if errors.Is(err, other) {
					t.Errorf("a %s failure also matches the %s sentinel; the branches would collide", cause, otherCause)
				}
			}
		})
	}
}

// TestCapabilityErrorWithAnUnmappedCauseStillMatchesTheRoot is the fail-closed
// direction for a cause nobody has wired a sentinel for: it must still reach a
// caller's catch-all rather than matching nothing.
func TestCapabilityErrorWithAnUnmappedCauseStillMatchesTheRoot(t *testing.T) {
	err := &CapabilityError{Capability: CapabilityMount, Cause: Cause("invented"), Probe: "p"}

	if !errors.Is(err, ErrUnavailable) {
		t.Error("a failure with an unmapped cause does not match ErrUnavailable")
	}
	if errors.Is(err, ErrPrivilegeMissing) {
		t.Error("a failure with an unmapped cause matched a specific sentinel")
	}
}

// TestRemedyIsSpecificWhereThereIsASpecificAnswer checks the per-capability
// remedy wins over the per-cause fallback, since the specific one names the
// actual flag.
func TestRemedyIsSpecificWhereThereIsASpecificAnswer(t *testing.T) {
	specific := (&CapabilityError{Capability: CapabilityDeviceMapper, Cause: CauseDeviceMissing}).Remedy()
	if !strings.Contains(specific, "--device /dev/mapper/control") {
		t.Errorf("the device-mapper/device-missing remedy does not name the flag:\n%s", specific)
	}

	fallback := (&CapabilityError{Capability: CapabilityMount, Cause: CauseDeviceMissing}).Remedy()
	if fallback == specific {
		t.Error("a capability with no specific row got the other capability's remedy")
	}
	if !strings.Contains(fallback, "device node") {
		t.Errorf("the per-cause fallback is not about a device node:\n%s", fallback)
	}
}

// TestRemedyForAnUnknownCauseSaysSoRatherThanGuessing keeps the guard from
// handing an operator a fix for a condition it did not diagnose.
func TestRemedyForAnUnknownCauseSaysSoRatherThanGuessing(t *testing.T) {
	remedy := (&CapabilityError{Capability: CapabilityMount, Cause: Cause("invented")}).Remedy()
	if !strings.Contains(remedy, "not a condition this package knows a fix for") {
		t.Errorf("an unknown cause produced a confident remedy:\n%s", remedy)
	}
}

// TestNoRemedyEverRecommendsPrivileged is the standing rule, enforced over
// every remedy string rather than trusted to review.
//
// --privileged grants every capability, drops the seccomp profile AND the LSM
// confinement, and exposes every host device. It is the answer an operator will
// reach for on their own; nothing here may encourage it, and every mention must
// be a warning against it.
func TestNoRemedyEverRecommendsPrivileged(t *testing.T) {
	check := func(t *testing.T, name, remedy string) {
		t.Helper()
		if strings.Contains(remedy, "--privileged") && !strings.Contains(remedy, "Do NOT use --privileged") {
			t.Errorf("%s mentions --privileged without warning against it:\n%s", name, remedy)
		}
		if strings.Contains(remedy, "seccomp=unconfined") &&
			!strings.Contains(remedy, "narrow") && !strings.Contains(remedy, "NARROW") {
			t.Errorf("%s offers seccomp=unconfined without pointing at a narrow profile first:\n%s", name, remedy)
		}
	}

	for key, remedy := range remedies {
		t.Run(string(key.capability)+"/"+string(key.cause), func(t *testing.T) {
			check(t, "the remedy", remedy)
		})
	}
	for cause, remedy := range causeRemedies {
		t.Run("fallback/"+string(cause), func(t *testing.T) {
			check(t, "the fallback remedy", remedy)
		})
	}
}

// TestPlatformUnsupportedCarriesNoContainerAdvice is why a caller cannot assume
// every refusal mentions --privileged.
//
// On darwin and windows the live probes refuse with CausePlatformUnsupported,
// and there is no container there to make privileged — so the remedy correctly
// says nothing about it. A test that asserted the warning on EVERY refusal
// therefore passed on Linux and failed on a platform this repository supports
// building on. Codex caught it in review; this asserts the underlying fact from
// a test that runs everywhere, so the reason cannot be forgotten.
func TestPlatformUnsupportedCarriesNoContainerAdvice(t *testing.T) {
	remedy := (&CapabilityError{
		Capability: CapabilityDeviceMapper,
		Cause:      CausePlatformUnsupported,
		Probe:      "p",
	}).Remedy()

	if strings.Contains(remedy, "--privileged") {
		t.Errorf("the platform-unsupported remedy talks about container privileges:\n%s", remedy)
	}
	if !strings.Contains(remedy, "Linux") {
		t.Errorf("the platform-unsupported remedy does not say what the fix is:\n%s", remedy)
	}
}

// TestEveryCauseHasARemedy keeps a new cause from reaching an operator with
// nothing to do about it.
func TestEveryCauseHasARemedy(t *testing.T) {
	for cause := range causeSentinels {
		if _, ok := causeRemedies[cause]; !ok {
			t.Errorf("cause %q has a sentinel but no remedy", cause)
		}
	}
}

// TestEveryPackageFailureReachesTheCatchAll is the contract the documentation
// states: errors.Is(err, ErrUnavailable) is the catch-all branch, so every
// refusal this package can produce has to match it.
//
// The two that did not were the fail-closed ones — an empty capability list and
// an unregistered capability — which is the worst place to have a gap: a caller
// that built its list dynamically and got an empty one is precisely the caller
// whose only branch is the catch-all. Found by Codex on review.
func TestEveryPackageFailureReachesTheCatchAll(t *testing.T) {
	cases := map[string]error{
		"an empty capability list": ErrNoCapabilities,
		"an unknown capability":    &UnknownCapabilityError{Capability: Capability("nope")},
		"a probed refusal":         &CapabilityError{Capability: CapabilityMount, Cause: CausePrivilegeMissing},
	}

	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(err, ErrUnavailable) {
				t.Errorf("%v does not match ErrUnavailable, so the documented catch-all misses it", err)
			}
		})
	}

	// The message has to say what went wrong AND that it is not a pass, since
	// this one is reported to a caller who believes it checked something.
	msg := ErrNoCapabilities.Error()
	for _, want := range []string{"no capabilities were requested", "not a pass"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message is missing %q:\n%s", want, msg)
		}
	}

	// Identity still has to work, or a caller cannot tell the empty-list mistake
	// apart from a real capability failure.
	if !errors.Is(ErrNoCapabilities, ErrNoCapabilities) {
		t.Error("ErrNoCapabilities no longer matches itself")
	}
	if errors.Is(&CapabilityError{Capability: CapabilityMount, Cause: CausePrivilegeMissing}, ErrNoCapabilities) {
		t.Error("a probed refusal matches ErrNoCapabilities")
	}
}

// TestUnknownCapabilityErrorNamesWhatWasMeant checks the message is usable: the
// misspelling and the alternatives.
func TestUnknownCapabilityErrorNamesWhatWasMeant(t *testing.T) {
	err := &UnknownCapabilityError{
		Capability: Capability("device-maper"),
		Known:      []Capability{CapabilityDeviceMapper, CapabilityMount},
	}

	msg := err.Error()
	for _, want := range []string{"device-maper", "device-mapper", "mount"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message is missing %q:\n%s", want, msg)
		}
	}
}

// TestUnknownCapabilityErrorWithNothingRegisteredStillRenders covers the empty
// case, which is what a Checker built with every probe removed would produce.
func TestUnknownCapabilityErrorWithNothingRegisteredStillRenders(t *testing.T) {
	err := &UnknownCapabilityError{Capability: CapabilityMount}
	if msg := err.Error(); !strings.Contains(msg, "known capabilities are") {
		t.Errorf("the message does not survive an empty Known list:\n%s", msg)
	}
}

// TestMountPropagationVocabulary covers the capability added for the mount-time
// guard. It has no probe on purpose — there is no mount to ask about at startup
// — so what has to hold is that its findings classify, match and render like
// every other one, and that passing it to Check still fails closed.
func TestMountPropagationVocabulary(t *testing.T) {
	err := &CapabilityError{
		Capability: CapabilityMountPropagation,
		Cause:      CauseMountNotPropagated,
		Probe:      "reading the propagation of /mnt/data in /proc/self/mountinfo",
	}

	if !errors.Is(err, ErrMountNotPropagated) {
		t.Error("the finding does not match its own sentinel")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Error("the finding does not match the root sentinel")
	}
	if errors.Is(err, ErrIndeterminate) {
		t.Error("the finding matches a sentinel for a different cause")
	}

	// The remedy is the whole artifact for this one: nothing about a capability
	// or a syscall filter fixes it, and an operator told to grant CAP_SYS_ADMIN
	// would change nothing and conclude the guard is wrong.
	remedy := err.Remedy()
	for _, want := range []string{"Bidirectional", "HostToContainer", "rshared", "make-rshared", "findmnt"} {
		if !strings.Contains(remedy, want) {
			t.Errorf("the remedy does not mention %q", want)
		}
	}
	if !strings.Contains(remedy, "Do NOT use --privileged") {
		t.Error("the remedy does not carry the --privileged warning")
	}

	// And the rendered error names what was actually looked at.
	if !strings.Contains(err.Error(), "/mnt/data") {
		t.Errorf("the finding does not name the mount: %v", err)
	}
}

// TestMountPropagationHasNoProbe pins the deliberate absence. Check must refuse
// it rather than silently pass a capability nothing can establish at startup.
func TestMountPropagationHasNoProbe(t *testing.T) {
	err := New().Check(context.Background(), CapabilityMountPropagation)
	if err == nil {
		t.Fatal("Check accepted a capability with no probe")
	}

	var unknown *UnknownCapabilityError
	if !errors.As(err, &unknown) {
		t.Fatalf("error is not an *UnknownCapabilityError: %v", err)
	}
	if unknown.Capability != CapabilityMountPropagation {
		t.Errorf("the error names %q", unknown.Capability)
	}
}

// TestIndeterminatePropagationHasItsOwnRemedy covers the case where the guard's
// own check breaks: the remedy has to point at /proc rather than at the mount.
func TestIndeterminatePropagationHasItsOwnRemedy(t *testing.T) {
	err := &CapabilityError{
		Capability: CapabilityMountPropagation,
		Cause:      CauseIndeterminate,
		Probe:      "reading /proc/self/mountinfo",
		Err:        errors.New("no such file or directory"),
	}
	if !strings.Contains(err.Remedy(), "/proc") {
		t.Errorf("the remedy does not point at /proc: %s", err.Remedy())
	}
	if !errors.Is(err, ErrIndeterminate) {
		t.Error("an indeterminate propagation finding does not match ErrIndeterminate")
	}
}
