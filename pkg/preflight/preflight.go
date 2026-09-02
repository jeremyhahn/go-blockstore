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
	"sort"
)

// Capability names one thing the storage component must be able to do.
//
// The set is deliberately small and each member is a SEPARATE probe, because
// the mechanisms behind them are separate: a deployment can have device-mapper
// working and the keyring blocked, and reporting that as one "storage is
// broken" would hide which of the three knobs to turn.
type Capability string

const (
	// CapabilityDeviceMapper is the ability to issue device-mapper control
	// ioctls: creating, loading and removing mappings. LVM and dm-crypt both
	// need it, so every provider that touches local storage does.
	CapabilityDeviceMapper Capability = "device-mapper"

	// CapabilityMount is the ability to call mount(2). The storage component
	// mounts the filesystem and hands the workload the mounted directory, so
	// this belongs to the storage component and to nothing above it.
	CapabilityMount Capability = "mount"

	// CapabilityKernelKeyring is the ability to place a key in the kernel
	// keyring and take it out again. Encrypted volumes require it: the volume
	// key reaches dm-crypt as a keyring REFERENCE rather than inline in the
	// device-mapper table, which is what keeps it out of userspace memory.
	//
	// It is the capability most likely to be missing on a deployment that looks
	// correctly privileged, because a container runtime's default seccomp
	// profile blocks add_key, keyctl and request_key and granting CAP_SYS_ADMIN
	// does not lift that.
	CapabilityKernelKeyring Capability = "kernel-keyring"

	// CapabilityMountPropagation is a mount being visible outside the namespace
	// that made it.
	//
	// Unlike the three above it has NO registered probe and is never passed to
	// Check: nothing about it can be established at startup, because it is a
	// property of an individual mount and there is no mount yet. It is checked
	// after each mount, by the provider that made it, and it lives here so that
	// finding reaches an operator in the same vocabulary as the startup ones —
	// same type, same Cause, same remedy table. Passing it to Check yields
	// UnknownCapabilityError, which is the fail-closed direction.
	CapabilityMountPropagation Capability = "mount-propagation"
)

// Probe performs one capability check by ATTEMPTING the operation.
//
// A probe returns nil when the capability is available and a *CapabilityError
// when it is not. It must not infer from capability bits, kernel versions or
// the contents of /proc: reading CapEff and reasoning about it produces
// confident false positives in exactly the case that matters, where the
// capability is granted and a seccomp filter refuses the syscall anyway.
//
// A probe that creates anything must remove it before returning, and must scope
// what it creates to something it can prove it owns.
type Probe func(ctx context.Context) error

// Checker runs a set of probes.
//
// The zero value is not usable; construct one with New. Probes are injectable
// so the refusal paths can be driven in tests — most of them cannot be produced
// for real on any one host, and a guard whose refusal paths are untested is a
// guard whose refusal paths do not work.
type Checker struct {
	probes map[Capability]Probe
}

// Option configures a Checker.
type Option func(*Checker)

// WithProbe replaces the probe for a capability, or registers one for a
// capability this package does not know.
func WithProbe(capability Capability, probe Probe) Option {
	return func(c *Checker) { c.probes[capability] = probe }
}

// New returns a Checker running the live probes, with any options applied.
func New(opts ...Option) *Checker {
	c := &Checker{probes: liveProbes()}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// liveProbes returns the real probes for this platform. The name is spelled
// out in probe_linux.go and probe_other.go.
func liveProbes() map[Capability]Probe {
	probes := make(map[Capability]Probe, 3)
	for capability, probe := range platformProbes() {
		probes[capability] = probe
	}
	return probes
}

// Check verifies every named capability and returns nil only if all of them are
// available.
//
// It runs EVERY probe rather than stopping at the first failure, and joins the
// results: a container missing two of the three is a single configuration
// mistake, and reporting one per restart makes an operator discover them
// serially over three deployments.
//
// It fails closed in three ways that matter:
//
//   - An empty capability list is ErrNoCapabilities, not success.
//   - A capability with no registered probe is an *UnknownCapabilityError, not
//     a skip.
//   - A probe that returns something other than a *CapabilityError has its
//     error wrapped as CauseIndeterminate rather than passed through, so no
//     failure can reach a caller unclassified and no unclassified failure can
//     be mistaken for a pass.
//
// Duplicates are collapsed and the capabilities are checked in a stable order,
// so the same misconfiguration produces the same message every time.
func (c *Checker) Check(ctx context.Context, capabilities ...Capability) error {
	if len(capabilities) == 0 {
		return ErrNoCapabilities
	}

	wanted := make(map[Capability]struct{}, len(capabilities))
	for _, capability := range capabilities {
		wanted[capability] = struct{}{}
	}
	ordered := make([]Capability, 0, len(wanted))
	for capability := range wanted {
		ordered = append(ordered, capability)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	failures := make([]error, 0, len(ordered))
	for _, capability := range ordered {
		probe, ok := c.probes[capability]
		if !ok {
			failures = append(failures, &UnknownCapabilityError{
				Capability: capability,
				Known:      c.Capabilities(),
			})
			continue
		}
		if err := c.run(ctx, capability, probe); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// run invokes one probe and guarantees the result is classified.
//
// A nil probe is a registration mistake and is reported rather than treated as
// a capability that passed — the same reason the factory panics on a nil
// creator, arrived at one layer later where panicking would be wrong.
func (c *Checker) run(ctx context.Context, capability Capability, probe Probe) error {
	if probe == nil {
		return &CapabilityError{
			Capability: capability,
			Cause:      CauseIndeterminate,
			Probe:      "running the registered probe",
			Err:        errors.New("no probe function was registered for this capability"),
		}
	}

	err := probe(ctx)
	if err == nil {
		return nil
	}

	var typed *CapabilityError
	if errors.As(err, &typed) {
		if typed == nil {
			// A probe returned a nil *CapabilityError boxed in a non-nil error
			// — the interface trap. Whatever it meant, it is not evidence that
			// the capability is available, and rendering it would panic. It is
			// reported as indeterminate for the same reason every other
			// unanswerable probe is.
			return &CapabilityError{
				Capability: capability,
				Cause:      CauseIndeterminate,
				Probe:      "running the registered probe",
				Err:        errors.New("the probe returned a nil typed error, which is neither a pass nor a usable finding"),
			}
		}
		return err
	}
	return &CapabilityError{
		Capability: capability,
		Cause:      CauseIndeterminate,
		Probe:      "running the registered probe",
		Err:        err,
	}
}

// Capabilities returns the capabilities this Checker can probe, in a stable
// order.
func (c *Checker) Capabilities() []Capability {
	known := make([]Capability, 0, len(c.probes))
	for capability := range c.probes {
		known = append(known, capability)
	}
	sort.Slice(known, func(i, j int) bool { return known[i] < known[j] })
	return known
}

// Check verifies the named capabilities with the live probes.
//
// This is what a storage component calls during initialization, BEFORE it
// serves anything: a control-plane process, a CSI node plugin, an init
// container. Calling it there turns a deployment mistake into a refusal to
// start with an actionable message, instead of a failure at the first volume
// attach — which happens under load, looks like a storage fault rather than a
// container-configuration fault, and is discovered by a customer.
func Check(ctx context.Context, capabilities ...Capability) error {
	return New().Check(ctx, capabilities...)
}
