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

// Capability names one thing the storage component must be able to do; each has its own probe.
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

	// CapabilityKernelKeyring is adding and removing a kernel keyring key, needed by encrypted volumes; default seccomp profiles block it.
	CapabilityKernelKeyring Capability = "kernel-keyring"

	// CapabilityMountPropagation is a mount visible outside its namespace; it has no startup probe and Check refuses it as unknown.
	CapabilityMountPropagation Capability = "mount-propagation"

	// CapabilityNetAdmin is CAP_NET_ADMIN, needed by the replicated backend's DRBD netlink control path.
	CapabilityNetAdmin Capability = "net-admin"

	// CapabilityDRBDControl is the drbd module loaded with its generic-netlink family registered; it is fixed on the node, not a privilege.
	CapabilityDRBDControl Capability = "drbd-control"
)

// Probe checks one capability by attempting the operation, returning nil or a *CapabilityError, and removes anything it creates.
type Probe func(ctx context.Context) error

// Checker runs a set of injectable probes; construct one with New.
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

// Check runs every probe and joins the failures; an empty list, an unknown capability or an unclassified error all fail.
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

// run invokes one probe and classifies the result; a nil probe is reported as a failure.
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
			// A nil *CapabilityError in a non-nil error is reported as indeterminate.
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

// Check verifies the named capabilities with the live probes; call it during initialization, before serving.
func Check(ctx context.Context, capabilities ...Capability) error {
	return New().Check(ctx, capabilities...)
}
