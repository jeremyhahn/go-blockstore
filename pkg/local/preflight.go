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
	"context"
	"sort"

	"github.com/jeremyhahn/go-blockstore/pkg/preflight"
)

// PreflightMode selects which privilege checks New runs before it hands back a
// Provider.
//
// The checks exist because the privileges this provider needs are granted by
// three independent mechanisms — capabilities, seccomp and an LSM profile — and
// a deployment can satisfy two of them and fail the third silently until the
// first volume is attached. See package preflight.
type PreflightMode int

const (
	// PreflightConfigured checks the capabilities this provider's configuration
	// will actually exercise, for each seam left at its real implementation. It
	// is the zero value, so a provider built for production is checked without
	// anybody having to opt in.
	//
	// A seam replaced by the caller is NOT checked, and that is a derivation
	// rather than a guess: a Provider given its own Mounter does not call
	// mount(2), so mount(2) being unavailable would not affect it. Injecting a
	// seam is an explicit act that replaces the real operation.
	PreflightConfigured PreflightMode = iota

	// PreflightAll checks every capability the provider could need, whatever
	// seams were injected. Use it in a component that means to prove the
	// deployment is correct rather than merely that this provider will work.
	PreflightAll

	// PreflightOff runs no checks.
	//
	// It exists for callers that construct a Provider they will not perform
	// privileged operations with — enumerating configuration, validating
	// settings in a CLI, a test harness driving fakes through the factory. It
	// is an explicit, recorded choice in configuration, never a default and
	// never something this package infers, because the failure it re-enables is
	// exactly the one the checks were added to remove.
	PreflightOff
)

// preflightModeNames maps the mode onto the settings spelling, so the settings
// parser and the documentation cannot drift.
var preflightModeNames = map[string]PreflightMode{
	"configured": PreflightConfigured,
	"all":        PreflightAll,
	"off":        PreflightOff,
}

// preflightModeSpellings returns the accepted settings values in a stable
// order, for the error a misspelling produces.
func preflightModeSpellings() []string {
	spellings := make([]string, 0, len(preflightModeNames))
	for spelling := range preflightModeNames {
		spellings = append(spellings, spelling)
	}
	sort.Strings(spellings)
	return spellings
}

// requiredCapabilities derives the needed capabilities from the Options before defaults are applied.
func requiredCapabilities(opts Options, mode PreflightMode) []preflight.Capability {
	if mode == PreflightOff {
		return nil
	}

	all := mode == PreflightAll
	var capabilities []preflight.Capability

	// The real CommandRunner drives the LVM tools, and every LVM operation is a
	// device-mapper operation underneath.
	usesDeviceMapper := all || opts.Runner == nil

	// The real Mounter calls mount(2).
	if all || opts.Mounter == nil {
		capabilities = append(capabilities, preflight.CapabilityMount)
	}

	// Encryption needs the kernel keyring and implies device-mapper.
	if all || (opts.luks == nil && (opts.Encrypted || opts.KeyProvider != nil)) {
		capabilities = append(capabilities, preflight.CapabilityKernelKeyring)
		usesDeviceMapper = true
	}

	if usesDeviceMapper {
		capabilities = append(capabilities, preflight.CapabilityDeviceMapper)
	}
	return capabilities
}

// runPreflight runs last in New, after argument validation; an empty capability set checks nothing.
func runPreflight(opts Options, mode PreflightMode) error {
	capabilities := requiredCapabilities(opts, mode)
	if len(capabilities) == 0 {
		return nil
	}
	return preflight.Check(context.Background(), capabilities...)
}
