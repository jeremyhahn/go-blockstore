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

// Package preflight refuses to start a storage component that cannot perform the privileged work it will be asked for.
//
// Each check attempts the operation (device-mapper, mount(2), kernel keyring) and returns a typed refusal naming the missing mechanism: capability, seccomp or LSM.
// A check that cannot reach an answer fails with CauseIndeterminate. Probes clean up after themselves.
//
// The storage component needs CAP_SYS_ADMIN, seccomp default plus add_key, keyctl and request_key, an LSM profile permitting mount(2), /dev/mapper/control and the block device; never --privileged.
// The workload needs no privilege: it receives an already-mounted filesystem and never the key.
//
// Call Check during initialization:
//
//	preflight.Check(ctx, preflight.CapabilityDeviceMapper,
//	                     preflight.CapabilityMount,
//	                     preflight.CapabilityKernelKeyring)
package preflight
