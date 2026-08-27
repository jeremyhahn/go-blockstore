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

// Package common defines the core types, interfaces, and errors shared across
// go-blockstore.
//
// It declares the VolumeProvider and ReplicatedProvider interfaces that
// block-storage backends implement, the Coordinator and Lease interfaces the
// library depends on for distributed coordination (defined here so the library
// never imports a concrete consensus store — callers inject an implementation),
// the value types describing volumes, snapshots, replication and mount
// options, and the canonical error sentinels.
package common
