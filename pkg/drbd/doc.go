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

// Package drbd implements common.ReplicatedProvider over DRBD 9 for a two-node pair, driving drbdadm directly; build tag drbd.
// It never force-promotes and performs no initial sync: those data-loss decisions belong to the HA controller and the operator.
// Provision runs on both nodes; a caller pins the shared minor and port with LabelMinor and LabelPort. Snapshots are local LVM snapshots, Primary only, crash-consistent.
// Peer authentication uses cram-hmac sha256; the secret is written into the 0600 .res file, and rotation means regenerating and adjusting on both nodes.
// Replication is plaintext unless encrypted=true, which puts LUKS2 above the device, opened on Promote and closed before Demote.
package drbd
