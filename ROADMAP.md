# go-blockstore roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-26
> Changes are proposed by docs-only PR.

## Mission

Embedded block and volume storage for in-house services.
Lease-coordinated high availability, so one controller acts on a volume at a time.
Consumed through go-quicbaas, not called directly by applications.

## Current milestone

[Release candidate (M10)](../../milestone/10), target kind RC.
Projected 2026-10-15.

## Now

- [#75](../../issues/75) public release readiness signed off — in review
- readiness: readiness PR #76 merged — in review
- [#86](../../issues/86) release artifacts signed (IS-14) — open
- [#87](../../issues/87) docs index and Serena config conform — open

## Next

- readiness: release candidate tagged once #75 and #86 close — open

## Later

- [#97](../../issues/97) **VolumeProvider seam for go-trusted-platform's NBD export server** — accepted (CA order 2026-10-14, owner ruling).
  The consumer is go-trusted-platform `pkg/bootstrap/nbd`, through the go-quicbaas SDK, which re-exports it (go-quicbaas SPEC row `orchestration-volumes`); never a direct import.
  The interface is go-blockstore's. It offers:
  - **create**: a volume per device identity at a configured size, on first attach;
  - **grow-only resize**: grow to a larger configured size, refuse to shrink;
  - **attach to a device path**: a block device path the server reads and writes;
  - **promote and demote**: make this node's replica the writable one, or give that up.

  The DRBD provider replicates each device's volume between the gateway pair.
  A single boot node uses go-trusted-platform's local-file provider, which implements the same interface.
  It lands with go-trusted-platform's gateway HA (#710) and second gateway (#596), not with its #689.

  Open questions, recorded and not decided here:
  1. Promote and demote are performed by the provider only; go-trusted-platform's gateway HA (#710) decides which gateway is primary, and the provider elects none.
  2. go-blockstore defines VolumeProvider in this form, so the server codes against one interface.
  3. Size is in bytes, from the consumer's config. Resize happens when the configured size grows and the volume is next attached; there is no live resize under an attached client.

## Dependencies

- Up: `github.com/jeremyhahn/go-enclave` v0.8.0-alpha, `github.com/jeremyhahn/go-luks2` v1.0.0-rc.2
- Down: go-quicbaas

## Non-goals

Ownership boundaries are set in [00-ownership-and-sdk-boundary](../handbook/software/docs/00-ownership-and-sdk-boundary.md).
