# go-blockstore roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
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

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: `github.com/jeremyhahn/go-enclave` v0.8.0-alpha, `github.com/jeremyhahn/go-luks2` v1.0.0-rc.2
- Down: go-quicbaas

## Non-goals

Ownership boundaries are set in [00-ownership-and-sdk-boundary](../handbook/software/docs/00-ownership-and-sdk-boundary.md).
