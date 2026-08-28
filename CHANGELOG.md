# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Version headings are **unprefixed** (`0.3.1-alpha`), matching the `VERSION` file;
the corresponding git tag carries the `v` (`v0.3.1-alpha`). That split is the
portfolio convention, not an oversight — `conventions/release-versioning.md` §2.

Pre-1.0, **MINOR is where breakage lives**: an added API and a breaking change
both bump MINOR, and PATCH is reserved for fixes that move no API.

## [Unreleased]

### Added

- `VERSION`, this `CHANGELOG.md`, `make release-alpha`, and
  `.github/workflows/release.yml` — the release machinery the repo had been
  operating without. The four tags below were cut by hand; the next one is cut
  by the target (#8).

## [0.3.1-alpha] - 2026-08-27

### Fixed

- Renewal sleep is capped at the remaining lease. `0.3.0-alpha`'s
  `minRenewDelay` floor could sleep past a still-live sub-20ms deadline,
  forfeiting leadership by skipping the last renewal that could have saved it.
- Sentinel-contract test pins: `ErrRoleNotYielded` is now asserted present where
  the shutdown demote failed and asserted absent where it succeeded, so the
  contract is pinned in both directions rather than only one.

Consumers on `0.3.0-alpha` should take this release over it.

## [0.3.0-alpha] - 2026-08-27

### Added

- `pkg/ha` — the HA controller. A Coordinator-elected singleton holding
  per-volume primary leases with hard-deadline fencing, an adoption/promotion
  gate asymmetry, and machine-readable split-brain markers (`ErrFenced`,
  `ErrRoleNotYielded`).

With this the library is feature-complete for the DRBD-first storage program.

The controller is a **control-plane fence only**: production deployments pair it
with DRBD fencing/stonith or quorum. Embedded-coordinator deployments are gated
on go-qrdb #174, and hardware acceptance on the dellemc pair (issue #4's
acceptance list).

## [0.2.0-alpha] - 2026-08-27

### Added

- `local` provider — LVM/LUKS2 volumes with enclave-backed keys, FIPS-pinned
  parameters, `openat2`-pinned mounts, and a per-volume `flock`.
- `drbd` provider — DRBD9 protocol-C replication with cram-hmac peer
  authentication, exhaustive state mapping, and crash-durable state.
- `internal/mount`, shared by both providers.

### Changed

- `pkg/common`'s contract is complete: the snapshot lifecycle, portable
  sentinels, and the Delete-refuses rule.

The real-cluster drbd suite had **not** been run at this tag — it is gated on
issue #4's acceptance list (dellemc pair, week of 2026-08-31).

## [0.1.0-alpha] - 2026-08-26

### Added

- Scaffold: the `VolumeProvider` and `ReplicatedProvider` interfaces, the full
  snapshot lifecycle, the injected `Coordinator`/`Lease` contract aligned to
  go-qrdb `sdk v0.13.0-alpha`, and a thread-safe provider registry (#1, #5).
