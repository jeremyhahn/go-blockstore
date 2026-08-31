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

### BLOCKED — do not release the go-luks2 migration

The `pkg/local` move to go-luks2 below is **structurally complete and must not
ship**, because go-luks2 `v0.1.7-alpha` does not write or read a conformant
LUKS2 container. Four assertions in `pkg/local` fail deliberately and are the
gate; they go green when upstream is fixed, and they are not to be relaxed.

- **Existing encrypted volumes would become unopenable.** A LUKS2 pbkdf2 digest
  is the master key derived to the output length of the hash it declares — 64
  bytes for the `sha512` this package pins. go-luks2 hardcodes 32
  (`format.go:243`, `unlock.go:485`). Measured 2026-08-29 against cryptsetup
  2.7.0: a container formatted with this package's exact parameters stores a
  64-byte digest, and `luks2.TestKey` on it **with the correct passphrase**
  returns "incorrect passphrase". Every encrypted volume provisioned before this
  change is affected. Upstream go-luks2 #73.
- **Containers written by go-luks2 cannot be read by cryptsetup at all** — not
  "refuse the passphrase", but `cryptsetup isLuks` exit 1 and luksDump "is not a
  valid LUKS device", so `luksDump`, `luksHeaderBackup`, `luksChangeKey` and
  `luksOpen` are all unavailable and an encrypted volume has no recovery path.
  Three separate defects, each measured and each pinned by a subtest: `tokens`
  is omitted from the JSON area when empty (`types.go:67` `omitempty`);
  `keyslots_size` stores offset+area instead of the area, overrunning the data
  offset by 32768 (`format.go:207`); and the secondary header at `0x4000`
  carries the primary magic instead of `SKUL\xba\xbe`, so the backup header is
  unreadable. Patching all three into a go-luks2 container by hand makes
  cryptsetup accept, dump and open it — so they are the whole gap. Not the
  digest: cryptsetup derives its comparison to the length stored, and tolerates
  32. **Fixing #73 alone does not restore interop.** Not yet filed upstream.

Neither defect is detectable by round-tripping through go-luks2, whose Format
and Unlock share the same assumptions and therefore agree with each other. See
`TestNativeRoundTripIsNotEvidenceOfConformance`.

### Changed

- **`pkg/local` no longer forks `cryptsetup`.** Every LUKS2 operation — format,
  unlock, close, resize, passphrase check, header read, mapping lookup — is now
  performed in-process by [go-luks2](https://github.com/jeremyhahn/go-luks2)
  `v0.1.7-alpha`, which parses and writes headers in Go and creates the
  plaintext mapping with device-mapper ioctls. The `stat` shell-out behind the
  mapping-ownership check is gone too, replaced by `stat(2)` and a sysfs read of
  `/sys/dev/block/<major>:<minor>/slaves`; the integration suite attaches its
  loop device with the loop ioctls instead of forking `losetup`. **A host
  running this provider no longer needs `cryptsetup` installed.** Owner ruling
  2026-08-29: everything is done in pure Go unless there is absolutely no other
  way.

  **See the BLOCKED section above before acting on any of this.** The container
  layout is unchanged and was re-measured rather than assumed: the
  pinned FIPS parameters (PBKDF2-SHA-512, AES-256-XTS, 512-bit key, 512-byte
  sectors) produce the same 16 MiB data offset go-blockstore has always sized
  volumes against, so the `SizeBytes`-is-usable-capacity contract and the
  `blockstore.luks-header` tag are untouched.

  Two behavioral differences a deployment should know about:

  - A passphrase must be **8 to 512 bytes**. go-luks2 enforces that bound on
    every format and unlock; `cryptsetup --key-file` did not.
  - **`Resize` refuses an encrypted volume that is attached**, with the new
    `local.ErrResizeWhileAttached`, and refuses it before it grows anything —
    so nothing is left half-done and a caller that means it detaches and
    resizes again. Growing a live dm-crypt mapping needs the device-mapper
    table reloaded underneath it, which needs the container's master key;
    go-luks2 `v0.1.8-alpha` exposes neither a resize nor any way to obtain that
    key. The only mechanism reachable through it is to remove the mapping and
    unlock again, and a failure between the two — a rotated `KeyProvider`, a
    damaged header, any device-mapper refusal — leaves the caller with **no
    plaintext device at all** rather than an unresized one. Validating the key
    first narrows that window without closing it, so the operation is refused
    rather than attempted, and `luksBackend` has no resize operation for
    anything to call. The detached path is unaffected and unrestricted: it
    opens the container itself, grows the filesystem inside it and locks it
    again, so a failure anywhere costs the caller nothing it was using.

### Added

- `VERSION`, this `CHANGELOG.md`, `make release-alpha`, and
  `.github/workflows/release.yml` — the release machinery the repo had been
  operating without. The four tags below were cut by hand; the next one is cut
  by the target (#8).
- Unit tests that format real LUKS2 containers onto sparse files, needing
  neither root nor a block device, and assert the FIPS parameters and the 16 MiB
  data offset against the header that is actually written. Both were previously
  checkable only through a `cryptsetup` command line or the root-only
  integration suite.

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
