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

### Fixed — the make targets read GO_BUILD_TAGS (#98)

- **Every target ci-template v1.21+ calls now honours `GO_BUILD_TAGS`.** The
  template passes the CI tag set as `make <target> GO_BUILD_TAGS='a b'`
  (space-separated); the Makefile read only `TAGS`, so those tags never reached
  `go build` or `go test`. `build`, `test`, `race`, `coverage`, `bench`, `vet`,
  `security`/`security-go` (gosec and govulncheck), `integration-test` and the
  operator-run suites now add it, comma-joined and de-duplicated, to the tags
  each already uses (`TAGS`, or a target's fixed `integration`,
  `drbd_integration`, `local_integration`, ... tags). `golangci-lint` gets it
  as `--build-tags`, together with `run.build-tags` from `.golangci.yml`. An
  empty `GO_BUILD_TAGS` leaves every command exactly as before.
- **`make check-build-tags`** (run by `make test`, script
  `scripts/check-build-tags.sh`) reads `make -n` and fails if any of those
  targets drops `GO_BUILD_TAGS`, if an empty value changes a command, or if the
  Makefile's copy of the golangci-lint config tags drifts from `.golangci.yml`.

## [0.5.0-alpha] - 2026-10-08

### Changed — BREAKING: go-enclave v0.8.0-alpha and go-luks2 v1.0.0-rc.2 (#84)

- **go-enclave v0.8.0-alpha (from v0.6.0-alpha) and go-luks2 v1.0.0-rc.2 (from
  v0.2.0-alpha)** (#84). Both releases break their APIs and every caller here
  moved to the new one; nothing is wrapped to look like the old shape.
- The LUKS passphrase is now an enclave end to end. `luks.Backend`'s `Format`,
  `Open` and `TestKey` take a `*enclave.MemoryEnclave` instead of a `[]byte`:
  `Manager.withKey` lends the enclave for one call and destroys it, and go-luks2
  borrows it for the derivation. No code in this module turns the passphrase
  into a `[]byte` any more, so `withKey` is no longer a `WithBytes` window.
- `luks.Native` drives go-luks2's `Volume` (`luks2.Open`, `Format`, `Unlock`,
  `Header`) and `pkg/dmcrypt` (`Activate`, `Lookup`, `Deactivate`,
  `CheckKeyring`) in place of the device-path free functions. The data offset
  is read from `Header().Segments()`. `pkg/preflight`'s keyring probe is
  `dmcrypt.CheckKeyring`.
- `Destroy()` returns an error in go-enclave v0.8.0. The key and secret
  providers (`FileKeyProvider`, `StaticKeyProvider`, `FileSecretProvider`) and
  `Manager.withKey` join it into the error they return rather than drop it.
- The `key-material-custody` guard follows the model. The copying-exit rule is
  gone, because `MemoryEnclave.Open` and `OpenString` no longer exist and a call
  no longer compiles. `withKey` leaves the borrow-window table, with
  `FileKeyProvider` as the anchor, and the `Backend` seam is no longer exempt
  from the clear-text rule, since it carries an enclave. The remaining rules
  are renumbered 1–4.
- New test helper package `internal/luks/luktest`, for reading and rewriting
  LUKS2 headers on disk. go-luks2 v1.0.0-rc.2 has no raw header write, and the
  corruption and foreign-header tests need one. The rewrite recomputes the
  header checksum, and go-luks2 still accepts the result.
- `TestNativeMappingReportsAnAbsentNameAsAbsent` moved behind a new `kernel_dm`
  tag (`make test-kernel-dm`). `dmcrypt.Lookup` can only ask device-mapper
  through `/dev/mapper/control`, so a host without the node cannot answer "no
  such mapping", so the test cannot run there.

### Changed

- `golang.org/x/sys` v0.47.0 → v0.48.0 (#74), the floor go-enclave requires;
  minimal version selection raises it. (#74's move to go-enclave v0.6.0-alpha
  is superseded within this release by #84.)
- **CI tool pins moved to the upstream latest** (#82), in step with the
  ci-runner image: golangci-lint v2.13.2 → v2.14.0, govulncheck v1.7.0 →
  v1.8.0, actionlint v1.7.7 → v1.7.12, shellcheck 0.10.0 → 0.11.0 (with the
  SHA-256 of both archives and both extracted binaries, computed from the
  release assets), trivy 0.74.0 → 0.75.0. gosec stays at v2.29.0, already
  the latest. Go 1.27.0 → 1.27.1 in `go.mod` and the workflows.

### Fixed

- `pkg/local`'s `local_integration` suite did not compile at the previous
  release: `luksPBKDF`, `luksHash`, `luksCipher`, `luksCipherMode`,
  `luksKeySizeBits`, `luksSectorSize` and `nativeLUKS` were undefined. The
  constants are defined again, as the values the provider pins, and the suite
  uses `luks.Native`.

## [0.4.0-alpha] - 2026-09-17

### Resolved — the go-luks2 migration ships

The `pkg/local` move to go-luks2 was held back (from `v0.1.7-alpha`, below)
because go-luks2 neither wrote nor read a conformant LUKS2 container: a
32-byte pbkdf2 digest where the declared `sha512` needs 64, an omitted
`tokens` object, a `keyslots_size` that overran the data offset, and a
secondary header carrying the primary magic. All four are fixed upstream and
this release pins **go-luks2 `v0.2.0-alpha`**. The gate was four assertions in
`internal/luks` that were written to fail until upstream was right —
`TestNativeFormatWritesASpecLengthDigest`,
`TestNativeFormatWritesACryptsetupReadableHeader` (three subtests, each one
defect), `TestNativeFormatProducesTheHeaderTheSizingConstantAssumes` and
`TestNativeRoundTripIsNotEvidenceOfConformance` — and they pass, measured
against a real `cryptsetup` 2.7 on 2026-09-17, not against go-luks2 agreeing
with itself. Existing encrypted volumes open; `cryptsetup` can dump, back up
and open what go-luks2 writes. `v0.2.0-alpha` also rides out the transient
`EBUSY` a device-mapper close can return while udev still holds the node.

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

- **drbd: transit confidentiality — LUKS above the replicated device.** Setting
  `encrypted=true` with `luks_key_file` (or an injected `KeyProvider` through
  the new `WithKeyProvider`) puts a LUKS2 container over `/dev/drbd<minor>`, so
  DRBD replicates ciphertext and each node's backing volume holds ciphertext.
  Authenticating the peer and concealing the data are separate controls; this is
  the second one. Configuration is refused at startup in both directions — a
  provider told to encrypt with no way to obtain the passphrase, and one given a
  passphrase with encryption off — and the LUKS key file may not be the
  replication secret file, which is shared with the peer.

- **`Promote` performs the `luksOpen` and `Demote` performs the `luksClose`.**
  DRBD denies every open of a Secondary's device, so a promotion is the only
  moment a container over the replicated device can be formatted or unlocked,
  and the mapping has to be gone before the demotion because an open dm-crypt
  target holds the device and DRBD will not demote a device somebody has open.
  The first promotion of a volume whose device carries nothing at all formats the
  container; every failover after that unlocks the one the peer wrote. A device
  carrying anything else is refused rather than formatted over. A promotion whose
  unlock fails is rolled back — on a context of its own, so a cancelled caller
  cannot abort the cleanup — unless the node already held Primary on the way in.
  `Detach` and `Delete` close a stranded mapping before taking the resource down.

- **An encrypted volume's LUKS2 header is allocated on top of the request**,
  the way DRBD's metadata already is. `SizeBytes` is usable capacity: the DRBD
  device is sized at `SizeBytes + 16 MiB`, the backing volume at that plus DRBD's
  metadata for it, and `Status` reports the device less the header — in every
  state the device can be measured in. A same-size restore of an encrypted
  snapshot plans exactly the backing size a fresh provision would. This is the
  side of the request `pkg/local` has always put its header on; the two
  backends now agree.

- **`key-material-custody`, the fifth whole-tree guard (#37, closing the #29
  umbrella).** The key-material custody model — a LUKS passphrase lives in a
  go-enclave `MemoryEnclave`, becomes a `[]byte` only inside
  `internal/luks.(*Manager).withKey` for one `Backend` call, and never crosses
  a package boundary in the clear — was a convention no test could see broken.
  It is now enforced by a type-checked scanner in `internal/guards`, run by
  `make guards` and so by `make lint` and the CI Lint job. Five rules: no call
  to the enclave's copying exits `Open`/`OpenString`; `WithBytes` only from the
  named borrow windows, with `withKey` as an anchor that must borrow exactly
  once; the key-taking `Backend` methods called only from `internal/luks`; a
  borrowed `key`/`passphrase []byte` used only as a direct call argument; and
  no exported signature carrying key material as a `string` or `[]byte`. Every
  rule is proved to fire on a planted fixture, and the scanner fails rather
  than passes on a file no build configuration selects, a type error, or a
  tree that borrows from enclaves without the anchor. Measured on the tree it
  landed on: 76 files examined, no findings; each rule planted in `pkg/local`
  or `internal/luks` is reported at its file:line, and the sweep takes 2.9s.

- **`pkg/drbd` verifies mount propagation, off by default, and says so when it
  is off (#40).** `Mount` can now check that the mount it just made is visible
  outside this mount namespace and refuse a private one, the way `pkg/local` has
  since #34. Turn it on with `mount_propagation=shared`; the default is
  `unchecked`, so a replicated cluster whose mounts nobody consumes from another
  namespace is unaffected on upgrade.

  A refusal **unwinds the mount** rather than leaving a filesystem the caller was
  told did not appear — on a context of its own, so a caller whose deadline
  passed mid-verification still gets the cleanup, and only when the target is
  still the mount this call made, since `umount(2)` takes a path and would
  otherwise detach whatever landed there since.

  A mount table that **cannot answer** the propagation question is a failure, not
  a pass: `CauseIndeterminate` rather than the `nil` a passing guard returns. A
  provider configured for `shared` over an injected `MountTable` without
  `PropagationOf` is refused at construction, so the impossible configuration
  cannot be discovered after a mount has already happened.

- **`pkg/drbd.Provider.Posture()`**, which the package had no equivalent of. It
  names every guard this provider knows about — the four startup capability
  checks, mount propagation, peer authentication and the delete-time wipe —
  reporting each as `checked` or `NOT CHECKED` with the setting that changes it.
  An off-by-default guard with no way to see that it is off is a guard that is
  silently absent, which is the failure the guard exists to remove.

- **A liveness-oracle seam, so a deployment can answer the question the provider
  cannot.** `common.LivenessOracle` asks whether an attachment still has a live
  owner; `pkg/local` takes one through `Options.LivenessOracle`. Whether an
  attachment has an owner at all is a property of how a system is DEPLOYED — a
  leased HA controller has one, a CSI node plugin has the pod, a host running
  one component over local disks has none — so the provider exposes the question
  and the deployment supplies the answer, rather than a library every deployment
  consumes baking in one deployment's assumption. go-blockstore takes no
  dependency on `pkg/ha`, on a CSI layer, or on anything upstream (#41).

  The reaper consults it at **exactly one** point: a mapping this node made on
  the boot that is still running. That is the only case the boot ID cannot
  settle, and it is the case that motivates the whole guard — an init container
  attaches, mounts, exits, and the host stays up, leaving a mapping every local
  fact calls live. It is deliberately NOT consulted on an ended boot, which is
  already proof and where an oracle outage could only erase a verdict reached
  without one, nor on another node's mapping.

- **`liveness unknown`, a verdict for an oracle that could not answer.** Not
  `live`, which would make an oracle outage look like a fleet with no orphans,
  and not `orphaned`, which would point anything acting on these verdicts at
  volumes live workloads are using. `Liveness` is a two-valued enumeration
  rather than a `bool` so that the reclaimable answer cannot arrive as an
  implementation's zero value: `common.LivenessOf` refuses the zero value, an
  unrecognized value, a nil oracle, and any value returned beside an error, all
  as `ErrLivenessIndeterminate`.

- **`Posture()` reports the oracle, present or absent.** `attachment liveness:
  NOT CHECKED` names the consequence rather than the setting — a mapping made on
  this boot is reported as live whether or not anything still holds it — because
  an absent oracle is legitimate and otherwise indistinguishable from a
  deployment that needs none.

### Changed

- **`pkg/local` no longer forks `cryptsetup`.** Every LUKS2 operation — format,
  unlock, close, resize, passphrase check, header read, mapping lookup — is now
  performed in-process by [go-luks2](https://github.com/jeremyhahn/go-luks2)
  (`v0.1.7-alpha` at the time; `v0.2.0-alpha` now — see *Resolved* above), which parses and writes headers in Go and creates the
  plaintext mapping with device-mapper ioctls. The `stat` shell-out behind the
  mapping-ownership check is gone too, replaced by `stat(2)` and a sysfs read of
  `/sys/dev/block/<major>:<minor>/slaves`; the integration suite attaches its
  loop device with the loop ioctls instead of forking `losetup`. **A host
  running this provider no longer needs `cryptsetup` installed.** Owner ruling
  2026-08-29: everything is done in pure Go unless there is absolutely no other
  way.

  The container layout is unchanged and was re-measured rather than assumed: the
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

- The LUKS2 machinery moved to `internal/luks` and is now shared by `pkg/local`
  and `pkg/drbd`: the pinned cryptographic parameters, the key providers, the
  passphrase borrow window and the mapping ownership check. `pkg/local`'s public
  surface is unchanged — `KeyProvider`, `FileKeyProvider`, `StaticKeyProvider`
  and every error message are as they were.

- `pkg/drbd`'s preflight now requires the kernel-keyring capability when, and
  only when, the provider is configured to encrypt. The measured claim it
  replaces — "this package performs no LUKS operations at all" — was true when
  it was written and is not any more.

- The propagation guard and the posture report now live in `internal/mountguard`
  and `internal/posture`, shared by `pkg/local` and `pkg/drbd` rather than
  written twice. `local.MountPropagationPolicy`, `local.Posture` and
  `local.GuardStatus` are unchanged as aliases; `pkg/local`'s behavior and its
  tests are untouched. `Posture.String()` now names the provider it describes
  (`go-blockstore/local guards:`, `go-blockstore/drbd guards:`).

- **go-enclave v0.5.0-alpha (from v0.4.0-alpha), and with it the toolchain floor
  is Go 1.27.0 (from 1.26.7).** The `go` directive, `GO_VERSION` in `ci.yml`
  and `nightly.yml`, and therefore the `golang:` image `make test-container`
  pulls, all read 1.27.0; the Makefile already derived its value from `go.mod`.
  Every constructor, method and error this module uses is unchanged in v0.5.0:
  `ErrLockedMemoryUnavailable` still carries the same text and every
  `LockedMemoryError` still reports it through `errors.Is`, so the
  RLIMIT_MEMLOCK refusal an operator sees is word-for-word what it was. The
  go-luks2 pin stays at v0.2.0-alpha, which itself requires v0.4.0-alpha;
  minimal version selection compiles it against v0.5.0 (the API is additive),
  and go-luks2 #201 tracks its own adoption.

- go-enclave is now distributed under the MIT License (it was AGPL-3.0).
  Nothing in this module changes, but a consumer that inherits this module's
  dependency tree no longer inherits a copyleft obligation from that one.

- `golang.org/x/crypto` v0.55.0 → v0.56.0 (indirect, via go-luks2). Clears two
  of the three module-level govulncheck advisories that scan reported at
  v0.55.0; the one that remains (GO-2026-5932) has no fixed version yet and is
  not reachable from this module — `make security-go` still reports 0
  vulnerabilities in code this module calls.

### Fixed

- **drbd: an encrypted volume can be resized, and a stale mapping is an error
  rather than a reported success.** The dm-crypt
  mapping over the replicated device is sized when `Promote` opens it, and
  go-luks2 v0.2.0-alpha exposes no table reload (re-measured: its device-mapper
  layer has create-and-load, info and remove, and `Unlock` computes a dynamic
  segment's length once from the device's size at that moment), so `Resize` is
  size-at-open. It grows the backing volume and the DRBD device as before, then:
  with the container closed — a Secondary — it completes, records the size, and
  records that the filesystem is owed a grow (`FSGrowPending`); with an open
  mapping that still covers the device it grows the filesystem through the
  mapping, online when mounted; with an open mapping the device has OUTGROWN it
  refuses with the new `ErrMappingStale`, after the idempotent device half and
  before any grow tool runs, without advancing the record, naming the remedy
  (unmount, `Demote`, `Promote` — which reopens the mapping over the device as
  it is now — then repeat the `Resize`). A restore that has to grow its
  destination on an encrypted provider takes the same path instead of being
  refused. `ErrMappingStale` does not wrap `common.ErrUnsupported`: one role
  cycle serves the request, which is the opposite of what that sentinel tells a
  caller.

- **`Mount` finishes a grow the record owes, online.** After a `Resize` (or a
  growing restore) that ran while the volume was Secondary, the first `Mount`
  from a Primary runs `resize2fs` against the mounted ext4 or `xfs_growfs`
  against the mount point — the first point at which both filesystems can be
  grown without a check — and clears the debt; a failed grow unwinds the mount
  and leaves the debt standing. This is deliberately not done at `Promote`,
  where the only ext4 route is a forced `e2fsck` of the whole filesystem in the
  failover path, XFS cannot be grown at all, and a per-node record cannot know
  whether the peer already grew the shared filesystem online. The record field
  is absent from records written before it existed, which therefore owe
  nothing and behave as before.

- **`internal/luks`: a mapping reports its length and its backing device's
  current size.** `MappingInfo` gains `SizeBytes` and `BackingSizeBytes`, read
  from sysfs (no open of the device, which DRBD refuses on a Secondary), and
  `Manager.MeasureMapping` decides freshness from them against the header's
  data offset — fail-closed on any size it cannot establish, including a
  mapping longer than the device's data area, which is a device that shrank
  under a live mapping. The seam still offers no resize, and the comment on
  it now records the measurement that keeps that absence load-bearing.

### Unchanged

- **Nothing tears a mapping down.** `InspectMappings` still reports and removes
  nothing; the acting half deleted in #43 stays deleted. This lands the fact that
  would make removal decidable, not the removal.


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
