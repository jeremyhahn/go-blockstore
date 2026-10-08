### Changed

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

### Fixed

- `pkg/local`'s `local_integration` suite did not compile at the previous
  release: `luksPBKDF`, `luksHash`, `luksCipher`, `luksCipherMode`,
  `luksKeySizeBits`, `luksSectorSize` and `nativeLUKS` were undefined. The
  constants are defined again, as the values the provider pins, and the suite
  uses `luks.Native`.
