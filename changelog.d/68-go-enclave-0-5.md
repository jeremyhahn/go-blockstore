### Changed

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
