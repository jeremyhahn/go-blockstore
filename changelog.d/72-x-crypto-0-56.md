### Changed

- `golang.org/x/crypto` v0.55.0 → v0.56.0 (indirect, via go-luks2). Clears two
  of the three module-level govulncheck advisories that scan reported at
  v0.55.0; the one that remains (GO-2026-5932) has no fixed version yet and is
  not reachable from this module — `make security-go` still reports 0
  vulnerabilities in code this module calls.
