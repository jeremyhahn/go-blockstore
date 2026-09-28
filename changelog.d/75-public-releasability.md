### Added

- **A public-releasability gate** (`internal/releasability`, `make
  releasability`, part of `make lint` and the CI Lint job). Every tracked file
  is read and the tree fails if it carries a lab address (any RFC 1918 range,
  or the lab's own public prefixes), an internal domain, a fleet hostname or an
  owner path — matched case-insensitively, in symlink targets as well, which
  are read and never followed — or a shell script (by extension or by
  shebang), an AI agent file, or key and certificate material. It fails closed:
  a binary or oversized tracked file fails unless `releasability-exempt.txt`
  lists it with a reason. See `docs/release/public-releasability.md`.
- `internal/toolinstall` and its `install-tool` command: the pinned,
  checksum-verified shellcheck and trivy installer, in Go.
- `internal/preflightmatrix`: the preflight container matrix, in Go, with its
  probe committed as `internal/preflightmatrix/probe` instead of generated.

### Removed — BREAKING: the shell scripts under `scripts/`

The public release is Go only. `scripts/install-shellcheck.sh`,
`scripts/install-trivy.sh` and `scripts/preflight-container-matrix.sh` are
gone; the Makefile targets that called them are unchanged, so a caller of
`make install-tools` or `make preflight-matrix` sees no difference. A caller
of a script by path moves to:

- `go run ./internal/toolinstall/cmd/install-tool shellcheck <dir> [version]`
- `go run ./internal/toolinstall/cmd/install-tool trivy <dir> [version]`
- `go run ./internal/preflightmatrix/cmd/preflight-matrix [docker-binary]`

The guards' `run.sh` fixtures are now Makefile fixtures, one recipe line per
exit-swallow spelling, as before.

### Changed — BREAKING: `make release-alpha` needs `AGENT_GIT`

`AGENT_GIT` no longer defaults to a path on the owner's workstation. Pass it:
`make release-alpha VERSION=vX.Y.Z-alpha AGENT_GIT=/path/to/agent-git.sh`.
The recipe refuses to start without an executable there, as it always did.

### Changed

- Test fixtures use RFC 5737 documentation addresses (`192.0.2.1`,
  `192.0.2.2`) and RFC 2606 names instead of private addresses, internal
  domains and fleet hostnames. No assertion changed.
- `.gitignore` excludes `.claude/`, `.serena/` and `CLAUDE.md`.
