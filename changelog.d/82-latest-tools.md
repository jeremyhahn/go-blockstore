### Changed

- **CI tool pins moved to the upstream latest** (#82), in step with the
  ci-runner image: golangci-lint v2.13.2 → v2.14.0, govulncheck v1.7.0 →
  v1.8.0, actionlint v1.7.7 → v1.7.12, shellcheck 0.10.0 → 0.11.0 (with the
  SHA-256 of both archives and both extracted binaries, computed from the
  release assets), trivy 0.74.0 → 0.75.0. gosec stays at v2.29.0, already
  the latest. Go 1.27.0 → 1.27.1 in `go.mod` and the workflows.
