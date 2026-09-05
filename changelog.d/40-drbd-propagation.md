### Added

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

### Changed

- The propagation guard and the posture report now live in `internal/mountguard`
  and `internal/posture`, shared by `pkg/local` and `pkg/drbd` rather than
  written twice. `local.MountPropagationPolicy`, `local.Posture` and
  `local.GuardStatus` are unchanged as aliases; `pkg/local`'s behavior and its
  tests are untouched. `Posture.String()` now names the provider it describes
  (`go-blockstore/local guards:`, `go-blockstore/drbd guards:`).
