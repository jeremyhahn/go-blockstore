### Added

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
