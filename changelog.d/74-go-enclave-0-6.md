### Changed

- **go-enclave v0.6.0-alpha (from v0.5.0-alpha)** (#74). The release is
  additive: it adds `SetAllocator` / `ProcessAllocator` and the errors
  `ErrAllocatorInstalled` and `ErrNilAllocator`. Every constructor, method and
  error this module uses is unchanged, so no code here moves. This module does
  not adopt the process allocator in this change. The `go` directive stays at
  1.27.0, the same floor go-enclave uses.
- `golang.org/x/sys` v0.47.0 → v0.48.0, the floor go-enclave v0.6.0-alpha
  requires. Minimal version selection raises it.
- The go-luks2 pin stays at v0.2.0-alpha, its newest tag. Adopting its next
  release waits for go-luks2 to tag v0.3.0-alpha (go-luks2#211).
