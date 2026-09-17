### Fixed

- **drbd: an encrypted volume can be resized, and a stale mapping is an error
  rather than a reported success.** `ErrResizeEncrypted` is gone. The dm-crypt
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
