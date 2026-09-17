### Added

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

- **`Resize` refuses an encrypted volume with `ErrResizeEncrypted`** (wrapping
  `common.ErrUnsupported`), before anything is extended, and so does a restore
  that would have to grow its destination. The dm-crypt mapping is sized when
  `Promote` opens it and go-luks2 exposes no table reload, so the filesystem
  inside the container cannot be grown to the new size while it is open; growing
  the device and recording a size the filesystem never reached would be a silent
  wrong answer. Issue #62 (header-on-top sizing and a mapping-aware grow) lifts
  the refusal.

### Changed

- The LUKS2 machinery moved to `internal/luks` and is now shared by `pkg/local`
  and `pkg/drbd`: the pinned cryptographic parameters, the key providers, the
  passphrase borrow window and the mapping ownership check. `pkg/local`'s public
  surface is unchanged — `KeyProvider`, `FileKeyProvider`, `StaticKeyProvider`
  and every error message are as they were.

- `pkg/drbd`'s preflight now requires the kernel-keyring capability when, and
  only when, the provider is configured to encrypt. The measured claim it
  replaces — "this package performs no LUKS operations at all" — was true when
  it was written and is not any more.
