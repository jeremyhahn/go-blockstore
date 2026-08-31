// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-blockstore.
//
// go-blockstore is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package local implements the common.VolumeProvider contract over LVM and
// LUKS2 on a single host. It carries no build tag and is always compiled: it is
// the fundamental backend, the one that has to exist for a binary built with no
// tags at all to be able to do anything.
//
// # The model
//
// A volume is a logical volume in one configured volume group, and its ID is
// that logical volume's name. There is no sidecar metadata store and no
// in-memory volume table — everything the provider needs to answer a question
// it reads back from LVM, blkid and findmnt at the time it is asked. A provider
// restarted mid-flight therefore sees exactly what its predecessor saw, and two
// processes pointed at the same volume group do not have to agree on anything
// beyond the group's name. The cost is that most calls run a few commands
// instead of consulting a cache, which is not the expensive part of creating a
// filesystem.
//
// The state a volume moves through maps onto LVM and device-mapper directly:
//
//	Provision  lvcreate, optional LUKS2 format, optional mkfs;
//	           the volume is left deactivated and reports as available
//	Attach     lvchange -ay, and a LUKS unlock when the volume is a container;
//	           reports the plaintext device either way
//	Mount      mount(8) against the attached device
//	Unmount    umount(8), converging when the volume is not mounted there
//	Detach     LUKS close, lvchange -an
//	Delete     unmount, lock, lvremove
//
// Volumes are created with LVM autoactivation switched off, which is what makes
// Detach mean anything: autoactivation is on by default and udev reactivates a
// whole volume group in response to unrelated device events, so a detached
// volume otherwise reappears within seconds and Status starts reporting it
// attached again. Activation belongs to this provider, not to boot or udev.
// That flag needs LVM 2.03.12 (2021) or newer, which is the library's floor.
//
// Encryption is DISCOVERED, and remembered only where it cannot be discovered.
// Attach probes the logical volume with blkid and reaches for LUKS only on a
// crypto_LUKS signature, so a provider configured without Options.Encrypted
// still handles volumes that are encrypted, and a host that has no encrypted
// volumes never touches device-mapper at all. Discovery is the authority
// wherever it can run, and no cached answer overrides it.
//
// It cannot run on a DETACHED volume: an inactive logical volume has no device
// node, so there is nothing to probe. That is the one case where the fact is
// remembered instead — an LVM tag written when the volume becomes a container,
// read back from the volume listing, and used only by Status, only while
// detached, and only to report capacity. It is a fallback for a blind spot, not
// a cache in front of the probe: on an active volume the probe decides, and a
// tag that contradicts it is an error rather than a tiebreak — both about
// whether the volume is a container at all AND about how large its header is,
// since the header size is the part the tag carries and the part a detached
// read depends on. A tag can therefore only stay wrong for as long as the
// volume stays detached.
//
// That holds because every operation which both holds the volume's lock and
// looks at the volume with a device node in front of it reconciles the tag with
// what it found: Attach, Resize, and — the one that matters most — Detach,
// which is the transition INTO the state where the tag starts being believed
// and the last moment the container is readable. A container gets its measured
// header recorded; a volume that turns out not to be one has the tag removed.
// Mount and Unmount probe too but leave the volume ACTIVE, where the tag is not
// consulted and Status refuses a contradiction outright, so there is nothing
// there for a stale tag to mislead. Delete is exempt on purpose: it is removing
// the volume, and refusing to destroy something because a note about it could
// not be rewritten would be obstruction.
//
// The tag records the header's SIZE, not just that there is one, because the
// size is known wherever a tag is written and is not recoverable afterwards. A
// volume restored verbatim from an outside snapshot carries that snapshot's
// header, which need not be the 16 MiB this package formats. See
// encryptedTagPrefix.
//
// # Capacity
//
// VolumeSpec.SizeBytes is the capacity the CALLER CAN USE, and this provider
// puts its overhead on top of it. An encrypted volume asked for at a gibibyte
// gets a logical volume a LUKS header larger, so the plaintext mapping Attach
// hands back holds the gibibyte that was asked for; a plain volume has no
// overhead and the two figures coincide. Resize follows the same rule, and
// VolumeStatus.SizeBytes reports the usable figure rather than the backing
// device's.
//
// The header is 16 MiB. It is a constant because every parameter that
// determines it is pinned at format time rather than left to the library, and
// it is a MEASURED constant: see luksHeaderBytes for the derivation, against
// cryptsetup 2.7.0 and again against go-luks2. Two tests re-derive it from a
// real container rather than trusting the comment —
// TestNativeFormatProducesTheHeaderTheSizingConstantAssumes on every `go test`,
// and TestIntegrationEncryptedVolumeDeliversTheRequestedCapacity on every
// integration run.
//
// What an EXISTING container costs is read from that container's own header
// instead of assumed, because a volume restored from an encrypted snapshot
// carries its source's header and that header need not be one this package
// wrote. The constant sizes what this provider creates; measurement describes
// what it finds.
//
// A detached volume reports usable capacity too, from the tag described above,
// which carries the header size that was measured when the volume became a
// container — so a volume with a foreign header is reported correctly whether
// it is attached or not, and Status agrees with itself across an attach without
// ever taking a lock.
//
// One residual: a volume provisioned before the tag existed carries none, and
// reports its backing size while detached. Its next Attach records one, from a
// header read off the container rather than assumed, so a fleet heals one
// attach at a time.
//
// # What a restore preserves
//
// A restore preserves DATA lineage, not header lineage. Which of the two a
// given restore also preserves depends on what the snapshot holds:
//
//   - A PLAINTEXT snapshot restored by a provider configured to encrypt is
//     re-encrypted on the way in. The destination is formatted as a LUKS2
//     container under this provider's key and the image is copied THROUGH the
//     plaintext mapping, so dm-crypt encrypts it in flight and no plaintext is
//     ever written to an extent. The restored volume has a different header
//     from its source — its source had none — and opens with the key
//     KeyProvider returns for the restored volume's own ID.
//
//   - An ENCRYPTED snapshot is ciphertext at the logical-volume level and is
//     copied verbatim, header included, without being reformatted. Reformatting
//     would be destructive rather than merely different: a fresh header carries
//     a fresh master key and the ciphertext copied over it would decrypt to
//     nothing, silently. So the restored volume shares its source's header,
//     master key and UUID, and opens with the SOURCE's passphrase.
//
//     KeyProvider is called with the volume's own ID, so an implementation
//     holding a distinct key per volume has to answer for the restored volume's
//     name with the source's key. That is CHECKED against the snapshot's header
//     before anything is created, rather than discovered at the first Attach —
//     a volume that restores cleanly and cannot be opened is the one outcome
//     this path must not produce.
//
// # Keys
//
// A passphrase never exists as an ordinary []byte. It arrives through a
// KeyProvider callback as a go-enclave MemoryEnclave — mlock'd pages, fenced by
// guard pages, kept out of core dumps and wiped on release — and becomes a
// []byte only inside the WithBytes borrow that hands it to go-luks2 for one
// call, which the provider then destroys. It does not leave the process at all:
// before 2026-08-29 that borrow wrote it to a cryptsetup child's standard
// input, and now there is no child. A []byte would have been
// unfixable: zeroing the slice a caller holds reaches neither the copies the
// garbage collector may have made nor the pages the kernel may have swapped,
// and the material would be in any core dump taken meanwhile.
//
// If the kernel will not lock pages — RLIMIT_MEMLOCK, almost always — the
// operation FAILS with an error naming the limit. It does not fall back to
// unprotected memory, because a silent fallback would leave callers believing in
// a guarantee that had stopped holding.
//
// The provider has no opinion about where a key came from: a TPM-sealed key is
// unsealed by whoever holds the TPM — go-trusted-platform, in this stack — and
// handed over already unsealed, in an enclave. Keeping TPM specifics out of this
// package is what lets the same provider run on hardware that has no TPM, and
// keeps the library free of dependencies its other backends have no use for.
//
// # Concurrency
//
// Every state-changing operation holds a per-volume advisory lock for its whole
// read-decide-act sequence, rollback included. The provider keeps no state of
// its own — it reads the volume group, decides, and acts across several
// commands — so without one, two operations interleave inside that gap and act
// on a world that moved underneath them. Resize reads a volume as detached and
// starts growing it; Attach completes in between; Resize's closing deactivation
// then detaches a volume the other caller was just told it could use.
//
// The lock is an flock on a file per volume under Options.LockDir. That choice
// buys two things a mutex could not. Two Provider values in one process open
// the file separately and so conflict, and two separate DAEMONS over one volume
// group conflict as well — which is not hypothetical, since nothing here stops
// an operator running a second one. It is also released by the kernel when the
// process dies, so a crash mid-operation leaves no volume locked forever.
//
// Locks are taken once at the operation boundary and never nested, and a
// snapshot has no lock of its own: operations touching an origin and its
// snapshot take the ORIGIN's, since a snapshot is created under its origin,
// shares its activation and dies with it. The one operation needing two is a
// restore, which reads one volume's snapshot while creating another; it takes
// both in sorted order, so two such operations cannot each hold one and wait for
// the other.
//
// Status and ListSnapshots take no lock. They change nothing, and a caller
// acting on what they return would be racing whatever happened next however the
// read were synchronized — the lock a transition needs is the one the transition
// takes.
//
// # What a deleted volume leaves behind
//
// LVM does not clear an extent when a volume is deleted, and it does not clear
// one when it allocates it to the next volume either — lvcreate zeroes the first
// few kilobytes, enough that a stale filesystem signature is not detected, not
// enough that the last tenant's data is gone. The extents lvextend adds to a
// growing volume come from the same free pool. Attach hands back the raw logical
// volume for an unencrypted volume, so a caller reading past its filesystem, or
// reading a raw volume at all, can find what a deleted volume wrote there.
//
// Put plainly: an unencrypted volume on non-discarding media retains readable
// data after Delete unless Options.WipeOnDelete is set.
//
// This is LVM's behavior rather than something this provider introduces, and
// how much of it bites depends on the storage: a host with
// devices/issue_discards set to 1 over a backing device that supports discard
// gets zeroed extents for free, because lvremove discards them. LVM's default
// is 0, and rotating disks do not discard at all.
//
// Options.Encrypted is the recommended answer. What survives in a freed extent
// is then ciphertext whose key went away with the LUKS header, and it costs
// nothing at delete time. Options.WipeOnDelete is the direct one for
// deployments that cannot encrypt, zero-filling a volume before removing it so
// extents are clean before anything reuses them; it is off by default because
// zero-filling every deleted volume costs minutes per terabyte on rotating
// disks, which is not a cost to impose on deployments that do not need it.
//
// # What WipeOnDelete does not cover
//
// It covers the volume's CURRENT contents. It does not cover the history a
// snapshot holds.
//
// An LVM classic snapshot's exception store holds the ORIGINAL blocks that were
// overwritten on the origin since the snapshot was taken — real data, not
// bookkeeping. DeleteSnapshot removes that store with lvremove and nothing
// else, so those extents go back to the free pool unwiped, and they do so
// whether or not WipeOnDelete is set. A deployment that wipes every volume it
// deletes can still leave a deleted volume's earlier contents readable in the
// extents its snapshots occupied.
//
// This is not an oversight that a wipe in DeleteSnapshot would close. Both ways
// of reaching the exception store were measured on a loopback LVM harness
// (2026-08-27, LVM 2.03.16), against the only test that counts — read the
// physical extents back after lvremove and look for the plaintext:
//
//   - blkdiscard --zeroout over the visible snapshot device fails with EIO and
//     INVALIDATES the snapshot. The device is origin-sized while the exception
//     store is not, so zeroing it pushes the origin's blocks into a CoW area
//     far too small to hold them. Plaintext survives.
//   - blkdiscard over /dev/mapper/<vg>-<snap>-cow cannot open the device at
//     all: EBUSY while the snapshot exists.
//   - dd of zeroes over that same -cow device EXITS 0, writes the whole device,
//     and leaves the snapshot healthy — and the plaintext still survives.
//     Shipping that would have been worse than shipping nothing, because it
//     would have made the guarantee look kept.
//
// So the honest statement is the one above, and Options.Encrypted is the answer
// here too — more so than for the volume itself. What a snapshot's exception
// store holds on an encrypted volume is ciphertext, and its key went away with
// the LUKS header. If the history has to be unreadable, encrypt; do not reach
// for WipeOnDelete and assume it reached the snapshots.
//
// # Mount targets
//
// A mount target is resolved to a DESCRIPTOR before it is used, with openat2
// refusing to traverse a symlink anywhere along the path, and the mount is then
// performed against that descriptor. Validating a path and handing the string to
// a mount leaves a window in which the path can become a symlink, and the mount
// that follows it is privileged: it lands wherever the link points, including
// over the root filesystem. No amount of checking around a path can close that,
// because the check and the use are separate resolutions of the same name.
//
// This is why mounting does not go through CommandRunner like everything else.
// It is the one pair of operations where the target has to be held, so they go
// through Mounter instead, which mount(2) and umount2(2) reach directly. The
// unmount pins the target's PARENT and passes UMOUNT_NOFOLLOW, since a
// descriptor on the target itself holds the mounted filesystem open and the
// unmount then fails.
//
// A kernel without openat2 — before Linux 5.6 — is refused rather than served by
// the racy path.
//
// # Hostile input
//
// common.VolumeProvider makes the provider responsible for validating the
// free-form strings it is handed, and this one does it with allowlists at the
// API boundary, before any command is built. Volume and snapshot names are
// letters, digits and non-leading hyphens; filesystem types are looked up in a
// table that also decides which mkfs binary runs; mount flags are matched whole
// against a fixed set; mount targets must be clean absolute paths. Everything
// that passes goes to the CommandRunner as individual argv elements, and
// nothing anywhere is escaped and passed on — a value that fails validation is
// rejected with common.ErrInvalidArgument.
//
// # Testing
//
// Every system command goes through CommandRunner and every LUKS operation
// through luksBackend, so the unit tests drive the whole provider against a
// fake and need no root, no LVM and no block device. The LUKS backend is also
// exercised for real without root, by formatting containers onto sparse files
// and reading the headers back — which is where the FIPS parameters and the
// 16 MiB data offset are pinned. Tests that need a real volume group or a real
// plaintext mapping live behind the local_integration build tag.
package local
