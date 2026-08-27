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

package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// defaultSnapshotCoWPercent is the share of the origin's size given to a
// snapshot's copy-on-write area when none is configured.
//
// An LVM classic snapshot is invalidated once its CoW area fills, so the figure
// is a bet on how much of the origin will be rewritten before the snapshot is
// dropped. 20% suits the backup-then-delete pattern the provider is built for;
// a long-lived snapshot over a busy volume wants more, which is what
// Options.SnapshotCoWPercent is for.
const defaultSnapshotCoWPercent = 20

// Provider is the always-compiled VolumeProvider backed by local LVM, with
// optional LUKS2 encryption. See the package documentation for the model it
// implements.
type Provider struct {
	volumeGroup        string
	nodeID             common.NodeID
	runner             CommandRunner
	encrypted          bool
	keyProvider        KeyProvider
	snapshotCoWPercent int
	wipeOnDelete       bool
	lockDir            string
	mounter            Mounter
}

// Ensure the provider satisfies the contract at compile time.
var _ common.VolumeProvider = (*Provider)(nil)

// Options configures a Provider.
type Options struct {
	// VolumeGroup is the LVM volume group every volume is carved out of. It is
	// required, and is validated on the same allowlist as volume names because
	// it too reaches the lvm tools as an argument.
	VolumeGroup string

	// NodeID identifies the host this provider runs on. It defaults to the
	// system hostname. Attach and Detach accept it, or the empty NodeID
	// meaning "here", and reject any other node.
	NodeID common.NodeID

	// Runner executes the system tools. It defaults to an os/exec-backed
	// implementation; tests substitute a fake.
	Runner CommandRunner

	// Mounter mounts and unmounts. It defaults to the pinning implementation
	// described on the Mounter interface; tests substitute a fake.
	Mounter Mounter

	// Encrypted provisions new volumes as LUKS2 containers. It requires
	// KeyProvider. Volumes already on disk are detected by probing rather than
	// by this flag, so a provider with Encrypted false still attaches and
	// mounts an encrypted volume as long as KeyProvider is set.
	//
	// The container is LUKS2 with every cryptographic parameter pinned:
	// PBKDF2-SHA-512, AES-256-XTS, and a 512-bit key. Nothing is left to
	// cryptsetup's compiled-in defaults, which are neither stable across
	// versions nor FIPS-approved — cryptsetup 2.7.0 defaults LUKS2 to argon2id
	// and to a 256-bit key that XTS halves to AES-128. Every volume this
	// provider creates is therefore identical whatever the host prefers, and
	// deployable where FIPS 140-3 is required.
	//
	// PBKDF2 rather than argon2id is the one choice that looks like a
	// downgrade and is not. Argon2's memory-hardness defends a LOW-ENTROPY
	// secret against parallel guessing, and there is no such secret here: the
	// KDF stretches KeyProvider material, which comes from a file or an enclave
	// and is machine-generated, never an interactive human passphrase. What is
	// required fleet-wide is FIPS approval, which argon2id does not have. A
	// caller with a human-chosen passphrase should stretch it where it is
	// entered and hand this provider the result — feeding it in raw uses the
	// wrong layer for the job, whichever KDF sits here.
	//
	// VolumeSpec.SizeBytes sizes the BACKING DEVICE, not the plaintext space on
	// it. A LUKS2 header and its keyslot area live at the front of the container
	// — 16 MiB with cryptsetup's defaults — so the mapping Attach hands back is
	// that much smaller than the volume was asked for, and VolumeStatus.SizeBytes
	// reports the backing device rather than the usable capacity. Size an
	// encrypted volume with that overhead in mind. Whether SizeBytes should
	// instead mean usable capacity is a contract question that reaches every
	// backend with per-volume metadata, not something this provider should
	// settle on its own.
	Encrypted bool

	// KeyProvider supplies LUKS passphrases. It is required when Encrypted is
	// set and when operating on volumes that are already encrypted.
	KeyProvider KeyProvider

	// SnapshotCoWPercent sizes a snapshot's copy-on-write area as a percentage
	// of its origin, between 1 and 100. It defaults to
	// defaultSnapshotCoWPercent.
	SnapshotCoWPercent int

	// LockDir holds the per-volume lock files that serialize state-changing
	// operations. It defaults to DefaultLockDir and is created 0700 on first
	// use.
	//
	// Two Providers over one volume group must share it, and that is the whole
	// point: the lock is what keeps their operations from interleaving. Put it
	// on a filesystem local to the host — the guarantee is between processes on
	// one machine, and a network filesystem's locking is not something to build
	// this on.
	LockDir string

	// WipeOnDelete zero-fills a volume before removing it, so its contents do
	// not survive in the volume group's free extents.
	//
	// Read this before leaving it at its default: AN UNENCRYPTED VOLUME ON
	// NON-DISCARDING MEDIA RETAINS READABLE DATA AFTER Delete UNLESS
	// WipeOnDelete IS SET. Its extents go back to the volume group holding
	// whatever was written to them, and the next volume to be allocated those
	// extents can read it — lvcreate zeroes only the first few kilobytes of a
	// new volume, enough that a stale filesystem signature is not detected, not
	// enough that the last tenant's data is gone. The extents lvextend adds to a
	// growing volume come from the same pool.
	//
	// THE RECOMMENDED MITIGATION IS Encrypted, not this option. What survives in
	// a freed extent is then ciphertext whose key went away with the LUKS header,
	// at none of the cost: a wipe writes the whole volume, which is minutes per
	// terabyte on rotating disks, while encryption costs nothing at delete time.
	// Reach for WipeOnDelete when encryption is not available — volumes that must
	// stay readable by something that cannot unlock them, or a migration off
	// plaintext volumes that already exist.
	//
	// How much the exposure bites depends on the storage. With LVM's
	// devices/issue_discards set to 1 over a backing device that supports
	// discard, lvremove discards the freed extents and they read back as zeroes
	// whatever this option says. The LVM default is 0, and rotating disks do not
	// discard at all, which is the case the option is for. Do not infer from a
	// host where the data happens to be gone that it will be gone on the next
	// one.
	//
	// ONE LIMIT WORTH KNOWING BEFORE RELYING ON THIS: a volume that has been
	// snapshotted keeps some of its history in the volume group even after a
	// wiping delete. A snapshot's copy-on-write area holds the pre-snapshot
	// copies of everything the origin has overwritten since, Delete frees those
	// extents when it removes the snapshot, and there is no way to clear them
	// first — writing through the snapshot device overflows the CoW area rather
	// than clearing it, and the underlying <vg>-<snap>-cow device refuses to
	// open for writing while the snapshot exists. Encrypted is the only complete
	// answer for a volume with snapshots.
	//
	// It defaults to false, matching LVM's own behavior rather than imposing a
	// full-volume zero-fill on every deletion in every deployment.
	WipeOnDelete bool
}

// New creates a Provider from opts.
func New(opts Options) (*Provider, error) {
	if err := validateName("volume group", opts.VolumeGroup); err != nil {
		return nil, err
	}
	if opts.Encrypted && opts.KeyProvider == nil {
		return nil, fmt.Errorf("%w: Encrypted requires a KeyProvider", common.ErrInvalidArgument)
	}

	pct := opts.SnapshotCoWPercent
	if pct == 0 {
		pct = defaultSnapshotCoWPercent
	}
	if pct < 1 || pct > 100 {
		return nil, fmt.Errorf("%w: SnapshotCoWPercent %d is outside 1-100", common.ErrInvalidArgument, pct)
	}

	lockDir := opts.LockDir
	if lockDir == "" {
		lockDir = DefaultLockDir
	}
	if err := validateAbsPath("lock directory", lockDir); err != nil {
		return nil, err
	}

	runner := opts.Runner
	if runner == nil {
		runner = execRunner{}
	}

	mounter := opts.Mounter
	if mounter == nil {
		mounter = systemMounter{}
	}

	node := opts.NodeID
	if node == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("go-blockstore/local: determining node ID: %w", err)
		}
		node = common.NodeID(hostname)
	}

	return &Provider{
		volumeGroup:        opts.VolumeGroup,
		nodeID:             node,
		runner:             runner,
		encrypted:          opts.Encrypted,
		keyProvider:        opts.KeyProvider,
		snapshotCoWPercent: pct,
		wipeOnDelete:       opts.WipeOnDelete,
		lockDir:            lockDir,
		mounter:            mounter,
	}, nil
}

// NodeID reports the node this provider manages volumes on.
func (p *Provider) NodeID() common.NodeID { return p.nodeID }

// Provision creates a logical volume, optionally wrapping it in a LUKS2
// container and creating a filesystem on it.
//
// The volume is left inactive: Provision produces an available volume, and it
// takes Attach to turn it into a block device on this host. A failure partway
// through removes the logical volume again rather than leaving a half-built one
// behind for the next Provision to trip over with ErrAlreadyExists.
func (p *Provider) Provision(ctx context.Context, spec common.VolumeSpec) (common.Volume, error) {
	if err := validateName("volume", spec.Name); err != nil {
		return common.Volume{}, err
	}
	if err := validateFSType(spec.FSType); err != nil {
		return common.Volume{}, err
	}
	if spec.SizeBytes <= 0 {
		return common.Volume{}, fmt.Errorf("%w: SizeBytes must be positive, got %d", common.ErrInvalidArgument, spec.SizeBytes)
	}
	// Negative is malformed rather than unsupported: VolumeSpec.Replicas
	// defines 0 and 1 as the non-replicated request and counts upward from
	// there, so a negative count is not a number of replicas any provider could
	// serve. Falling through would provision a volume for a request nobody
	// meant.
	// This backend carves every volume out of one configured volume group and
	// has no notion of tiers, so it cannot honor a storage class. Taking one and
	// ignoring it would return a Volume whose Spec names a class the volume is
	// not on — the same untruth as accepting an FSType on a restore. It is
	// ErrUnsupported rather than malformed input: the request is well formed,
	// and a backend with tiers could serve it.
	if spec.StorageClass != "" {
		return common.Volume{}, fmt.Errorf("%w: the local provider has no storage classes; volume group %q backs every volume, and StorageClass %q cannot be honored",
			common.ErrUnsupported, p.volumeGroup, spec.StorageClass)
	}
	if spec.Replicas < 0 {
		return common.Volume{}, fmt.Errorf("%w: Replicas must not be negative, got %d", common.ErrInvalidArgument, spec.Replicas)
	}
	if spec.Replicas > 1 {
		return common.Volume{}, fmt.Errorf("%w: the local provider does not replicate; Replicas=%d", common.ErrUnsupported, spec.Replicas)
	}
	if spec.SourceSnapshotID != "" {
		if err := validateSnapshotID(spec.SourceSnapshotID); err != nil {
			return common.Volume{}, err
		}
		// A restore copies the snapshot's image, filesystem and all, so there is
		// nothing for FSType to select. Accepting it and ignoring it would hand
		// back a Volume whose Spec says "xfs" over an ext4 image — a description
		// of the volume that is simply untrue, and one a caller has every reason
		// to believe.
		if spec.FSType != "" {
			return common.Volume{}, fmt.Errorf("%w: FSType %q cannot be applied to a restore from %q; "+
				"the restored volume carries the snapshot's filesystem",
				common.ErrInvalidArgument, spec.FSType, spec.SourceSnapshotID)
		}
	}

	// The new volume, and on a restore the volume that owns the source
	// snapshot: reading that snapshot activates its origin, so the origin's own
	// operations have to be held off for the duration. lockVolumes sorts and
	// deduplicates, so the pair is always taken in the same order and a restore
	// into the origin's own name takes one lock rather than blocking on itself.
	locked := []string{spec.Name}
	if spec.SourceSnapshotID != "" {
		owner, _, _ := splitSnapshotID(string(spec.SourceSnapshotID))
		locked = append(locked, owner)
	}
	release, err := p.lockVolumes(ctx, locked...)
	if err != nil {
		return common.Volume{}, err
	}
	defer release()

	lvs, err := p.listLVs(ctx)
	if err != nil {
		return common.Volume{}, err
	}
	if _, exists := lookupLV(lvs, spec.Name); exists {
		return common.Volume{}, fmt.Errorf("%w: volume %q", common.ErrAlreadyExists, spec.Name)
	}

	if spec.SourceSnapshotID != "" {
		return p.provisionFromSnapshot(ctx, spec, lvs)
	}

	if err := p.createLV(ctx, spec.Name, spec.SizeBytes); err != nil {
		return common.Volume{}, err
	}

	if err := p.buildVolume(ctx, spec); err != nil {
		return common.Volume{}, errors.Join(err, p.abandon(ctx, spec.Name))
	}

	// The closing deactivation is part of provisioning, so its failure rolls
	// back like any other. Returning the error and keeping the volume would
	// leave a caller that was told the request failed getting ErrAlreadyExists
	// when it retried.
	if err := p.deactivate(ctx, spec.Name); err != nil {
		return common.Volume{}, errors.Join(err, p.abandon(ctx, spec.Name))
	}
	return common.Volume{ID: spec.Name, Spec: spec}, nil
}

// buildVolume applies encryption and the filesystem to a freshly created
// logical volume, leaving no LUKS mapping open behind it.
func (p *Provider) buildVolume(ctx context.Context, spec common.VolumeSpec) error {
	device := p.lvPath(spec.Name)

	if p.encrypted {
		if err := p.luksFormat(ctx, spec.Name, device); err != nil {
			return err
		}
		if err := p.luksOpen(ctx, spec.Name, device); err != nil {
			return err
		}
		device = p.cryptPath(spec.Name)
	}

	if spec.FSType != "" {
		if err := p.mkfs(ctx, spec.FSType, device); err != nil {
			if p.encrypted {
				_ = p.luksClose(ctx, spec.Name)
			}
			return err
		}
	}

	if p.encrypted {
		return p.luksClose(ctx, spec.Name)
	}
	return nil
}

// abandon removes a logical volume that failed to finish provisioning. Errors
// are returned for the caller to join onto the failure that caused the
// rollback, never in place of it: the original failure is what explains what
// went wrong, and a cleanup error that replaced it would send the reader after
// the wrong thing. A rollback that could not finish still has to be reportable,
// because it leaves a volume behind.
//
// An encrypted volume has its mapping torn down first. lvremove refuses a
// logical volume with an open dm-crypt mapping over it, so a rollback that went
// straight to lvremove would fail silently over exactly the case that needs it —
// a cryptsetup close that did not work — and leave behind the half-built volume
// whose whole purpose here is to disappear.
func (p *Provider) abandon(ctx context.Context, name string) error {
	var closeErr error
	if p.encrypted {
		// Through luksIsOpen, so the rollback inherits the ownership check
		// rather than working around it. Closing by name alone would tear down
		// a stale or hand-made mapping sitting under this volume's
		// deterministic name — a mapping over somebody else's device, which
		// this provision never opened and has no business closing. It is also
		// the case where the close is least likely to be needed: a rollback
		// reaches here after a FAILED open.
		open, err := p.luksIsOpen(ctx, name)
		switch {
		case err != nil:
			closeErr = err
		case open:
			closeErr = p.luksClose(ctx, name)
		}
	}
	return errors.Join(closeErr, p.removeLV(ctx, name))
}

// provisionFromSnapshot creates an independent volume holding a snapshot's
// contents.
//
// The copy is a full byte-for-byte transfer rather than an LVM snapshot of the
// snapshot, because a restored volume that stayed dependent on the snapshot
// would die with it — and the point of restoring is to get something that
// outlives the snapshot. The consequence worth knowing: restoring an encrypted
// volume reproduces its LUKS header exactly, so the copy shares the original's
// master key and UUID, and the same KeyProvider passphrase unlocks both.
func (p *Provider) provisionFromSnapshot(ctx context.Context, spec common.VolumeSpec, lvs []lvInfo) (common.Volume, error) {
	snapID := string(spec.SourceSnapshotID)
	snap, ok := lookupLV(lvs, snapID)
	if !ok || !ownsSnapshot(snap) {
		return common.Volume{}, fmt.Errorf("%w: %q", common.ErrSnapshotNotFound, snapID)
	}
	origin, ok := lookupLV(lvs, snap.Origin)
	if !ok {
		return common.Volume{}, fmt.Errorf("go-blockstore/local: snapshot %q names origin %q, which does not exist", snapID, snap.Origin)
	}

	// The IMAGE size, taken from the snapshot, not the origin's size today. LVM
	// lets an origin with snapshots be grown while it is inactive — the state
	// this provider leaves volumes in — so the two diverge in ordinary use, and
	// every decision here is about the bytes the snapshot presents. Measured:
	// after growing a 64 MiB origin to 192 MiB, the snapshot still presented
	// 64 MiB while the origin's own size read 192 MiB. Sizing from the origin
	// would reject a restore correctly sized for the image, and would start the
	// tail zeroing 128 MiB past what dd actually copied — leaving exactly the
	// stale extents that zeroing exists to remove.
	imageSize := snap.OriginSizeBytes
	if spec.SizeBytes < imageSize {
		return common.Volume{}, fmt.Errorf("%w: restoring %q needs at least %d bytes, spec asks for %d and this provider does not shrink during restore",
			common.ErrUnsupported, snapID, imageSize, spec.SizeBytes)
	}

	// A restore is a byte copy, so the restored volume is encrypted exactly when
	// its source was. On a provider configured to encrypt, copying a plaintext
	// snapshot would hand back a plaintext volume under a configuration whose
	// whole point is that it does not do that — silently, since nothing else in
	// the call says otherwise. Refused rather than served.
	if p.encrypted {
		if err := p.requireEncryptedSource(ctx, snapID, origin); err != nil {
			return common.Volume{}, err
		}
	}

	if err := p.createLV(ctx, spec.Name, spec.SizeBytes); err != nil {
		return common.Volume{}, err
	}

	if err := p.copySnapshot(ctx, snapID, origin, spec.Name); err != nil {
		return common.Volume{}, errors.Join(err, p.abandon(ctx, spec.Name))
	}

	// Restoring into a volume larger than the snapshot leaves everything past
	// the copied image holding whatever the volume group's free extents held —
	// the same stale data a fresh volume would expose, arriving through a path
	// that looks like it wrote the whole device. dd copies the origin's size and
	// stops, so the tail is zeroed explicitly.
	//
	// An exact-size restore has no tail and is left alone. An origin's size is a
	// whole number of extents by construction, so asking for exactly that size
	// yields exactly that volume with nothing past the image — and issuing a
	// zero-length zeroout there would make the ordinary restore depend on how
	// the kernel and the device handle an operation at EOF.
	if spec.SizeBytes > imageSize {
		if err := p.zeroTail(ctx, spec.Name, imageSize); err != nil {
			return common.Volume{}, errors.Join(err, p.abandon(ctx, spec.Name))
		}
	}

	if err := p.deactivate(ctx, spec.Name); err != nil {
		return common.Volume{}, errors.Join(err, p.abandon(ctx, spec.Name))
	}
	return common.Volume{ID: spec.Name, Spec: spec}, nil
}

// requireEncryptedSource refuses a restore that would produce a plaintext volume
// on a provider configured to encrypt.
//
// The check runs before anything is created, so a refusal leaves no volume
// behind and — the part that matters — never writes the plaintext to extents it
// would then have to free. Encrypting during the restore instead would mean
// re-encrypting the image under this provider's key as it is copied, which gives
// the restored volume a different LUKS header from the one it was taken from;
// that is a change in what a restore MEANS, not an implementation detail, so it
// is a decision for the owner rather than something to slip in here.
func (p *Provider) requireEncryptedSource(ctx context.Context, snapID string, origin lvInfo) (err error) {
	originWasActive := origin.active()
	if activateErr := p.activate(ctx, snapID); activateErr != nil {
		return activateErr
	}
	defer func() {
		err = errors.Join(err, p.restoreOriginActivation(ctx, origin.Name, originWasActive))
	}()

	fsType, probeErr := p.probeFSType(ctx, p.lvPath(snapID))
	if probeErr != nil {
		return probeErr
	}
	if fsType == fsTypeLUKS {
		return nil
	}
	return fmt.Errorf("%w: this provider is configured to encrypt, and restoring from %q would copy a plaintext volume; "+
		"restore with an unencrypted provider, or take the snapshot from an encrypted volume",
		common.ErrUnsupported, snapID)
}

// copySnapshot transfers a snapshot's contents onto a new logical volume, with
// both activated for the duration and the origin put back as it was found.
//
// LVM activates an origin and its snapshots as a single unit — measured on LVM
// 2.03.16, activating a snapshot brings its origin up, and deactivating the
// snapshot takes the origin back down. Reading a snapshot therefore moves the
// origin whether or not anyone asked it to, in both directions: over a detached
// origin it exposes a device the caller never attached, and over an attached one
// the closing deactivation pulls /dev/<vg>/<origin> out from under whoever is
// using it, mounted filesystem included. So the origin's activation is captured
// before the copy and restored after it, rather than the snapshot simply being
// switched off.
func (p *Provider) copySnapshot(ctx context.Context, snapID string, origin lvInfo, volID string) (err error) {
	originWasActive := origin.active()

	if activateErr := p.activate(ctx, snapID); activateErr != nil {
		return activateErr
	}
	// Joined onto the named return rather than dropped: failing to put the
	// origin back is not cosmetic, it leaves a volume the caller believes is
	// detached still active, or one it believes is attached gone.
	defer func() {
		err = errors.Join(err, p.restoreOriginActivation(ctx, origin.Name, originWasActive))
	}()

	if activateErr := p.activate(ctx, volID); activateErr != nil {
		return activateErr
	}

	_, err = p.runner.Run(ctx, nil, "dd",
		"if="+p.lvPath(snapID),
		"of="+p.lvPath(volID),
		"bs=4M",
		"conv=fsync",
		"status=none",
	)
	if err != nil {
		return fmt.Errorf("go-blockstore/local: copying snapshot %q into %q: %w", snapID, volID, err)
	}
	return nil
}

// zeroTail clears everything past offset on a freshly restored volume.
//
// What this guarantees is that the extents beyond the copied image no longer
// hold what a PREVIOUS tenant wrote there. They came out of the volume group's
// free pool carrying it, dd stops at the image, and without this the restore
// would hand those bytes to the new volume's owner. That is a confidentiality
// property and the zeros are written where it lives: on the logical volume.
//
// It deliberately does NOT mean the plaintext view past the image reads as
// zeros on an encrypted volume — zeros written to the container decrypt to
// arbitrary bytes, and writing through the mapping instead would only move
// which layer sees zeros while costing a passphrase borrow and a full
// encrypted rewrite of the tail. Nothing needs that. Unwritten space inside a
// LUKS container ALWAYS decrypts to garbage; it is the normal state of every
// encrypted volume this provider freshly provisions, and no caller can read
// meaning into it. The stale-data hazard is the one that was real, and it is on
// the disk, not in the mapping.
//
// The offset is a whole number of LVM extents — it is the origin's size — so it
// is aligned well past anything blkdiscard requires. The volume is activated for
// the write and put back afterwards, in the state Provision hands it over in.
func (p *Provider) zeroTail(ctx context.Context, volID string, offset int64) (err error) {
	if activateErr := p.activate(ctx, volID); activateErr != nil {
		return activateErr
	}
	defer func() {
		err = errors.Join(err, p.deactivate(ctx, volID))
	}()

	_, runErr := p.runner.Run(ctx, nil, "blkdiscard", "--zeroout",
		"--offset", strconv.FormatInt(offset, 10), p.lvPath(volID))
	if runErr != nil {
		return fmt.Errorf("go-blockstore/local: zeroing %s past %d bytes: %w", p.lvRef(volID), offset, runErr)
	}
	return nil
}

// ownsSnapshot reports whether a logical volume is a snapshot this provider
// created: named the way it names them, AND actually a snapshot of the volume
// that name encodes.
//
// Both halves are required. A volume group is shared, so it can hold a snapshot
// created out of band whose name happens to match the pattern while its origin
// is some other volume — and trusting the name alone would let DeleteSnapshot
// remove it and let a restore copy the wrong volume's data into a volume the
// caller thinks it restored from a snapshot of its own.
//
// The name is put through validateSnapshotID rather than re-checked here, so
// that what ListSnapshots reports and what DeleteSnapshot and a restore accept
// cannot drift apart. They did: splitSnapshotID cuts at the FIRST separator, so
// an out-of-band "data_snap_daily_snap_manual" over origin "data" parses with a
// matching owner while its second half holds an underscore that validateName
// refuses — listed as a snapshot, rejected by every method that could act on it.
func ownsSnapshot(lv lvInfo) bool {
	owner, _, ok := splitSnapshotID(lv.Name)
	if !ok || lv.Origin == "" || lv.Origin != owner {
		return false
	}
	return validateSnapshotID(common.SnapshotID(lv.Name)) == nil
}

// restoreOriginActivation puts a snapshot's origin back into the activation
// state a restore found it in. Acting on the origin rather than the snapshot is
// what makes it work in both directions, since the two move together.
//
// The ORIGIN is the only state worth restoring, and the snapshot's cannot be
// restored separately anyway. Measured on LVM 2.03.16, an origin and its
// snapshots are one activation unit in both directions: bringing the origin up
// brings every snapshot of it up unasked, and taking a snapshot down takes the
// origin down with it — the origin's device node disappears.
//
// Both halves matter here. Over an origin that was already active, the snapshot
// was already active too, before this code ran, so a restore leaves nothing
// behind that it created. And deactivating the snapshot to "tidy up" would
// detach the origin underneath whoever is using it, which is the failure this
// function exists to prevent, not a refinement of it.
func (p *Provider) restoreOriginActivation(ctx context.Context, origin string, wasActive bool) error {
	if wasActive {
		return p.activate(ctx, origin)
	}
	return p.deactivate(ctx, origin)
}

// mkfs creates a filesystem on the device.
//
// The binary comes from the mkfsBinaries table rather than from concatenating
// the caller's FSType onto "mkfs.", so an unsupported type is a rejected
// request and never a choice of which program to run. The force flag is
// required: the device may carry a signature from a previous life, and mkfs
// would otherwise stop to ask a question no library call can answer.
func (p *Provider) mkfs(ctx context.Context, fsType, device string) error {
	binary, ok := mkfsBinaries[fsType]
	if !ok {
		return fmt.Errorf("%w: filesystem type %q is not supported", common.ErrInvalidArgument, fsType)
	}
	force := "-F"
	if fsType == "xfs" {
		force = "-f"
	}
	if _, err := p.runner.Run(ctx, nil, binary, force, device); err != nil {
		return fmt.Errorf("go-blockstore/local: creating %s filesystem on %s: %w", fsType, device, err)
	}
	return nil
}

// Attach activates the volume on this node and, when it holds a LUKS
// container, unlocks it — the device path returned is the plaintext mapping in
// that case, so a caller never has to know whether a volume is encrypted.
func (p *Provider) Attach(ctx context.Context, volID string, node common.NodeID) (common.AttachInfo, error) {
	if err := validateName("volume", volID); err != nil {
		return common.AttachInfo{}, err
	}
	if err := p.checkNode(node); err != nil {
		return common.AttachInfo{}, err
	}

	release, lockErr := p.lockVolumes(ctx, volID)
	if lockErr != nil {
		return common.AttachInfo{}, lockErr
	}
	defer release()
	lvs, err := p.listLVs(ctx)
	if err != nil {
		return common.AttachInfo{}, err
	}
	lv, exists := lookupLV(lvs, volID)
	if !exists {
		return common.AttachInfo{}, fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	}

	wasActive := lv.active()
	if activateErr := p.activate(ctx, volID); activateErr != nil {
		return common.AttachInfo{}, activateErr
	}

	device, err := p.unlockForAttach(ctx, volID)
	if err != nil {
		// A failed Attach leaves nothing behind. Unlocking can fail after
		// activation succeeded — a wrong key, a cryptsetup that will not run —
		// and a volume left active after an error the caller saw as a failure
		// is state nobody knows to clean up. The rollback is skipped when the
		// volume was already active on the way in, since that activation
		// belongs to whoever attached it first.
		if !wasActive {
			err = errors.Join(err, p.deactivate(ctx, volID))
		}
		return common.AttachInfo{}, err
	}

	return common.AttachInfo{DevicePath: device, Node: p.nodeID}, nil
}

// unlockForAttach resolves an activated volume to the device a caller can
// mount, unlocking its LUKS container along the way when it has one.
func (p *Provider) unlockForAttach(ctx context.Context, volID string) (string, error) {
	fsType, err := p.probeFSType(ctx, p.lvPath(volID))
	if err != nil {
		return "", err
	}
	if fsType != fsTypeLUKS {
		return p.lvPath(volID), nil
	}

	open, err := p.luksIsOpen(ctx, volID)
	if err != nil {
		return "", err
	}
	if !open {
		if err := p.luksOpen(ctx, volID, p.lvPath(volID)); err != nil {
			return "", err
		}
	}
	return p.cryptPath(volID), nil
}

// Detach locks the volume's LUKS container, if it has one, and deactivates the
// logical volume. A volume still mounted cannot be deactivated; unmount first.
func (p *Provider) Detach(ctx context.Context, volID string, node common.NodeID) error {
	if err := validateName("volume", volID); err != nil {
		return err
	}
	if err := p.checkNode(node); err != nil {
		return err
	}

	release, lockErr := p.lockVolumes(ctx, volID)
	if lockErr != nil {
		return lockErr
	}
	defer release()
	lvs, err := p.listLVs(ctx)
	if err != nil {
		return err
	}
	lv, exists := lookupLV(lvs, volID)
	if !exists {
		return fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	}
	if !lv.active() {
		return nil
	}

	if err := p.closeIfEncrypted(ctx, volID); err != nil {
		return err
	}
	return p.deactivate(ctx, volID)
}

// closeIfEncrypted tears down the volume's LUKS mapping when it has one.
//
// Whether to involve cryptsetup at all is decided by probing the logical
// volume, not by the Encrypted option: a host that runs only plain volumes
// never invokes cryptsetup and so does not need it installed.
func (p *Provider) closeIfEncrypted(ctx context.Context, volID string) error {
	fsType, err := p.probeFSType(ctx, p.lvPath(volID))
	if err != nil {
		return err
	}
	if fsType != fsTypeLUKS {
		return nil
	}
	open, err := p.luksIsOpen(ctx, volID)
	if err != nil {
		return err
	}
	if !open {
		return nil
	}
	return p.luksClose(ctx, volID)
}

// Mount mounts an attached volume at target.
func (p *Provider) Mount(ctx context.Context, volID, target string, opts common.MountOptions) error {
	if err := validateName("volume", volID); err != nil {
		return err
	}
	if err := validateTarget(target); err != nil {
		return err
	}
	if err := validateFSType(opts.FSType); err != nil {
		return err
	}
	if err := validateMountFlags(opts.ReadOnly, opts.Flags); err != nil {
		return err
	}

	release, lockErr := p.lockVolumes(ctx, volID)
	if lockErr != nil {
		return lockErr
	}
	defer release()
	lvs, err := p.listLVs(ctx)
	if err != nil {
		return err
	}
	lv, exists := lookupLV(lvs, volID)
	if !exists {
		return fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	}

	device, err := p.attachedDevice(ctx, volID, lv)
	if err != nil {
		return err
	}
	if device == "" {
		return fmt.Errorf("%w: volume %q is not attached on %q", common.ErrNotAttached, volID, p.nodeID)
	}

	fsType := opts.FSType
	if fsType == "" {
		if fsType, err = p.probeFSType(ctx, device); err != nil {
			return err
		}
	}
	// mount(2) needs the type named; there is no auto-detection behind it the
	// way mount(8) has one. The probe above supplies it for a formatted volume,
	// and a volume with nothing on it has nothing to mount.
	if fsType == "" {
		return fmt.Errorf("%w: volume %q carries no filesystem to mount", common.ErrInvalidArgument, volID)
	}

	flags, data := mountArguments(opts)
	return p.mounter.Mount(ctx, device, target, fsType, flags, data)
}

// Unmount unmounts the volume from target, converging rather than failing when
// the volume is not mounted there: an unattached volume, a target that is not a
// mountpoint, and a target mounted from some other device all return nil, so a
// teardown path can call this without first working out how far setup got.
func (p *Provider) Unmount(ctx context.Context, volID, target string) error {
	if err := validateName("volume", volID); err != nil {
		return err
	}
	if err := validateTarget(target); err != nil {
		return err
	}

	release, lockErr := p.lockVolumes(ctx, volID)
	if lockErr != nil {
		return lockErr
	}
	defer release()
	lvs, err := p.listLVs(ctx)
	if err != nil {
		return err
	}
	lv, exists := lookupLV(lvs, volID)
	if !exists {
		return fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	}

	device, err := p.attachedDevice(ctx, volID, lv)
	if err != nil {
		return err
	}
	if device == "" {
		return nil
	}

	mounts, err := p.mountpointsFor(ctx, p.sourceAliases(volID, device))
	if err != nil {
		return err
	}
	if !contains(mounts, target) {
		return nil
	}
	return p.umount(ctx, target)
}

func (p *Provider) umount(ctx context.Context, target string) error {
	return p.mounter.Unmount(ctx, target)
}

// Resize grows the volume to newSize bytes and, where it can, grows what sits
// on top of it: the LUKS mapping when the volume is unlocked, and the
// filesystem when one is present and its tooling can grow it in the volume's
// current state.
//
// Shrinking returns ErrUnsupported. LVM can shrink a logical volume, but doing
// so under a filesystem that has not been shrunk first destroys data, and a
// provider that cannot verify the filesystem was prepared has no business
// making that call.
//
// LVM allocates in whole extents, so the volume can end up slightly larger than
// newSize. It is never smaller. The shrink test is made against newSize rounded
// up the same way, so repeating a request LVM has already rounded is a no-op
// rather than a rejected shrink.
//
// Resize is written to converge on repetition. It grows the mapping and the
// filesystem even when the block device is already large enough, because that
// is the state a previous call leaves behind when lvextend succeeded and the
// filesystem growth after it did not; returning early there would report
// success over a filesystem still at its old size.
func (p *Provider) Resize(ctx context.Context, volID string, newSize int64) error {
	if err := validateName("volume", volID); err != nil {
		return err
	}
	if newSize <= 0 {
		return fmt.Errorf("%w: newSize must be positive, got %d", common.ErrInvalidArgument, newSize)
	}

	release, lockErr := p.lockVolumes(ctx, volID)
	if lockErr != nil {
		return lockErr
	}
	defer release()
	lvs, err := p.listLVs(ctx)
	if err != nil {
		return err
	}
	lv, exists := lookupLV(lvs, volID)
	if !exists {
		return fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	}

	extent, err := p.extentSize(ctx)
	if err != nil {
		return err
	}
	// A size that cannot survive being rounded up is malformed input rather than
	// an unsupported operation: no backend could serve it, and the caller has to
	// change the number rather than pick another provider.
	if limit := maxRoundableBytes(extent); newSize > limit {
		return fmt.Errorf("%w: newSize %d exceeds the largest size representable after rounding to this volume group's %d-byte extents, %d",
			common.ErrInvalidArgument, newSize, extent, limit)
	}
	target := roundUpToExtent(newSize, extent)
	if target < lv.SizeBytes {
		return fmt.Errorf("%w: shrinking %q from %d to %d bytes", common.ErrUnsupported, volID, lv.SizeBytes, target)
	}

	if target > lv.SizeBytes {
		_, err = p.runner.Run(ctx, nil, "lvextend", "--size", strconv.FormatInt(newSize, 10)+"b", p.lvRef(volID))
		if err != nil {
			return fmt.Errorf("go-blockstore/local: growing %s: %w", p.lvRef(volID), err)
		}
	}

	device, err := p.attachedDevice(ctx, volID, lv)
	if err != nil {
		return err
	}
	if device == "" {
		return p.growDetachedFilesystem(ctx, volID)
	}
	if device == p.cryptPath(volID) {
		if err := p.luksResize(ctx, volID); err != nil {
			return err
		}
	}
	return p.growFilesystem(ctx, volID, device)
}

// growDetachedFilesystem grows the filesystem on a volume that is not attached,
// activating it just long enough to do so and putting it back afterwards.
//
// Without this, an ext filesystem on a detached volume would be left at its old
// size while its block device grew — which contradicts both this provider's own
// documentation and VolumeProvider.Resize, and hands the caller a volume that
// looks resized until it mounts it. Growing it here rather than making the
// caller attach first is what lets Resize mean the same thing in both states.
//
// An encrypted volume is unlocked for the duration and locked again afterwards.
// Skipping it would be the worse of the two options available: Attach only opens
// the container, it does not grow what is inside one, so a volume left this way
// keeps its old filesystem indefinitely behind a block device that says
// otherwise — and Resize would have reported success for it.
func (p *Provider) growDetachedFilesystem(ctx context.Context, volID string) (err error) {
	if activateErr := p.activate(ctx, volID); activateErr != nil {
		return activateErr
	}
	defer func() {
		err = errors.Join(err, p.deactivate(ctx, volID))
	}()

	fsType, probeErr := p.probeFSType(ctx, p.lvPath(volID))
	if probeErr != nil {
		return probeErr
	}
	if fsType == fsTypeLUKS {
		return p.growDetachedEncryptedFilesystem(ctx, volID)
	}
	return p.growFilesystem(ctx, volID, p.lvPath(volID))
}

// growDetachedEncryptedFilesystem opens a locked container just long enough to
// grow the filesystem inside it, and locks it again on the way out.
//
// The mapping needs no cryptsetup resize. It is opened here, after the logical
// volume has already grown, and cryptsetup sizes a mapping to the device it
// finds — measured on cryptsetup 2.7.0, growing a 64 MiB volume to 128 MiB and
// re-opening took the mapping from 50331648 to 117440512 bytes with no resize
// asked for. Issuing one anyway would borrow the passphrase a second time to
// achieve nothing, and every borrow is an exposure this package works to avoid.
//
// This is also the one path that unlocks a volume the caller had locked. It is
// justified by the alternative, which is reporting success over a filesystem
// that was never grown, and the volume ends the operation exactly as it was
// found: locked, and deactivated by the caller of this function.
func (p *Provider) growDetachedEncryptedFilesystem(ctx context.Context, volID string) (err error) {
	if openErr := p.luksOpen(ctx, volID, p.lvPath(volID)); openErr != nil {
		return openErr
	}
	defer func() {
		err = errors.Join(err, p.luksClose(ctx, volID))
	}()

	return p.growFilesystem(ctx, volID, p.cryptPath(volID))
}

// growFilesystem extends the filesystem on device to fill it.
//
// ext2/3/4 grow either way, but not by the same route. Mounted, resize2fs grows
// the filesystem online. Unmounted, it REFUSES until the filesystem has been
// checked — measured on e2fsprogs 1.47.0, an offline resize2fs answers "Please
// run 'e2fsck -f <device>' first." and exits 1 even for a filesystem whose own
// state field reads clean — so the check is run first, and only when the device
// is genuinely unmounted. Running e2fsck against a MOUNTED filesystem would
// corrupt it, which is why this decides from the mount table rather than from a
// flag.
//
// XFS grows only through xfs_growfs against a live mountpoint, so an unmounted
// XFS volume is left for the caller to grow after mounting; the block device is
// already the new size, which is the part Resize is responsible for. A raw
// volume, or one carrying a filesystem this provider does not manage, is left
// alone.
func (p *Provider) growFilesystem(ctx context.Context, volID, device string) error {
	fsType, err := p.probeFSType(ctx, device)
	if err != nil {
		return err
	}
	if fsType == "" {
		return nil
	}

	mounts, err := p.mountpointsFor(ctx, p.sourceAliases(volID, device))
	if err != nil {
		return err
	}

	switch fsType {
	case "ext2", "ext3", "ext4":
		if len(mounts) == 0 {
			if err := p.checkExtFilesystem(ctx, device); err != nil {
				return err
			}
		}
		if _, err := p.runner.Run(ctx, nil, "resize2fs", device); err != nil {
			return fmt.Errorf("go-blockstore/local: growing %s filesystem on %s: %w", fsType, device, err)
		}
	case "xfs":
		if len(mounts) == 0 {
			return nil
		}
		if _, err := p.runner.Run(ctx, nil, "xfs_growfs", mounts[0]); err != nil {
			return fmt.Errorf("go-blockstore/local: growing xfs filesystem at %s: %w", mounts[0], err)
		}
	}
	return nil
}

// e2fsckCorrected is the exit status e2fsck uses for "errors were found and
// fixed". Together with 0 it is a filesystem that can now be resized; 2 and
// above mean errors it could not fix, an operational failure, or a check that
// did not finish, none of which should be followed by a resize.
const e2fsckCorrected = 1

// checkExtFilesystem runs the forced check resize2fs demands before an offline
// grow.
//
// -f forces it even on a filesystem marked clean, which is what resize2fs is
// asking for. -p makes it non-interactive, fixing only what can be fixed
// without a question — there is nobody to answer one, and the alternative is a
// command that blocks forever holding a volume open.
func (p *Provider) checkExtFilesystem(ctx context.Context, device string) error {
	_, err := p.runner.Run(ctx, nil, "e2fsck", "-f", "-p", device)
	if err == nil {
		return nil
	}
	if exitErr, ok := asExitError(err); ok && exitErr.Code == e2fsckCorrected {
		return nil
	}
	return fmt.Errorf("go-blockstore/local: checking the filesystem on %s before growing it: %w", device, err)
}

// Snapshot takes a copy-on-write snapshot of the volume.
//
// The snapshot's ID is the logical volume name it was created under,
// "<volume>_snap_<name>", which is what makes the volume/snapshot pairing
// recoverable from a bare LVM listing — including by a later process that never
// saw the Snapshot call.
func (p *Provider) Snapshot(ctx context.Context, volID, name string) (common.SnapshotID, error) {
	if err := validateName("volume", volID); err != nil {
		return "", err
	}
	if err := validateName("snapshot", name); err != nil {
		return "", err
	}

	// The ORIGIN's lock covers the snapshot too. A snapshot has no independent
	// existence — it is created under its origin, shares its activation, and
	// dies with it — so one lock on the origin serializes every operation that
	// can touch either, and there is never a second lock to order against.
	release, lockErr := p.lockVolumes(ctx, volID)
	if lockErr != nil {
		return "", lockErr
	}
	defer release()
	lvs, err := p.listLVs(ctx)
	if err != nil {
		return "", err
	}
	if _, exists := lookupLV(lvs, volID); !exists {
		return "", fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	}

	snapLV := volID + snapSeparator + name
	if _, exists := lookupLV(lvs, snapLV); exists {
		return "", fmt.Errorf("%w: snapshot %q of volume %q", common.ErrAlreadyExists, name, volID)
	}

	// A snapshot gets no --setautoactivation: lvcreate rejects the flag
	// outright for snapshots ("unsupported with snapshots"). It is not needed
	// either, because a snapshot's activation is tied to its origin's, and the
	// origin was created with autoactivation off.
	_, err = p.runner.Run(ctx, nil, "lvcreate",
		"--snapshot",
		"--yes",
		"--name", snapLV,
		"--extents", strconv.Itoa(p.snapshotCoWPercent)+"%ORIGIN",
		p.lvRef(volID),
	)
	if err != nil {
		return "", fmt.Errorf("go-blockstore/local: snapshotting %s: %w", p.lvRef(volID), err)
	}
	return common.SnapshotID(snapLV), nil
}

// ListSnapshots returns the volume's snapshots, newest-first order not
// guaranteed. A volume with none yields an empty slice and a nil error.
//
// Like Status it takes no lock and reports a moment: it is one lvs read and
// changes nothing.
//
// SizeBytes is the space each snapshot occupies — its copy-on-write area scaled
// by how much of that area has been written — and so grows as the origin
// diverges. It is not the origin's capacity.
func (p *Provider) ListSnapshots(ctx context.Context, volID string) ([]common.SnapshotInfo, error) {
	if err := validateName("volume", volID); err != nil {
		return nil, err
	}

	lvs, err := p.listLVs(ctx)
	if err != nil {
		return nil, err
	}
	if _, exists := lookupLV(lvs, volID); !exists {
		return nil, fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	}

	snapshots := make([]common.SnapshotInfo, 0)
	for _, lv := range lvs {
		if lv.Origin != volID {
			continue
		}
		// Only snapshots this provider named. A volume group is a shared place
		// and can hold snapshots of this volume taken by hand or by other
		// tooling; reporting one would hand the caller an ID that
		// DeleteSnapshot and SourceSnapshotID then reject as malformed, which is
		// an API that lists what it will not act on. Filtering here rather than
		// widening those methods is the safe direction: the alternative lets a
		// caller delete a snapshot somebody else is relying on.
		if !ownsSnapshot(lv) {
			continue
		}
		_, name, _ := splitSnapshotID(lv.Name)
		snapshots = append(snapshots, common.SnapshotInfo{
			ID:        common.SnapshotID(lv.Name),
			VolumeID:  volID,
			Name:      name,
			CreatedAt: lv.CreatedAt,
			SizeBytes: lv.usedBytes(),
		})
	}
	return snapshots, nil
}

// DeleteSnapshot removes a snapshot. Volumes restored from it are unaffected:
// a restore is a full copy, so nothing keeps depending on the snapshot once it
// has been made.
func (p *Provider) DeleteSnapshot(ctx context.Context, snapID common.SnapshotID) error {
	if err := validateSnapshotID(snapID); err != nil {
		return err
	}

	// Locked on the OWNING volume, not on the snapshot's own name: the origin's
	// lock is what every operation touching this pair takes.
	owner, _, _ := splitSnapshotID(string(snapID))
	release, lockErr := p.lockVolumes(ctx, owner)
	if lockErr != nil {
		return lockErr
	}
	defer release()

	lvs, err := p.listLVs(ctx)
	if err != nil {
		return err
	}
	lv, exists := lookupLV(lvs, string(snapID))
	if !exists || !ownsSnapshot(lv) {
		return fmt.Errorf("%w: %q", common.ErrSnapshotNotFound, snapID)
	}
	return p.removeLV(ctx, string(snapID))
}

// Delete destroys the volume, unmounting and locking it first so that a caller
// tearing down does not have to sequence the teardown itself. An unmount that
// fails stops the delete: a filesystem still in use is a better outcome than a
// removed volume underneath it.
//
// lvremove takes the volume's snapshots with it. They are copy-on-write areas
// over an origin that is going away and cannot outlive it.
//
// With Options.WipeOnDelete the volume is zero-filled first, so its contents do
// not linger in the free extents LVM hands to the next volume.
func (p *Provider) Delete(ctx context.Context, volID string) error {
	if err := validateName("volume", volID); err != nil {
		return err
	}

	release, lockErr := p.lockVolumes(ctx, volID)
	if lockErr != nil {
		return lockErr
	}
	defer release()
	lvs, err := p.listLVs(ctx)
	if err != nil {
		return err
	}
	lv, exists := lookupLV(lvs, volID)
	if !exists {
		return fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	}

	if lv.active() {
		device, err := p.attachedDevice(ctx, volID, lv)
		if err != nil {
			return err
		}
		mounts, err := p.mountpointsFor(ctx, p.sourceAliases(volID, device))
		if err != nil {
			return err
		}
		for _, target := range deepestFirst(mounts) {
			if err := p.umount(ctx, target); err != nil {
				return err
			}
		}
		if err := p.closeIfEncrypted(ctx, volID); err != nil {
			return err
		}
	}

	wasActive := lv.active()

	if p.wipeOnDelete {
		// Snapshots go first, and the order is not a preference. Zeroing an
		// origin that still has a snapshot is copy-on-write's worst case: every
		// block written pushes the block it replaced into the snapshot's CoW
		// area, so the wipe duplicates the very data it is destroying into
		// extents lvremove then frees. Measured on LVM 2.03.16, wiping a 64 MiB
		// origin under one snapshot drove CoW occupancy from 0% to 100% and
		// overflowed the snapshot into an unreadable state.
		for _, snap := range lvs {
			if snap.Origin != volID {
				continue
			}
			if err := p.removeLV(ctx, snap.Name); err != nil {
				return err
			}
		}
		if err := p.wipe(ctx, volID, wasActive); err != nil {
			return err
		}
	}

	if err := p.removeLV(ctx, volID); err != nil {
		// A wipe has to activate the volume to have a device to write to, and
		// leaves it that way because the removal was about to happen. When the
		// removal is what failed, that activation is left over from an operation
		// the caller watched fail — an available volume turned attached with
		// nobody owning the change.
		if p.wipeOnDelete && !wasActive {
			return errors.Join(err, p.deactivate(ctx, volID))
		}
		return err
	}
	return nil
}

// wipe zero-fills a volume so nothing of it survives in the extents LVM returns
// to the free pool.
//
// The wipe goes over the logical volume rather than any LUKS mapping over it:
// the ciphertext is what stays behind in the extents, so that is what has to be
// overwritten. blkdiscard --zeroout uses the device's own zeroing offload where
// the hardware has one and falls back to writing zeroes where it does not, which
// is the difference between seconds and hours on a large volume.
//
// What this cannot reach is a snapshot's copy-on-write extents. They are freed
// by the lvremove that takes the snapshot away, and they hold the pre-snapshot
// copies of whatever the origin overwrote since. Zeroing them through the
// snapshot device would overflow the CoW area rather than clear it, and the
// underlying <vg>-<snap>-cow device cannot be opened for writing while the
// snapshot exists — measured, it reports EBUSY. So a volume that has ever been
// snapshotted keeps some of its history in the volume group after a wiping
// delete, and Encrypted is the only complete answer for that case.
//
// The volume has to be active to have a device node to write to. On success
// that activation is left alone, because the volume is removed immediately
// afterwards. On failure it is undone: the delete does not happen, so a volume
// the caller left available must not come back attached just because a wipe it
// never saw succeed activated it. blkdiscard is exactly the step likely to fail
// on a host that does not support it, which is the case that would strand the
// volume.
func (p *Provider) wipe(ctx context.Context, volID string, wasActive bool) error {
	if err := p.activate(ctx, volID); err != nil {
		return err
	}
	if _, err := p.runner.Run(ctx, nil, "blkdiscard", "--zeroout", p.lvPath(volID)); err != nil {
		wipeErr := fmt.Errorf("go-blockstore/local: wiping %s: %w", p.lvRef(volID), err)
		if wasActive {
			return wipeErr
		}
		return errors.Join(wipeErr, p.deactivate(ctx, volID))
	}
	return nil
}

// Status reports the volume's size and how far along the
// available/attached/mounted progression it currently is.
//
// It takes NO lock, and so reports a moment rather than a guarantee. It changes
// nothing, and a caller that acted on the answer would be racing whatever
// happened next regardless of how this read were synchronized — the lock a
// transition needs is the one the transition itself takes. A caller that needs
// a volume to still be in the state it just read has to hold something of its
// own at a higher level; nothing this method could do would provide it.
func (p *Provider) Status(ctx context.Context, volID string) (common.VolumeStatus, error) {
	if err := validateName("volume", volID); err != nil {
		return common.VolumeStatus{}, err
	}

	lvs, err := p.listLVs(ctx)
	if err != nil {
		return common.VolumeStatus{}, err
	}
	lv, exists := lookupLV(lvs, volID)
	if !exists {
		return common.VolumeStatus{}, fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	}

	status := common.VolumeStatus{
		ID:        volID,
		State:     common.VolumeStateAvailable,
		SizeBytes: lv.SizeBytes,
	}

	device, err := p.attachedDevice(ctx, volID, lv)
	if err != nil {
		return common.VolumeStatus{}, err
	}
	if device == "" {
		return status, nil
	}

	status.State = common.VolumeStateAttached
	status.AttachedNodes = []common.NodeID{p.nodeID}

	mounts, err := p.mountpointsFor(ctx, p.sourceAliases(volID, device))
	if err != nil {
		return common.VolumeStatus{}, err
	}
	if len(mounts) > 0 {
		status.State = common.VolumeStateMounted
	}
	return status, nil
}

// attachedDevice resolves the block device a volume is currently reachable at,
// or "" when it is not attached on this node.
//
// An encrypted volume counts as attached only once its plaintext mapping
// exists. An active logical volume whose LUKS container is still locked has a
// device node, but nothing a filesystem can be mounted from, so reporting it as
// attached would turn a clear ErrNotAttached from Mount into an obscure mount
// failure.
func (p *Provider) attachedDevice(ctx context.Context, volID string, lv lvInfo) (string, error) {
	if !lv.active() {
		return "", nil
	}

	fsType, err := p.probeFSType(ctx, p.lvPath(volID))
	if err != nil {
		return "", err
	}
	if fsType != fsTypeLUKS {
		return p.lvPath(volID), nil
	}

	open, err := p.luksIsOpen(ctx, volID)
	if err != nil {
		return "", err
	}
	if !open {
		return "", nil
	}
	return p.cryptPath(volID), nil
}

// checkNode accepts this provider's node, or the empty NodeID meaning "here".
//
// Any other node is ErrUnsupported, per the rule on VolumeProvider.Attach: the
// request is well formed, and a replicated backend could serve it, so it is
// reported as a capability this one lacks rather than as a bad argument. This
// backend manages a volume group on one host and has no way to make its volumes
// appear on another.
//
// The contract's other branch — ErrInvalidArgument for a node absent from the
// backend's configuration — has no counterpart here. A single-host provider has
// no roster of nodes to be absent from, so every node but its own falls under
// the first rule. A replicated backend, which does have one, distinguishes them.
func (p *Provider) checkNode(node common.NodeID) error {
	if node == "" || node == p.nodeID {
		return nil
	}
	return fmt.Errorf("%w: the local provider manages volume group %q on node %q and cannot act on node %q",
		common.ErrUnsupported, p.volumeGroup, p.nodeID, node)
}

// validateSnapshotID checks that an ID is one this provider composed and that
// both halves are still names it would accept.
func validateSnapshotID(snapID common.SnapshotID) error {
	volID, name, ok := splitSnapshotID(string(snapID))
	if !ok {
		return fmt.Errorf("%w: snapshot id %q is not of the form <volume>%s<snapshot>", common.ErrInvalidArgument, snapID, snapSeparator)
	}
	if err := validateName("volume", volID); err != nil {
		return err
	}
	return validateName("snapshot", name)
}

// deepestFirst orders mountpoints so a nested one is unmounted before the mount
// it sits inside.
//
// One volume can be mounted at both /mnt/data and /mnt/data/sub, and the kernel
// refuses to unmount the parent while the child is still there. findmnt's order
// is its own, so Delete would fail to tear down mounts it is supposed to clear
// itself. A nested path is always longer than the one containing it, so length
// descending puts children first; equal lengths cannot nest, and are ordered by
// name only so the sequence is the same every run.
func deepestFirst(mounts []string) []string {
	ordered := append([]string(nil), mounts...)
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) != len(ordered[j]) {
			return len(ordered[i]) > len(ordered[j])
		}
		return ordered[i] < ordered[j]
	})
	return ordered
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
