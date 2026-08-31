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
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-blockstore/pkg/common"

	"github.com/jeremyhahn/go-blockstore/internal/mount"
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
	luks               luksBackend
}

// Ensure the provider satisfies the contract at compile time.
var _ common.VolumeProvider = (*Provider)(nil)

// Mounter is the seam through which mounting and unmounting happen.
//
// It is an alias for internal/mount's type, not a copy of it: the
// implementation is shared with every other provider that mounts, because the
// reason it exists — a target has to be pinned to a descriptor before a
// privileged mount addresses it — is the same for all of them.
//
// The alias is what keeps that sharing from reaching the API. Options.Mounter
// is settable from outside this module either way, since Go satisfies an
// interface structurally, but without a name here a caller could not DECLARE
// one: no "var m local.Mounter", no function returning one. The type was
// exported at v0.1.0-alpha and stays nameable.
type Mounter = mount.Mounter

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
	// PBKDF2-SHA-512, AES-256-XTS, and a 512-bit key. Nothing is left to the
	// library's defaults, which are not FIPS-approved — go-luks2 formats with
	// argon2id and derives with SHA-256 when it is not told otherwise. Every
	// volume this provider creates is therefore identical on every host and in
	// every build, and deployable where FIPS 140-3 is required.
	//
	// No cryptsetup binary is involved, and none needs to be installed: the
	// header is written and parsed in this process by go-luks2, and the
	// plaintext mapping is created with device-mapper ioctls.
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
	// VolumeSpec.SizeBytes is USABLE capacity, and encryption does not change
	// that: the logical volume is created luksHeaderBytes larger than the
	// request so the plaintext mapping Attach hands back is at least the size
	// that was asked for. Resize works the same way, and VolumeStatus.SizeBytes
	// reports the usable figure. An encrypted volume is sized exactly like a
	// plain one, and the header is this provider's problem rather than the
	// caller's.
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

	// luks performs the LUKS2 operations. It defaults to nativeLUKS, which does
	// them in this process with go-luks2; tests substitute a fake.
	//
	// It is unexported, unlike Runner and Mounter, because it is not a seam a
	// caller has any business filling. Those two exist for callers as much as
	// for tests — a deployment can legitimately want its own exec or mount
	// implementation — while an outside implementation of this one would be an
	// outside implementation of the encryption, which is exactly the thing this
	// package pins rather than delegates.
	luks luksBackend
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
		mounter = mount.System()
	}

	luks := opts.luks
	if luks == nil {
		luks = nativeLUKS{}
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
		luks:               luks,
	}, nil
}

// NodeID reports the node this provider manages volumes on.
func (p *Provider) NodeID() common.NodeID { return p.nodeID }

// newVolumeOverhead is what this provider adds on top of a requested capacity
// when it creates a volume: a LUKS2 header when it is configured to encrypt,
// nothing when it is not.
//
// It applies to volumes this provider is about to CREATE, which is why it reads
// the configuration rather than the volume. What an existing volume costs is a
// question about that volume, and volumeOverhead answers it by looking.
func (p *Provider) newVolumeOverhead() int64 {
	if p.encrypted {
		return luksHeaderBytes
	}
	return 0
}

// volumeOverhead reports what an EXISTING volume spends on its own header, so
// that a usable capacity can be turned into a backing size for it.
//
// It probes rather than consulting Options.Encrypted, for the same reason
// Attach does: encryption is a property of the volume on disk, and a provider
// configured either way handles volumes that are the other. Where the volume is
// a LUKS container the figure comes from that container's own header, not from
// luksHeaderBytes, because a volume restored from an encrypted snapshot carries
// its source's header and that header need not be one this package wrote.
//
// A DETACHED volume has to be activated to be probed at all: an inactive
// logical volume has no device node, and blkid answers a path that does not
// exist with the same "nothing here" status it uses for a device with no
// signature — so probing one without activating it would report every encrypted
// volume as plain. It is put back as it was found.
func (p *Provider) volumeOverhead(ctx context.Context, volID string, lv lvInfo) (overhead int64, err error) {
	if !lv.active() {
		if activateErr := p.activate(ctx, volID); activateErr != nil {
			return 0, activateErr
		}
		defer func() {
			err = errors.Join(err, p.deactivate(ctx, volID))
		}()
	}

	fsType, probeErr := p.probeFSType(ctx, p.lvPath(volID))
	if probeErr != nil {
		return 0, probeErr
	}

	// Resize holds the lock and has just probed the volume, which makes it the
	// other place a wrong tag can be put right. It does not NEED the tag — it
	// sizes from the measured offset below — but a volume that is only ever
	// resized and never attached would otherwise keep a lying tag forever, and
	// the contract is that a tag can stay wrong only while the volume is
	// detached.
	if tagErr := p.reconcileHeaderTag(ctx, volID, lv, fsType); tagErr != nil {
		return 0, tagErr
	}

	if fsType != fsTypeLUKS {
		return 0, nil
	}
	return p.luksDataOffset(ctx, p.lvPath(volID))
}

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
	// SizeBytes is usable capacity, so the backing device is that plus this
	// provider's overhead — and the addition has to be representable. A signed
	// overflow in Go wraps rather than trapping, so without this check a size
	// near math.MaxInt64 would reach lvcreate as a NEGATIVE byte count. It is
	// malformed input rather than an unsupported operation: no backend could
	// serve it, and the caller has to change the number rather than choose
	// another provider.
	if limit := math.MaxInt64 - p.newVolumeOverhead(); spec.SizeBytes > limit {
		return common.Volume{}, fmt.Errorf("%w: SizeBytes %d exceeds the largest usable capacity this provider can back, %d",
			common.ErrInvalidArgument, spec.SizeBytes, limit)
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

	// The backing device carries the caller's capacity AND this provider's
	// header, so it is created larger than the request by exactly the latter.
	if err := p.createLV(ctx, spec.Name, spec.SizeBytes+p.newVolumeOverhead()); err != nil {
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
		// Tagged the moment the container exists, and not before. Tagging at
		// lvcreate would be one command fewer and would leave a window in which
		// the tag claims an encryption that a failed luksFormat never
		// delivered.
		if err := p.addTag(ctx, spec.Name, encryptedTagFor(luksHeaderBytes)); err != nil {
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
// a LUKS close that did not work — and leave behind the half-built volume
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
// outlives the snapshot.
//
// # What a restore preserves
//
// A restore preserves DATA lineage, not header lineage. The restored volume
// holds the bytes the snapshot held; whether it holds them under the same LUKS
// header depends on which of the three cases below it is, and the difference is
// worth knowing because it decides which passphrase opens the result.
//
//   - A PLAINTEXT snapshot restored by a provider that does not encrypt is
//     copied onto the new logical volume directly. Nothing to say about keys.
//
//   - A PLAINTEXT snapshot restored by a provider configured to encrypt is
//     RE-ENCRYPTED on the way in: the new volume is formatted as a LUKS2
//     container under this provider's own key, and the image is copied through
//     the plaintext mapping so dm-crypt encrypts it in flight. The restored
//     volume therefore has a DIFFERENT header from anything the source had —
//     it had none — and opens with the key KeyProvider returns for the restored
//     volume's own ID. No plaintext is written to the volume's extents at any
//     point, and a failure part-way removes the volume rather than leaving one
//     behind.
//
//   - An ENCRYPTED snapshot is ciphertext at the logical-volume level, header
//     included, and is copied verbatim WITHOUT being reformatted. Reformatting
//     it would be destructive rather than merely different: a fresh luksFormat
//     writes a new header with a new master key, and the ciphertext copied over
//     it was encrypted under the old one, so the result decrypts to nothing and
//     does so silently. The restored volume consequently shares its source's
//     header, master key and UUID, and it opens with the SOURCE's passphrase.
//     Since KeyProvider is called with the volume's own ID, an implementation
//     holding a distinct key per volume has to answer for the restored volume's
//     name with the source's key — which is checked before anything is created,
//     rather than discovered at the first Attach. See
//     requireRestoredVolumeOpens.
//
// spec.SizeBytes is usable capacity in every case, and is compared against the
// snapshot's USABLE capacity rather than its image size, so that the threshold
// is in the units the caller asked in.
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

	// The extent size is needed to know how far lvcreate will round the request
	// up, which is where the restored volume actually ends. See
	// zeroRestoreTail.
	extent, err := p.extentSize(ctx)
	if err != nil {
		return common.Volume{}, err
	}

	plan, err := p.planRestore(ctx, spec, snapID, origin, imageSize, extent)
	if err != nil {
		return common.Volume{}, err
	}

	if err := p.createLV(ctx, spec.Name, plan.backing); err != nil {
		return common.Volume{}, err
	}

	if err := p.restoreImage(ctx, snapID, origin, spec.Name, plan); err != nil {
		return common.Volume{}, errors.Join(err, p.abandon(ctx, spec.Name))
	}

	if err := p.zeroRestoreTail(ctx, spec.Name, plan); err != nil {
		return common.Volume{}, errors.Join(err, p.abandon(ctx, spec.Name))
	}

	if err := p.deactivate(ctx, spec.Name); err != nil {
		return common.Volume{}, errors.Join(err, p.abandon(ctx, spec.Name))
	}
	return common.Volume{ID: spec.Name, Spec: spec}, nil
}

// restorePlan is how one restore will be carried out, decided before anything
// is created so that every refusal happens while there is still nothing to
// clean up.
type restorePlan struct {
	// backing is the size of the logical volume to create: the caller's usable
	// capacity plus whatever header the restored volume will end up carrying.
	backing int64

	// imageEnd is the offset ON THE LOGICAL VOLUME one byte past the copied
	// image, which is where tail zeroing starts. It is past the LUKS header on
	// a re-encrypting restore, because there the image lands inside a container
	// rather than at the front of the volume.
	imageEnd int64

	// volumeEnd is where the logical volume will actually end: backing rounded
	// up to a whole extent, the way lvcreate rounds it. Anything between
	// imageEnd and here is tail.
	volumeEnd int64

	// reencrypt copies the image through a freshly formatted LUKS mapping
	// instead of onto the logical volume directly.
	reencrypt bool

	// encrypted is whether the RESTORED volume ends up holding a LUKS
	// container, which is true both when this provider formats one and when the
	// copied image already was one. It is what decides whether the volume is
	// tagged, and the two cases become true at different moments — see
	// restoreImage.
	encrypted bool

	// overhead is the header the restored volume ends up carrying: this
	// package's own when it formats the container, and the SOURCE's when the
	// image is copied verbatim. It is what gets recorded on the volume, which
	// is the whole reason it is kept rather than folded into backing — the
	// source's header is measured here and nowhere else afterwards.
	overhead int64
}

// planRestore settles the sizing and the encryption route for a restore, and
// performs every check that can refuse one.
//
// Everything it does happens before createLV, which is the property that
// matters: a refusal leaves no volume behind, and — for the case that motivated
// it — never writes a plaintext image to extents it would then have to free.
func (p *Provider) planRestore(ctx context.Context, spec common.VolumeSpec, snapID string, origin lvInfo, imageSize, extent int64) (restorePlan, error) {
	srcOffset, err := p.inspectSource(ctx, spec.Name, snapID, origin)
	if err != nil {
		return restorePlan{}, err
	}

	// Compared in USABLE bytes on both sides. The image includes the source's
	// header when it has one, and the caller's request never does, so comparing
	// the request against the raw image size would demand an extra header's
	// worth of capacity for an encrypted source and reject restores that fit.
	srcUsable := usableBytes(imageSize, srcOffset)
	if spec.SizeBytes < srcUsable {
		return restorePlan{}, fmt.Errorf("%w: restoring %q needs at least %d bytes of usable capacity, spec asks for %d and this provider does not shrink during restore",
			common.ErrUnsupported, snapID, srcUsable, spec.SizeBytes)
	}

	// The overhead the RESTORED volume will carry, and where the image will sit
	// on it. An encrypted source keeps its own header, so the copy starts at
	// offset zero and the volume inherits that header's size; a plaintext image
	// into an encrypting provider goes inside a container this package formats,
	// so it starts past a header of this package's own size.
	overhead, imageEnd, reencrypt := int64(0), imageSize, false
	switch {
	case srcOffset > 0:
		overhead = srcOffset
	case p.encrypted:
		overhead, imageEnd, reencrypt = luksHeaderBytes, luksHeaderBytes+imageSize, true
	}

	// Guarded again here, and against the overhead the RESTORE will use:
	// Provision's guard was against this provider's own, which is not the
	// source's, and neither guard covered the extent rounding below.
	if limit := maxUsableBytes(extent, overhead); spec.SizeBytes > limit {
		return restorePlan{}, fmt.Errorf("%w: SizeBytes %d exceeds the largest usable capacity a restore of %q can hold, %d "+
			"(this volume group's extents are %d bytes and the restored volume carries %d bytes of header)",
			common.ErrInvalidArgument, spec.SizeBytes, snapID, limit, extent, overhead)
	}

	backing := spec.SizeBytes + overhead
	return restorePlan{
		backing:   backing,
		imageEnd:  imageEnd,
		volumeEnd: roundUpToExtent(backing, extent),
		reencrypt: reencrypt,
		encrypted: overhead > 0,
		overhead:  overhead,
	}, nil
}

// inspectSource reports what the snapshot's image holds: the data offset of the
// LUKS container on it, or zero for plaintext.
//
// Reading either answer needs the snapshot activated, and activating a snapshot
// activates its origin, so the origin's activation is captured and put back
// around the whole inspection. The key check for an encrypted source rides
// along inside the same activation rather than taking one of its own.
func (p *Provider) inspectSource(ctx context.Context, destVolID, snapID string, origin lvInfo) (offset int64, err error) {
	originWasActive := origin.active()
	if activateErr := p.activate(ctx, snapID); activateErr != nil {
		return 0, activateErr
	}
	defer func() {
		err = errors.Join(err, p.restoreOriginActivation(ctx, origin.Name, originWasActive))
	}()

	fsType, probeErr := p.probeFSType(ctx, p.lvPath(snapID))
	if probeErr != nil {
		return 0, probeErr
	}
	if fsType != fsTypeLUKS {
		return 0, nil
	}

	offset, err = p.luksDataOffset(ctx, p.lvPath(snapID))
	if err != nil {
		return 0, err
	}
	if checkErr := p.requireRestoredVolumeOpens(ctx, destVolID, snapID); checkErr != nil {
		return 0, checkErr
	}
	return offset, nil
}

// requireRestoredVolumeOpens refuses a restore that would produce an encrypted
// volume nobody can unlock.
//
// An encrypted snapshot is copied verbatim, master key and all, so the restored
// volume opens with the SOURCE's passphrase and with nothing else. KeyProvider
// is called with the volume's own ID, though, and an implementation holding a
// distinct key per volume answers for the restored volume's name with a key
// that opens nothing. Left unchecked that produces a volume which restores
// cleanly, reports available, and fails at its first Attach — a silently
// unreadable volume, which is the one outcome this path must not have.
//
// So the key is tested against the SNAPSHOT's header, which is the header the
// restored volume is about to receive. --test-passphrase verifies it without
// creating a mapping, so the snapshot is never exposed as a plaintext device to
// answer the question, and the check runs before createLV, so a refusal costs
// nothing and copies nothing.
//
// The fix, when it fires, is on the caller's side: have KeyProvider return the
// source volume's passphrase for the restored volume's ID.
func (p *Provider) requireRestoredVolumeOpens(ctx context.Context, destVolID, snapID string) error {
	if p.keyProvider == nil {
		return fmt.Errorf("%w: snapshot %q holds an encrypted volume, and restoring it with no KeyProvider configured "+
			"would produce a container this provider has no key for; set Options.KeyProvider",
			common.ErrInvalidArgument, snapID)
	}
	if err := p.luksTestPassphrase(ctx, destVolID, p.lvPath(snapID)); err != nil {
		return fmt.Errorf("%w: restoring %q would give volume %q that snapshot's LUKS header, and the key KeyProvider "+
			"returns for %q does not open it; a restore preserves the source's master key, so the restored volume "+
			"needs the SOURCE's passphrase: %w",
			common.ErrInvalidArgument, snapID, destVolID, destVolID, err)
	}
	return nil
}

// restoreImage transfers a snapshot's contents onto a new logical volume, with
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
//
// On a RE-ENCRYPTING restore the destination is formatted and unlocked first,
// and dd writes to the plaintext mapping rather than to the logical volume. The
// bytes are encrypted by dm-crypt on their way to the disk, so the plaintext
// exists only in the pipe between the two devices and never lands on an extent
// — which is what lets a failure here be cleaned up by simply removing the
// volume, since everything written to it is ciphertext.
func (p *Provider) restoreImage(ctx context.Context, snapID string, origin lvInfo, volID string, plan restorePlan) (err error) {
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

	dest := p.lvPath(volID)
	if plan.reencrypt {
		if formatErr := p.luksFormat(ctx, volID, p.lvPath(volID)); formatErr != nil {
			return formatErr
		}
		if tagErr := p.addTag(ctx, volID, encryptedTagFor(luksHeaderBytes)); tagErr != nil {
			return tagErr
		}
		if openErr := p.luksOpen(ctx, volID, p.lvPath(volID)); openErr != nil {
			return openErr
		}
		// Registered after the origin's, so it runs first: the mapping is torn
		// down before anything else moves, and the volume is left the way
		// Attach expects to find it — locked.
		defer func() {
			err = errors.Join(err, p.luksClose(ctx, volID))
		}()
		dest = p.cryptPath(volID)
	}

	if _, runErr := p.runner.Run(ctx, nil, "dd",
		"if="+p.lvPath(snapID),
		"of="+dest,
		"bs=4M",
		"conv=fsync",
		"status=none",
	); runErr != nil {
		return fmt.Errorf("go-blockstore/local: copying snapshot %q into %q: %w", snapID, volID, runErr)
	}

	// A VERBATIM copy of an encrypted image is what makes this volume a
	// container, so that is the moment it gets tagged — there was no luksFormat
	// here to hang the tag on, and before the copy landed the claim would have
	// been false. The re-encrypting path tagged itself earlier, when its own
	// luksFormat made it true.
	if plan.encrypted && !plan.reencrypt {
		return p.addTag(ctx, volID, encryptedTagFor(plan.overhead))
	}
	return nil
}

// zeroRestoreTail clears whatever the restored volume holds past the copied
// image.
//
// Restoring into a volume larger than the snapshot leaves everything past the
// image holding what the volume group's free extents held — the same stale data
// a fresh volume would expose, arriving through a path that looks like it wrote
// the whole device. dd copies the image and stops, so the rest is zeroed
// explicitly.
//
// The comparison is against where the volume will actually END — the request
// rounded up to a whole extent, the way lvcreate rounds it — and not against
// the request itself. Those used to be the same number and no longer are: an
// origin's size is a whole number of extents by construction, so the old
// "restore into exactly the image size" case really did produce a volume with
// nothing past the image, but a backing size is now a usable capacity with a
// header added to it and is extent-aligned only by luck. Deciding from the
// request would leave that rounding slice — up to one extent of it — holding
// whatever the previous tenant of those extents wrote, on exactly the restores
// that look most ordinary.
//
// blkdiscard zeroes from the offset to the end of the device, so the slice is
// covered as soon as the zeroing happens at all; the only thing this decides is
// whether it happens.
//
// A volume with no tail is left alone: issuing a zero-length zeroout at EOF
// would make the ordinary restore depend on how the kernel and the device
// handle an operation there.
func (p *Provider) zeroRestoreTail(ctx context.Context, volID string, plan restorePlan) error {
	if plan.volumeEnd <= plan.imageEnd {
		return nil
	}
	return p.zeroTail(ctx, volID, plan.imageEnd)
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
// The offset is an origin's size, optionally past a LUKS header: a whole number
// of LVM extents, or that plus luksHeaderBytes. Either way it is aligned well
// past anything blkdiscard requires — the header is a whole number of
// mebibytes, and blkdiscard asks for sectors. The volume is activated for the
// write and put back afterwards, in the state Provision hands it over in.
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

	device, err := p.unlockForAttach(ctx, volID, lv)
	if err != nil {
		// A failed Attach leaves nothing behind. Unlocking can fail after
		// activation succeeded — a wrong key, a device-mapper that will not
		// take the mapping —
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
//
// It is also where a volume that predates the header tag acquires one. Attach is
// the only operation that both HOLDS THE VOLUME'S LOCK and has already proved
// the volume is a container by probing it, so the repair costs nothing here and
// has nowhere else to live. A fleet provisioned before the tag existed heals
// itself one attach at a time rather than needing a migration pass.
func (p *Provider) unlockForAttach(ctx context.Context, volID string, lv lvInfo) (string, error) {
	fsType, err := p.probeFSType(ctx, p.lvPath(volID))
	if err != nil {
		return "", err
	}

	// Before the plain-volume shortcut, not after it: a volume that is NOT a
	// container can still be carrying a header tag that says it is, and this is
	// the place holding the lock needed to take that back.
	if recordErr := p.reconcileHeaderTag(ctx, volID, lv, fsType); recordErr != nil {
		return "", recordErr
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

// reconcileHeaderTag makes the volume's recorded header agree with what the
// probe just found. It is the repair, and it runs from the two operations that
// can perform one: Attach and Resize, both of which hold the volume's lock and
// have just looked at the volume with a device node in front of them.
//
// It settles two different disagreements, and the right answer differs:
//
//   - A LUKS CONTAINER gets the measured offset recorded. That covers a volume
//     provisioned before the tag existed, and one whose tag has drifted from
//     the container. The number written is read out of the header rather than
//     assumed, so a repair never invents one.
//   - ANYTHING ELSE carrying a header tag has that tag REMOVED, because the
//     probe has just proved it false. Status refuses such a volume while it is
//     active, which is useful but cannot fix anything; this is where it gets
//     fixed.
//
// A FAILED TAG WRITE IS TOLERATED IN EXACTLY ONE CASE: a LUKS container that
// had NO header tag to begin with. The volume then stays untagged, which is the
// legacy state Status documents and falls back for — nothing left behind lies,
// and the next attempt tries again. That tolerance is what keeps a volume group
// whose metadata is READ-ONLY usable for a recovery: such a group still
// ACTIVATES volumes, because activation writes no metadata, so an attach gets
// this far and only the tag write is refused, and turning that into an outage
// to record a capacity hint would be the wrong trade.
//
// Every other failure is fatal, and the difference is what is left behind. An
// absent tag claims nothing. A wrong or false one is consulted as authoritative
// the moment the volume is detached, where there is no probe to catch it, and a
// stale-smaller offset OVER-states usable capacity. Reporting success would
// hand the caller a working volume and leave it misdescribed for every reader
// after them.
//
// Reading the header is a different matter and is always fatal: this is reached
// only after blkid called the volume a LUKS container, so a header that will
// not read means the container is not in the state the probe said it was.
func (p *Provider) reconcileHeaderTag(ctx context.Context, volID string, lv lvInfo, fsType string) error {
	existing := lv.luksHeaderTags()

	if fsType != fsTypeLUKS {
		if len(existing) == 0 {
			return nil
		}
		return p.deleteHeaderTags(ctx, volID, existing)
	}

	offset, err := p.luksDataOffset(ctx, p.lvPath(volID))
	if err != nil {
		return err
	}

	want := encryptedTagFor(offset)
	if len(existing) == 1 && existing[0] == want {
		return nil
	}

	retagErr := p.retagLUKSHeader(ctx, volID, existing, want)
	if retagErr == nil {
		return nil
	}
	if len(existing) == 0 {
		return nil
	}
	return retagErr
}

// Detach locks the volume's LUKS container, if it has one, and deactivates the
// logical volume. A volume still mounted cannot be deactivated; unmount first.
//
// It also reconciles the volume's recorded header, and this is the transition
// where that matters most. Detach is the moment a volume enters the state in
// which the tag is the ONLY source of its capacity, and the last moment the
// container is readable — so a wrong tag surviving here is not latent, it is
// load-bearing on the very next Status with no probe left to contradict it. The
// reconcile therefore happens BEFORE the deactivation, and its failure fails
// the Detach: leaving the volume active is a better outcome than putting it
// away misdescribed.
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

	fsType, err := p.probeFSType(ctx, p.lvPath(volID))
	if err != nil {
		return err
	}
	if err := p.reconcileHeaderTag(ctx, volID, lv, fsType); err != nil {
		return err
	}

	if err := p.closeMapping(ctx, volID, fsType); err != nil {
		return err
	}
	return p.deactivate(ctx, volID)
}

// closeIfEncrypted tears down the volume's LUKS mapping when it has one.
//
// Whether to involve LUKS at all is decided by probing the logical volume, not
// by the Encrypted option: a host that runs only plain volumes never touches
// device-mapper.
func (p *Provider) closeIfEncrypted(ctx context.Context, volID string) error {
	fsType, err := p.probeFSType(ctx, p.lvPath(volID))
	if err != nil {
		return err
	}
	return p.closeMapping(ctx, volID, fsType)
}

// closeMapping is closeIfEncrypted for a caller that has already probed, so the
// volume is not blkid'd twice on a path that needs the answer for something
// else as well.
//
// It is deliberately NOT where the header tag gets reconciled, even though both
// callers hold the lock and have the probe in hand. Delete reaches this through
// closeIfEncrypted, and Delete is removing the volume — tag and all. Refusing to
// destroy something because a piece of bookkeeping about it could not be
// rewritten would be obstruction: there is no later reader left to mislead.
// Detach reconciles explicitly instead, because Detach is the transition into
// the state where the tag starts being believed.
func (p *Provider) closeMapping(ctx context.Context, volID, fsType string) error {
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

	flags, data := mount.Arguments(opts.ReadOnly, opts.Flags)
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

// Resize grows the volume to newSize bytes and, where it can, grows the
// filesystem on top of it — when one is present and its tooling can grow it in
// the volume's current state.
//
// AN ENCRYPTED VOLUME THAT IS ATTACHED IS REFUSED, with ErrResizeWhileAttached,
// and refused before anything moves. Growing its plaintext mapping would mean
// removing that mapping and unlocking again, and a failure between the two
// leaves the caller with no device at all rather than with an unresized one.
// Detaching first costs one call and removes the hazard entirely: a detached
// resize opens the container itself, grows the filesystem inside it and locks
// it again, so there is no mapping belonging to anyone else to lose. See
// ErrResizeWhileAttached for why this is not ErrUnsupported.
//
// Shrinking returns ErrUnsupported. LVM can shrink a logical volume, but doing
// so under a filesystem that has not been shrunk first destroys data, and a
// provider that cannot verify the filesystem was prepared has no business
// making that call.
//
// newSize is USABLE capacity, matching VolumeSpec.SizeBytes: an encrypted
// volume's logical volume is grown by newSize plus its LUKS header, so the
// plaintext mapping ends up the size that was asked for. Whether the volume is
// encrypted is discovered by probing it, which a DETACHED volume has to be
// activated for — so a resize of one activates it briefly to look, and again to
// grow its filesystem, leaving it detached either way.
//
// LVM allocates in whole extents, so the volume can end up slightly larger than
// newSize. It is never smaller. The shrink test is made against newSize plus
// the overhead and rounded up the same way, so repeating a request LVM has
// already rounded is a no-op rather than a rejected shrink.
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
	// newSize is USABLE capacity, so the backing device has to grow by the
	// volume's own header as well. The overhead is read off the volume rather
	// than assumed from this provider's configuration, because a provider
	// handles volumes that were encrypted when it is not and the other way
	// round.
	overhead, err := p.volumeOverhead(ctx, volID, lv)
	if err != nil {
		return err
	}
	// A size that cannot survive having the overhead added and then being
	// rounded up is malformed input rather than an unsupported operation: no
	// backend could serve it, and the caller has to change the number rather
	// than pick another provider.
	if limit := maxUsableBytes(extent, overhead); newSize > limit {
		return fmt.Errorf("%w: newSize %d exceeds the largest usable capacity representable on this volume, %d "+
			"(this volume group's extents are %d bytes and the volume carries %d bytes of header)",
			common.ErrInvalidArgument, newSize, limit, extent, overhead)
	}
	backing := newSize + overhead
	target := roundUpToExtent(backing, extent)
	if target < lv.SizeBytes {
		return fmt.Errorf("%w: shrinking %q from %d to %d usable bytes", common.ErrUnsupported,
			volID, usableBytes(lv.SizeBytes, overhead), newSize)
	}

	// Resolved BEFORE anything is grown, so that the one case this provider
	// will not serve is refused while the volume is still exactly as the caller
	// left it. Reading it here rather than after the lvextend costs nothing —
	// it is a probe, the lock is held, and growing a logical volume changes
	// neither its activation nor what it holds.
	device, err := p.attachedDevice(ctx, volID, lv)
	if err != nil {
		return err
	}
	if device == p.cryptPath(volID) {
		return fmt.Errorf("%w: %q is unlocked as %s, and growing that mapping in place would mean "+
			"tearing it down and unlocking again — which loses the caller's plaintext device outright "+
			"if the second half fails. Detach the volume and resize it again; a detached resize grows "+
			"the filesystem inside the container and cannot lose a mapping, because it opens and closes "+
			"its own",
			ErrResizeWhileAttached, volID, device)
	}

	if target > lv.SizeBytes {
		_, err = p.runner.Run(ctx, nil, "lvextend", "--size", strconv.FormatInt(backing, 10)+"b", p.lvRef(volID))
		if err != nil {
			return fmt.Errorf("go-blockstore/local: growing %s: %w", p.lvRef(volID), err)
		}
	}

	if device == "" {
		return p.growDetachedFilesystem(ctx, volID)
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
// The mapping needs no resize, and this is the reason an attached volume is
// refused while a detached one is not. It is opened HERE, after the logical
// volume has already grown, and the container's data segment is "dynamic", so
// whoever opens it sizes the mapping to the device it finds — measured on
// cryptsetup 2.7.0, growing a 64 MiB volume to 128 MiB and re-opening took the
// mapping from 50331648 to 117440512 bytes with no resize asked for, and
// go-luks2 computes the length the same way. Nothing is torn down to achieve
// that: the mapping this function closes on the way out is the one it opened on
// the way in, so a failure anywhere leaves the volume as detached as it started
// and costs the caller nothing it was using.
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
// It REFUSES a volume that still has snapshots, with common.ErrHasSnapshots
// naming them. lvremove would take them with it — they are copy-on-write areas
// over an origin that cannot outlive it — and destroying a restore point as a
// side effect of destroying something else is not a default worth having in a
// stack whose volumes are the ones people restore from. A caller that means it
// deletes the snapshots first, which is one more call and an explicit one.
//
// The refusal also removes a hazard that used to need careful ordering here.
// Zeroing an origin that still has a snapshot is copy-on-write's worst case:
// every block written pushes the block it replaced into the snapshot's CoW
// area, so the wipe duplicates the very data it is destroying into extents
// lvremove then frees. Measured on LVM 2.03.16, wiping a 64 MiB origin under
// one snapshot drove CoW occupancy from 0% to 100% and overflowed the snapshot
// into an unreadable state. With snapshots refused outright, a wipe can no
// longer run under one.
//
// With Options.WipeOnDelete the volume is zero-filled first, so its contents do
// not linger in the free extents LVM hands to the next volume. See the package
// doc for exactly what that covers and what it does not.
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

	// Checked before any teardown: refusing after unmounting and closing the
	// volume would leave the caller worse off than when it asked, for an
	// operation that was never going to complete.
	var snapshots []string
	for i := range lvs {
		if lvs[i].Origin == volID {
			snapshots = append(snapshots, lvs[i].Name)
		}
	}
	if len(snapshots) > 0 {
		sort.Strings(snapshots)
		return fmt.Errorf("volume %q: delete %s first: %w",
			volID, strings.Join(snapshots, ", "), common.ErrHasSnapshots)
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
		// No snapshot can exist here — Delete refused above — so the
		// copy-on-write ordering this used to need is gone with the hazard that
		// motivated it. See the godoc.
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

// Status reports the volume's usable capacity and how far along the
// available/attached/mounted progression it currently is.
//
// It takes NO lock, and so reports a moment rather than a guarantee. It changes
// nothing, and a caller that acted on the answer would be racing whatever
// happened next regardless of how this read were synchronized — the lock a
// transition needs is the one the transition itself takes. A caller that needs
// a volume to still be in the state it just read has to hold something of its
// own at a higher level; nothing this method could do would provide it.
//
// SizeBytes is USABLE capacity, per VolumeStatus.SizeBytes: for an encrypted
// volume the header is subtracted, and it is subtracted whether the volume is
// attached or not.
//
// Getting that right while holding no lock takes two sources, and they are not
// equals. While a volume is ACTIVE the header is DISCOVERED — blkid, then the
// container's own header — which is exact even for a volume restored verbatim
// from an outside snapshot, whose header this package did not write. A DETACHED
// volume cannot be probed at all: an inactive logical volume is absent from
// /dev, and blkid answers a path that does not exist with the same status it
// uses for a device carrying no signature, so probing one would report every
// encrypted volume as plain. Activating it to look is not available here —
// this method holds no lock, and moving a volume while another operation owns
// it is what the locking exists to prevent. So the fact is REMEMBERED as an LVM
// tag when it becomes true, and read back from the same lvs listing this method
// already fetches. See encryptedTagPrefix.
//
// Two consequences worth stating. A tag that CONTRADICTS what blkid can see on
// an active volume is an error rather than a tiebreak, because a tag that lies
// should not outlive the one moment something could catch it. And a volume
// provisioned before the tag existed carries none, so while detached it still
// reports its backing size — the old behavior, now scoped to legacy volumes and
// self-healing, since its next Attach tags it. reportedSize has the detail.
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

	device, fsType, err := p.resolveDevice(ctx, volID, lv)
	if err != nil {
		return common.VolumeStatus{}, err
	}

	status := common.VolumeStatus{
		ID:        volID,
		State:     common.VolumeStateAvailable,
		SizeBytes: lv.SizeBytes,
	}
	size, sizeErr := p.reportedSize(ctx, volID, lv, fsType)
	if sizeErr != nil {
		return common.VolumeStatus{}, sizeErr
	}
	status.SizeBytes = size

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

// reportedSize is the capacity Status reports, which is usable capacity
// wherever this provider can establish what the volume's overhead is.
//
// There are two sources for that and they are not equals. DISCOVERY — blkid on
// the logical volume, then the container's own header — is the authority, and
// it is exact: it reads the header the volume actually has, which matters for a
// volume restored verbatim from somebody else's snapshot. It needs a device
// node, so it is available only while the volume is active. The TAG is what
// makes the answer survive into the state where discovery cannot run at all.
//
// So the three cases:
//
//   - ACTIVE: discovery decides, and a tag that disagrees with it is an error
//     rather than a tiebreak. See below.
//
//   - DETACHED AND TAGGED: the header size comes off the tag, which recorded
//     the number that was measured when the volume became a container. It is
//     therefore exact for a volume carrying a FOREIGN header — one restored
//     verbatim from an outside snapshot — and not only for containers this
//     package formatted.
//
//     The tag is trusted here BECAUSE it cannot survive being wrong while the
//     volume is up: an active volume has its tag checked against the container's
//     real header, and a disagreement is refused rather than outvoted. So a tag
//     that reaches this branch has either been validated against the header
//     since it was written, or has never been attachable since — and either way
//     the next Attach re-records it from the container.
//
//     A tag that is present but UNREADABLE — not a number, or several tags
//     disagreeing — is an error rather than a fallback. It cannot happen by
//     any path in this package, so it means the tag was hand-edited or two
//     writers disagreed, and answering with a number anyway would be inventing
//     one.
//
//   - DETACHED AND UNTAGGED: reported as the backing size. This is the legacy
//     case and nothing else: a volume provisioned before the tag existed, or
//     one whose repair-on-attach has not happened yet. It is the deviation this
//     provider used to have for EVERY detached encrypted volume, now scoped to
//     volumes that predate the tag and self-healing on their next Attach.
//
// A tag claiming encryption over a volume blkid can see is NOT encrypted is
// refused outright, in the same spirit as a device-mapper name found over the
// wrong backing device: it means the tag was applied to the wrong volume, or
// somebody rewrote the container out of band, and either way something believes
// this volume is encrypted when it is not. Reporting a capacity for it would be
// the smallest of the problems. There is no logger in this package to warn
// through, and quietly letting discovery win would leave the lie in place for
// the next reader — including the detached path above, which has no probe to
// correct it.
func (p *Provider) reportedSize(ctx context.Context, volID string, lv lvInfo, fsType string) (int64, error) {
	if !lv.active() {
		return p.detachedSize(volID, lv)
	}

	tagged := len(lv.luksHeaderTags()) > 0

	if fsType != fsTypeLUKS {
		// A tag over a volume the probe says is NOT a container. Before calling
		// that a contradiction, check it is not simply a volume that moved:
		// this method holds no lock, and a Detach between the listing and the
		// probe takes the device node away, which blkid reports with the same
		// status it uses for a device carrying no signature. Reporting a
		// tampering error for an ordinary detach would be worse than the bug it
		// is looking for.
		if !tagged {
			return lv.SizeBytes, nil
		}
		current, exists, listErr := p.currentLV(ctx, volID)
		switch {
		case listErr != nil:
			return 0, listErr
		case !exists:
			return 0, fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
		case !current.active():
			// It was detached underneath us. Answered by the detached path
			// itself, not by something that resembles it.
			return p.detachedSize(volID, current)
		}
		return 0, fmt.Errorf("go-blockstore/local: %s is tagged %q but carries %s, not a LUKS container; "+
			"something rewrote it out of band or the tag was applied to the wrong volume. "+
			"Remove the tag with `lvchange --deltag %s %s` once you have established which",
			p.lvRef(volID), strings.Join(lv.luksHeaderTags(), ", "), describeFSType(fsType),
			strings.Join(lv.luksHeaderTags(), " --deltag "), p.lvRef(volID))
	}
	return p.usableSize(ctx, volID, lv)
}

// currentLV re-reads one volume from the volume group, for the paths that have
// to tell "the world moved underneath a lockless read" from "something is
// genuinely wrong".
func (p *Provider) currentLV(ctx context.Context, volID string) (lvInfo, bool, error) {
	lvs, err := p.listLVs(ctx)
	if err != nil {
		return lvInfo{}, false, err
	}
	lv, exists := lookupLV(lvs, volID)
	return lv, exists, nil
}

// describeFSType renders what blkid found for an error message, giving the
// no-signature answer a name rather than printing an empty string.
func describeFSType(fsType string) string {
	if fsType == "" {
		return "no filesystem signature"
	}
	return fsType
}

// usableSize reports the usable capacity of a volume that was just found to
// hold a LUKS container, by reading that container's own header.
//
// The complication is that Status holds no lock, so the volume can move between
// the probe that said "LUKS container" and the read of the header: a concurrent
// Detach takes the device node away, a concurrent Delete takes the volume
// itself, and the header read fails either way. Before this, both of those
// races degraded quietly — blkid and the mapping lookup report a vanished
// device as "nothing here" rather than as a failure — and turning them into a hard
// Status error would make the method unreliable in exactly the concurrent use
// it exists for.
//
// So a failed read is not believed on its own. The volume group is consulted
// again, and the three cases are told apart:
//
//   - GONE: the volume was deleted, and ErrNotFound is the accurate answer —
//     the same one Status would have given had the race resolved a moment
//     earlier.
//   - PRESENT BUT INACTIVE: the volume was detached, and the answer is whatever
//     the DETACHED path gives for it — detachedSize, the same function an
//     ordinary Status over a detached volume goes through. That is a subtracted
//     header for a tagged volume, the backing size for an untagged legacy one,
//     and an error for a tag that cannot be read. This branch used to answer
//     with the backing size directly, which was right only while the detached
//     answer was always the backing size, and silently over-stated capacity by
//     a whole header once the tag arrived.
//   - STILL ACTIVE: nothing moved, so the header genuinely cannot be read, and
//     that is reported. Inventing a number here would put a plausible-looking
//     figure where an unreadable one was, which is the failure mode this
//     package refuses everywhere it reads a number back from a tool.
func (p *Provider) usableSize(ctx context.Context, volID string, lv lvInfo) (int64, error) {
	offset, err := p.luksDataOffset(ctx, p.lvPath(volID))
	if err == nil {
		if tagErr := p.requireTagMatchesHeader(volID, lv, offset); tagErr != nil {
			return 0, tagErr
		}
		return usableBytes(lv.SizeBytes, offset), nil
	}

	lvs, listErr := p.listLVs(ctx)
	if listErr != nil {
		return 0, errors.Join(err, listErr)
	}
	current, exists := lookupLV(lvs, volID)
	switch {
	case !exists:
		return 0, fmt.Errorf("%w: volume %q", common.ErrNotFound, volID)
	case !current.active():
		// Detached underneath the header read. This is the DETACHED case and
		// gets the detached answer — which consults the tag. Returning the
		// backing size here is what this function used to do, from before the
		// tag existed, and it over-stated usable capacity by a whole header on
		// exactly the volumes the tag was added to describe.
		return p.detachedSize(volID, current)
	default:
		return 0, err
	}
}

// requireTagMatchesHeader refuses a recorded header size that disagrees with the
// header the container actually has.
//
// This is the rest of "on an active volume, discovery is the authority". That
// rule was applied to WHETHER a volume is a container; it has to apply to the
// header's SIZE too, because the size is the part the tag carries and the part
// a detached read depends on. A tag recording 16 MiB over a 32 MiB header
// returns the right number while the volume is up — the value is measured — and
// then over-states usable capacity by 16 MiB the moment the volume is detached
// and the stale tag becomes the only source. While the volume is active is the
// LAST moment anything can catch that, so it is caught rather than outvoted.
//
// An UNTAGGED volume is the explicit exception, not an oversight: it is the
// legacy state, it claims nothing, and there is nothing to disagree with.
//
// Nothing is repaired here. Status holds no lock, and rewriting a tag without
// one races every operation that could be moving the volume. The repair belongs
// to Attach, which holds the lock and reads the same header — so the error says
// to attach it.
func (p *Provider) requireTagMatchesHeader(volID string, lv lvInfo, offset int64) error {
	header, tagged, err := lv.luksHeaderFromTags()
	switch {
	case !tagged:
		return nil
	case err != nil:
		return fmt.Errorf("go-blockstore/local: %s records its LUKS header unreadably: %w; "+
			"its container really has a %d-byte header. Attach the volume to have it re-recorded",
			p.lvRef(volID), err, offset)
	case header != offset:
		return fmt.Errorf("go-blockstore/local: %s records a %d-byte LUKS header but its container has a "+
			"%d-byte one; a detached read of this volume would report its capacity wrongly. "+
			"Attach the volume to have the tag re-recorded from the container",
			p.lvRef(volID), header, offset)
	}
	return nil
}

// detachedSize is the capacity reported for a volume that is not active, and
// the ONLY place that decision is made.
//
// Three paths arrive at it: an ordinary Status over a detached volume, and two
// races where a volume was found active and had been detached by the time
// something looked closer — once before the probe, once before the header read.
// They are the same question about the same volume and have to give the same
// answer, so they share this function rather than agreeing by inspection. They
// did not, once: the header-read race returned the backing size while the
// ordinary path subtracted the header, which over-stated usable capacity by
// exactly the amount the tag exists to record.
//
// Nothing here can probe. There is no device node on a detached volume and no
// lock held to make one, so the tag is the only source, and its absence is a
// legitimate answer rather than a failure — see reportedSize for what each
// outcome means.
func (p *Provider) detachedSize(volID string, lv lvInfo) (int64, error) {
	header, tagged, err := lv.luksHeaderFromTags()
	switch {
	case err != nil:
		return 0, fmt.Errorf("go-blockstore/local: %s records its LUKS header unreadably: %w; "+
			"attach the volume to have it re-recorded from the container itself",
			p.lvRef(volID), err)
	case tagged:
		return usableBytes(lv.SizeBytes, header), nil
	default:
		return lv.SizeBytes, nil
	}
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
	device, _, err := p.resolveDevice(ctx, volID, lv)
	return device, err
}

// resolveDevice is attachedDevice plus what the logical volume was found to
// hold, for the one caller that needs both.
//
// fsType is what blkid reported for the logical volume, and "" for a volume
// that was not probed at all because it is inactive — which is a third answer,
// distinct from "probed and found to carry no signature". Only an active
// volume has a device node to probe, so the two cases cannot be told apart
// downstream and are not asked to be: every caller treats a non-crypto_LUKS
// answer as "not known to be encrypted".
//
// Returning it rather than probing twice is what keeps Status to one blkid.
func (p *Provider) resolveDevice(ctx context.Context, volID string, lv lvInfo) (device, fsType string, err error) {
	if !lv.active() {
		return "", "", nil
	}

	fsType, err = p.probeFSType(ctx, p.lvPath(volID))
	if err != nil {
		return "", "", err
	}
	if fsType != fsTypeLUKS {
		return p.lvPath(volID), fsType, nil
	}

	open, err := p.luksIsOpen(ctx, volID)
	if err != nil {
		return "", "", err
	}
	if !open {
		return "", fsType, nil
	}
	return p.cryptPath(volID), fsType, nil
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
