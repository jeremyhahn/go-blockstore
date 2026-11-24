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
	"github.com/jeremyhahn/go-blockstore/pkg/preflight"

	"github.com/jeremyhahn/go-blockstore/internal/blkdev"
	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/internal/mountguard"
	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
)

// defaultSnapshotCoWPercent is the share of the origin given to a snapshot's CoW area when none is configured.
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
	keyFile            string
	snapshotCoWPercent int
	wipeOnDelete       bool
	lockDir            string
	mounter            Mounter
	mountTable         MountTable
	mountPropagation   MountPropagationPolicy
	bootID             func() (string, error)
	liveness           LivenessOracle

	// preflightChecked is the capabilities the startup checks covered for this
	// configuration, kept so Posture can name them rather than reporting that
	// "preflight ran" — which says nothing about which of them it covered.
	preflightChecked []preflight.Capability
	blockDevices     BlockDevices
	luks             luksBackend

	// crypt is the shared LUKS machinery bound to this provider's mapping
	// namespace. See pkg/local/luks.go for what this package keeps of its own.
	crypt *luks.Manager
}

// ErrMountedBeneathAnother reports a volume mounted at a path where something else was mounted on top; the other mount must go first.
var ErrMountedBeneathAnother = errors.New("volume is mounted beneath another filesystem")

// excluding returns the items of all that are not in keep, in order.
func excluding(all, keep []string) []string {
	var out []string
	for _, item := range all {
		if !contains(keep, item) {
			out = append(out, item)
		}
	}
	return out
}

// Ensure the provider satisfies the contract at compile time.
var _ common.VolumeProvider = (*Provider)(nil)

// Mounter is the seam through which mounting and unmounting happen; an alias for internal/mount's type.
type Mounter = mount.Mounter

// MountTable is the seam through which the provider asks what is mounted.
type MountTable = mountinfo.Table

// MountPropagationReader is the optional half of the mount-table seam; a table without it is refused when the guard is on.
type MountPropagationReader = mountinfo.PropagationReader

// LivenessOracle is the seam through which the provider asks whether an attachment still has a live owner; an alias for pkg/common's.
type LivenessOracle = common.LivenessOracle

// BlockDevices is the seam through which the provider copies and zeroes block
// devices — what it used to reach for dd and blkdiscard to do.
type BlockDevices = blkdev.Operator

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

	// MountPropagation selects whether Mount verifies the mount is visible outside this namespace; default MountPropagationUnchecked.
	MountPropagation MountPropagationPolicy

	// bootID reads this boot's identifier. It is unexported, like luks, because
	// it is not a seam a caller has any reason to replace — only a test, which
	// needs a boot that can be made to end.
	bootID func() (string, error)

	// MountTable answers what is mounted. It defaults to reading
	// /proc/self/mountinfo; tests substitute a fake.
	MountTable MountTable

	// BlockDevices copies and zeroes block devices. It defaults to the real
	// syscalls; tests substitute a fake.
	BlockDevices BlockDevices

	// LivenessOracle answers whether an attachment still has a live owner; nil is valid. Supply one where an owner can exit while the host stays up. Options only.
	LivenessOracle LivenessOracle

	// Encrypted provisions new volumes as LUKS2 (PBKDF2-SHA-512, AES-256-XTS, FIPS-approved, no cryptsetup) and requires KeyProvider; existing volumes are detected by probing.
	// SizeBytes stays usable capacity: the header is added on top.
	Encrypted bool

	// luksKeyFile is the path SettingLUKSKeyFile named, when the KeyProvider was built from it; used to keep it out of workload paths.
	luksKeyFile string

	// KeyProvider supplies LUKS passphrases. It is required when Encrypted is
	// set and when operating on volumes that are already encrypted.
	KeyProvider KeyProvider

	// SnapshotCoWPercent sizes a snapshot's copy-on-write area as a percentage
	// of its origin, between 1 and 100. It defaults to
	// defaultSnapshotCoWPercent.
	SnapshotCoWPercent int

	// LockDir holds the per-volume lock files; default DefaultLockDir, created 0700. Providers over one volume group must share it, on a local filesystem.
	LockDir string

	// WipeOnDelete zero-fills a volume before removing it; default false.
	// Without it, an unencrypted volume on non-discarding media leaves readable data in freed extents; Encrypted is the better mitigation, and the only complete one with snapshots.
	WipeOnDelete bool

	// Preflight selects which privilege checks New performs; default PreflightConfigured. See package preflight.
	Preflight PreflightMode

	// luks performs the LUKS2 operations; nativeLUKS by default, a fake in tests. Unexported on purpose.
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

	mountTable := opts.MountTable
	if mountTable == nil {
		mountTable = mountinfo.System{}
	}

	blockDevices := opts.BlockDevices
	if blockDevices == nil {
		blockDevices = blkdev.System{}
	}

	mounter := opts.Mounter
	if mounter == nil {
		mounter = mount.System()
	}

	backend := opts.luks
	if backend == nil {
		backend = luks.Native{}
	}

	node := opts.NodeID
	if node == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("go-blockstore/local: determining node ID: %w", err)
		}
		node = common.NodeID(hostname)
	}

	// Last, after every argument has been validated.
	bootID := opts.bootID
	if bootID == nil {
		bootID = readBootID
	}

	// Requiring propagation over a table that cannot report it is refused at startup.
	if opts.MountPropagation == MountPropagationShared && mountTable != nil {
		if !(mountguard.Guard{Policy: opts.MountPropagation, Table: mountTable}).CanReport() {
			return nil, fmt.Errorf("%w: %s is %s, and the configured MountTable cannot report propagation (it does not implement MountPropagationReader)",
				common.ErrInvalidArgument, SettingMountPropagation, MountPropagationShared)
		}
	}

	if !opts.MountPropagation.Valid() {
		return nil, fmt.Errorf("%w: MountPropagation is %s, not one of %s",
			common.ErrInvalidArgument, opts.MountPropagation, strings.Join(mountPropagationSpellings(), ", "))
	}

	checked := requiredCapabilities(opts, opts.Preflight)
	if err := runPreflight(opts, opts.Preflight); err != nil {
		return nil, err
	}

	return &Provider{
		volumeGroup:        opts.VolumeGroup,
		nodeID:             node,
		runner:             runner,
		encrypted:          opts.Encrypted,
		keyProvider:        opts.KeyProvider,
		keyFile:            opts.luksKeyFile,
		snapshotCoWPercent: pct,
		wipeOnDelete:       opts.WipeOnDelete,
		lockDir:            lockDir,
		mounter:            mounter,
		mountTable:         mountTable,
		mountPropagation:   opts.MountPropagation,
		preflightChecked:   checked,
		bootID:             bootID,
		liveness:           opts.LivenessOracle,
		blockDevices:       blockDevices,
		luks:               backend,
		crypt: luks.NewManager(backend, opts.KeyProvider,
			luks.MappingPrefix+opts.VolumeGroup+"_", errScope),
	}, nil
}

// NodeID reports the node this provider manages volumes on.
func (p *Provider) NodeID() common.NodeID { return p.nodeID }

// newVolumeOverhead is what this provider adds on top of a new volume's capacity: a LUKS2 header when encrypting.
func (p *Provider) newVolumeOverhead() int64 {
	if p.encrypted {
		return luksHeaderBytes
	}
	return 0
}

// volumeOverhead reports what an existing volume's own header costs, probing it (activating a detached volume and restoring it).
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

	// Resize also corrects a wrong header tag.
	if tagErr := p.reconcileHeaderTag(ctx, volID, lv, fsType); tagErr != nil {
		return 0, tagErr
	}

	if fsType != fsTypeLUKS {
		return 0, nil
	}
	return p.luksDataOffset(ctx, p.lvPath(volID))
}

// Provision creates a logical volume, optionally LUKS2 and a filesystem, and leaves it inactive; a failure removes it again.
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
	// The backing size must not overflow int64.
	if limit := math.MaxInt64 - p.newVolumeOverhead(); spec.SizeBytes > limit {
		return common.Volume{}, fmt.Errorf("%w: SizeBytes %d exceeds the largest usable capacity this provider can back, %d",
			common.ErrInvalidArgument, spec.SizeBytes, limit)
	}
	// No storage classes or replicas here (ErrUnsupported); a negative replica count is ErrInvalidArgument.
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
		// A restore copies the image, so FSType is refused.
		if spec.FSType != "" {
			return common.Volume{}, fmt.Errorf("%w: FSType %q cannot be applied to a restore from %q; "+
				"the restored volume carries the snapshot's filesystem",
				common.ErrInvalidArgument, spec.FSType, spec.SourceSnapshotID)
		}
	}

	// Lock the new volume and, on a restore, the snapshot's origin.
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

	// A failed closing deactivation rolls back too.
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
		// Tag only once the container exists.
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

// abandon removes a volume that failed to finish provisioning, closing any mapping first; its errors are joined onto the original failure.
func (p *Provider) abandon(ctx context.Context, name string) error {
	var closeErr error
	if p.encrypted {
		// Through luksIsOpen, so the rollback never closes a foreign mapping under this name.
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

// provisionFromSnapshot creates an independent volume holding a snapshot's contents by a full copy.
// A plaintext snapshot is copied directly, or re-encrypted through a new container when this provider encrypts; an encrypted snapshot is copied verbatim and opens with the source's passphrase.
// spec.SizeBytes is compared against the snapshot's usable capacity.
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

	// The image size from the snapshot, not the origin's current size, which may have grown since.
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

	// imageEnd is the LV offset one byte past the copied image, where tail zeroing starts.
	imageEnd int64

	// volumeEnd is where the logical volume will actually end: backing rounded
	// up to a whole extent, the way lvcreate rounds it. Anything between
	// imageEnd and here is tail.
	volumeEnd int64

	// reencrypt copies the image through a freshly formatted LUKS mapping
	// instead of onto the logical volume directly.
	reencrypt bool

	// encrypted is whether the restored volume ends up holding a LUKS container; see restoreImage.
	encrypted bool

	// overhead is the header the restored volume carries: ours when formatting, the source's when copying verbatim.
	overhead int64
}

// planRestore settles sizing and the encryption route and makes every refusing check before createLV.
func (p *Provider) planRestore(ctx context.Context, spec common.VolumeSpec, snapID string, origin lvInfo, imageSize, extent int64) (restorePlan, error) {
	srcOffset, err := p.inspectSource(ctx, spec.Name, snapID, origin)
	if err != nil {
		return restorePlan{}, err
	}

	// Compared in usable bytes on both sides.
	srcUsable := usableBytes(imageSize, srcOffset)
	if spec.SizeBytes < srcUsable {
		return restorePlan{}, fmt.Errorf("%w: restoring %q needs at least %d bytes of usable capacity, spec asks for %d and this provider does not shrink during restore",
			common.ErrUnsupported, snapID, srcUsable, spec.SizeBytes)
	}

	// The restored volume's overhead and the image's offset on it.
	overhead, imageEnd, reencrypt := int64(0), imageSize, false
	switch {
	case srcOffset > 0:
		overhead = srcOffset
	case p.encrypted:
		overhead, imageEnd, reencrypt = luksHeaderBytes, luksHeaderBytes+imageSize, true
	}

	// Guarded again against the restore's own overhead and the extent rounding.
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

// inspectSource reports the LUKS data offset of the snapshot's image, or zero for plaintext, restoring the origin's activation after.
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

// requireRestoredVolumeOpens refuses a verbatim encrypted restore unless KeyProvider's key for the new ID opens the snapshot's header.
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

// restoreImage copies a snapshot onto a new LV, restoring the origin's activation after; a re-encrypting restore writes through the new mapping.
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

	if runErr := p.blockDevices.Copy(ctx, p.lvPath(snapID), dest); runErr != nil {
		return fmt.Errorf("go-blockstore/local: copying snapshot %q into %q: %w", snapID, volID, runErr)
	}

	// A verbatim copy of an encrypted image is tagged once it lands.
	if plan.encrypted && !plan.reencrypt {
		return p.addTag(ctx, volID, encryptedTagFor(plan.overhead))
	}
	return nil
}

// zeroRestoreTail zeroes the restored volume past the copied image, judged against the extent-rounded end; a volume with no tail is left alone.
func (p *Provider) zeroRestoreTail(ctx context.Context, volID string, plan restorePlan) error {
	if plan.volumeEnd <= plan.imageEnd {
		return nil
	}
	return p.zeroTail(ctx, volID, plan.imageEnd)
}

// zeroTail zeroes the LV from offset to the end, so no previous tenant's data remains; the volume's activation is restored after.
func (p *Provider) zeroTail(ctx context.Context, volID string, offset int64) (err error) {
	if activateErr := p.activate(ctx, volID); activateErr != nil {
		return activateErr
	}
	defer func() {
		err = errors.Join(err, p.deactivate(ctx, volID))
	}()

	if runErr := p.blockDevices.ZeroOut(ctx, p.lvPath(volID), offset); runErr != nil {
		return fmt.Errorf("go-blockstore/local: zeroing %s past %d bytes: %w", p.lvRef(volID), offset, runErr)
	}
	return nil
}

// ownsSnapshot reports whether an LV is a snapshot this provider named, via validateSnapshotID, of the volume the name encodes.
func ownsSnapshot(lv lvInfo) bool {
	owner, _, ok := splitSnapshotID(lv.Name)
	if !ok || lv.Origin == "" || lv.Origin != owner {
		return false
	}
	return validateSnapshotID(common.SnapshotID(lv.Name)) == nil
}

// restoreOriginActivation puts a snapshot's origin back in the activation state a restore found it in; origin and snapshots activate together.
func (p *Provider) restoreOriginActivation(ctx context.Context, origin string, wasActive bool) error {
	if wasActive {
		return p.activate(ctx, origin)
	}
	return p.deactivate(ctx, origin)
}

// mkfs creates a filesystem on the device, choosing the binary from mkfsBinaries and forcing over old signatures.
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

	device, err := p.unlockForAttach(ctx, volID, lv, lvs)
	if err != nil {
		// Roll back an activation this call made if the unlock fails.
		if !wasActive {
			err = errors.Join(err, p.deactivate(ctx, volID))
		}
		return common.AttachInfo{}, err
	}

	return common.AttachInfo{DevicePath: device, Node: p.nodeID}, nil
}

// unlockForAttach resolves an activated volume to its mountable device, unlocking LUKS when present and adding a missing header tag.
func (p *Provider) unlockForAttach(ctx context.Context, volID string, lv lvInfo, lvs []lvInfo) (string, error) {
	// Refuse if the key file lies inside any path where one of this provider's volumes is mounted.
	if err := p.checkKeyFileOutsideOurVolumes(ctx, lvs); err != nil {
		return "", err
	}

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
	// Refresh the ownership record whether the mapping was opened or adopted; best effort.
	p.recordMappingOwner(ctx, volID, lv)

	if !open {
		if err := p.luksOpen(ctx, volID, p.lvPath(volID)); err != nil {
			return "", err
		}
	}
	return p.cryptPath(volID), nil
}

// reconcileHeaderTag records the measured header size on a container and removes a header tag from anything else.
// A failed write is tolerated only for a container that had no tag; every other failure is fatal.
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

// Detach locks the volume's LUKS container, if any, and deactivates the LV; unmount first. The header tag is reconciled before deactivating.
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

// closeIfEncrypted tears down the volume's LUKS mapping when probing finds one.
func (p *Provider) closeIfEncrypted(ctx context.Context, volID string) error {
	fsType, err := p.probeFSType(ctx, p.lvPath(volID))
	if err != nil {
		return err
	}
	return p.closeMapping(ctx, volID, fsType)
}

// closeMapping is closeIfEncrypted for a caller that already probed; it does not reconcile the tag.
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
	if err := p.luksClose(ctx, volID); err != nil {
		return err
	}

	// Clear the ownership record after the close; a failure here does not fail the close.
	lvs, listErr := p.listLVs(ctx)
	if listErr != nil {
		return nil
	}
	if lv, found := lookupLV(lvs, volID); found {
		//nolint:errcheck // the mapping is gone, which is what mattered; a stale
		// record with nothing behind it is inert and read as nothing to do.
		_ = p.clearMappingOwner(ctx, volID, lv)
	}
	return nil
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

	// The key-path guard before mount(2) may only refuse; the check after the mount decides.
	if err := p.checkKeyFileOutside(target, "the path this volume is being mounted on"); err != nil {
		return err
	}
	// Also check where this volume is already mounted, on every Mount.
	if err := p.checkKeyFileOutsideOurVolumes(ctx, lvs); err != nil {
		return err
	}

	flags, data := mount.Arguments(opts.ReadOnly, opts.Flags)
	if err := p.mounter.Mount(ctx, device, target, fsType, flags, data); err != nil {
		return err
	}

	// Observe key-file containment in the mounted filesystem, before the propagation check.
	if finding := p.checkKeyFileAgainstMountedFilesystem(ctx, target, lvs); finding != nil {
		return p.unwindRefusedMount(ctx, device, target, finding)
	}

	// Check the mount is visible to the workload's namespace.
	if id, finding := p.verifyMountPropagation(ctx, device, target); finding != nil {
		return p.unwindUnverifiedMount(ctx, device, target, id, finding)
	}
	return nil
}

// Unmount unmounts the volume from target; not attached, not a mountpoint, or another device there all return nil.
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

	// Only where this volume is visible; an over-mounted target is a no-op.
	mounts, err := p.visibleMountpointsFor(ctx, device)
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

// Resize grows the volume to newSize usable bytes and, where it can, the filesystem; it converges on repetition.
// An attached encrypted volume is refused with ErrResizeWhileAttached; a shrink is ErrUnsupported; the result may round up to a whole extent.
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
	// Grow the backing device by the volume's own measured header too.
	overhead, err := p.volumeOverhead(ctx, volID, lv)
	if err != nil {
		return err
	}
	// A size that overflows after overhead and rounding is ErrInvalidArgument.
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

	// Resolved before anything grows, so a refusal leaves the volume untouched.
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

// growDetachedFilesystem grows the filesystem on a detached volume, activating and unlocking it only for the duration.
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

// growDetachedEncryptedFilesystem opens the container after the LV grew, so the mapping takes the new size, grows the filesystem and locks it again.
func (p *Provider) growDetachedEncryptedFilesystem(ctx context.Context, volID string) (err error) {
	if openErr := p.luksOpen(ctx, volID, p.lvPath(volID)); openErr != nil {
		return openErr
	}
	defer func() {
		err = errors.Join(err, p.luksClose(ctx, volID))
	}()

	return p.growFilesystem(ctx, volID, p.cryptPath(volID))
}

// growFilesystem grows ext2/3/4 (online, or offline after e2fsck -f when the mount table shows it unmounted) and mounted XFS; others are left alone.
func (p *Provider) growFilesystem(ctx context.Context, volID, device string) error {
	fsType, err := p.probeFSType(ctx, device)
	if err != nil {
		return err
	}
	if fsType == "" {
		return nil
	}

	mounts, err := p.mountpointsFor(ctx, device)
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

// e2fsckCorrected is e2fsck's "errors found and fixed" status; with 0 the filesystem may be resized.
const e2fsckCorrected = 1

// checkExtFilesystem runs e2fsck -f -p, the forced non-interactive check resize2fs demands before an offline grow.
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

// Snapshot takes a CoW snapshot named "<volume>_snap_<name>", which is its ID.
func (p *Provider) Snapshot(ctx context.Context, volID, name string) (common.SnapshotID, error) {
	if err := validateName("volume", volID); err != nil {
		return "", err
	}
	if err := validateName("snapshot", name); err != nil {
		return "", err
	}

	// The origin's lock covers its snapshots.
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

	// lvcreate rejects --setautoactivation for snapshots; activation follows the origin.
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

// ListSnapshots returns the volume's snapshots in no guaranteed order, without a lock; SizeBytes is the space each occupies.
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
		// Only snapshots this provider named.
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

	// Locked on the owning volume.
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

// Delete unmounts, locks and removes the volume; a failed unmount stops it. Snapshots are refused with common.ErrHasSnapshots. WipeOnDelete zero-fills first.
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
		mounts, err := p.mountpointsFor(ctx, device)
		if err != nil {
			return err
		}
		visible, err := p.visibleMountpointsFor(ctx, device)
		if err != nil {
			return err
		}
		// An over-mounted mount cannot be unmounted from here; stop the delete.
		if hidden := excluding(mounts, visible); len(hidden) > 0 {
			return fmt.Errorf(
				"go-blockstore/local: volume %q is mounted at %s beneath another filesystem; unmount that first: %w",
				volID, strings.Join(hidden, ", "), ErrMountedBeneathAnother)
		}
		for _, target := range deepestFirst(visible) {
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
		// Undo the wipe's activation when the removal fails.
		if p.wipeOnDelete && !wasActive {
			return errors.Join(err, p.deactivate(ctx, volID))
		}
		return err
	}
	return nil
}

// wipe zero-fills the LV (not the mapping) with blkdiscard --zeroout; snapshot CoW extents are out of reach. A failure undoes its activation.
func (p *Provider) wipe(ctx context.Context, volID string, wasActive bool) error {
	if err := p.activate(ctx, volID); err != nil {
		return err
	}
	if err := p.blockDevices.ZeroOut(ctx, p.lvPath(volID), 0); err != nil {
		wipeErr := fmt.Errorf("go-blockstore/local: wiping %s: %w", p.lvRef(volID), err)
		if wasActive {
			return wipeErr
		}
		return errors.Join(wipeErr, p.deactivate(ctx, volID))
	}
	return nil
}

// Status reports usable capacity and attachment state without a lock.
// An active volume's header is discovered by probing; a detached one's comes from its LVM tag; an untagged detached legacy volume reports its backing size.
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

	mounts, err := p.mountpointsFor(ctx, device)
	if err != nil {
		return common.VolumeStatus{}, err
	}
	if len(mounts) > 0 {
		status.State = common.VolumeStateMounted
	}
	return status, nil
}

// reportedSize is the capacity Status reports: discovered when active (a disagreeing tag is an error), from the tag when detached, the backing size when detached and untagged.
func (p *Provider) reportedSize(ctx context.Context, volID string, lv lvInfo, fsType string) (int64, error) {
	if !lv.active() {
		return p.detachedSize(volID, lv)
	}

	tagged := len(lv.luksHeaderTags()) > 0

	if fsType != fsTypeLUKS {
		// A tag over a non-container: first rule out a concurrent detach.
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

// usableSize reads a just-probed container's header; on failure it re-reads the group: gone is ErrNotFound, detached goes through detachedSize, still active is an error.
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
		// Detached underneath the header read: the detached answer.
		return p.detachedSize(volID, current)
	default:
		return 0, err
	}
}

// requireTagMatchesHeader refuses a recorded header size that disagrees with the container's; untagged volumes pass, and Attach repairs.
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

// detachedSize is the capacity reported for an inactive volume, from its tag; the only place that decision is made.
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

// attachedDevice resolves the device a volume is reachable at, or ""; an encrypted volume counts only once its mapping exists.
func (p *Provider) attachedDevice(ctx context.Context, volID string, lv lvInfo) (string, error) {
	device, _, err := p.resolveDevice(ctx, volID, lv)
	return device, err
}

// resolveDevice is attachedDevice plus blkid's fsType for the LV ("" when inactive), so Status probes once.
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

// checkNode accepts this provider's node or ""; any other is ErrUnsupported.
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

// deepestFirst orders mountpoints longest first, so nested mounts unmount before their parents.
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
