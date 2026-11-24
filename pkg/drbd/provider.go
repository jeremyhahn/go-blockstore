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

//go:build drbd

package drbd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-blockstore/internal/blkdev"
	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-blockstore/internal/mount"
	"github.com/jeremyhahn/go-blockstore/internal/mountguard"
	"github.com/jeremyhahn/go-blockstore/internal/mountinfo"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// The system tooling this provider execs, beyond the LVM binaries in lvm.go.
const (
	binDRBDAdm   = "drbdadm"
	binDRBDSetup = "drbdsetup"
	binBlkid     = "blkid"
	binResize2fs = "resize2fs"
	binXFSGrowfs = "xfs_growfs"
	binE2fsck    = "e2fsck"
)

// Exit codes this package interprets rather than treats as failure.
const (
	blkidNoSig = 2 // blkid: the device carries no recognized signature.

	// e2fsck exit 1: errors found and fixed; with 0 the filesystem can be resized, 2 and above cannot.
	e2fsckCorrected = 1
)

// rollbackTimeout bounds the cleanup that unwinds a failed Provision, so it cannot hold the mutex forever.
const rollbackTimeout = 2 * time.Minute

// cleanupContext detaches a compensating action from the caller's possibly canceled context, with its own bound.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
}

// statusSizeUnit converts the device size in a drbdsetup status document to
// bytes. DRBD reports sizes in KiB throughout, the JSON "size" field included.
const statusSizeUnit = 1024

// drbdReplicas is this provider's natural replica count, and the only one it
// can serve: the resource template writes exactly two hosts. It is what a
// VolumeSpec with Replicas unset resolves to.
const drbdReplicas = 2

// ErrPrimary is returned by an operation that refuses to run while the local
// node holds Primary — tearing the device down or deleting it out from under
// whatever has it open.
//
// It stays package-local, unlike its opposite. common.ErrNotPrimary is the
// portable "promote first, then retry" branch that an HA controller acts on;
// nothing outside this package yet needs to distinguish "refused because you
// ARE primary" from any other refusal, and a sentinel in pkg/common with no
// portable consumer is a contract nobody is holding up.
var ErrPrimary = errors.New("volume is primary on this node")

// ErrRoleUnknown is returned by a destructive operation that cannot establish
// what role the local node holds for a resource that is up.
//
// It exists because "not Primary" and "not known to be Primary" are different
// answers, and only the first one makes a teardown safe. drbdsetup reports the
// role as "Unknown" in some states, and a version this parser does not know
// could report something else again; either way the mapped role is
// common.ReplRoleUnknown, and treating that as permission to run drbdadm down
// and lvremove is deciding the safe case by default. The refusal carries the
// role string exactly as drbdsetup gave it, since that is the only thing that
// makes an unrecognized value diagnosable.
//
// Package-local for the same reason as ErrPrimary: it is a "this provider will
// not do that" answer with no portable consumer. An HA controller acts on
// common.ErrNotPrimary; nothing outside needs to branch on this.
var ErrRoleUnknown = errors.New("the resource's replication role could not be determined")

// Provider is the DRBD 9 implementation of common.ReplicatedProvider.
//
// It is safe for concurrent use. The mutex serializes the operations that both
// read and then write the state directory — provisioning, which allocates a
// device minor and a port, and deletion, which frees them — so two concurrent
// Provisions cannot hand out the same minor.
//
// It also serializes every operation that CHECKS a condition and then acts on
// it against every operation that can change what was checked: Snapshot's
// Primary requirement against Promote and Demote, Delete's and Detach's
// Secondary and no-snapshots requirements against Snapshot, Promote and Demote,
// Delete's not-up observation against Attach, and Mount's and Unmount's whole
// bodies against the Delete-then-Provision pair that can recycle a minor
// underneath them.
//
// Every mutating method is therefore in the set, and each of the three ways of
// deciding otherwise turned out to be wrong:
//
// The DIRECTION of a change is not the test. A demotion only ever makes a
// volume less writable, which is exactly what invalidates Snapshot's check; a
// promotion only ever makes one more writable, which is exactly what
// invalidates Detach's.
//
// Whether the method has a PRECONDITION OF ITS OWN is not the test. Attach
// checks nothing and belongs here because the check it breaks is Delete's.
//
// And failing closed on ROLE is not failing closed on IDENTITY. Mount was left
// out on the argument that a demotion in its window makes the device open fail,
// since DRBD refuses every open of a Secondary — true, and irrelevant to the
// case where the volume is deleted and its minor reused, because the
// replacement is perfectly willing to be Primary. The stale record then points
// every step at a device belonging to a volume the call never looked up. That
// is why the lookup is inside the lock in every one of these methods and not
// merely the command that follows it.
//
// What is left out is read-only: ListSnapshots, Status and ReplicationState.
type Provider struct {
	cfg          Config
	runner       CommandRunner
	mounter      Mounter
	mountTable   MountTable
	blockDevices BlockDevices

	// injected records which seams the caller replaced, so runPreflight skips their checks.
	injected    injectedSeams
	secrets     SecretProvider
	keyProvider KeyProvider
	luks        luks.Backend

	// crypt is the shared LUKS machinery bound to this provider's mapping
	// namespace. See luks.go for what this package keeps of its own.
	crypt *luks.Manager

	mu sync.Mutex
}

// Compile-time proof that the provider satisfies the replicated contract, not
// just the base one.
var _ common.ReplicatedProvider = (*Provider)(nil)

// Mounter is the seam through which mounting and unmounting happen.
//
// It is an alias for internal/mount's type, not a copy of it: the pinning
// implementation is shared with pkg/local because the reason it exists — a
// target has to be resolved to a descriptor with symlink resolution refused
// before a privileged mount addresses it — is the same for both. The alias is
// what lets a caller outside this module NAME the type it is handing to
// WithMounter, which an internal package's own name would not.
type Mounter = mount.Mounter

// MountTable is the seam through which the provider asks what is mounted.
//
// It replaced asking findmnt, and it is shared with pkg/local for the same
// reason Mounter is: reading /proc/self/mountinfo is not a DRBD concern, and
// two copies of a parser would be two chances to disagree about the kernel's
// escaping.
type MountTable = mountinfo.Table

// BlockDevices is the seam through which the provider copies and zeroes block
// devices — what it used to reach for dd and blkdiscard to do.
type BlockDevices = blkdev.Operator

// Option customizes a Provider at construction.
type Option func(*Provider)

// WithRunner replaces the command runner. Tests use it to script the system
// tooling; production leaves it alone and gets a plain exec.
func WithRunner(r CommandRunner) Option {
	return func(p *Provider) { p.runner = r; p.injected.runner = true }
}

// WithSecretProvider supplies the shared secret DRBD authenticates the peer
// with. It takes precedence over replication_secret_file.
//
// A caller with the secret somewhere this package should not know about — a
// TPM-sealed blob, an operator prompt, a KMS — unseals it into an enclave and
// hands it over here. That is the whole of this package's involvement with
// secret management, for the same reason pkg/local's KeyProvider is: a provider
// that knew how to talk to a TPM would drag hardware-specific dependencies into
// a library whose other backends have no use for them.
func WithSecretProvider(s SecretProvider) Option {
	return func(p *Provider) { p.secrets = s }
}

// WithMounter replaces the mounter. Tests use it to record mounts without root
// or a real filesystem; production leaves it alone and gets the pinning
// implementation from internal/mount.
func WithMounter(m Mounter) Option {
	return func(p *Provider) { p.mounter = m; p.injected.mounter = true }
}

// WithMountTable replaces the mount table. Tests use it to describe what is
// mounted without mounting anything.
func WithMountTable(m MountTable) Option {
	return func(p *Provider) { p.mountTable = m; p.injected.mountTable = true }
}

// WithBlockDevices replaces the block-device operations. Tests use them to
// record copies and zeroing without a device to perform them on.
func WithBlockDevices(b BlockDevices) Option {
	return func(p *Provider) { p.blockDevices = b; p.injected.blockDevices = true }
}

// New builds a DRBD provider from a settings map. See the Setting constants for
// the accepted keys; an unknown key is an error rather than a no-op.
//
// It creates the configuration and state directories if they do not exist, so a
// freshly imaged node needs no preparation beyond DRBD itself.
func New(settings map[string]string, opts ...Option) (*Provider, error) {
	cfg, err := ParseConfig(settings)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		cfg:          cfg,
		runner:       execRunner{},
		mounter:      mount.System(),
		mountTable:   mountinfo.System{},
		blockDevices: blkdev.System{},
		luks:         luks.Native{},
	}
	for _, o := range opts {
		o(p)
	}
	if p.runner == nil {
		return nil, fmt.Errorf("%w: command runner is nil", common.ErrInvalidArgument)
	}
	if p.mounter == nil {
		return nil, fmt.Errorf("%w: mounter is nil", common.ErrInvalidArgument)
	}
	if p.mountTable == nil {
		return nil, fmt.Errorf("%w: mount table is nil", common.ErrInvalidArgument)
	}
	if p.blockDevices == nil {
		return nil, fmt.Errorf("%w: block devices is nil", common.ErrInvalidArgument)
	}
	if p.luks == nil {
		return nil, fmt.Errorf("%w: luks backend is nil", common.ErrInvalidArgument)
	}
	// Requiring propagation over a mount table that cannot report it is refused at startup.
	if !p.mountGuard().Policy.Valid() {
		return nil, fmt.Errorf("%w: %s is %s, not one of %s",
			common.ErrInvalidArgument, SettingMountPropagation, cfg.MountPropagation, strings.Join(mountguard.Spellings(), ", "))
	}
	if cfg.MountPropagation == MountPropagationShared && !p.mountGuard().CanReport() {
		return nil, fmt.Errorf("%w: %s is %s, and the configured MountTable cannot report propagation (it does not implement MountPropagationReader)",
			common.ErrInvalidArgument, SettingMountPropagation, MountPropagationShared)
	}
	// An injected provider wins over the file setting, for the reason it does
	// with the replication secret: a caller unsealing from a TPM should not also
	// have to leave the setting unset.
	if p.keyProvider == nil && cfg.LUKSKeyFile != "" {
		p.keyProvider = FileKeyProvider(cfg.LUKSKeyFile)
	}
	// Encryption without a key source is refused at construction.
	if cfg.Encrypted && p.keyProvider == nil {
		return nil, fmt.Errorf("%w: %s is set but there is no way to obtain the passphrase: set %s or inject a KeyProvider",
			common.ErrInvalidArgument, SettingEncrypted, SettingLUKSKeyFile)
	}
	// And the other way round, because a key that is configured and never used
	// is a deployment that believes it is encrypting and is not.
	if !cfg.Encrypted && p.keyProvider != nil {
		return nil, fmt.Errorf("%w: a LUKS passphrase is configured but %s is not set, so nothing would be encrypted",
			common.ErrInvalidArgument, SettingEncrypted)
	}
	p.crypt = luks.NewManager(p.luks, p.keyProvider, p.mappingNamespace(), errScope)
	// An injected provider wins over the file setting, so a caller unsealing
	// from a TPM does not also have to leave the setting unset.
	if p.secrets == nil && cfg.ReplicationSecretFile != "" {
		p.secrets = FileSecretProvider(cfg.ReplicationSecretFile)
	}
	// Refused at construction rather than at the first Provision. A node
	// brought up with no way to authenticate its peer is a deployment mistake,
	// and finding out when the first volume is created is finding out late.
	if p.secrets == nil && !cfg.AllowUnauthenticatedPeers {
		return nil, fmt.Errorf("%w: no peer authentication is configured: set %s, inject a SecretProvider, or acknowledge the exposure with %s=true",
			common.ErrInvalidArgument, SettingReplicationSecretFile, SettingAllowUnauthenticatedPeers)
	}

	// 0750: only root and its group may read the replication topology.
	if err := os.MkdirAll(cfg.ConfigDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating %s %q: %w", SettingConfigDir, cfg.ConfigDir, err)
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s %q: %w", SettingStateDir, cfg.StateDir, err)
	}

	// Preflight runs last, after every setting is validated; see requiredCapabilities.
	if err := runPreflight(p.injected, cfg.Encrypted, cfg.Preflight); err != nil {
		return nil, err
	}
	return p, nil
}

// Config returns the provider's validated configuration.
//
// The addresses are CLONED. Config is a value, which looks like a copy already
// — but net.IP is a slice, so returning the struct as it stands hands out the
// provider's own backing arrays. A caller that inspected its configuration and
// then wrote to the address it got back would be editing validated state from
// outside, and every resource file generated afterwards would carry the change
// without having gone near ParseConfig. Measured before this: the address
// became "::" and the generated resource file carried it.
//
// Everything else in Config is a string, an int or a bool, and copies with the
// struct.
func (p *Provider) Config() Config {
	cfg := p.cfg
	cfg.NodeAddress = slices.Clone(p.cfg.NodeAddress)
	cfg.PeerAddress = slices.Clone(p.cfg.PeerAddress)
	return cfg
}

// -----------------------------------------------------------------------------
// Status helpers
// -----------------------------------------------------------------------------

// status reads the whole node's DRBD status.
func (p *Provider) status(ctx context.Context) ([]resourceStatus, error) {
	out, err := p.runner.Run(ctx, binDRBDSetup, "status", "--json")
	if err != nil {
		return nil, fmt.Errorf("reading drbd status: %w", err)
	}
	return parseStatus(out)
}

// resourceStatus returns the named resource's status and whether it is up.
func (p *Provider) resourceStatus(ctx context.Context, name string) (resourceStatus, bool, error) {
	all, err := p.status(ctx)
	if err != nil {
		return resourceStatus{}, false, err
	}
	rs, ok := findResource(all, name)
	return rs, ok, nil
}

// localRole reports the role the local node holds for a resource, and whether
// the resource is up at all.
func (p *Provider) localRole(ctx context.Context, name string) (common.ReplRole, bool, error) {
	role, _, up, err := p.localRoleRaw(ctx, name)
	return role, up, err
}

// localRoleRaw is localRole plus drbdsetup's role string, empty when the resource is not up.
func (p *Provider) localRoleRaw(ctx context.Context, name string) (common.ReplRole, string, bool, error) {
	rs, up, err := p.resourceStatus(ctx, name)
	if err != nil || !up {
		return common.ReplRoleUnknown, "", up, err
	}
	role, ok := parseRole(rs.Role)
	if !ok {
		return common.ReplRoleUnknown, rs.Role, true, nil
	}
	return role.common(), rs.Role, true, nil
}

// requirePrimary fails unless the resource is up and Primary on this node.
func (p *Provider) requirePrimary(ctx context.Context, name string) error {
	role, up, err := p.localRole(ctx, name)
	if err != nil {
		return err
	}
	if !up {
		return fmt.Errorf("volume %q: resource is not up: %w", name, common.ErrNotAttached)
	}
	if role != common.ReplRolePrimary {
		return fmt.Errorf("volume %q: role is %s: %w", name, role, common.ErrNotPrimary)
	}
	return nil
}

// -----------------------------------------------------------------------------
// drbdadm wrappers
// -----------------------------------------------------------------------------

func (p *Provider) drbdadm(ctx context.Context, args ...string) error {
	_, err := p.runner.Run(ctx, binDRBDAdm, args...)
	return err
}

// createMetadata initializes DRBD internal metadata; --force only skips drbdmeta's overwrite prompt on the fresh LV.
func (p *Provider) createMetadata(ctx context.Context, res string) error {
	if err := p.drbdadm(ctx, "--", "--force", "create-md", res); err != nil {
		return fmt.Errorf("creating drbd metadata for %q: %w", res, err)
	}
	return nil
}

func (p *Provider) resourceUp(ctx context.Context, res string) error {
	if err := p.drbdadm(ctx, "up", res); err != nil {
		return fmt.Errorf("bringing up drbd resource %q: %w", res, err)
	}
	return nil
}

func (p *Provider) resourceDown(ctx context.Context, res string) error {
	if err := p.drbdadm(ctx, "down", res); err != nil {
		return fmt.Errorf("bringing down drbd resource %q: %w", res, err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// VolumeProvider
// -----------------------------------------------------------------------------

// Provision creates a backing logical volume, generates and installs the DRBD
// resource file, initializes metadata and brings the resource up.
//
// The resource comes up Secondary and Inconsistent on both nodes, which is
// where a two-node resource that has never synchronized belongs. Making one
// side authoritative for the first time is not done here; see the package doc
// on initial sync.
//
// spec.SizeBytes is USABLE capacity, per common.VolumeSpec.SizeBytes: the
// backing logical volume is created at backingBytes(spec.SizeBytes, encrypted),
// so DRBD's internal metadata — and, on an encrypted provider, the LUKS2
// header — comes out of space added for it rather than out of what the caller
// asked for. The record keeps the usable figure.
//
// spec.Replicas may be left unset: zero means unspecified and resolves to this
// provider's natural count of two.
//
// A non-empty spec.FSType is validated and recorded but no filesystem is
// created: mkfs needs to open the device read/write, which DRBD permits only on
// a Primary. Mount creates the filesystem on first use instead, once the HA
// controller has promoted the volume.
//
// A non-empty spec.SourceSnapshotID restores by copying the snapshot's blocks
// into the new backing device before DRBD metadata is written. The restored
// volume inherits the SOURCE volume's filesystem, since the copy is
// byte-for-byte, so spec.FSType must be empty on a restore.
//
// spec.SizeBytes may exceed the snapshot's size. The backing volume is created
// at the SOURCE's size — a whole-device copy into a longer device would strand
// the source's metadata partway through the new volume's data — and the volume
// is then grown to the requested size through the same sequence Resize runs,
// which relocates the metadata properly. The filesystem inside it is grown only
// where it can be, which on a freshly provisioned Secondary is nowhere: the
// device is the requested size and the filesystem is the source's, and the
// record says so (FSGrowPending) so that the first Mount after a promotion
// grows it online. That is the Resize contract, reached by the same route. The
// copy is a full one, so the restored volume has no continuing dependency on
// the snapshot and the snapshot can be deleted afterwards.
//
// The VolumeSpec is taken by value because common.VolumeProvider says so; a
// provider that took a pointer would not implement the interface. The linter's
// hugeParam threshold is set for exactly that in .golangci.yml, so this needs
// no suppression.
func (p *Provider) Provision(ctx context.Context, spec common.VolumeSpec) (common.Volume, error) {
	if err := validateName("volume name", spec.Name); err != nil {
		return common.Volume{}, err
	}
	if spec.SizeBytes <= 0 {
		return common.Volume{}, fmt.Errorf("%w: size must be positive, got %d", common.ErrInvalidArgument, spec.SizeBytes)
	}
	// Refuse sizes whose header and metadata additions would overflow int64.
	if limit := maxDataBytes(0, p.cfg.Encrypted); spec.SizeBytes > limit {
		return common.Volume{}, fmt.Errorf("%w: size %d exceeds the largest usable capacity this provider can back, %d (a larger request overflows the backing size once DRBD's internal metadata, and the LUKS2 header on an encrypted provider, is added)",
			common.ErrInvalidArgument, spec.SizeBytes, limit)
	}
	if err := validateFSType(spec.FSType); err != nil {
		return common.Volume{}, err
	}
	// This provider has no storage classes, so a requested class is ErrUnsupported.
	if spec.StorageClass != "" {
		return common.Volume{}, fmt.Errorf("%w: the drbd provider has no storage classes; volume group %q backs every volume, and StorageClass %q cannot be honored",
			common.ErrUnsupported, p.cfg.VG, spec.StorageClass)
	}
	// A restore carries the snapshot's filesystem, so FSType must be empty.
	if spec.SourceSnapshotID != "" && spec.FSType != "" {
		return common.Volume{}, fmt.Errorf("%w: FSType %q cannot be applied to a restore from %q; the restored volume carries the snapshot's filesystem",
			common.ErrInvalidArgument, spec.FSType, spec.SourceSnapshotID)
	}
	// The natural count is two: 0 means two, negative is ErrInvalidArgument, any other count ErrUnsupported.
	switch {
	case spec.Replicas < 0:
		return common.Volume{}, fmt.Errorf("%w: replicas must not be negative, got %d", common.ErrInvalidArgument, spec.Replicas)
	case spec.Replicas == 0 || spec.Replicas == drbdReplicas:
		// Unspecified, or exactly what this provider is for.
	default:
		return common.Volume{}, fmt.Errorf("%w: the drbd provider replicates across exactly %d nodes, %d requested",
			common.ErrUnsupported, drbdReplicas, spec.Replicas)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// readMeta, not loadMeta: a record left behind by a provision that did not
	// finish still claims the name, and reusing it would build a second volume
	// over the first one's reserved minor and port. Delete clears it.
	if existing, err := p.readMeta(spec.Name); err == nil {
		if existing.Incomplete {
			return common.Volume{}, fmt.Errorf("volume %q was left half-provisioned by an earlier attempt; delete it first: %w",
				spec.Name, common.ErrAlreadyExists)
		}
		return common.Volume{}, fmt.Errorf("volume %q: %w", spec.Name, common.ErrAlreadyExists)
	} else if !errors.Is(err, common.ErrNotFound) {
		return common.Volume{}, err
	}

	existing, err := p.listMeta()
	if err != nil {
		return common.Volume{}, err
	}
	minor, port, err := p.resolveMinorAndPort(&spec, existing)
	if err != nil {
		return common.Volume{}, fmt.Errorf("volume %q: %w", spec.Name, err)
	}

	// Resolve the restore source before anything is created, so a bad snapshot
	// id costs nothing.
	fsType := spec.FSType
	var plan *restorePlan
	if spec.SourceSnapshotID != "" {
		plan, err = p.restoreSource(ctx, &spec)
		if err != nil {
			return common.Volume{}, err
		}
		fsType = plan.fsType
	}

	meta := resourceMeta{
		Name:      spec.Name,
		LV:        spec.Name,
		VG:        p.cfg.VG,
		SizeBytes: spec.SizeBytes,
		FSType:    fsType,
		Minor:     minor,
		Port:      port,
		Labels:    spec.Labels,
		CreatedAt: time.Now().UTC(),

		// Cleared once the volume exists. Until then the record reserves the
		// minor and port without making the volume visible to anything else.
		Incomplete: true,
	}

	// Write the record first, marked incomplete, to reserve the minor and port; every failure below unwinds it.
	if err := p.writeMeta(&meta); err != nil {
		return common.Volume{}, err
	}

	var lvCreated, resWritten bool

	// rollback undoes the build in reverse order on a detached context, stops before lvremove if drbdadm down fails, keeps the files unless teardown is confirmed, and returns what it could not undo.
	rollback := func() error {
		cleanupCtx, cancel := cleanupContext(ctx)
		defer cancel()

		// incomplete reports a partial cleanup, naming everything left on the node.
		incomplete := func(errs []error, retained []string) error {
			if resWritten {
				retained = append(retained, "resource file "+p.resPath(meta.Name))
			}
			retained = append(retained, "state record "+p.metaPath(meta.Name))
			errs = append(errs, fmt.Errorf(
				"cleanup did not finish, so these were kept for you to remove by hand rather than orphaned: %s; "+
					"the state record continues to reserve minor %d and port %d",
				strings.Join(retained, ", "), meta.Minor, meta.Port))
			return errors.Join(errs...)
		}

		var errs []error
		var retained []string
		if resWritten {
			if downErr := p.resourceDown(cleanupCtx, meta.Name); downErr != nil {
				// Stop here: a resource that would not go down may still be attached to this LV.
				errs = append(errs, downErr)
				retained = append(retained, fmt.Sprintf("drbd resource %q may still be up", meta.Name))
				if lvCreated {
					retained = append(retained, "logical volume "+p.lvRef(meta.LV)+", left alone because the resource may still be using it")
				}
				return incomplete(errs, retained)
			}
		}
		if lvCreated {
			// The resource is confirmed down, so the device is closed and this
			// refusal is about the volume itself.
			if lvErr := p.lvRemove(cleanupCtx, meta.LV); lvErr != nil {
				errs = append(errs, lvErr)
				retained = append(retained, "logical volume "+p.lvRef(meta.LV))
			}
		}

		// Only now, with the node provably clear, do the files describing it go.
		if len(errs) == 0 && resWritten {
			if rmErr := os.Remove(p.resPath(meta.Name)); rmErr != nil && !os.IsNotExist(rmErr) {
				errs = append(errs, rmErr)
			}
		}
		if len(errs) == 0 {
			if rmErr := os.Remove(p.metaPath(meta.Name)); rmErr != nil && !os.IsNotExist(rmErr) {
				errs = append(errs, rmErr)
			}
		}
		if len(errs) == 0 {
			return nil
		}
		return incomplete(errs, retained)
	}

	// A restore creates the backing volume at the source's size and grows after bring-up; see restorePlan.
	createSize := backingBytes(meta.SizeBytes, p.cfg.Encrypted)
	if plan != nil {
		createSize = plan.backingSize
	}
	if err := p.lvCreate(ctx, meta.LV, createSize); err != nil {
		return common.Volume{}, errors.Join(err, rollback())
	}
	lvCreated = true

	if plan != nil {
		if copyErr := p.copyDevice(ctx, plan.device, p.lvPath(meta.LV)); copyErr != nil {
			return common.Volume{}, errors.Join(copyErr, rollback())
		}
	}

	if err := p.writeResourceFile(ctx, &meta); err != nil {
		return common.Volume{}, errors.Join(err, rollback())
	}
	resWritten = true

	if err := p.createMetadata(ctx, meta.Name); err != nil {
		return common.Volume{}, errors.Join(err, rollback())
	}

	if err := p.resourceUp(ctx, meta.Name); err != nil {
		return common.Volume{}, errors.Join(err, rollback())
	}

	// Grow a restore that asked for more than the source, through the Resize sequence.
	if plan != nil && plan.grow {
		if growErr := p.resizeLocked(ctx, &meta, spec.SizeBytes); growErr != nil {
			return common.Volume{}, errors.Join(growErr, rollback())
		}
	}

	// The volume exists now, so the record stops being a reservation and starts
	// being the answer to "does this volume exist".
	meta.Incomplete = false
	if err := p.writeMeta(&meta); err != nil {
		return common.Volume{}, errors.Join(err, rollback())
	}

	return common.Volume{ID: meta.Name, Spec: spec}, nil
}

// Labels that pin the minor and port both nodes of a pair must agree on; see resolveMinorAndPort.
const (
	// LabelMinor pins the DRBD device minor.
	LabelMinor = "drbd.minor"

	// LabelPort pins the TCP port the resource replicates over.
	LabelPort = "drbd.port"
)

// labelPrefix namespaces this provider's labels; an unrecognized label under it is rejected.
const labelPrefix = "drbd."

// resolveMinorAndPort uses LabelMinor and LabelPort when both are pinned, else allocates locally; pinning only one is refused.
func (p *Provider) resolveMinorAndPort(spec *common.VolumeSpec, existing []resourceMeta) (minor, port int, err error) {
	for k := range spec.Labels {
		if strings.HasPrefix(k, labelPrefix) && k != LabelMinor && k != LabelPort {
			return 0, 0, fmt.Errorf("%w: unknown label %q (this provider reads %s and %s)", common.ErrInvalidArgument, k, LabelMinor, LabelPort)
		}
	}

	rawMinor, haveMinor := spec.Labels[LabelMinor]
	rawPort, havePort := spec.Labels[LabelPort]

	switch {
	case haveMinor != havePort:
		return 0, 0, fmt.Errorf("%w: %s and %s must be given together: both are written into the resource file and both halves of the pair must agree on them",
			common.ErrInvalidArgument, LabelMinor, LabelPort)

	case !haveMinor:
		return allocate(existing, p.cfg.MinorBase, p.cfg.PortBase)
	}

	if minor, err = parseLabelInt(LabelMinor, rawMinor, 0, maxMinor); err != nil {
		return 0, 0, err
	}
	if port, err = parseLabelInt(LabelPort, rawPort, 1, maxPort); err != nil {
		return 0, 0, err
	}
	// A pinned value still has to be free locally, or two resources on this
	// node would claim one device number or one listening port.
	for i := range existing {
		m := &existing[i]
		if m.Minor == minor {
			return 0, 0, fmt.Errorf("%w: %s %d is already used by volume %q", common.ErrInvalidArgument, LabelMinor, minor, m.Name)
		}
		if m.Port == port {
			return 0, 0, fmt.Errorf("%w: %s %d is already used by volume %q", common.ErrInvalidArgument, LabelPort, port, m.Name)
		}
	}
	return minor, port, nil
}

func parseLabelInt(label, raw string, min, max int) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: label %s is not an integer: %q", common.ErrInvalidArgument, label, raw)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%w: label %s must be in [%d,%d], got %d", common.ErrInvalidArgument, label, min, max, n)
	}
	return n, nil
}

// resolveSnapshot returns the snapshot LV and its owning volume's record, or common.ErrSnapshotNotFound if this provider did not take it.
func (p *Provider) resolveSnapshot(ctx context.Context, snapID common.SnapshotID) (lvEntry, resourceMeta, error) {
	volLV, snapName, err := p.parseSnapshotID(string(snapID))
	if err != nil {
		return lvEntry{}, resourceMeta{}, err
	}

	owner, metaErr := p.loadMeta(volLV)
	if metaErr != nil {
		if errors.Is(metaErr, common.ErrNotFound) {
			return lvEntry{}, resourceMeta{}, fmt.Errorf("snapshot %q names volume %q, which this provider does not manage: %w",
				snapID, volLV, common.ErrSnapshotNotFound)
		}
		return lvEntry{}, resourceMeta{}, metaErr
	}

	lvs, err := p.lvs(ctx)
	if err != nil {
		return lvEntry{}, resourceMeta{}, err
	}
	entry, ok := findLV(lvs, snapshotLV(volLV, snapName))
	if !ok {
		return lvEntry{}, resourceMeta{}, fmt.Errorf("snapshot %q: %w", snapID, common.ErrSnapshotNotFound)
	}
	// An LV with the right name but a different origin — or none, meaning it is
	// not a snapshot at all — is not the snapshot the caller means, and acting
	// on it would read or destroy somebody else's data.
	if entry.Origin != volLV {
		return lvEntry{}, resourceMeta{}, fmt.Errorf("snapshot %q: logical volume %q has origin %q, not %q: %w",
			snapID, entry.Name, entry.Origin, volLV, common.ErrSnapshotNotFound)
	}
	return entry, owner, nil
}

// restorePlan copies into a backing volume of the source's size, then grows through the Resize sequence, because DRBD metadata sits at the device end.
type restorePlan struct {
	// device is the snapshot's logical volume, the source of the copy.
	device string

	// fsType is the filesystem the copy carries, inherited from the source
	// volume because the copy is byte-for-byte.
	fsType string

	// backingSize is the source's backing size, which the destination's
	// backing volume is created at.
	backingSize int64

	// grow says the caller asked for more than the source's size, so the
	// volume is enlarged once it is up.
	grow bool
}

// restoreSource validates spec.SourceSnapshotID and plans the restore.
func (p *Provider) restoreSource(ctx context.Context, spec *common.VolumeSpec) (*restorePlan, error) {
	entry, owner, err := p.resolveSnapshot(ctx, spec.SourceSnapshotID)
	if err != nil {
		return nil, err
	}

	// origin_size is the size of the volume the snapshot was taken from — the
	// snapshot's own lv_size is only the copy-on-write space it was given — and
	// what the restore has to hold.
	src := entry.originSizeBytes()
	if src <= 0 {
		return nil, fmt.Errorf("snapshot %q: lvs reported no origin_size for %q, so the restore cannot be sized: %w",
			spec.SourceSnapshotID, entry.Name, common.ErrUnsupported)
	}

	// Refuse sizes whose backing size would overflow.
	if limit := maxDataBytes(entry.extentSizeBytes(), p.cfg.Encrypted); spec.SizeBytes > limit {
		return nil, fmt.Errorf("%w: size %d exceeds the largest usable capacity representable on this volume group, %d (extents are %d bytes and DRBD's internal metadata, and the LUKS2 header on an encrypted provider, is added on top)",
			common.ErrInvalidArgument, spec.SizeBytes, limit, entry.extentSizeBytes())
	}
	// Compare against the extent-rounded size lvcreate would give the destination, header included when encrypted.
	dst := roundUpTo(backingBytes(spec.SizeBytes, p.cfg.Encrypted), entry.extentSizeBytes())
	if src > dst {
		return nil, fmt.Errorf("%w: restoring snapshot %q needs a %d-byte backing volume, but %d usable (%d backing) was requested: this provider does not shrink during restore",
			common.ErrUnsupported, spec.SourceSnapshotID, src, spec.SizeBytes, dst)
	}

	// A growing restore runs resizeLocked after bring-up; the filesystem grow is deferred to the first Mount.
	return &restorePlan{
		device:      p.lvPath(entry.Name),
		fsType:      owner.FSType,
		backingSize: src,
		grow:        dst > src,
	}, nil
}

// copyDevice copies one block device onto another.
func (p *Provider) copyDevice(ctx context.Context, src, dst string) error {
	if err := p.blockDevices.Copy(ctx, src, dst); err != nil {
		return fmt.Errorf("copying %q to %q: %w", src, dst, err)
	}
	return nil
}

// Attach brings the resource up on the local node and reports the block device
// it appears at.
//
// The device exists in both roles: DRBD creates it when the resource comes up,
// and refuses to open it while the node is Secondary. Attaching is therefore
// separate from, and a precondition of, promotion.
//
// node must be the local node. The peer is a host of the resource and asking to
// attach there is well-formed, but this provider drives the local DRBD instance
// and has no channel to the other one, so that request is ErrUnsupported and
// the peer's own provider is what serves it. A name that is neither host is not
// a node of this volume at all and is common.ErrInvalidArgument.
//
// It is serialized against Delete: see the lock below.
func (p *Provider) Attach(ctx context.Context, volID string, node common.NodeID) (common.AttachInfo, error) {
	if err := p.requireLocalNode(node); err != nil {
		return common.AttachInfo{}, err
	}

	// Lookup and up are serialized with Delete, which removes storage after seeing the resource down.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return common.AttachInfo{}, err
	}

	// An already-up resource converges without a second drbdadm up.
	if _, up, statusErr := p.resourceStatus(ctx, meta.Name); statusErr != nil {
		return common.AttachInfo{}, statusErr
	} else if up {
		return common.AttachInfo{DevicePath: devicePath(meta.Minor), Node: node}, nil
	}

	if err := p.resourceUp(ctx, meta.Name); err != nil {
		return common.AttachInfo{}, err
	}
	return common.AttachInfo{DevicePath: devicePath(meta.Minor), Node: node}, nil
}

// Detach takes the resource down on the local node, removing its block device.
//
// Replication stops until Attach brings it back up: DRBD has no way to keep a
// device replicating without a device. The resource is taken down only once it
// is affirmatively Secondary: a local node holding Primary is the node serving
// writes and is refused with ErrPrimary — the HA controller demotes first — and
// a role that cannot be established is refused with ErrRoleUnknown, on the same
// reasoning as Delete's.
//
// It is serialized against the other role-changing operations: see the lock
// below.
func (p *Provider) Detach(ctx context.Context, volID string, node common.NodeID) error {
	if nodeErr := p.requireLocalNode(node); nodeErr != nil {
		return nodeErr
	}

	// Serialized with Promote so the role cannot change between check and teardown; lookup inside the lock.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return err
	}

	role, rawRole, up, err := p.localRoleRaw(ctx, meta.Name)
	if err != nil {
		return err
	}
	if !up {
		return nil // Already detached; teardown converges.
	}
	if role != common.ReplRoleSecondary {
		if role == common.ReplRolePrimary {
			return fmt.Errorf("volume %q: demote before detaching: %w", meta.Name, ErrPrimary)
		}
		return fmt.Errorf("volume %q: drbdsetup reports role %q: %w", meta.Name, rawRole, ErrRoleUnknown)
	}

	// Close any mapping left open before taking the resource down.
	if err := p.closeContainer(ctx, &meta); err != nil {
		return err
	}
	return p.resourceDown(ctx, meta.Name)
}

// Mount mounts an attached volume.
//
// The volume must be Primary on this node: DRBD denies every open of a
// Secondary's device, read-only mounts included, so MountOptions.ReadOnly does
// not relax the requirement.
//
// If the device carries no filesystem signature, the recorded filesystem is
// created on it first. That is the only circumstance in which this provider
// runs mkfs: blkid must report the device as carrying nothing at all, and a
// blkid that fails for any other reason leaves the device untouched. A
// read-only mount never formats — it is refused instead, since creating a
// filesystem is the one write a caller asking for read-only most clearly did
// not ask for.
//
// The target is PINNED before it is mounted on: internal/mount resolves it to a
// descriptor with symlink resolution refused and mounts against the descriptor,
// so a path swapped after validation changes nothing about where the mount
// lands. mount(8) would have canonicalized the string and followed it.
func (p *Provider) Mount(ctx context.Context, volID, target string, opts common.MountOptions) error {
	if targetErr := validateMountTarget(target); targetErr != nil {
		return targetErr
	}
	if flagErr := validateMountFlags(opts.Flags); flagErr != nil {
		return flagErr
	}
	if fsErr := validateFSType(opts.FSType); fsErr != nil {
		return fsErr
	}

	// Serialized with the lookup inside, so a reused minor cannot point the mount at another volume.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return err
	}

	fsType := opts.FSType
	if fsType == "" {
		fsType = meta.FSType
	}
	if fsType == "" {
		return fmt.Errorf("%w: volume %q was provisioned as a raw device; mounting needs a filesystem type", common.ErrInvalidArgument, meta.Name)
	}

	if primaryErr := p.requirePrimary(ctx, meta.Name); primaryErr != nil {
		return primaryErr
	}

	// Require an open container before the format; a no-op for an unencrypted volume.
	if unlockErr := p.requireContainerOpen(ctx, &meta); unlockErr != nil {
		return unlockErr
	}

	// Check the target with mount.Check before the format; Mount pins it again.
	if targetErr := mount.Check(target); targetErr != nil {
		return fmt.Errorf("%w: mount target %q: %w", common.ErrInvalidArgument, target, targetErr)
	}

	dev := p.fsDevice(&meta)
	// The returned type is the one on the device.
	onDisk, err := p.ensureFilesystem(ctx, &meta, fsType, opts.ReadOnly)
	if err != nil {
		return err
	}
	fsType = onDisk

	flags, data := mount.Arguments(opts.ReadOnly, opts.Flags)
	if err := p.mounter.Mount(ctx, dev, target, fsType, flags, data); err != nil {
		return fmt.Errorf("mounting volume %q at %q: %w", meta.Name, target, err)
	}

	// Check propagation now, when it is set; off unless configured (MountPropagationPolicy), and a refusal unwinds the mount.
	if id, finding := p.verifyMountPropagation(ctx, dev, target); finding != nil {
		return p.unwindUnverifiedMount(ctx, dev, target, id, finding)
	}

	// Pay a deferred grow after mounting, where ext4 and XFS both grow online; see FSGrowPending.
	if meta.FSGrowPending {
		if err := p.payDeferredGrow(ctx, &meta, target); err != nil {
			return err
		}
	}
	return nil
}

// payDeferredGrow grows the just-mounted filesystem and clears the debt; on error it unmounts on its own context and leaves the debt.
func (p *Provider) payDeferredGrow(ctx context.Context, meta *resourceMeta, target string) error {
	grown, err := p.growFilesystem(ctx, meta)
	if err == nil && grown {
		meta.FSGrowPending = false
		err = p.writeMeta(meta)
	}
	if err == nil && !grown {
		// Mounted ext4 and xfs always grow; anything else is an error.
		err = fmt.Errorf("volume %q: the grow it owes could not be performed even mounted at %q", meta.Name, target)
	}
	if err == nil {
		return nil
	}
	cleanupCtx, cancel := cleanupContext(ctx)
	defer cancel()
	if unmountErr := p.mounter.Unmount(cleanupCtx, target); unmountErr != nil {
		return errors.Join(err, fmt.Errorf("unmounting %q after the grow it owed failed: %w", target, unmountErr))
	}
	return err
}

// probeDevice reports the filesystem type blkid finds and whether the device carries no signature at all; only blkid's nothing-found exit counts as empty.
func (p *Provider) probeDevice(ctx context.Context, dev string) (fsType string, empty bool, err error) {
	out, err := p.runner.Run(ctx, binBlkid, "-p", "-o", "export", dev)
	if err != nil {
		if code, ok := exitCode(err); ok && code == blkidNoSig {
			return "", true, nil
		}
		return "", false, fmt.Errorf("probing %q: %w", dev, err)
	}
	// export format is KEY=VALUE per line; PTTYPE alone means a partition table, not empty.
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "TYPE="); ok {
			return strings.Trim(value, `"`), false, nil
		}
	}
	return "", false, nil
}

// ensureFilesystem probes, formats an empty device and records the type in one critical section, and returns the type actually on the device.
func (p *Provider) ensureFilesystem(ctx context.Context, meta *resourceMeta, fsType string, readOnly bool) (string, error) {
	// The caller holds p.mu.
	dev := p.fsDevice(meta)
	found, empty, err := p.probeDevice(ctx, dev)
	if err != nil {
		return "", err
	}
	if !empty {
		// Reconcile the record with a supported filesystem already on the device, e.g. from an attempt that failed before recording.
		if _, supported := supportedFilesystems[found]; supported {
			// What is on the device wins over what the caller asked for and
			// over what the record said, because it is the only one of the
			// three that is a fact.
			return found, p.reconcileFSType(meta.Name, found)
		}
		// Something this provider does not manage. The record is left alone —
		// it drives mkfs and grow decisions that only make sense for the two
		// filesystems supported — and so is the caller's type.
		return fsType, nil
	}

	// A read-only mount does not get to write, and creating a filesystem is the
	// largest write there is. Refusing says so plainly; going ahead would
	// format a volume for a caller who asked not to change it.
	if readOnly {
		return "", fmt.Errorf("%w: volume %q carries no filesystem and a read-only mount cannot create one: mount it read-write once first",
			common.ErrInvalidArgument, meta.Name)
	}
	if mkfsErr := p.mkfs(ctx, fsType, dev); mkfsErr != nil {
		return "", mkfsErr
	}

	// MountOptions.FSType may override the recorded type.
	return fsType, p.reconcileFSType(meta.Name, fsType)
}

// reconcileFSType re-reads the record and stores the filesystem now on the volume; callers hold the provider lock.
func (p *Provider) reconcileFSType(name, fsType string) error {
	current, err := p.readMeta(name)
	if err != nil {
		return err
	}
	if current.FSType == fsType {
		return nil
	}
	current.FSType = fsType
	return p.writeMeta(&current)
}

// mkfs creates a filesystem. fsType has already been checked against the
// allowlist, which is what makes concatenating it into a binary name safe.
func (p *Provider) mkfs(ctx context.Context, fsType, dev string) error {
	if _, err := p.runner.Run(ctx, "mkfs."+fsType, "-q", dev); err != nil {
		return fmt.Errorf("creating %s filesystem on %q: %w", fsType, dev, err)
	}
	return nil
}

// Unmount unmounts the volume from target.
//
// The target is pinned by its PARENT before the unmount, so a swapped final
// component cannot redirect it onto somebody else's mount; see internal/mount.
//
// A target this volume is not mounted at is not an error, so a teardown
// converges however far it got. That covers both shapes it takes: a path that
// is not a mount point at all, and a path where something else has since been
// mounted. Neither unmounts anything — this provider unmounts its own volume,
// not whatever happens to be at the path it was given.
func (p *Provider) Unmount(ctx context.Context, volID, target string) error {
	if targetErr := validateMountTarget(target); targetErr != nil {
		return targetErr
	}

	// Serialized with the lookup inside, so a recycled minor cannot match another volume's device.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return err
	}

	mounted, err := p.mountedAt(ctx, p.fsDevice(&meta), target)
	if err != nil {
		return err
	}
	if !mounted {
		// Nothing or another device is mounted at the target; neither is an error and nothing is unmounted.
		return nil
	}

	if err := p.mounter.Unmount(ctx, target); err != nil {
		return fmt.Errorf("unmounting %q: %w", target, err)
	}
	return nil
}

// mountedAt reports whether dev is mounted and visible at target, matching by device number; a missing device node means not mounted.
func (p *Provider) mountedAt(ctx context.Context, dev, target string) (bool, error) {
	// Visible, not merely mounted: umount(2) detaches what is visible at the path.
	targets, err := p.mountTable.VisibleMountPointsFor(ctx, dev)
	if err != nil {
		// Only a missing device converges; an unreadable mount table is an error.
		var deviceErr *mountinfo.DeviceError
		if errors.As(err, &deviceErr) && errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("looking up mounts of %q: %w", dev, err)
	}
	return slices.Contains(targets, target), nil
}

// mountTarget returns the first path the device is mounted at, if any.
func (p *Provider) mountTarget(ctx context.Context, dev string) (string, bool, error) {
	targets, err := p.mountTable.MountPointsFor(ctx, dev)
	if err != nil {
		return "", false, fmt.Errorf("looking up mounts of %q: %w", dev, err)
	}
	if len(targets) == 0 {
		return "", false, nil
	}
	return targets[0], true, nil
}

// isMounted reports whether the device is mounted anywhere.
func (p *Provider) isMounted(ctx context.Context, dev string) (bool, error) {
	_, mounted, err := p.mountTarget(ctx, dev)
	return mounted, err
}

// Resize grows the volume.
//
// Both halves have to happen: the backing logical volume is extended locally,
// then drbdadm resize tells DRBD to use the new space. The peer's backing
// volume is not touched — this provider drives one node — so the call must be
// made on both nodes, and DRBD holds the device at the smaller of the two sizes
// until it has been.
//
// The filesystem is grown too. ext4 grows mounted or not — unmounted it is
// checked first, which is what resize2fs demands — and XFS only while mounted,
// having no offline form. Where the filesystem cannot be grown as things stand
// (an unmounted XFS volume, or any filesystem on a Secondary, whose device DRBD
// will not open) the device still grows and the call still succeeds, the record
// notes the grow it owes (FSGrowPending), and the next Mount from a Primary
// pays it online; repeating the same request from the Primary finishes the job
// as well. See growFilesystem.
//
// AN ENCRYPTED VOLUME follows the same rule with one more state in it. Its
// filesystem lives on a dm-crypt mapping that Promote sized when it opened the
// container, and nothing reloads that mapping (see ErrMappingStale). So:
//
//   - Container closed — a Secondary, or a Primary nothing has unlocked: the
//     device grows, the record follows and owes the grow, and the next Promote
//     opens the mapping over the device as it is by then, sized to it, for the
//     next Mount to grow into.
//   - Container open and the mapping still covering the device — the peer
//     was grown first, or this is the repeat after the remedy: the filesystem
//     is grown through the mapping, online if mounted.
//   - Container open and the mapping STALE — the device grew under it, here or
//     by the peer's resize landing: refused with ErrMappingStale after the
//     device half, which stands, and before any grow tool runs. The record is
//     not advanced. The error names the remedy — unmount, Demote, Promote,
//     repeat — and the repeat converges.
//
// Grow the Secondary first, then the Primary. DRBD holds the device at the
// smaller of the pair's two backing sizes, so a Primary grown first sees no
// device change, grows nothing, and is left with a mapping that goes stale
// the moment the peer catches up; the repeat from that Primary is then the
// refused-and-cycled path above rather than the online one.
//
// newSize is USABLE capacity, in the same units Provision and Status use, so
// the backing logical volume grows to backingBytes(newSize, encrypted) — by more than the
// difference between the two sizes, since the metadata reservation grows with
// the device. The shrink check compares usable against usable; the "is the
// device already big enough" check compares backing against backing.
//
// The resource must be up. Extending the backing device of a resource that is
// down leaves DRBD's internal metadata stranded away from the end of the device
// with no drbdadm resize available to follow it, so this refuses with
// ErrNotAttached before anything is extended.
//
// Shrinking is refused. DRBD can shrink online, but the filesystem above it has
// to be shrunk first and this provider has no way to know whether that has
// happened; getting the order wrong truncates live data.
func (p *Provider) Resize(ctx context.Context, volID string, newSize int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return err
	}
	return p.resizeLocked(ctx, &meta, newSize)
}

// resizeLocked is Resize with the lock held and the volume looked up, shared with a growing restore.
func (p *Provider) resizeLocked(ctx context.Context, metaPtr *resourceMeta, newSize int64) error {
	meta := *metaPtr
	if newSize <= 0 {
		return fmt.Errorf("%w: size must be positive, got %d", common.ErrInvalidArgument, newSize)
	}
	if newSize < meta.SizeBytes {
		return fmt.Errorf("%w: volume %q is %d bytes and this provider does not shrink", common.ErrUnsupported, meta.Name, meta.SizeBytes)
	}
	// An equal size is not a no-op: every step is idempotent and the repeat finishes a partial resize.

	// The resource must be up, or extending the LV strands DRBD's metadata; ErrNotAttached otherwise.
	if _, up, roleErr := p.localRole(ctx, meta.Name); roleErr != nil {
		return roleErr
	} else if !up {
		return fmt.Errorf("volume %q: the resource is not up, so its backing device cannot be extended safely: %w",
			meta.Name, common.ErrNotAttached)
	}

	// Recompute the backing target and skip steps already done, so a retried resize converges.
	lvs, err := p.lvs(ctx)
	if err != nil {
		return err
	}
	entry, ok := findLV(lvs, meta.LV)
	if !ok {
		return fmt.Errorf("volume %q: backing logical volume %q is missing", meta.Name, p.lvRef(meta.LV))
	}
	// Refuse sizes whose extent-rounded backing would overflow int64.
	if limit := maxDataBytes(entry.extentSizeBytes(), p.cfg.Encrypted); newSize > limit {
		return fmt.Errorf("%w: newSize %d exceeds the largest usable capacity representable on this volume, %d (this volume group's extents are %d bytes and DRBD's internal metadata, and the LUKS2 header on an encrypted provider, is added on top)",
			common.ErrInvalidArgument, newSize, limit, entry.extentSizeBytes())
	}
	if target := roundUpTo(backingBytes(newSize, p.cfg.Encrypted), entry.extentSizeBytes()); entry.sizeBytes() < target {
		if err := p.lvExtend(ctx, meta.LV, backingBytes(newSize, p.cfg.Encrypted)); err != nil {
			return err
		}
	}
	// drbdadm resize is idempotent: it takes the backing device's size as it
	// finds it.
	if err := p.drbdadm(ctx, "resize", meta.Name); err != nil {
		return fmt.Errorf("resizing drbd resource %q: %w", meta.Name, err)
	}

	grown, growErr := p.growFilesystem(ctx, &meta)
	if growErr != nil {
		// Record nothing; the device half stands and the repeat converges.
		return growErr
	}

	meta.SizeBytes = newSize
	// The record follows the device, and says whether the filesystem did. A
	// grow that could not be performed from here is owed to the next Mount;
	// one that was performed clears any debt an earlier call left.
	meta.FSGrowPending = !grown
	if err := p.writeMeta(&meta); err != nil {
		return err
	}
	*metaPtr = meta
	return nil
}

// growFilesystem grows the filesystem after the device grew and reports whether it did; false with nil means deferred (Secondary, unmounted XFS, closed container), and a stale mapping is ErrMappingStale.
func (p *Provider) growFilesystem(ctx context.Context, meta *resourceMeta) (bool, error) {
	if p.cfg.Encrypted {
		open, err := p.containerIsOpen(ctx, meta)
		if err != nil {
			return false, err
		}
		if !open {
			// Deferred, unless there is nothing to defer: a raw volume's
			// plaintext device is sized afresh by whichever Promote next
			// opens it, and owes nothing.
			return meta.FSType == "", nil
		}
		if err := p.requireFreshMapping(ctx, meta); err != nil {
			return false, err
		}
	}

	if meta.FSType == "" {
		return true, nil
	}

	dev := p.fsDevice(meta)
	target, mounted, err := p.mountTarget(ctx, dev)
	if err != nil {
		return false, err
	}

	switch meta.FSType {
	case "ext4":
		if !mounted {
			// Mounted implies Primary — DRBD will not open a Secondary's
			// device at all — so the role only has to be established here.
			role, up, roleErr := p.localRole(ctx, meta.Name)
			if roleErr != nil {
				return false, roleErr
			}
			if !up || role != common.ReplRolePrimary {
				return false, nil
			}
			if err := p.checkExtFilesystem(ctx, dev); err != nil {
				return false, err
			}
		}
		// resize2fs takes the device and finds the mount point itself.
		if _, err := p.runner.Run(ctx, binResize2fs, dev); err != nil {
			return false, fmt.Errorf("growing the ext4 filesystem on %q: %w", dev, err)
		}
	case "xfs":
		if !mounted {
			return false, nil
		}
		// xfs_growfs takes the mount point; there is no offline form.
		if _, err := p.runner.Run(ctx, binXFSGrowfs, target); err != nil {
			return false, fmt.Errorf("growing the xfs filesystem at %q: %w", target, err)
		}
	default:
		// Unreachable: FSType passed validateFSType at provision time, and the
		// allowlist is these two. A third filesystem added there without a
		// grow here would otherwise silently leave the filesystem short.
		return false, fmt.Errorf("%w: no way to grow a %q filesystem", common.ErrUnsupported, meta.FSType)
	}
	return true, nil
}

// checkExtFilesystem runs e2fsck -f -p, the check resize2fs requires before an offline grow.
func (p *Provider) checkExtFilesystem(ctx context.Context, dev string) error {
	_, err := p.runner.Run(ctx, binE2fsck, "-f", "-p", dev)
	if err == nil {
		return nil
	}
	if code, ok := exitCode(err); ok && code == e2fsckCorrected {
		return nil
	}
	return fmt.Errorf("checking the filesystem on %q before growing it: %w", dev, err)
}

// Snapshot takes an LVM snapshot of the backing device.
//
// It is refused on a Secondary with common.ErrNotPrimary. A Secondary's backing
// device is written by the replication stream with no filesystem above it to
// order those writes, so a snapshot of one captures a state no filesystem ever
// had — and the condition is fixed by a Promote, which is what that sentinel
// says. On the Primary the snapshot is crash-consistent: it is what a power cut
// would leave, which a journaling filesystem recovers from and an application
// with unflushed state does not.
//
// The snapshot exists only on this node and is not replicated.
//
// It is serialized against Delete: see the lock below.
func (p *Provider) Snapshot(ctx context.Context, volID, name string) (common.SnapshotID, error) {
	// Serialized with Delete, which refuses a volume that has snapshots.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return "", err
	}
	if nameErr := validateName("snapshot name", name); nameErr != nil {
		return "", nameErr
	}

	role, up, err := p.localRole(ctx, meta.Name)
	if err != nil {
		return "", err
	}
	if !up || role != common.ReplRolePrimary {
		return "", fmt.Errorf("volume %q must be primary on this node to snapshot its backing device (role %s): %w",
			meta.Name, role, common.ErrNotPrimary)
	}

	snapLV := snapshotLV(meta.LV, name)
	lvs, err := p.lvs(ctx)
	if err != nil {
		return "", err
	}
	if _, exists := findLV(lvs, snapLV); exists {
		return "", fmt.Errorf("snapshot %q of volume %q: %w", name, meta.Name, common.ErrAlreadyExists)
	}

	if err := p.lvCreateSnapshot(ctx, meta.LV, snapLV); err != nil {
		return "", err
	}
	return common.SnapshotID(p.snapshotID(meta.LV, name)), nil
}

// ListSnapshots returns the snapshots taken from the volume on this node.
//
// Snapshots are matched by their LVM origin, so an LV that merely looks like
// one of ours but was taken from something else is not reported.
//
// SizeBytes is what each snapshot OCCUPIES, not the copy-on-write area it was
// given; see lvEntry.usedBytes for what that means for an inactive one.
func (p *Provider) ListSnapshots(ctx context.Context, volID string) ([]common.SnapshotInfo, error) {
	meta, err := p.lookup(volID)
	if err != nil {
		return nil, err
	}
	lvs, err := p.lvs(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]common.SnapshotInfo, 0, len(lvs))
	for i := range lvs {
		lv := &lvs[i]
		if lv.Origin != meta.LV {
			continue
		}
		originLV, snapName, ok := splitSnapshotLV(lv.Name)
		if !ok || originLV != meta.LV {
			continue
		}
		// A name this provider could not have created was not created by it.
		// Reporting one would hand the caller a snapshot id that DeleteSnapshot
		// and restore then reject as invalid.
		if validateName("snapshot name", snapName) != nil {
			continue
		}
		// An occupancy that cannot be read fails the listing rather than being
		// reported as zero. A fabricated measurement is worse than no listing:
		// it is what a caller sizes a restore against.
		used, usedErr := lv.usedBytes()
		if usedErr != nil {
			return nil, usedErr
		}
		out = append(out, common.SnapshotInfo{
			ID:        common.SnapshotID(p.snapshotID(meta.LV, snapName)),
			VolumeID:  meta.Name,
			Name:      snapName,
			CreatedAt: lv.createdAt(),
			SizeBytes: used,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteSnapshot removes a snapshot.
//
// Volumes restored from it are unaffected: Provision copies the snapshot's
// blocks rather than layering onto it, so nothing depends on the snapshot once
// the restore has finished. A restore still IN PROGRESS does depend on it, and
// is serialized against by the lock below.
func (p *Provider) DeleteSnapshot(ctx context.Context, snapID common.SnapshotID) error {
	// Serialized with Provision and Snapshot so a restore's source cannot vanish mid-copy.
	p.mu.Lock()
	defer p.mu.Unlock()

	entry, _, err := p.resolveSnapshot(ctx, snapID)
	if err != nil {
		return err
	}
	return p.lvRemove(ctx, entry.Name)
}

// Delete takes the resource down and removes its backing volume, resource file
// and state record.
//
// It refuses while snapshots of the volume remain — lvremove would take them
// with the origin, so that deletion stays the caller's explicit choice — and it
// tears a running resource down only once that resource is affirmatively
// Secondary. A local node holding Primary is refused with ErrPrimary; a role
// that cannot be established at all is refused with ErrRoleUnknown, because
// only "is Secondary" makes the teardown safe and "is not Primary" does not
// mean the same thing.
//
// With Config.WipeOnDelete the backing volume is zero-filled before it is
// removed, so its contents do not linger in the free extents LVM hands to the
// next volume. See that field for what the wipe covers and what it does not.
//
// The snapshot refusal above is also what makes that wipe safe to run
// unconditionally, and it is worth saying why rather than leaving it to
// coincidence. Zeroing an origin that still has a snapshot is copy-on-write's
// worst case: every block written pushes the block it replaced into the
// snapshot's CoW area, so the wipe duplicates the very data it is destroying
// into extents lvremove then frees. Measured by the local lane on LVM 2.03.16,
// wiping a 64 MiB origin under one snapshot drove CoW occupancy from 0% to 100%
// and overflowed the snapshot into an unreadable state. Because a volume with
// snapshots never reaches the wipe here, that trap is unreachable rather than
// merely avoided by ordering — but it becomes reachable the moment the refusal
// is relaxed, so the two belong together.
func (p *Provider) Delete(ctx context.Context, volID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookupAny(volID)
	if err != nil {
		return err
	}

	// Snapshots are checked before the role, since demoting does not remove them.
	lvs, err := p.lvs(ctx)
	if err != nil {
		return err
	}
	var snaps []string
	for i := range lvs {
		if lvs[i].Origin == meta.LV {
			snaps = append(snaps, lvs[i].Name)
		}
	}
	if len(snaps) > 0 {
		sort.Strings(snaps)
		return fmt.Errorf("volume %q: delete %s first: %w", meta.Name, strings.Join(snaps, ", "), common.ErrHasSnapshots)
	}

	// An up resource is torn down only when affirmatively Secondary; a resource that is not up is deletable.
	role, rawRole, up, err := p.localRoleRaw(ctx, meta.Name)
	if err != nil {
		return err
	}
	if up && role != common.ReplRoleSecondary {
		if role == common.ReplRolePrimary {
			return fmt.Errorf("volume %q: demote before deleting: %w", meta.Name, ErrPrimary)
		}
		return fmt.Errorf("volume %q: drbdsetup reports role %q: %w", meta.Name, rawRole, ErrRoleUnknown)
	}

	if up {
		// Close any open mapping before the teardown while the resource is up.
		if err := p.closeContainer(ctx, &meta); err != nil {
			return err
		}
		if err := p.resourceDown(ctx, meta.Name); err != nil {
			return err
		}
	}
	// A volume left half-provisioned may never have got its backing device.
	// Removing what is not there is not a failure, and refusing to converge
	// would leave the record needing to be deleted by hand.
	if entry, exists := findLV(lvs, meta.LV); exists {
		// The listing above already carries lv_attr, so the activation state
		// costs no extra command to read.
		wasActive := entry.active()
		if p.cfg.WipeOnDelete {
			if err := p.wipe(ctx, meta.LV, wasActive); err != nil {
				return err
			}
		}
		if err := p.lvRemove(ctx, meta.LV); err != nil {
			// Give back the wipe's activation when the removal failed.
			if p.cfg.WipeOnDelete && !wasActive {
				cleanupCtx, cancel := cleanupContext(ctx)
				defer cancel()
				return errors.Join(err, p.lvDeactivate(cleanupCtx, meta.LV))
			}
			return err
		}
	}
	if err := os.Remove(p.resPath(meta.Name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing resource file for %q: %w", meta.Name, err)
	}
	if err := os.Remove(p.metaPath(meta.Name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing state for %q: %w", meta.Name, err)
	}
	return nil
}

// wipe zero-fills the backing LV with blkdiscard --zeroout after the resource is down and before lvremove, activating an inactive LV and deactivating it again on failure; a failure stops the delete.
func (p *Provider) wipe(ctx context.Context, lv string, wasActive bool) error {
	if !wasActive {
		if err := p.lvActivate(ctx, lv); err != nil {
			return err
		}
	}
	if err := p.blockDevices.ZeroOut(ctx, p.lvPath(lv), 0); err != nil {
		wipeErr := fmt.Errorf("wiping %s before deleting it: %w", p.lvRef(lv), err)
		if wasActive {
			return wipeErr
		}
		cleanupCtx, cancel := cleanupContext(ctx)
		defer cancel()
		return errors.Join(wipeErr, p.lvDeactivate(cleanupCtx, lv))
	}
	return nil
}

// Status reports the volume's observed state.
//
// The size is the DRBD device's, as drbdsetup reports it, not the backing
// volume's: the backing volume also holds DRBD's internal metadata, and LVM
// rounds its allocation up to the volume group's extent size, so neither number
// is the capacity a caller can write to. On an encrypted provider the device
// is not that capacity either — it holds the LUKS2 container, header included
// — so the header is taken back off through usableBytes, in every state the
// device can be measured in; the container need not be open for the figure to
// be right, because the header's size is a constant of this package and not
// something read from the mapping. A resource that is not up has no device to
// measure and falls back to the size the volume was provisioned or resized to,
// which the record keeps in usable bytes already.
//
// AttachedNodes lists the local node when the resource is up, and the peer when
// the connection to it is established — a connected peer necessarily has the
// resource up too. A peer that is unreachable is omitted rather than guessed
// at.
//
// SizeBytes is USABLE capacity in both branches, per VolumeStatus.SizeBytes,
// but they are two different flavors of it and the difference is visible. With
// the resource DOWN it is the capacity that was REQUESTED, from the record.
// With it UP it is the capacity DRBD actually exports, which is larger: the
// backing volume was rounded up to a whole LVM extent and the metadata
// reservation deliberately over-reserves, and everything left over is usable.
// So the number rises slightly when a volume is brought up — for a 1 GiB
// request, by about 4 MiB. It is never below what was requested in either
// branch, which is the guarantee callers need; a caller diffing Status across
// an attach should expect the step.
func (p *Provider) Status(ctx context.Context, volID string) (common.VolumeStatus, error) {
	meta, err := p.lookup(volID)
	if err != nil {
		return common.VolumeStatus{}, err
	}

	status := common.VolumeStatus{
		ID:        meta.Name,
		State:     common.VolumeStateAvailable,
		SizeBytes: meta.SizeBytes,
	}

	rs, up, err := p.resourceStatus(ctx, meta.Name)
	if err != nil {
		return common.VolumeStatus{}, err
	}
	if !up {
		// Set explicitly: the zero value means not replicated.
		status.Replication = downReplState()
		return status, nil
	}

	status.State = common.VolumeStateAttached
	status.AttachedNodes = []common.NodeID{common.NodeID(p.cfg.NodeName)}
	for _, c := range rs.Connections {
		if conn, ok := parseConn(c.Connection); ok && conn == connConnected {
			status.AttachedNodes = append(status.AttachedNodes, common.NodeID(c.Name))
		}
	}

	if repl, ok := rs.replState(); ok {
		status.Replication = repl
	}

	if dev, ok := rs.device(); ok {
		if dev.Size > 0 {
			usable, sizeErr := usableBytes(dev.Size*statusSizeUnit, p.cfg.Encrypted)
			if sizeErr != nil {
				return common.VolumeStatus{}, fmt.Errorf("volume %q: %w", meta.Name, sizeErr)
			}
			status.SizeBytes = usable
		}
		// A device that has failed or gone away outranks anything else the
		// status might say: the volume exists but cannot serve reads.
		if disk, ok := parseDisk(dev.DiskState); ok && (disk == diskFailed || disk == diskDiskless) {
			status.State = common.VolumeStateError
			return status, nil
		}
	}

	mounted, err := p.fsDeviceMounted(ctx, &meta)
	if err != nil {
		return common.VolumeStatus{}, err
	}
	if mounted {
		status.State = common.VolumeStateMounted
	}
	return status, nil
}

// fsDeviceMounted reports whether the filesystem device is mounted, skipping the lookup when the container is provably closed.
func (p *Provider) fsDeviceMounted(ctx context.Context, meta *resourceMeta) (bool, error) {
	if p.cfg.Encrypted {
		open, err := p.containerIsOpen(ctx, meta)
		if err != nil {
			return false, err
		}
		if !open {
			return false, nil
		}
	}
	return p.isMounted(ctx, p.fsDevice(meta))
}

// -----------------------------------------------------------------------------
// ReplicatedProvider
// -----------------------------------------------------------------------------

// Promote makes the local copy Primary.
//
// It runs "drbdadm primary" and never "drbdadm primary --force". DRBD refuses
// the promotion when the local copy is not UpToDate or the peer already holds
// Primary, and that refusal is the point: forcing past it publishes a copy that
// may be stale or diverged and discards the peer's. See the package doc.
//
// The call is idempotent — promoting a resource that is already Primary
// succeeds — and gated by nothing here against the PEER. The HA controller
// holds the per-volume primary lease and is what makes a promotion safe across
// the pair; this method is the mechanism it drives. It is serialized against
// this provider's own role- and lifecycle-changing methods, which is a
// different concern: see the lock below.
func (p *Provider) Promote(ctx context.Context, volID string) error {
	// Serialized with Delete and Snapshot.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return err
	}

	// Read before promoting: only a promotion this call made is rolled back.
	wasPrimary := false
	if p.cfg.Encrypted {
		role, up, roleErr := p.localRole(ctx, meta.Name)
		if roleErr != nil {
			return roleErr
		}
		wasPrimary = up && role == common.ReplRolePrimary
	}

	if err := p.drbdadm(ctx, "primary", meta.Name); err != nil {
		return fmt.Errorf("promoting volume %q: %w", meta.Name, err)
	}

	// Open the container after the role change; a no-op for an unencrypted volume.
	if err := p.openContainer(ctx, &meta); err != nil {
		if wasPrimary {
			return err
		}
		// Demote again on a fresh context when the unlock failed.
		cleanupCtx, cancel := cleanupContext(ctx)
		defer cancel()
		if demoteErr := p.drbdadm(cleanupCtx, "secondary", meta.Name); demoteErr != nil {
			return errors.Join(err, fmt.Errorf("demoting volume %q after a failed unlock: %w", meta.Name, demoteErr))
		}
		return err
	}
	return nil
}

// Demote makes the local copy Secondary, leaving it replicating but not
// writable. It fails while the device is open — mounted, or held by a
// process — which is DRBD refusing to pull a live device out from under its
// user rather than a condition this provider can resolve.
//
// It is serialized against Snapshot, Promote and Delete: see the lock below.
func (p *Provider) Demote(ctx context.Context, volID string) error {
	// Serialized with Snapshot, whose Primary check a demotion would invalidate.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return err
	}

	// Close the mapping before the role change; on failure the volume stays Primary and unlocked.
	if err := p.closeContainer(ctx, &meta); err != nil {
		return err
	}

	if err := p.drbdadm(ctx, "secondary", meta.Name); err != nil {
		// The mapping is not re-opened; the next Promote opens one.
		return fmt.Errorf("demoting volume %q: %w", meta.Name, err)
	}
	return nil
}

// downReplState is what a configured resource that is not running reports, shared by Status and ReplicationState.
func downReplState() common.ReplState {
	return common.ReplState{Conn: common.ReplStateDown, Role: common.ReplRoleUnknown}
}

// ReplicationState reports the volume's replication state.
//
// A resource that is not up reports common.ReplStateDown with an unknown role:
// it is configured for replication, this provider knows about it, and nothing
// is running. That is a definite answer, which is why it is not unknown, and it
// is not standalone either — standalone means the resource IS up and has
// stopped talking to its peer. A resource that is down holds no role at all.
//
// common.ErrNotReplicated is returned only when the resource is up and has no
// peer connection configured at all. A peer that is merely unreachable still
// appears, in StandAlone or one of the failure states, and reports as such.
func (p *Provider) ReplicationState(ctx context.Context, volID string) (common.ReplState, error) {
	meta, err := p.lookup(volID)
	if err != nil {
		return common.ReplState{}, err
	}
	rs, up, err := p.resourceStatus(ctx, meta.Name)
	if err != nil {
		return common.ReplState{}, err
	}
	if !up {
		return downReplState(), nil
	}
	state, ok := rs.replState()
	if !ok {
		return common.ReplState{}, fmt.Errorf("volume %q has no peer connection: %w", meta.Name, common.ErrNotReplicated)
	}
	return state, nil
}

// -----------------------------------------------------------------------------
// Shared preconditions
// -----------------------------------------------------------------------------

// lookup validates a volume id and loads its record, mapping an unknown volume
// to common.ErrNotFound.
func (p *Provider) lookup(volID string) (resourceMeta, error) {
	if err := validateName("volume id", volID); err != nil {
		// An id that could never have been provisioned names no volume, which
		// is what ErrNotFound says; the validation detail rides along for a
		// caller that wants to know why.
		return resourceMeta{}, fmt.Errorf("%w: %w", common.ErrNotFound, err)
	}
	return p.loadMeta(volID)
}

// lookupAny is lookup without the completeness filter, so Delete can clean up a half-provisioned volume.
func (p *Provider) lookupAny(volID string) (resourceMeta, error) {
	if err := validateName("volume id", volID); err != nil {
		return resourceMeta{}, fmt.Errorf("%w: %w", common.ErrNotFound, err)
	}
	return p.readMeta(volID)
}

// requireLocalNode allows only the local node; the peer is ErrUnsupported and any other name ErrInvalidArgument.
func (p *Provider) requireLocalNode(node common.NodeID) error {
	switch string(node) {
	case p.cfg.NodeName:
		return nil
	case p.cfg.PeerNode:
		return fmt.Errorf("%w: this provider drives the local node %q; %q is served by its own provider",
			common.ErrUnsupported, p.cfg.NodeName, node)
	default:
		return fmt.Errorf("%w: node %q is not part of this volume's resource (its hosts are %q and %q)",
			common.ErrInvalidArgument, node, p.cfg.NodeName, p.cfg.PeerNode)
	}
}
