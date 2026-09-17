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

	// e2fsck: errors were found and fixed. Together with 0 that is a filesystem
	// which can now be resized; 2 and above mean errors it could not fix, an
	// operational failure, or a check that did not finish, none of which should
	// be followed by a resize.
	e2fsckCorrected = 1
)

// rollbackTimeout bounds the cleanup that unwinds a failed Provision. It is
// generous because the commands it runs — drbdadm down, lvremove — touch the
// kernel and the LVM metadata lock, and it is bounded at all because a cleanup
// that hangs would hold the provider's mutex indefinitely.
const rollbackTimeout = 2 * time.Minute

// cleanupContext detaches from the caller's context for a compensating action,
// bounded so a cleanup cannot hang forever either.
//
// The most likely reason to be running one is that ctx was canceled or its
// deadline passed partway through the operation being compensated. Reusing it
// makes every cleanup command fail instantly — the production runner execs
// through exec.CommandContext, so a canceled context means the process never
// starts — and leaves behind exactly the state the cleanup exists to undo. That
// is worse than not attempting it, because the code reads as though the state
// were restored.
//
// One function rather than the expression written at each site: the three
// callers are a provisioning rollback and two deletion paths that give back a
// borrowed activation, and they must not drift apart on a subtlety this easy to
// get wrong by copying.
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

	// injected records which seams the caller replaced, so runPreflight checks
	// exactly the operations this provider will actually perform. A seam that
	// was replaced is not checked: that is a derivation from the configuration,
	// not a guess — a provider given its own Mounter does not call mount(2).
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
	// A provider told to require propagation, over a mount table that cannot
	// report it, is a configuration that cannot work — and discovering it after
	// the first mount is worse than useless: the mount has already happened, the
	// guard cannot judge it, and the rollback cannot identify it either, so
	// Mount would return an error over a filesystem it left mounted. It is a
	// startup refusal for the same reason the preflight checks are, and it is
	// only reachable through WithMountTable: the real mountinfo.System answers
	// the question.
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
	// Refused at construction rather than at the first Promote. A node
	// configured to encrypt with no way to obtain the passphrase is a
	// deployment mistake, and finding out at the first failover is finding out
	// at the worst possible moment.
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

	// 0750, not the 0755 /etc/drbd.d conventionally carries: nothing outside
	// root and its group has any business reading a node's replication
	// topology, and MkdirAll leaves an existing directory's mode alone, so this
	// only applies to one this provider creates.
	if err := os.MkdirAll(cfg.ConfigDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating %s %q: %w", SettingConfigDir, cfg.ConfigDir, err)
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s %q: %w", SettingStateDir, cfg.StateDir, err)
	}

	// Last, after every setting has been validated: a caller who got the
	// configuration wrong should hear about the configuration, not about the
	// node's capabilities. And at construction rather than at the first
	// Provision, because what it detects is fixed when the process starts —
	// discovering it at the first volume operation turns a deployment mistake
	// into an outage. The capability set is derived, and it is NOT the local
	// provider's; see requiredCapabilities.
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

// localRoleRaw is localRole plus the role string exactly as drbdsetup reported
// it, empty when the resource is not up.
//
// Delete is what needs the raw string. A role this parser does not recognize is
// what makes it refuse, and that refusal is only actionable if it names the
// value it could not recognize; the mapped common.ReplRoleUnknown has thrown
// that away by then, and cannot tell an unparsed string from a literal
// "Unknown" either.
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

// createMetadata initializes DRBD's internal metadata on the backing device.
//
// The --force here suppresses drbdmeta's confirmation prompt about overwriting
// what it finds on the device. That device was created by the immediately
// preceding lvcreate, so anything on it is a remnant of a previous logical
// volume that occupied the same extents — LVM zeroes only the first sectors of
// a new LV, which is not where internal metadata lives. This force destroys
// nothing a caller has; it is unrelated to the promotion force this provider
// refuses to expose. See the package doc.
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
	// The backing volume is created at backingBytes(spec.SizeBytes, encrypted),
	// and those additions have to be representable. A signed overflow in Go
	// wraps rather than trapping, so without this a size near math.MaxInt64
	// would reach lvcreate as a NEGATIVE byte count. It is malformed input
	// rather than an unsupported operation: no backend could back it, and the
	// caller has to change the number rather than choose another provider.
	// Extent rounding is lvcreate's here, so the bound is the header and
	// metadata additions alone; the restore and resize paths, which round in
	// Go, bound that too.
	if limit := maxDataBytes(0, p.cfg.Encrypted); spec.SizeBytes > limit {
		return common.Volume{}, fmt.Errorf("%w: size %d exceeds the largest usable capacity this provider can back, %d (a larger request overflows the backing size once DRBD's internal metadata, and the LUKS2 header on an encrypted provider, is added)",
			common.ErrInvalidArgument, spec.SizeBytes, limit)
	}
	if err := validateFSType(spec.FSType); err != nil {
		return common.Volume{}, err
	}
	// Every volume is carved out of the one configured volume group, and this
	// provider has no notion of tiers. Taking a storage class and ignoring it
	// would return a Volume whose Spec names a class the volume is not on — a
	// description of the volume that is simply untrue. It is ErrUnsupported
	// rather than malformed input: the request is well formed, and a backend
	// with tiers could serve it.
	if spec.StorageClass != "" {
		return common.Volume{}, fmt.Errorf("%w: the drbd provider has no storage classes; volume group %q backs every volume, and StorageClass %q cannot be honored",
			common.ErrUnsupported, p.cfg.VG, spec.StorageClass)
	}
	// A restore is a byte-for-byte copy, so the restored volume carries the
	// SNAPSHOT's filesystem whatever the spec says. Accepting an FSType here
	// and recording it would hand back a Volume whose Spec claims "xfs" over an
	// ext4 image, and every later Mount and Resize would reach for the wrong
	// tooling on the strength of it.
	if spec.SourceSnapshotID != "" && spec.FSType != "" {
		return common.Volume{}, fmt.Errorf("%w: FSType %q cannot be applied to a restore from %q; the restored volume carries the snapshot's filesystem",
			common.ErrInvalidArgument, spec.FSType, spec.SourceSnapshotID)
	}
	// This provider has exactly one shape: the two-node pair the resource
	// template describes, so its natural count is two.
	//
	// The three branches are VolumeSpec.Replicas's, and the distinction between
	// the last two is load-bearing. A negative count is meaningless anywhere
	// and is a malformed request. A positive count this provider cannot honor
	// is a WELL-FORMED request that the local provider serves happily, so the
	// caller's fix is to choose that one — which is what ErrUnsupported means,
	// and what reporting a bad argument would hide.
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

	// The record is written first so that the minor and port it holds are
	// reserved for the rest of this call and for any concurrent one, and marked
	// incomplete so that a concurrent Status or Mount still sees no volume.
	// Every failure below unwinds it.
	if err := p.writeMeta(&meta); err != nil {
		return common.Volume{}, err
	}

	var lvCreated, resWritten bool

	// rollback undoes what has been built so far and returns what it could not
	// undo, in reverse order of construction.
	//
	// It runs on a context detached from the caller's. The most likely reason
	// to be here is that ctx was canceled or its deadline passed partway
	// through a long dd or initial "up" — and reusing it would make every
	// cleanup command fail instantly, leaving exactly the half-built resource
	// this exists to remove.
	//
	// The teardown is attempted whenever the resource file exists, not only
	// once "drbdadm up" has returned: an up that fails partway can leave the
	// device attached, and "drbdadm down" on a resource that never came up
	// succeeds anyway.
	//
	// What it could not undo is joined to the failure that triggered it rather
	// than discarded. A cleanup that itself failed has left a logical volume or
	// a resource file on the node, and an operator who is only told about the
	// original failure has no reason to go looking for it.
	//
	// The two files are removed only once the teardown they describe has been
	// CONFIRMED. Removing them regardless is worse than leaving them, in three
	// separate ways: the resource file is what drbdadm needs to take a resource
	// down, so deleting it after "drbdadm down" failed strips the node of the
	// means to clean up a resource that may still be live; the state record is
	// what makes the reservation visible to listMeta, so deleting it frees a
	// minor and a port that a still-running resource is holding, and the next
	// Provision collides with it; and both together are the only evidence that
	// anything was left behind at all.
	//
	// Retaining them is therefore the safe direction, and it composes with
	// listMeta's fail-closed read: a record that could not be removed and a
	// record that cannot be parsed both stop the allocator from reusing what
	// they describe.
	//
	// For the same reason the steps are ordered and the order is enforced: a
	// "drbdadm down" that failed stops the cleanup before it reaches lvremove,
	// because the resource it could not take down may still be attached to the
	// volume that removal would destroy.
	rollback := func() error {
		cleanupCtx, cancel := cleanupContext(ctx)
		defer cancel()

		// incomplete reports a cleanup that stopped early or partly failed,
		// naming everything still on the node so an operator has somewhere to
		// start. The two files are always among them: reaching here means they
		// were kept.
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
				// Stop the cleanup here rather than carrying on to lvremove.
				// A resource that would not go down may still be attached to
				// this logical volume, and the removal is "lvremove --force",
				// which is the flag that talks past a refusal. Whether LVM
				// declines to pull a device out from under an open holder is
				// its business and its version's; a rollback that only avoids
				// destroying live data because something downstream said no is
				// not relying on its own ordering, and ordering is the part
				// this code controls.
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

	// A restore creates the backing volume at the SOURCE's size and grows to the
	// requested one after bring-up; see restorePlan for why the copy cannot go
	// straight into a longer device.
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

	// A restore that asked for more than the source held is grown now, through
	// the same sequence a caller's Resize runs. The resource was brought up
	// immediately above, so the up-first guard that refuses to extend a
	// detached resource is satisfied rather than bypassed.
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

// Labels through which a caller pins the two values that BOTH halves of a pair
// must agree on. See resolveMinorAndPort.
const (
	// LabelMinor pins the DRBD device minor.
	LabelMinor = "drbd.minor"

	// LabelPort pins the TCP port the resource replicates over.
	LabelPort = "drbd.port"
)

// labelPrefix namespaces this provider's labels. An unrecognized label under it
// is rejected rather than ignored: a mistyped "drbd.prt" that silently fell
// back to local allocation is precisely the failure the labels exist to
// prevent, and it would not show up until the two nodes failed to connect.
const labelPrefix = "drbd."

// resolveMinorAndPort decides the device minor and replication port for a new
// volume.
//
// Both values are written into the resource file at resource scope, which means
// both halves of the pair use them: the port appears in each host's address,
// and the minor is the one device number the resource has. The two nodes must
// therefore agree, and this provider allocates from its OWN state directory —
// so two nodes whose state directories have drifted, because a volume was
// created on one and not the other or a provision failed halfway, would pick
// different numbers for the same volume and the resource would never connect.
//
// A caller that coordinates the pair — the HA controller, which holds the
// Coordinator and can allocate cluster-wide — pins both through the LabelMinor
// and LabelPort labels, and both nodes then render identical files. Local
// allocation remains the default for a pair driven by hand, where the operator
// is the thing keeping the two sides in step.
//
// Pinning one and not the other is refused, for the same reason a half-given
// node id is: it mixes a coordinated value with a locally invented one.
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

// resolveSnapshot turns a caller-supplied snapshot id into the logical volume
// it names, having proved that the snapshot is one this provider took.
//
// Three things must hold, and a caller-supplied id is not trusted on any of
// them. The id must parse and name this provider's volume group. The volume
// half must be a volume this provider has a record of, so that an id shaped
// like ours cannot reach an LV that merely happens to be named that way. And
// the LV must be an LVM snapshot whose origin is that volume, so that an
// ordinary logical volume with a snapshot-shaped name is not mistaken for one.
//
// A failure on the last two is common.ErrSnapshotNotFound rather than a
// permission-flavored error: from the caller's side, a snapshot this provider
// did not take is a snapshot this provider does not have.
//
// It returns the owning volume's record alongside the snapshot, because a
// restore needs it: the copy carries that volume's filesystem.
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

// restorePlan is how a restore is carried out.
//
// A restore is a whole-device copy, so the destination's backing volume is
// created at the SOURCE's size — not at the size the caller asked for. With
// internal metadata, DRBD keeps its metadata at the END of the backing device,
// and copying a shorter source into a longer destination would land the
// source's metadata partway through what the new volume presents as data, where
// create-md, which writes at the destination's own end, never touches it.
//
// A larger volume is then reached by GROWING, through the same sequence a
// caller's Resize runs: lvextend, drbdadm resize — which relocates the metadata
// to the new end because that is its job — and the filesystem where it can be
// grown. Which is exactly what this provider used to tell callers to do for
// themselves, in an error. Doing it here is the same operation with the caller
// left out of it.
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

	// The destination's backing size — data plus DRBD metadata, rounded up to a
	// whole extent — has to be representable before it is computed. Past the
	// bound, backingBytes or the rounding on top of it wraps NEGATIVE, and the
	// src > dst comparison below would read a wrapped-negative destination as a
	// shrink the caller never asked for. Malformed input rather than an
	// unsupported restore: no volume group could hold it.
	if limit := maxDataBytes(entry.extentSizeBytes(), p.cfg.Encrypted); spec.SizeBytes > limit {
		return nil, fmt.Errorf("%w: size %d exceeds the largest usable capacity representable on this volume group, %d (extents are %d bytes and DRBD's internal metadata, and the LUKS2 header on an encrypted provider, is added on top)",
			common.ErrInvalidArgument, spec.SizeBytes, limit, entry.extentSizeBytes())
	}
	// Both are logical volumes, whose sizes LVM rounds up to the volume group's
	// extent, so the comparison is against the size lvcreate would give the
	// destination rather than the unrounded request — comparing a rounded
	// origin against an unrounded request reads a restore at exactly the
	// original size as a shrink. The conversion is this provider's, header
	// included when it encrypts: a snapshot of an encrypted volume has the
	// encrypted backing size as its origin, so a same-size restore of it lands
	// on exactly that figure and is neither a grow nor a shrink.
	dst := roundUpTo(backingBytes(spec.SizeBytes, p.cfg.Encrypted), entry.extentSizeBytes())
	if src > dst {
		return nil, fmt.Errorf("%w: restoring snapshot %q needs a %d-byte backing volume, but %d usable (%d backing) was requested: this provider does not shrink during restore",
			common.ErrUnsupported, spec.SourceSnapshotID, src, spec.SizeBytes, dst)
	}

	// A restore that would have to GROW runs resizeLocked once the resource is
	// up, on an encrypted provider like any other. The restored resource comes
	// up Secondary, its container closed, so the grow it runs is the deferring
	// one: the device grows, the record follows, and the filesystem — the
	// source's, copied byte for byte — is owed a grow that the first Promote
	// sizes the mapping for and the first Mount pays. See FSGrowPending.
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

	// Serialized with Delete. This method has no precondition of its own to
	// invalidate, which is why it looks safe unlocked and is not: the check it
	// breaks belongs to Delete, which observes that a resource is not up, skips
	// the teardown on that basis, and then removes the backing volume and the
	// state files. A "drbdadm up" anywhere in that span brings the resource up
	// onto storage that is about to be lvremove'd, and hands this caller a
	// device path for a volume whose record no longer exists.
	//
	// The LOOKUP is inside the lock, not just the drbdadm call. Reading the
	// record first and locking afterwards leaves the same bug with extra steps:
	// the wait ends after the delete has finished, and this method then acts on
	// a record that no longer exists on disk.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return common.AttachInfo{}, err
	}

	// Attaching a resource that is already up converges rather than running
	// "drbdadm up" a second time. Detach's counterpart of this — returning nil
	// when the resource is already down — has been here from the start, and an
	// Attach that does not converge in the same way is the asymmetry, not this.
	//
	// It is also the normal path: Provision brings the resource up before it
	// returns, so a caller following the contract's Provision, Attach, Mount
	// order arrives here with the resource already up. Whether a repeated
	// "drbdadm up" is a no-op or an error on a real node is a question this
	// removes rather than answers; it has never been exercised against
	// hardware, so it is not a question worth leaving on that path.
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

	// Serialized with Promote for the reason Snapshot is serialized with
	// Demote, in the opposite direction: reading the role and taking the
	// resource down are two steps, and a promotion between them means this
	// method tears down a device on the strength of a precondition that stopped
	// holding — the caller of Promote was told its volume is Primary and the
	// device is gone underneath it. Checking that a volume is not writable does
	// not keep it that way; the lock does.
	//
	// The lookup is inside the lock for the reason given in Attach: a record
	// read before the wait can have been deleted by the time the wait ends.
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

	// Converging rather than expected: a Secondary reached through Demote has
	// no mapping left, because Demote closes it and DRBD would not have
	// demoted otherwise. What this covers is the mapping nobody closed — a run
	// that ended between the two, an operator who opened one by hand — and it
	// has to go before the resource does, since an open mapping holds the
	// device and fails the drbdadm down.
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

	// The whole method is serialized, with the LOOKUP inside, and the reason is
	// identity rather than role. This once relied on failing closed: a demotion
	// between the Primary check and the open makes the open fail, because DRBD
	// refuses every open of a Secondary. That argument is sound and it is not
	// enough, because it only covers the volume STAYING the volume.
	//
	// A record read before the lock names a minor, and a minor is reusable. Let
	// Delete free this volume's record and a following Provision take the same
	// number — which the allocator will do, and which a caller can pin outright
	// — and every step below is then pointed at /dev/drbd<minor> belonging to a
	// DIFFERENT volume. The probe reads it, and if it reads as empty the format
	// destroys it. Failing closed on the role does not help: the replacement is
	// perfectly happy to be Primary, so the check passes and the mkfs proceeds
	// against a volume this call never looked up.
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

	// And that the container is open, which Primary implies in the ordinary
	// case and does not guarantee. Checked before the format for the reason the
	// target is: ensureFilesystem writes to the plaintext device, and a device
	// node that is not there is not a mkfs to attempt and hope for a legible
	// error from. A no-op for an unencrypted volume.
	if unlockErr := p.requireContainerOpen(ctx, &meta); unlockErr != nil {
		return unlockErr
	}

	// Before the format, not merely before the mount. Mount creates a
	// filesystem on an empty device, and that is the destructive step: a
	// request that is going to fail on its target must fail BEFORE it, or a
	// rejected call still leaves the volume formatted.
	//
	// It is the SAME resolution the mount will do — mount.Check pins the target
	// exactly as Mount would and lets it go — because a cheaper lookalike
	// diverges. An Lstat here would pass a path whose PARENT is a symlink,
	// which the pin then refuses, and the format would already have happened.
	//
	// This is still an ordering control rather than a security one: passing
	// here does not make the later mount safe, since the path can be swapped in
	// between. Mount resolves again and mounts against what it pinned itself.
	if targetErr := mount.Check(target); targetErr != nil {
		return fmt.Errorf("%w: mount target %q: %w", common.ErrInvalidArgument, target, targetErr)
	}

	dev := p.fsDevice(&meta)
	// The type that comes back is the one on the device, which may not be the
	// one that went in: a volume formatted by an attempt that failed before
	// recording carries a filesystem neither the record nor the caller knows
	// about, and mounting it as anything else fails.
	onDisk, err := p.ensureFilesystem(ctx, &meta, fsType, opts.ReadOnly)
	if err != nil {
		return err
	}
	fsType = onDisk

	flags, data := mount.Arguments(opts.ReadOnly, opts.Flags)
	if err := p.mounter.Mount(ctx, dev, target, fsType, flags, data); err != nil {
		return fmt.Errorf("mounting volume %q at %q: %w", meta.Name, target, err)
	}

	// The mount exists in THIS namespace now. Whether it exists in the
	// workload's is a different question, and the only moment it can be asked is
	// this one: propagation is inherited from the parent at the instant mount(2)
	// is called, so there was nothing to inspect before, and by the time a
	// caller notices the workload's directory is empty the answer is expensive.
	//
	// Off unless the deployment asked for it; see MountPropagationPolicy. A
	// refusal unwinds the mount rather than leaving one the caller was told did
	// not happen.
	if id, finding := p.verifyMountPropagation(ctx, dev, target); finding != nil {
		return p.unwindUnverifiedMount(ctx, dev, target, id, finding)
	}

	// A grow the record owes is paid HERE, after the mount, because this is
	// the first point at which both filesystems this package manages can be
	// grown online: resize2fs against a mounted ext4 needs no check, and
	// xfs_growfs has no other form. It is not paid at Promote, where the only
	// ext4 route is a forced e2fsck of the whole filesystem in the failover
	// path and XFS cannot be grown at all, and the record cannot even be sure
	// the debt is real — see FSGrowPending. A mount that returns an error has
	// mounted nothing, the same promise the propagation check keeps.
	if meta.FSGrowPending {
		if err := p.payDeferredGrow(ctx, &meta, target); err != nil {
			return err
		}
	}
	return nil
}

// payDeferredGrow grows the filesystem Mount just mounted, because a Resize
// left it behind its device, and clears the record's debt.
//
// An error unwinds the mount. The two silent alternatives are both wrong
// answers: mounted behind an error reports a mount that did not happen, and
// success with the grow undone reports a size the filesystem never reached.
// The debt is left standing either way, so the next Mount tries again — and
// for a stale mapping the error names what has to happen first.
//
// The unwind runs on a context of its own, like Promote's rollback: the
// likeliest reason to be unwinding is that ctx died partway through the grow,
// and an unmount on that context fails before it starts, leaving exactly the
// mount this reports as undone.
func (p *Provider) payDeferredGrow(ctx context.Context, meta *resourceMeta, target string) error {
	grown, err := p.growFilesystem(ctx, meta)
	if err == nil && grown {
		meta.FSGrowPending = false
		err = p.writeMeta(meta)
	}
	if err == nil && !grown {
		// Unreachable by construction — mounted ext4 and xfs both grow — and
		// a filesystem left short behind a successful mount is precisely the
		// silent answer this refuses to give, so it is an error rather than a
		// pass if the construction ever changes.
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

// probeDevice reports what blkid recognizes on the device: the filesystem type
// if there is one, and whether the device is empty of ANY signature.
//
// Both answers come from one probe, and both are needed. Emptiness decides
// whether to format, and it asks for everything rather than filtering to the
// filesystem type — a device holding a partition table and no filesystem
// reports only PTTYPE, so a TYPE-filtered probe exits successfully with empty
// output, indistinguishable from an empty device and enough to format over
// somebody's partitioned volume. The filesystem type is what the record is
// reconciled against, so a device formatted by an attempt that then failed to
// record it does not stay mis-described forever.
//
// Only blkid's "nothing found" exit status counts as empty. A successful exit
// means it recognized something, and any other failure means the answer is
// unknown; neither may lead to a mkfs.
func (p *Provider) probeDevice(ctx context.Context, dev string) (fsType string, empty bool, err error) {
	out, err := p.runner.Run(ctx, binBlkid, "-p", "-o", "export", dev)
	if err != nil {
		if code, ok := exitCode(err); ok && code == blkidNoSig {
			return "", true, nil
		}
		return "", false, fmt.Errorf("probing %q: %w", dev, err)
	}
	// export format is KEY=VALUE per line. TYPE is the filesystem; a device
	// with only PTTYPE has a partition table and no filesystem, which is not
	// empty and not something to reconcile a record against.
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "TYPE="); ok {
			return strings.Trim(value, `"`), false, nil
		}
	}
	return "", false, nil
}

// ensureFilesystem creates the filesystem on a device that carries nothing,
// records what is on it either way, and RETURNS the type that is actually
// there.
//
// Returning it is not incidental. The record and the device can disagree — an
// earlier attempt formats and fails before recording — and reconciling the
// record while the caller went on to mount with the type it walked in holding
// would fix the bookkeeping and then fail the mount for the same reason it was
// wrong in the first place.
//
// The steps are ONE critical section, and that is the whole reason this is a
// function. Probing, formatting and recording are separately harmless and
// collectively destructive: two concurrent first mounts that both probe before
// either formats will both run mkfs on the same device, and with different
// filesystems if their callers asked for different ones. A provider documented
// as safe for concurrent use cannot leave that open.
//
// The lock covers the mkfs, which is not free — it is held for as long as
// making a filesystem takes. That is deliberate: it happens once in a volume's
// life, and the alternative is a race whose outcome is a corrupted volume. The
// MOUNT is outside it, so the slow, repeatable part does not serialize the
// provider.
func (p *Provider) ensureFilesystem(ctx context.Context, meta *resourceMeta, fsType string, readOnly bool) (string, error) {
	// The caller holds p.mu. This used to take it here, over the probe, the
	// format and the record write, because those three are what must not
	// interleave with each other. Mount now holds it across its whole body —
	// the lookup included, so that meta names a volume that still exists — and
	// this is its only caller, so taking it again would deadlock.
	dev := p.fsDevice(meta)
	found, empty, err := p.probeDevice(ctx, dev)
	if err != nil {
		return "", err
	}
	if !empty {
		// The device already carries a filesystem, and the record may not say
		// so: an earlier attempt can format and then fail before recording it,
		// and without this that volume stays described as raw forever — its
		// next Mount has no filesystem type to use and its next Resize grows
		// nothing. Reconciling here converges on the retry.
		//
		// Only a filesystem this provider understands. Something else on the
		// device is a fact worth not overwriting the record with, since the
		// record drives mkfs and grow decisions that only make sense for the
		// two it supports.
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

	// What is on the device is now known exactly, and it may not be what the
	// record says: MountOptions.FSType overrides the recorded type, so a volume
	// provisioned as ext4 — or as a raw device — can be formatted here as
	// something else.
	return fsType, p.reconcileFSType(meta.Name, fsType)
}

// reconcileFSType records the filesystem now known to be on a volume.
//
// The record is re-read rather than written back from a caller's copy, which
// may be stale — writing that back would undo a size a concurrent Resize had
// just recorded. Callers hold the provider lock.
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

	// Serialized with the lookup inside, for Mount's reason. The device
	// comparison below looks like it already settles identity, and it does not:
	// what it compares is the MINOR, and the minor is the thing that gets
	// recycled. A record read before the lock, whose volume is then deleted and
	// whose number a new volume takes, matches that new volume's device exactly
	// — so the check passes and this unmounts a filesystem belonging to someone
	// it was never asked about, out from under whatever is using it.
	//
	// With the lookup inside the lock the deleted volume is simply not found,
	// which is the honest answer, and the comparison goes back to doing the job
	// it was written for: refusing a target that holds some OTHER live volume.
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
		// Either nothing is mounted at the target or something else is. Neither
		// is an error by contract, and neither unmounts anything: this provider
		// unmounts its own volume, and another device is emphatically not ours
		// to take out from under whoever is using it.
		return nil
	}

	if err := p.mounter.Unmount(ctx, target); err != nil {
		return fmt.Errorf("unmounting %q: %w", target, err)
	}
	return nil
}

// mountedAt reports whether dev — this volume's device — is mounted at target.
//
// It asks which paths the DEVICE is mounted at rather than which device is
// mounted at the path, because the answer to the second question is a string:
// the mount source is whichever of the device's names was used to mount it, and
// a DRBD device has several — /dev/drbdN, /dev/drbd/by-res/<res>/0,
// /dev/drbd/by-disk/... . Comparing that string against the one name this
// provider spells would read a mount made through an alias as belonging to
// somebody else, and quietly not unmount a filesystem it was asked to unmount.
// Matching by the device number, which is what MountPointsFor does, has no such
// hole.
//
// A device node that does not exist is not an error: the resource is down, so
// nothing of this volume is mounted anywhere, which is the same converging
// no-op as a target it is not mounted at. Every other failure — a mount table
// that could not be read above all — stops the unmount, because "not mounted"
// is exactly the answer a teardown acts on.
func (p *Provider) mountedAt(ctx context.Context, dev, target string) (bool, error) {
	// Visible, not merely mounted: umount(2) detaches whatever is visible at
	// the path it is given, so a target this volume has been over-mounted at is
	// one where unmounting takes down somebody else's filesystem and leaves
	// this one where it was. That is not mounted "at" the target in any sense
	// this method should answer yes to.
	targets, err := p.mountTable.VisibleMountPointsFor(ctx, dev)
	if err != nil {
		// Only the DEVICE being absent converges. os.ErrNotExist alone is too
		// broad a test: a mount table that could not be opened reports the same
		// thing about /proc/self/mountinfo, and reading THAT as "not mounted"
		// is the fail-open this whole change removed. The error type is what
		// separates them.
		var deviceErr *mountinfo.DeviceError
		if errors.As(err, &deviceErr) && errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("looking up mounts of %q: %w", dev, err)
	}
	return slices.Contains(targets, target), nil
}

// mountTarget returns where the device is mounted, if it is. A device mounted
// at more than one path yields the first, which is all the callers here need:
// one asks whether it is mounted at all, the other wants a path to hand
// xfs_growfs, and growing through any of a filesystem's mount points grows the
// filesystem.
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

// resizeLocked is Resize with the lock already held and the volume already
// looked up.
//
// It exists because a restore into a larger volume finishes by growing, and
// Provision holds the lock throughout — so the grow has to be the SAME sequence
// a caller's Resize would run, not a second implementation of it that could
// drift from the one that knows about metadata at the end of the device.
func (p *Provider) resizeLocked(ctx context.Context, metaPtr *resourceMeta, newSize int64) error {
	meta := *metaPtr
	if newSize <= 0 {
		return fmt.Errorf("%w: size must be positive, got %d", common.ErrInvalidArgument, newSize)
	}
	if newSize < meta.SizeBytes {
		return fmt.Errorf("%w: volume %q is %d bytes and this provider does not shrink", common.ErrUnsupported, meta.Name, meta.SizeBytes)
	}
	// A request equal to the recorded size is NOT a no-op. Growing the device
	// and growing the filesystem on it are two halves of one operation, and the
	// second half can fail on its own — an unmounted XFS volume, a Secondary,
	// an e2fsck that found something. Returning early here would report success
	// over a filesystem still at its old size and leave no way to finish the
	// job. Every step below is idempotent, so a repeat costs a few commands and
	// completes what the first attempt could not.

	// The resource has to be UP before anything is extended.
	//
	// drbdadm resize only works on a running resource, and the backing volume
	// is where DRBD keeps its internal metadata — at the END of the device. So
	// extending the LV under a resource that is down moves the end away from
	// the metadata and there is no drbdadm resize available to follow it: the
	// call fails with the lower device already changed, the record still saying
	// the old size, and a resource that will not come up because its metadata
	// is no longer where it belongs.
	//
	// Refusing rather than bringing it up: Resize does not get to attach a
	// volume the caller detached. ErrNotAttached is the same answer Mount gives
	// for the same missing precondition.
	if _, up, roleErr := p.localRole(ctx, meta.Name); roleErr != nil {
		return roleErr
	} else if !up {
		return fmt.Errorf("volume %q: the resource is not up, so its backing device cannot be extended safely: %w",
			meta.Name, common.ErrNotAttached)
	}

	// The backing volume carries the metadata as well as the data, and the
	// bitmap grows with the device, so the target is recomputed rather than
	// extended by the difference.
	//
	// The current size is read first so that each of the three steps can be
	// skipped when it has already happened. A resize is two system operations
	// and a state write, and any of them can fail partway — a lost context, a
	// DRBD hiccup, a full state directory — leaving the backing volume grown
	// and the record still holding the old size. Retrying then runs lvextend
	// against a volume already at the target, which LVM refuses as not larger,
	// and the resize could never finish through this API. Skipping the step
	// that is already done lets the same call converge instead.
	lvs, err := p.lvs(ctx)
	if err != nil {
		return err
	}
	entry, ok := findLV(lvs, meta.LV)
	if !ok {
		return fmt.Errorf("volume %q: backing logical volume %q is missing", meta.Name, p.lvRef(meta.LV))
	}
	// The target below is backingBytes(newSize, encrypted) rounded up to a whole extent, and
	// that has to be representable BEFORE it is computed. Past the bound it wraps
	// NEGATIVE: entry.sizeBytes() < target is then false, so lvextend and the
	// drbdadm resize after it are SKIPPED, the filesystem is never grown, and yet
	// meta.SizeBytes is written as the fabricated size and nil returned — silent
	// success over a device that never moved, after which every legitimate Resize
	// is refused as a shrink against the recorded size. A size with no
	// representable backing is malformed input, not a supported grow.
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
		// Nothing is recorded. The device half stands — it is idempotent and
		// the repeat converges on it — but the record must never say a size
		// the filesystem did not reach, and must not owe a grow a repeat
		// would not perform (a stale mapping is refused again until the
		// remedy is applied).
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

// growFilesystem extends the filesystem on a volume whose device has just grown,
// and reports whether it did.
//
// ext4 grows either way, but not by the same route. Mounted, resize2fs grows it
// online. Unmounted, resize2fs refuses until the filesystem has been checked —
// it answers "Please run 'e2fsck -f <device>' first." even for a filesystem
// whose own state field reads clean — so the check runs first, and only when
// the device is genuinely unmounted, because running e2fsck against a MOUNTED
// filesystem would corrupt it. That is why this decides from the mount table
// and not from a flag. pkg/local reached the same arrangement against the same
// tools; this is deliberately the same shape.
//
// The offline route has one precondition that is this provider's alone: it has
// to open the device read/write, and DRBD permits that only on the Primary. On
// a Secondary the filesystem cannot be grown at all, so the device growth
// stands, the call succeeds, and the filesystem takes up the space the next
// time it is grown from the node holding Primary.
//
// XFS grows only through xfs_growfs against a live mountpoint, having no
// offline form, so an unmounted XFS volume is left for the caller to grow after
// mounting. A raw volume has nothing to grow but itself.
//
// AN ENCRYPTED VOLUME'S FILESYSTEM LIVES ON THE MAPPING, and the mapping is
// checked before anything else is decided. No mapping — the container is
// closed, which a Secondary's always is — means no plaintext device to grow
// into, so the grow is deferred exactly as a Secondary's is; the next Promote
// opens a mapping sized to the device as it is then. A mapping that no longer
// covers the device is refused with ErrMappingStale rather than grown into: a
// resize2fs against it would fit the filesystem to the OLD size and exit 0,
// and the caller would record the new one. This is the one place every grow
// passes through, which is what makes the check unavoidable; see
// requireFreshMapping. A raw encrypted volume is checked too, since its
// consumer uses the plaintext device directly.
//
// The bool is the caller's bookkeeping: true when the filesystem now fills the
// device (or there is none to fill it), false with a nil error when the grow
// was DEFERRED — nothing could be done from this node's state, and nothing is
// wrong. A grow that is attempted and fails is a real failure and is returned.
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

// checkExtFilesystem runs the forced check resize2fs demands before an offline
// grow.
//
// -f forces it even on a filesystem marked clean, which is what resize2fs is
// asking for. -p makes it non-interactive, fixing only what can be fixed
// without a question — there is nobody to answer one, and the alternative is a
// command that blocks forever holding the device open.
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
	// Serialized with Delete, which refuses a volume that still has snapshots.
	// That check and its lvremove are two steps, and a snapshot created between
	// them would be destroyed by the removal of its origin — the protection
	// bypassed by timing rather than by anything the caller did wrong.
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
	// Serialized with Provision and Snapshot for the same reason Snapshot is
	// serialized with Delete: resolving a snapshot and acting on it are two
	// steps, and a removal that lands between them destroys something another
	// operation has already accepted. A restore is the sharp case — Provision
	// validates the source snapshot and then copies it, holding this lock
	// throughout, so without it here the source could vanish mid-copy and a
	// restore that was legitimate when it started would fail or roll back.
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

	// Snapshots are checked BEFORE the role, and the order is deliberate.
	//
	// Both conditions block a delete, and only one of them changes with the
	// volume's role. Demoting does not make a snapshot go away: a caller told
	// "demote first" would demote, retry, and only then learn it has restore
	// points to decide about — the larger decision, discovered second. Told
	// about the snapshots first, it deals with the thing that is true either
	// way and finds the role waiting for it afterwards.
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

	// A resource that is up may be torn down only once it is affirmatively
	// Secondary. Testing for "is Primary" instead lets every answer that is
	// neither through — an unparsed role string, or the "Unknown" drbdsetup
	// reports in some states, both of which map to ReplRoleUnknown with no
	// error — and the next two steps are drbdadm down and lvremove. Written
	// this way a role added to the enum later also refuses by default, which is
	// the right default for the one operation here that destroys data.
	//
	// A resource that is NOT up is a different case and still deletable: it
	// holds no role because nothing is running, so it cannot be Primary, and
	// refusing would strand the half-provisioned records lookupAny exists to
	// clean up.
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
		// Before the teardown, for the reason it is before Demote's role
		// change: an open mapping holds the device open and drbdadm down fails
		// on it. Only while the resource is UP, because that is when the device
		// a mapping could be over exists at all.
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
			// A wipe activates an inactive volume to have a device to write to
			// and leaves it that way, because the removal was about to take it.
			// When the REMOVAL is what failed, that activation is left over
			// from an operation the operator watched fail — a volume they had
			// deactivated, now carrying a device node nobody asked for.
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

// wipe zero-fills a backing logical volume so nothing of it survives in the
// extents LVM returns to the free pool. It runs only with Config.WipeOnDelete
// set; that field documents what the exposure is and what this does not cover.
//
// It goes over the BACKING volume, not /dev/drbd<minor>. The extents that get
// freed are the logical volume's, so the logical volume is what has to be
// overwritten — and the DRBD metadata living at the end of that device goes with
// it, which is correct for something about to be removed. Writing through the
// DRBD device instead would also replicate every zero to the peer, turning a
// local cleanup into a full-volume resync of data that is being destroyed.
//
// blkdiscard --zeroout uses the device's own zeroing offload where the hardware
// has one and falls back to writing zeroes where it does not, which is the
// difference between seconds and hours on a large volume. It is the same
// mechanism and the same flag pkg/local uses, deliberately: the two providers
// carve from the same kind of volume group, and an operator comparing them
// should not find two different answers to one question.
//
// ORDERING: this runs after the resource is down and before lvremove, and both
// halves matter. DRBD holds its backing device open while the resource is up, so
// a wipe attempted first fails on a busy device rather than quietly doing
// nothing; and a wipe after the removal has nothing left to address.
//
// An INACTIVE backing volume is activated first, because it has no device node
// to write to otherwise. It is tempting to think that cannot happen — a DRBD
// backing volume is active whenever the resource has been up, and provisioning
// brings it up before returning — but Delete deliberately serves states where
// the resource is already down, and a volume reaches those with no device node
// after a reboot without autoactivation, after an administrator deactivates it,
// or from a provisioning run that failed partway. Assuming otherwise turns
// wipe_on_delete into a PERMANENT block on an otherwise valid deletion: the
// blkdiscard fails on a missing device, the wipe failure stops the delete by
// design, and the operator cannot get past it without turning the option off.
// The fail-closed retention is meant to protect data, not to strand a volume.
//
// A borrowed activation is given back on EITHER failure, and this function owns
// only the first of them. If the wipe fails, it deactivates here. If the wipe
// succeeds and the lvremove that follows fails, Delete deactivates there — the
// volume survives that path too, so the activation is just as much a leftover
// from an operation the operator watched fail. Restoring it matters for the
// reason it does in pkg/local: a volume they left deactivated must not come back
// carrying a device node nobody asked for. A volume that was already active is
// left exactly as it was found, with no lvchange run at all.
//
// A failure here stops the delete. The volume and its record stay, which is the
// honest outcome: the caller asked for the contents to be destroyed before the
// volume was, and if that did not happen the volume should still be there to try
// again on. Removing it anyway would hand the extents back holding exactly the
// data this option exists to keep out of them.
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
		// Said explicitly, because the zero value already means something else.
		// common.VolumeStatus reserves it for a volume that is NOT REPLICATED,
		// and this provider has no such volumes — every one it makes is a
		// two-host DRBD resource. Leaving the field alone here told an HA
		// controller that a replicated volume which is merely down has no peer
		// to fail over to, which is the one thing it must not be told.
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

// fsDeviceMounted reports whether the volume's filesystem device is mounted
// anywhere, on a volume whose plaintext mapping may not exist.
//
// The mount table resolves a device by stat(2) BEFORE it reads anything, so
// asking about a path with no node behind it is an error rather than an empty
// answer — and on an encrypted provider the filesystem device is the mapping,
// which exists only while the container is open. Every Secondary after a
// Demote, and every volume resized Secondary-side with its container closed,
// has no such node; asking anyway failed Status on exactly the volumes this
// provider is supposed to be able to describe (#69 review).
//
// The container's state is the gate, through the same ownership check every
// other path uses: a closed container has nothing mounted and is not looked
// up; an open one is asked about like any device. What is NOT absorbed is an
// error from that check — a mapping under our name over some other device —
// because reading that as "closed" would report Attached about a volume whose
// mapping is a conflict a human has to resolve. Nothing here is read as "not
// mounted" because a lookup failed; the lookup is skipped because the device
// provably does not exist. That is the difference from the fail-open the
// mount-table lookup was moved off findmnt to remove.
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
	// Serialized with Delete. Delete refuses a volume that is Primary and then
	// tears it down, and those are two steps: a promotion landing between them
	// defeats the demote-before-delete guard entirely, and the resource that
	// just became writable is removed underneath whatever started writing to
	// it.
	//
	// The same lock is what keeps this out of Snapshot's window, between its
	// Primary check and its lvcreate. A promotion there is harmless in the
	// direction that matters — the check demanded Primary and the promotion
	// only supplies it — but the lock covers both directions, so there is no
	// second rule to remember. Demote is where the direction is NOT harmless;
	// see the lock there.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return err
	}

	// Read BEFORE the promotion, because the rollback below turns on it and
	// afterwards there is no way to tell the two cases apart. It mirrors
	// pkg/local's Attach, which rolls its activation back only when the volume
	// was not already active: a promotion this call did not perform is not this
	// call's to undo, and undoing it would take the volume away from whoever
	// promoted it first.
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

	// AFTER the role change, because DRBD refuses every open of a Secondary's
	// device — there is no earlier moment at which the container can be
	// unlocked. A no-op for an unencrypted volume.
	if err := p.openContainer(ctx, &meta); err != nil {
		if wasPrimary {
			return err
		}
		// The promotion was this call's, and it did not achieve what the caller
		// asked for: a Primary with no plaintext device is a volume nothing can
		// mount, holding the pair's only writable copy away from the peer. It
		// goes back.
		//
		// On a context of ITS OWN. The most likely reason to be here is that
		// ctx was canceled or timed out partway through the unlock, and reusing
		// it makes the demotion fail instantly — the production runner execs
		// through exec.CommandContext — leaving behind exactly the state this
		// undoes, while the code reads as though it had been restored.
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
	// Serialized with Snapshot. Snapshot requires the volume to be Primary on
	// this node and then runs lvcreate, and those are two steps: a demotion
	// landing between them produces a snapshot of a Secondary's backing device,
	// which is precisely what the role check exists to refuse — a device
	// written by the replication stream with nothing above it ordering those
	// writes, so what is captured is not crash-consistent and not anything
	// else either.
	//
	// Making a volume LESS writable is not therefore harmless. That was the
	// reasoning this lock replaces: less-writable is exactly the direction that
	// invalidates a precondition another method has already checked and is
	// still acting on.
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, err := p.lookup(volID)
	if err != nil {
		return err
	}

	// BEFORE the role change, and the order is the operation. An open dm-crypt
	// mapping holds /dev/drbdN open, and DRBD refuses to demote a device
	// somebody has open — so a demotion attempted first fails on a busy device
	// and reports it as though a workload still held the volume. A no-op for an
	// unencrypted volume.
	//
	// A failure here is the caller's answer: the volume stays Primary and stays
	// unlocked, which is the state it was in, rather than half of a demotion.
	if err := p.closeContainer(ctx, &meta); err != nil {
		return err
	}

	if err := p.drbdadm(ctx, "secondary", meta.Name); err != nil {
		// The mapping is NOT re-opened. Demote is reached with the volume
		// already unmounted — the mapping is what a mount sits on — so what a
		// failed demotion leaves is a Primary with a closed container and
		// nothing using it, and the next Promote opens one. Re-opening here
		// would be a second operation that can fail on its own, in a path that
		// is already reporting a failure, to restore a plaintext device with no
		// user.
		return fmt.Errorf("demoting volume %q: %w", meta.Name, err)
	}
	return nil
}

// downReplState is what a resource that is configured for replication and not
// running reports, and it is one function rather than two literals so that
// Status and ReplicationState cannot drift into disagreeing about the same
// volume in the same state.
//
// Down is a definite answer, not an absent one: the resource exists, this
// provider knows about it, and nothing is running. It is not standalone either
// — standalone means the resource IS up and has stopped talking to its peer —
// and a resource that is down holds no role at all.
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

// lookupAny is lookup without the completeness filter. Delete uses it so that a
// volume left half-provisioned by a failed attempt — which every other method
// correctly reports as absent — can still be cleaned up rather than needing the
// state file removed by hand.
func (p *Provider) lookupAny(volID string) (resourceMeta, error) {
	if err := validateName("volume id", volID); err != nil {
		return resourceMeta{}, fmt.Errorf("%w: %w", common.ErrNotFound, err)
	}
	return p.readMeta(volID)
}

// requireLocalNode decides whether an operation may act on the named node, and
// separates the two ways it may not.
//
// A resource generated by this provider has exactly two hosts, so those are the
// only node names that mean anything to it. A name that is neither is not a
// node of this volume at all — a malformed request, reported as
// common.ErrInvalidArgument, which tells the caller to fix what it asked rather than
// to ask a different backend.
//
// The peer is a real node of the resource, and attaching there is a perfectly
// well-formed thing to want; this provider simply cannot do it. It drives the
// local DRBD instance and has no channel to the other one, so the peer's own
// provider is what serves that request. That is ErrUnsupported, per the Attach
// contract's rule for a request the provider cannot serve on the node asked
// for. Reporting success would claim something happened on a host this process
// never spoke to.
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
