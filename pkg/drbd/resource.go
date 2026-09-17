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
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// resourceTemplate renders a per-volume DRBD resource file.
//
// Every field it interpolates is either a typed integer or a string that has
// already passed an allowlist in validate.go, so a caller-supplied volume name
// cannot open a brace and add configuration of its own. The template is
// text/template rather than string concatenation for the same reason it is
// worth having at all: one place where the shape of the file lives, and no
// arithmetic on strings at the call site.
//
// Peer authentication is cram-hmac-alg with a shared secret, and the secret is
// written into this file because that is where drbdadm reads it from. There is
// no indirection DRBD offers — no key file, no agent — so the file carries the
// secret at the same trust level as a LUKS key file and is written 0600 in a
// directory this provider creates 0750. That constraint belongs to DRBD's
// design; what belongs here is not pretending otherwise. See the package doc.
//
// Protocol C is not configurable. It is the only one of DRBD's three protocols
// that acknowledges a write after the peer has it on stable storage, and the
// lease-gated failover this library exists to support assumes exactly that: a
// node that takes over must find every write the old primary acknowledged.
// Protocols A and B would make that false and are not offered.
//
// The connection between the two hosts is left implicit. DRBD 9 connects every
// pair of nodes that carry a node-id in the same resource, which for two hosts
// is the one connection wanted; spelling it out adds a place for the two halves
// to disagree.
// The template is split at the secret, into named pieces executed in sequence.
//
// That split is the whole point. The shared secret arrives in an enclave and
// must never become an ordinary Go value: a string handed to a template is
// copied into the template's output buffer and both live on the heap, outliving
// the enclave's destruction and reachable in a core dump or a swapped page. So
// the template renders everything EXCEPT the secret's bytes, and those go from
// the borrowed slice to the file descriptor directly.
//
// "head" ends immediately after the opening quote of the shared-secret line and
// "authClose" begins with the closing one, so the two fragments around the
// secret are fixed text this package wrote rather than anything interpolated.
// "tail" is shared by both the authenticated and unauthenticated forms, so the
// host stanzas exist once and cannot drift between them.
var resourceTemplate = template.Must(template.New("resource").Parse(
	`{{define "head"}}# Managed by go-blockstore (provider "drbd"). Do not edit by hand.
# Volume: {{.Name}}
# Generated: {{.Generated}}
resource "{{.Name}}" {
    device    minor {{.Minor}};
    disk      "/dev/{{.VG}}/{{.LV}}";
    meta-disk internal;

    net {
        protocol C;
        verify-alg crc32c;
        csums-alg  crc32c;
{{end}}{{define "authOpen"}}        cram-hmac-alg {{.HMACAlg}};
        shared-secret "{{end}}{{define "authClose"}}";
{{end}}{{define "noAuth"}}        # NO PEER AUTHENTICATION. Provisioned with {{.UnauthenticatedSetting}}
        # set: any host that can reach this address and speak DRBD can present
        # itself as the peer.
{{end}}{{define "tail"}}    }

    on "{{.NodeName}}" {
        node-id {{.NodeID}};
        address {{.NodeAddress}};
    }

    on "{{.PeerNode}}" {
        node-id {{.PeerNodeID}};
        address {{.PeerAddress}};
    }
}
{{end}}`))

// resourceParams is the rendering input. It has no field for the secret, and
// that absence is load-bearing: there is nowhere in this struct for the secret
// to be copied to.
type resourceParams struct {
	HMACAlg                string
	UnauthenticatedSetting string

	Name        string
	Generated   string
	Minor       int
	VG          string
	LV          string
	NodeName    string
	NodeID      int
	NodeAddress string
	PeerNode    string
	PeerNodeID  int
	PeerAddress string
}

// formatAddress renders an address in DRBD's syntax, which names the address
// family and brackets IPv6 literals.
func formatAddress(ip net.IP, port int) string {
	if ip.To4() != nil {
		return fmt.Sprintf("ipv4 %s:%d", ip.String(), port)
	}
	return fmt.Sprintf("ipv6 [%s]:%d", ip.String(), port)
}

// writeResourceFile renders a volume's resource file straight to disk.
//
// It renders to the FILE rather than to a buffer, because the shared secret
// passes through here and a buffer is a heap copy that outlives the enclave.
// The fragments around the secret are rendered from the template; the secret's
// bytes are written from inside the enclave borrow, to the same descriptor, and
// never exist as a Go string or a slice this package owns.
//
// The file is 0600: it carries the secret, so it is worth what a LUKS key file
// is worth.
func (p *Provider) writeResourceFile(ctx context.Context, m *resourceMeta) error {
	params, err := p.resourceParams(m)
	if err != nil {
		return err
	}
	return writeFileAtomicFunc(p.resPath(m.Name), 0o600, func(w io.Writer) error {
		if err := resourceTemplate.ExecuteTemplate(w, "head", params); err != nil {
			return fmt.Errorf("rendering resource %q: %w", m.Name, err)
		}
		if p.secrets == nil {
			if err := resourceTemplate.ExecuteTemplate(w, "noAuth", params); err != nil {
				return fmt.Errorf("rendering resource %q: %w", m.Name, err)
			}
		} else {
			if err := resourceTemplate.ExecuteTemplate(w, "authOpen", params); err != nil {
				return fmt.Errorf("rendering resource %q: %w", m.Name, err)
			}
			if err := p.writeSharedSecret(ctx, m.Name, w); err != nil {
				return err
			}
			if err := resourceTemplate.ExecuteTemplate(w, "authClose", params); err != nil {
				return fmt.Errorf("rendering resource %q: %w", m.Name, err)
			}
		}
		if err := resourceTemplate.ExecuteTemplate(w, "tail", params); err != nil {
			return fmt.Errorf("rendering resource %q: %w", m.Name, err)
		}
		return nil
	})
}

// resourceParams builds and re-validates the rendering input.
//
// Belt and braces: the fields are validated before they reach here, but a
// future caller that forgets should get a failure rather than a resource file
// with an injected block in it.
func (p *Provider) resourceParams(m *resourceMeta) (resourceParams, error) {
	params := resourceParams{
		HMACAlg:                sharedSecretHash,
		UnauthenticatedSetting: SettingAllowUnauthenticatedPeers,

		Name:        m.Name,
		Generated:   m.CreatedAt.UTC().Format(time.RFC3339),
		Minor:       m.Minor,
		VG:          p.cfg.VG,
		LV:          m.LV,
		NodeName:    p.cfg.NodeName,
		NodeID:      p.cfg.NodeID,
		NodeAddress: formatAddress(p.cfg.NodeAddress, m.Port),
		PeerNode:    p.cfg.PeerNode,
		PeerNodeID:  p.cfg.PeerNodeID,
		PeerAddress: formatAddress(p.cfg.PeerAddress, m.Port),
	}
	for field, value := range map[string]string{
		"name": params.Name, "volume group": params.VG, "logical volume": params.LV,
	} {
		if err := validateName(field, value); err != nil {
			return resourceParams{}, err
		}
	}
	for field, value := range map[string]string{
		SettingNodeName: params.NodeName, SettingPeerNode: params.PeerNode,
	} {
		if err := validateHostname(field, value); err != nil {
			return resourceParams{}, err
		}
	}
	return params, nil
}

// resourceMeta is what this provider records about a volume it provisioned.
//
// It lives in StateDir rather than in the resource file because the resource
// file belongs to DRBD: it is globbed by drbd.conf, parsed by drbdadm, and has
// no room for the volume's requested size, filesystem or labels. The record is
// also the provider's answer to "does this volume exist" — its presence is what
// separates common.ErrNotFound from a real lookup.
type resourceMeta struct {
	// Name is the volume ID, the DRBD resource name and the LV name.
	Name string `json:"name"`

	// LV is the backing logical volume name. It equals Name today; it is
	// recorded separately so a future naming change does not orphan volumes
	// provisioned before it.
	LV string `json:"lv"`

	// VG is the volume group the backing LV was carved from.
	VG string `json:"vg"`

	// SizeBytes is the USABLE capacity the volume was provisioned or resized to
	// — common.VolumeSpec.SizeBytes as the caller gave it, in the units that
	// field defines. It is NOT the size of the backing logical volume, which is
	// larger by the LUKS2 header on an encrypted provider (dataBytes), larger
	// by DRBD's internal metadata (backingBytes) and larger again by LVM's
	// rounding up to the volume group's extent size.
	//
	// Every comparison against this field is therefore in usable bytes and
	// every comparison against an lv_size is in backing bytes; the two are
	// converted through backingBytes and never mixed. Status reports the DRBD
	// device's real size brought back to usable through usableBytes.
	SizeBytes int64 `json:"size_bytes"`

	// FSType is the filesystem recorded for the volume, or empty for a raw
	// device. Mount uses it when MountOptions.FSType does not override it.
	FSType string `json:"fs_type,omitempty"`

	// FSGrowPending records that the device reached SizeBytes while the
	// filesystem on it could not be reached from this node's state — a
	// Resize, or a restore that grew, run while the volume was Secondary,
	// where DRBD will not open the device and an encrypted volume's container
	// is closed. The device half of a resize is done and recorded; this says
	// the filesystem half is owed, and Mount pays it: once the volume is
	// mounted both filesystems this package manages grow online, resize2fs
	// without a check and xfs_growfs by its only route.
	//
	// IT IS THIS NODE'S BOOKKEEPING, NOT THE PAIR'S. The filesystem is
	// replicated and the record is not, so the peer may have grown the
	// filesystem online after this node's Resize deferred it — the ordinary
	// order, Secondary first and then the mounted Primary. That is why the
	// debt is paid with an ONLINE grow that is idempotent and cheap when there
	// is nothing to do, and never with the offline route, which begins with a
	// forced e2fsck of the whole filesystem: a flag that can over-report must
	// not cost a full check each time it does.
	//
	// It is absent from a record that owes nothing, so a record written before
	// this field existed reads as owing nothing — which is what such a record
	// was promised: its filesystem is grown by the next Resize from the
	// Primary, as before.
	FSGrowPending bool `json:"fs_grow_pending,omitempty"`

	// Minor is the DRBD device minor, which fixes the device path.
	Minor int `json:"minor"`

	// Port is the TCP port the resource replicates over.
	Port int `json:"port"`

	// Labels is the caller's metadata from the VolumeSpec.
	Labels map[string]string `json:"labels,omitempty"`

	// CreatedAt is when the volume was provisioned.
	CreatedAt time.Time `json:"created_at"`

	// Incomplete marks a record written to reserve Minor and Port while the
	// volume is still being built, before its backing device, resource file and
	// DRBD metadata exist.
	//
	// The reservation has to be visible to the allocator — that is the whole
	// reason the record is written first — but the half-built volume must not
	// be visible to anything else, or a concurrent Status would report a volume
	// that is not there and a concurrent Mount would run commands against a
	// device that has not been created. loadMeta therefore hides an incomplete
	// record, while listMeta counts it.
	//
	// It is absent from a finished record, so a record written before this
	// field existed reads as complete.
	Incomplete bool `json:"incomplete,omitempty"`
}

// metaPath is where a volume's record lives.
func (p *Provider) metaPath(name string) string {
	return filepath.Join(p.cfg.StateDir, name+".json")
}

// resPath is where a volume's DRBD resource file is installed. The .res suffix
// is what drbd.conf's include glob matches, which is why nothing else this
// provider writes goes into ConfigDir.
func (p *Provider) resPath(name string) string {
	return filepath.Join(p.cfg.ConfigDir, name+".res")
}

// loadMeta reads the record of a volume that has finished being provisioned.
//
// It returns common.ErrNotFound both when there is no record and when the one
// there is still marked Incomplete: from any caller's point of view a volume
// whose Provision has not returned does not exist yet.
func (p *Provider) loadMeta(name string) (resourceMeta, error) {
	m, err := p.readMeta(name)
	if err != nil {
		return resourceMeta{}, err
	}
	if m.Incomplete {
		return resourceMeta{}, fmt.Errorf("volume %q is still being provisioned: %w", name, common.ErrNotFound)
	}
	return m, nil
}

// readMeta reads a volume's record whether or not it is complete. Provision
// uses it to detect a name already claimed, and Delete to clean up after a
// provision that did not finish. It returns common.ErrNotFound, wrapped, when
// there is no record.
func (p *Provider) readMeta(name string) (resourceMeta, error) {
	data, err := os.ReadFile(p.metaPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return resourceMeta{}, fmt.Errorf("volume %q: %w", name, common.ErrNotFound)
		}
		return resourceMeta{}, fmt.Errorf("reading state for volume %q: %w", name, err)
	}
	var m resourceMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return resourceMeta{}, fmt.Errorf("parsing state for volume %q: %w", name, err)
	}
	// A record describes a logical volume in the volume group it names, and
	// every path that acts on one builds "<configured vg>/<lv>" from the
	// CURRENT configuration. Let those two disagree and the record stops
	// describing what the operation will touch: a state directory carried
	// across a volume_group change, or copied between configurations, aims
	// Delete's lvremove at a same-named volume in the new group — destroying
	// something this provider never created while leaving the real volume
	// behind. Mount, Resize, Snapshot and the restore copy all read the same
	// way.
	//
	// Honoring the RECORDED group instead would be worse, not better: this
	// provider's own lvs listing covers only the configured group, so the
	// allocator and every listing would describe one group while the
	// destructive paths worked in another. Refusing keeps them describing the
	// same node and puts the misconfiguration in front of a human, which is the
	// only place it can actually be resolved. It also gives resourceMeta.VG a
	// job; until now it was written and never read.
	if m.VG != p.cfg.VG {
		return resourceMeta{}, fmt.Errorf(
			"state record %s describes volume group %q but this provider is configured for %q; "+
				"refusing to act on it — point the provider at the recorded group or remove the record by hand",
			p.metaPath(name), m.VG, p.cfg.VG)
	}
	return m, nil
}

// listMeta reads every volume record in StateDir.
//
// A record that cannot be read or parsed FAILS the call. That is the opposite
// of tolerating it, and deliberately so: the only caller is minor and port
// allocation, whose entire job is to avoid handing out a number something else
// already holds. A skipped record is a volume the allocator cannot see, and the
// resource or logical volume it describes is still out there — so the next
// Provision can hand a new volume a device minor or a replication port that a
// live resource is using, and two resources fighting over one minor is not a
// failure that announces itself.
//
// Refusing to provision until somebody looks at the state directory is the
// cheaper outcome. A file that is not a record at all — anything without the
// .json suffix — is not a corrupt record and is ignored.
func (p *Provider) listMeta() ([]resourceMeta, error) {
	entries, err := os.ReadDir(p.cfg.StateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing state directory %q: %w", p.cfg.StateDir, err)
	}
	var out []resourceMeta
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// readMeta, not loadMeta: a reservation for a volume still being built
		// is exactly what the allocator must not hand out twice.
		name := strings.TrimSuffix(e.Name(), ".json")
		m, err := p.readMeta(name)
		if err != nil {
			return nil, fmt.Errorf("state record for %q is unreadable, so allocation cannot tell what is already in use: %w", name, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// writeMeta installs a volume's record atomically.
func (p *Provider) writeMeta(m *resourceMeta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state for volume %q: %w", m.Name, err)
	}
	return writeFileAtomic(p.metaPath(m.Name), append(data, '\n'), 0o600)
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory, so a reader — drbdadm globbing ConfigDir, or this provider
// listing StateDir — never sees a half-written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomicFunc(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// writeFileAtomicFunc is the same, for content that must be streamed rather
// than handed over as a slice.
//
// fn receives the FILE, unbuffered and on purpose: a bufio.Writer would copy
// what it is given onto the heap, which is exactly what the shared secret must
// not have happen to it. Every Write here is a syscall against the caller's
// bytes.
//
// The three Close calls on the failure paths, and the Remove in the defer, are
// deliberately unchecked: each runs on a path that is already returning the
// error that matters, and a close or unlink failure there would displace it
// with something less useful. The calls that decide whether the write actually
// landed — Sync, the Close on the success path, and Rename — are all checked.
func writeFileAtomicFunc(path string, perm os.FileMode, fn func(w io.Writer) error) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("creating temporary file in %q: %w", dir, err)
	}
	tmp := f.Name()
	defer func() {
		// Harmless once the rename has happened: the name no longer exists.
		_ = os.Remove(tmp)
	}()

	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return fmt.Errorf("setting mode on %q: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("syncing %q: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("installing %q: %w", path, err)
	}
	// The rename is atomic but not durable. Until the containing directory is
	// synced the new entry can exist only in the page cache, so a crash after
	// this function reported success can leave the file absent — the file whose
	// contents were carefully fsynced a few lines up.
	//
	// A failure here is an error, not a warning. Both files this writes are
	// things later code trusts to still be there: the resource file is what
	// drbdadm needs to take a resource down, and the state record is what
	// reserves a minor and a port — the reservation a failed rollback now
	// deliberately keeps. A reservation that does not survive a crash is a
	// reservation that has stopped protecting anything, and reporting success
	// would be promising durability this has not established.
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("syncing directory %q after installing %q: %w", dir, path, err)
	}
	return nil
}

// syncDir flushes a directory's own entries to disk, which is what makes a
// rename into it survive a crash.
//
// It is a variable solely so the tests can make the step fail; nothing in the
// package replaces it.
var syncDir = func(dir string) error {
	// #nosec G304 -- dir is the directory of a path this package built, which is
	// StateDir or the drbd.d directory from operator configuration joined with
	// an allowlist-validated resource name; it is opened to fsync it and never
	// read.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

// allocate picks the lowest free device minor and TCP port at or above the
// configured bases, given the volumes already recorded.
//
// The record in StateDir is the only input: this provider owns the range, and a
// minor or port inside it that belongs to something else is a deployment
// mistake the bases exist to avoid. Reading the live drbdsetup status instead
// would make provisioning depend on the kernel module being loaded and would
// still miss resources that are configured but down.
func allocate(existing []resourceMeta, minorBase, portBase int) (minor, port int, err error) {
	usedMinor := make(map[int]struct{}, len(existing))
	usedPort := make(map[int]struct{}, len(existing))
	for i := range existing {
		usedMinor[existing[i].Minor] = struct{}{}
		usedPort[existing[i].Port] = struct{}{}
	}

	minor = -1
	for c := minorBase; c <= maxMinor; c++ {
		if _, taken := usedMinor[c]; !taken {
			minor = c
			break
		}
	}
	if minor < 0 {
		return 0, 0, fmt.Errorf("no free device minor at or above %d", minorBase)
	}

	port = -1
	for c := portBase; c <= maxPort; c++ {
		if _, taken := usedPort[c]; !taken {
			port = c
			break
		}
	}
	if port < 0 {
		return 0, 0, fmt.Errorf("no free replication port at or above %d", portBase)
	}

	return minor, port, nil
}

// Sizing constants for DRBD 9 internal metadata.
const (
	// sectorBytes is the 512-byte sector DRBD's metadata arithmetic is in.
	sectorBytes = 512

	// bitmapUnitSectors is how much data one bitmap allocation unit covers:
	// 2^18 sectors, or 128 MiB, tracked by 8 sectors of bitmap per peer.
	bitmapUnitSectors = 1 << 18

	// bitmapSectorsPerUnit is those 8 sectors.
	bitmapSectorsPerUnit = 8

	// superblockSectors is the 36 KiB DRBD reserves for the superblock and the
	// activity log, independent of the device size.
	superblockSectors = 72

	// drbdPeers is the number of peers a resource generated here has, and so
	// the number of bitmap slots its metadata holds. The template writes
	// exactly two hosts, which is one peer.
	drbdPeers = 1
)

// metadataBytes is the space DRBD 9 reserves for internal metadata on a backing
// device holding dataBytes of data.
//
// It is this backend's half of the contract on common.VolumeSpec.SizeBytes:
// that field is the capacity the CALLER CAN USE, and a provider with per-volume
// overhead of its own allocates that overhead ON TOP rather than taking it out
// of what was asked for. "meta-disk internal" puts the metadata at the END of
// the backing device, so a backing volume created at exactly the requested size
// would export a DRBD device smaller than the caller asked for. Provision
// therefore adds this on top, and the caller gets the capacity in the spec.
//
// pkg/local implements the same contract against a LUKS2 header; see
// luksHeaderBytes there. This package now does too: on an encrypted provider
// the header is added on top of the request FIRST, giving the data area DRBD
// exports (dataBytes), and this reservation is computed from that data area —
// the bitmap covers the header's blocks like any others. The two backends
// differ in what the overhead IS and agree on which side of the request it
// falls.
//
// The size follows DRBD's own formula, in sectors:
//
//	M = ceil(C / 2^18) * 8 * peers + 72
//
// where C is the data area in sectors — one bit of bitmap per 4 KiB of data
// per peer, plus the fixed superblock and activity log. The division rounds up
// by a whole unit rather than exactly, because C is the data area of the
// finished device and this is computed from the requested size, which is
// fractionally smaller. Over-reserving by 4 KiB per peer costs nothing next to
// LVM's 4 MiB extent rounding; under-reserving would truncate the volume.
func metadataBytes(dataBytes int64) int64 {
	dataSectors := (dataBytes + sectorBytes - 1) / sectorBytes
	units := dataSectors/bitmapUnitSectors + 1
	sectors := units*bitmapSectorsPerUnit*drbdPeers + superblockSectors
	return sectors * sectorBytes
}

// dataBytes is the DRBD data area — the size of the device DRBD exports — that
// yields usableBytes of capacity the caller can write to.
//
// On a plain provider the two are the same number. On an encrypted one the
// LUKS2 container sits INSIDE the DRBD device, so the device has to hold the
// container's header as well as the caller's data, and the header is allocated
// on top of the request like every other overhead in this package. Status
// reverses this when it reads the device's size back; see usableBytes.
//
// It is unchecked, like backingBytes, for the hot path once a size is known
// representable; backingBytesChecked guards the addition.
func dataBytes(usableBytes int64, encrypted bool) int64 {
	if !encrypted {
		return usableBytes
	}
	return usableBytes + luks.HeaderBytes
}

// usableBytes is dataBytes inverted: the capacity a caller can write to on a
// DRBD device of the given size. It is what Status reports for a device it has
// measured, and what a size read back from DRBD has to go through before it
// is compared against anything in a VolumeSpec's units.
//
// A device on an encrypted provider that is not even a header long cannot be
// one this provider sized, and the caller sees an error rather than a zero or
// negative capacity — an invented number is the failure this package refuses
// to report.
func usableBytes(deviceBytes int64, encrypted bool) (int64, error) {
	if !encrypted {
		return deviceBytes, nil
	}
	if deviceBytes <= luks.HeaderBytes {
		return 0, fmt.Errorf("DRBD device is %d bytes, no larger than the %d-byte LUKS2 header an encrypted volume carries, so it holds no usable capacity", deviceBytes, int64(luks.HeaderBytes))
	}
	return deviceBytes - luks.HeaderBytes, nil
}

// backingBytes is the backing volume size that yields usableBytes of capacity
// the caller can write to — the conversion from the units
// common.VolumeSpec.SizeBytes is in to the units an lv_size is in: the data
// area (usable plus, on an encrypted provider, the LUKS2 header) plus DRBD's
// metadata for that data area. Every size comparison in this package goes
// through it rather than mixing the two.
func backingBytes(usableBytes int64, encrypted bool) int64 {
	data := dataBytes(usableBytes, encrypted)
	return data + metadataBytes(data)
}

// backingBytesChecked is backingBytes with its intermediate arithmetic guarded
// against int64 overflow: ok is false when a step would wrap. A signed overflow
// in Go wraps rather than trapping, so an unchecked backingBytes near
// math.MaxInt64 comes back NEGATIVE — a backing size smaller than the data it is
// supposed to hold, which then reads as a SHRINK everywhere a size is compared.
//
// It is the predicate the size bounds below binary-search and the check the
// validators call before committing to a caller-controlled size. The unchecked
// backingBytes stays for the hot path, once a size is known representable.
func backingBytesChecked(usableBytes int64, encrypted bool) (int64, bool) {
	if usableBytes < 0 {
		return 0, false
	}
	// The header addition is the first step that can wrap on an encrypted
	// provider, before the metadata step below ever sees the data area; an
	// unguarded wrap here would hand metadataBytes a NEGATIVE data area.
	if encrypted && usableBytes > math.MaxInt64-luks.HeaderBytes {
		return 0, false
	}
	data := dataBytes(usableBytes, encrypted)
	// metadataBytes rounds the data area up to a whole sector first, and that
	// addition is the next step that can wrap. Once it is safe, everything
	// downstream of it is: the bitmap math divides down before it multiplies
	// back up, so metadataBytes itself cannot overflow for any data area this
	// far below the ceiling.
	if data > math.MaxInt64-(sectorBytes-1) {
		return 0, false
	}
	meta := metadataBytes(data)
	if data > math.MaxInt64-meta {
		return 0, false
	}
	return data + meta, true
}

// maxRoundableBytes is the largest byte count roundUpTo can take for a given
// extent without the addition inside it overflowing. It mirrors the bound the
// local provider guards against; a value past it wraps NEGATIVE. An extent of
// one or less rounds nothing, so the whole range is roundable.
func maxRoundableBytes(extent int64) int64 {
	if extent <= 1 {
		return math.MaxInt64
	}
	return math.MaxInt64 - (extent - 1)
}

// maxDataBytes is the largest USABLE capacity whose backing size stays
// representable as an int64: the data area, plus DRBD's internal metadata, then
// rounded up to a whole extent of the volume group. Past it, backingBytes — or
// the extent rounding layered on top of it — wraps NEGATIVE, and a negative
// backing target reads as a SHRINK: resizeLocked then finds the backing volume
// already "larger" than the target, skips lvextend and the drbdadm resize that
// follows it, and records the fabricated size as reached. The next legitimate
// grow is refused against that recorded size. A caller that asks for more than
// this bound gets common.ErrInvalidArgument naming it, because a size that has
// no representable backing is malformed input, not an operation some other
// backend could serve.
//
// Pass extent <= 0 where the caller does no rounding of its own — lvcreate
// rounds internally, so only the metadata addition is bounded there. On an
// encrypted provider the bound is one LUKS2 header lower, since the header is
// part of the data area the metadata and the rounding are computed over.
//
// backingBytes and roundUpTo are both monotonic non-decreasing, so the
// representable capacities form a prefix [0, max] and a binary search finds its
// top exactly, without inverting metadataBytes's nested ceilings by hand.
func maxDataBytes(extent int64, encrypted bool) int64 {
	limit := maxRoundableBytes(extent)
	lo, hi := int64(0), int64(math.MaxInt64)
	for lo < hi {
		// Bias the midpoint upward so the search converges on the last value that
		// satisfies the predicate. Written as hi-(hi-lo)/2 rather than
		// lo+(hi-lo+1)/2 because the +1 there overflows when the range is the
		// whole int64 axis (lo 0, hi math.MaxInt64), which is exactly the extent
		// <= 0 case.
		mid := hi - (hi-lo)/2
		if b, ok := backingBytesChecked(mid, encrypted); ok && b <= limit {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// devicePath is the block device a resource's volume appears at.
//
// The minor is used rather than the /dev/drbd/by-res/<name>/0 symlink because
// the minor is recorded by this provider and the symlink is created by udev:
// the device node exists as soon as the resource is up, while the symlink
// depends on a udev rule being installed and a uevent being processed.
func devicePath(minor int) string {
	return fmt.Sprintf("/dev/drbd%d", minor)
}
