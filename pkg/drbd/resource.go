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

// resourceTemplate renders a per-volume DRBD resource file from typed integers and allowlisted strings; protocol C only.
// It is split around the shared secret, whose bytes are written from the enclave straight to the file.
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

// writeResourceFile renders a volume's resource file straight to disk, 0600, writing the secret from inside the enclave borrow.
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

// resourceMeta is what this provider records about a volume it provisioned, in StateDir; its presence means the volume exists.
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

// loadMeta reads a finished volume's record; missing or incomplete is common.ErrNotFound.
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

// readMeta reads a volume's record whether or not it is complete; common.ErrNotFound, wrapped, when absent.
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
	// A record naming a volume group other than the configured one is refused, so destructive paths never act on a same-named LV elsewhere.
	if m.VG != p.cfg.VG {
		return resourceMeta{}, fmt.Errorf(
			"state record %s describes volume group %q but this provider is configured for %q; "+
				"refusing to act on it — point the provider at the recorded group or remove the record by hand",
			p.metaPath(name), m.VG, p.cfg.VG)
	}
	return m, nil
}

// listMeta reads every volume record in StateDir; an unreadable record fails the call, non-.json files are ignored.
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

// writeFileAtomicFunc streams content to the unbuffered file; Sync, the final Close and Rename are checked.
func writeFileAtomicFunc(path string, perm os.FileMode, fn func(w io.Writer) error) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("creating temporary file in %q: %w", dir, err)
	}
	tmp := f.Name()
	defer func() {
		// Harmless once the rename has happened.
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
	// Sync the directory so the rename survives a crash; a failure is an error.
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("syncing directory %q after installing %q: %w", dir, path, err)
	}
	return nil
}

// syncDir flushes a directory's entries to disk; a variable so tests can make it fail.
var syncDir = func(dir string) error {
	// #nosec G304 -- dir is a directory this package built from configuration and a validated name; opened only to fsync.
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

// allocate picks the lowest free minor and port at or above the configured bases, from the StateDir records.
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

// metadataBytes is the internal metadata DRBD 9 reserves for dataBytes of data, added on top of the request:
//
//	M = ceil(C / 2^18) * 8 * peers + 72 sectors, C the data area in sectors, rounded up by a whole unit.
func metadataBytes(dataBytes int64) int64 {
	dataSectors := (dataBytes + sectorBytes - 1) / sectorBytes
	units := dataSectors/bitmapUnitSectors + 1
	sectors := units*bitmapSectorsPerUnit*drbdPeers + superblockSectors
	return sectors * sectorBytes
}

// dataBytes is the DRBD device size that yields usableBytes; on an encrypted provider it adds the LUKS2 header.
func dataBytes(usableBytes int64, encrypted bool) int64 {
	if !encrypted {
		return usableBytes
	}
	return usableBytes + luks.HeaderBytes
}

// usableBytes inverts dataBytes; a device smaller than the header is an error.
func usableBytes(deviceBytes int64, encrypted bool) (int64, error) {
	if !encrypted {
		return deviceBytes, nil
	}
	if deviceBytes <= luks.HeaderBytes {
		return 0, fmt.Errorf("DRBD device is %d bytes, no larger than the %d-byte LUKS2 header an encrypted volume carries, so it holds no usable capacity", deviceBytes, int64(luks.HeaderBytes))
	}
	return deviceBytes - luks.HeaderBytes, nil
}

// backingBytes converts usable capacity to backing LV size: data area plus DRBD metadata.
func backingBytes(usableBytes int64, encrypted bool) int64 {
	data := dataBytes(usableBytes, encrypted)
	return data + metadataBytes(data)
}

// backingBytesChecked is backingBytes with int64 overflow detected (ok false), for caller-controlled sizes.
func backingBytesChecked(usableBytes int64, encrypted bool) (int64, bool) {
	if usableBytes < 0 {
		return 0, false
	}
	// The header addition can wrap first.
	if encrypted && usableBytes > math.MaxInt64-luks.HeaderBytes {
		return 0, false
	}
	data := dataBytes(usableBytes, encrypted)
	// Rounding up to a sector can wrap next; nothing after it can.
	if data > math.MaxInt64-(sectorBytes-1) {
		return 0, false
	}
	meta := metadataBytes(data)
	if data > math.MaxInt64-meta {
		return 0, false
	}
	return data + meta, true
}

// maxRoundableBytes is the largest count roundUpTo can take for extent without overflow.
func maxRoundableBytes(extent int64) int64 {
	if extent <= 1 {
		return math.MaxInt64
	}
	return math.MaxInt64 - (extent - 1)
}

// maxDataBytes is the largest usable capacity whose rounded backing size fits an int64; larger requests are common.ErrInvalidArgument. Found by binary search; extent <= 0 means no rounding.
func maxDataBytes(extent int64, encrypted bool) int64 {
	limit := maxRoundableBytes(extent)
	lo, hi := int64(0), int64(math.MaxInt64)
	for lo < hi {
		// Bias the midpoint up; hi-(hi-lo)/2 cannot overflow over the whole int64 range.
		mid := hi - (hi-lo)/2
		if b, ok := backingBytesChecked(mid, encrypted); ok && b <= limit {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// devicePath is /dev/drbd<minor>, which exists as soon as the resource is up.
func devicePath(minor int) string {
	return fmt.Sprintf("/dev/drbd%d", minor)
}
