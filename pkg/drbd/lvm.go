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
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// The LVM tooling this provider execs. Named as constants so the fake runner in
// the tests and the argv built here cannot drift apart.
const (
	binLVCreate = "lvcreate"
	binLVRemove = "lvremove"
	binLVExtend = "lvextend"
	binLVS      = "lvs"
	binLVChange = "lvchange"
)

// snapSeparator joins a volume name and a snapshot name into one LV name.
//
// The dot is excluded from the name allowlist precisely so that this
// decomposition is unambiguous: neither half can contain the separator, so
// splitting on it recovers exactly the two names that went in.
const snapSeparator = ".snap."

// snapshotLV builds the backing LV name for a snapshot.
func snapshotLV(volLV, snapName string) string {
	return volLV + snapSeparator + snapName
}

// splitSnapshotLV recovers the volume and snapshot names from an LV name, and
// reports whether the name has the shape this provider creates. An LV in the
// volume group that does not is somebody else's and is left alone.
func splitSnapshotLV(lv string) (volLV, snapName string, ok bool) {
	volLV, snapName, ok = strings.Cut(lv, snapSeparator)
	if !ok || volLV == "" || snapName == "" {
		return "", "", false
	}
	// A second separator means the name is ambiguous; the allowlist forbids it,
	// so such an LV was not created here.
	if strings.Contains(snapName, snapSeparator) {
		return "", "", false
	}
	return volLV, snapName, true
}

// snapshotID renders the caller-facing snapshot identifier. It carries the
// volume group so the identifier says which pool it belongs to and a provider
// pointed at a different group can reject it instead of acting on a name that
// happens to exist locally.
func (p *Provider) snapshotID(volLV, snapName string) string {
	return p.cfg.VG + "/" + snapshotLV(volLV, snapName)
}

// parseSnapshotID is the inverse of snapshotID.
func (p *Provider) parseSnapshotID(id string) (volLV, snapName string, err error) {
	vg, lv, ok := strings.Cut(id, "/")
	if !ok {
		return "", "", fmt.Errorf("%w: snapshot id %q must be \"<vg>/<lv>\"", common.ErrInvalidArgument, id)
	}
	if vg != p.cfg.VG {
		return "", "", fmt.Errorf("%w: snapshot id %q names volume group %q, this provider manages %q", common.ErrInvalidArgument, id, vg, p.cfg.VG)
	}
	volLV, snapName, ok = splitSnapshotLV(lv)
	if !ok {
		return "", "", fmt.Errorf("%w: snapshot id %q is not in \"<vg>/<volume>%s<name>\" form", common.ErrInvalidArgument, id, snapSeparator)
	}
	if err := validateName("volume name", volLV); err != nil {
		return "", "", err
	}
	if err := validateName("snapshot name", snapName); err != nil {
		return "", "", err
	}
	return volLV, snapName, nil
}

// lvReport models "lvs --reportformat json". LVM emits every field as a string
// in that format, including the numeric ones, so they are parsed here rather
// than by the JSON decoder.
type lvReport struct {
	Report []struct {
		LV []lvEntry `json:"lv"`
	} `json:"report"`
}

type lvEntry struct {
	Name        string `json:"lv_name"`
	VG          string `json:"vg_name"`
	Size        string `json:"lv_size"`
	Origin      string `json:"origin"`
	OriginSize  string `json:"origin_size"`
	Time        string `json:"lv_time"`
	Attr        string `json:"lv_attr"`
	ExtentSize  string `json:"vg_extent_size"`
	DataPercent string `json:"data_percent"`
}

// sizeBytes parses lv_size, which "--units b --nosuffix" renders as a plain
// byte count.
func (e *lvEntry) sizeBytes() int64 { return parseLVMInt(e.Size) }

// originSizeBytes parses origin_size: for a snapshot, the size of the volume it
// was taken from, which is the size a restore has to accommodate. It is empty
// for a non-snapshot LV.
//
// It is a BACKING size, DRBD's internal metadata included, because the volume
// it measures is one this provider created at backingBytes(...) and LVM then
// rounded up. That is what makes it comparable against a restore's own
// backingBytes figure and NOT against a caller's common.VolumeSpec.SizeBytes,
// which is usable capacity.
func (e *lvEntry) originSizeBytes() int64 { return parseLVMInt(e.OriginSize) }

// usedBytes is the space a copy-on-write snapshot currently OCCUPIES: its CoW
// area scaled by how much of that area has been written.
//
// That is what SnapshotInfo.SizeBytes is defined as, and it is not lv_size.
// lv_size is the CoW area this provider allocated — a fixed share of the origin
// — and reporting it would tell a caller that a snapshot taken a second ago
// already occupies twenty percent of its origin.
//
// It is 0 for an INACTIVE snapshot, which is what this provider leaves them as.
// LVM reports occupancy only while the kernel has the device mapped, and the
// figure is not worth activating a snapshot to obtain — activating one activates
// its origin too, which would move a volume the caller is using. Measured on
// LVM 2.03.16 by the local lane: an inactive snapshot reports data_percent
// empty as its ordinary state, so an empty field there is a real answer and not
// a missing one. pkg/local reports the same 0 for the same reason, and the two
// providers implement one contract; a snapshot listing that failed here and
// succeeded there for identical volumes would make SnapshotInfo.SizeBytes mean
// something different depending on which provider produced it.
//
// Empty on an ACTIVE snapshot is a different matter and is an error: the kernel
// has a figure and lvs failed to render it. So is a value that is malformed,
// negative, or above 100 — those are not measurements this provider can pass
// off as one. Returning 0 for them would put a plausible-looking number where an
// unreadable one was, and callers size restores and report occupancy from it.
func (e *lvEntry) usedBytes() (int64, error) {
	raw := strings.TrimSpace(e.DataPercent)
	if raw == "" {
		if e.isSnapshot() && e.active() {
			return 0, fmt.Errorf("lvs reported no data_percent for active snapshot %s/%s", e.VG, e.Name)
		}
		return 0, nil
	}
	pct, err := parseLVMPercent(raw)
	if err != nil {
		return 0, fmt.Errorf("lvs reported data_percent %q for %s/%s: %w", e.DataPercent, e.VG, e.Name, err)
	}
	return int64(float64(e.sizeBytes()) * pct / 100), nil
}

// active reports whether the logical volume is active on this host. The fifth
// character of lv_attr is the state field, where 'a' means active.
func (e *lvEntry) active() bool { return len(e.Attr) >= 5 && e.Attr[4] == 'a' }

// isSnapshot reports whether the logical volume is a snapshot of another.
func (e *lvEntry) isSnapshot() bool { return e.Origin != "" }

// parseLVMPercent reads the data_percent column, refusing anything that is not
// a finite percentage between 0 and 100.
//
// Unlike the byte counts the fraction here is the point, so this cannot reuse
// parseLVMInt's tolerance for trailing formatting. It refuses rather than
// coercing, for the reason pkg/local's parseLVNumber gives: the zero value on a
// parse failure puts a plausible-looking number where an unreadable one was, and
// occupancy is reported to callers as a measurement rather than a hint.
func parseLVMPercent(s string) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, errors.New("not a number")
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, errors.New("not finite")
	}
	if v < 0 {
		return 0, errors.New("negative")
	}
	if v > 100 {
		return 0, errors.New("above 100")
	}
	return v, nil
}

// extentSizeBytes parses vg_extent_size: the allocation unit of the volume
// group, which every logical volume's size is a whole multiple of. It is
// reported alongside each LV rather than fetched separately, so no extra
// command is needed to know what a size will be rounded to.
func (e *lvEntry) extentSizeBytes() int64 { return parseLVMInt(e.ExtentSize) }

// roundUpTo rounds n up to the next multiple of unit. A unit of zero or less
// means the granularity is unknown, and n is returned unchanged.
func roundUpTo(n, unit int64) int64 {
	if unit <= 0 {
		return n
	}
	return (n + unit - 1) / unit * unit
}

// parseLVMInt reads a byte count out of an lvs report field.
//
// "--units b --nosuffix" is asked for, but what comes back is not reliably a
// bare integer: LVM formats report sizes to two decimal places by default, so
// the same column reads "1073741824" on one build and "1073741824.00" on
// another, and some configurations still pad the field with spaces. A byte
// count has no meaningful fraction, so the part before the decimal point is the
// answer and the rest is formatting.
//
// The fraction is dropped rather than rounded, and the integer part is parsed
// exactly rather than through a float, which would start losing byte precision
// at 8 PiB.
func parseLVMInt(s string) int64 {
	s = strings.TrimSpace(s)
	// A stray unit suffix, if --nosuffix was not honored.
	s = strings.TrimSuffix(s, "B")
	s = strings.TrimSuffix(s, "b")
	if whole, _, found := strings.Cut(s, "."); found {
		s = whole
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// lvmTimeLayouts are the shapes lv_time takes. LVM formats it with the local
// zone offset by default and with a named zone under some locales; a value that
// matches neither yields the zero time rather than an error, because a
// snapshot's timestamp is reporting detail and not worth failing a list over.
var lvmTimeLayouts = []string{
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05 MST",
	time.RFC3339,
}

func (e *lvEntry) createdAt() time.Time {
	s := strings.TrimSpace(e.Time)
	for _, layout := range lvmTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// lvsFields is the column set every lvs call in this package asks for.
const lvsFields = "lv_name,vg_name,lv_size,origin,origin_size,lv_time,lv_attr,vg_extent_size,data_percent"

// lvs reports the logical volumes in the provider's volume group.
func (p *Provider) lvs(ctx context.Context) ([]lvEntry, error) {
	out, err := p.runner.Run(ctx, binLVS,
		"--reportformat", "json",
		"--units", "b",
		"--nosuffix",
		"-o", lvsFields,
		p.cfg.VG,
	)
	if err != nil {
		return nil, fmt.Errorf("listing logical volumes in %q: %w", p.cfg.VG, err)
	}
	var rep lvReport
	if err := json.Unmarshal(out, &rep); err != nil {
		return nil, fmt.Errorf("parsing lvs report for %q: %w", p.cfg.VG, err)
	}
	var lvs []lvEntry
	for _, r := range rep.Report {
		lvs = append(lvs, r.LV...)
	}
	return lvs, nil
}

// findLV returns the named logical volume from a report.
func findLV(lvs []lvEntry, name string) (lvEntry, bool) {
	for i := range lvs {
		if lvs[i].Name == name {
			return lvs[i], true
		}
	}
	return lvEntry{}, false
}

// lvActivate gives a logical volume a device node.
//
// --yes answers the confirmation lvchange raises in the cases that prompt; it
// matches pkg/local's invocation, since both providers are activating the same
// kind of volume for the same reason.
func (p *Provider) lvActivate(ctx context.Context, lv string) error {
	if _, err := p.runner.Run(ctx, binLVChange, "--activate", "y", "--yes", p.lvRef(lv)); err != nil {
		return fmt.Errorf("activating %s: %w", p.lvRef(lv), err)
	}
	return nil
}

// lvDeactivate withdraws a logical volume's device node.
func (p *Provider) lvDeactivate(ctx context.Context, lv string) error {
	if _, err := p.runner.Run(ctx, binLVChange, "--activate", "n", "--yes", p.lvRef(lv)); err != nil {
		return fmt.Errorf("deactivating %s: %w", p.lvRef(lv), err)
	}
	return nil
}

// lvPath is the device path of a logical volume in the provider's group.
func (p *Provider) lvPath(lv string) string {
	return "/dev/" + p.cfg.VG + "/" + lv
}

// lvRef is the "<vg>/<lv>" reference the LVM tools take.
func (p *Provider) lvRef(lv string) string {
	return p.cfg.VG + "/" + lv
}

// lvCreate creates a backing logical volume of the given size.
func (p *Provider) lvCreate(ctx context.Context, lv string, sizeBytes int64) error {
	_, err := p.runner.Run(ctx, binLVCreate,
		"--yes",
		"--name", lv,
		"--size", strconv.FormatInt(sizeBytes, 10)+"b",
		p.cfg.VG,
	)
	if err != nil {
		return fmt.Errorf("creating logical volume %q: %w", p.lvRef(lv), err)
	}
	return nil
}

// lvCreateSnapshot takes a copy-on-write snapshot of a logical volume, sized as
// a percentage of the origin.
func (p *Provider) lvCreateSnapshot(ctx context.Context, originLV, snapLV string) error {
	_, err := p.runner.Run(ctx, binLVCreate,
		"--yes",
		"--snapshot",
		"--name", snapLV,
		"--extents", strconv.Itoa(p.cfg.SnapshotSizePercent)+"%ORIGIN",
		p.lvRef(originLV),
	)
	if err != nil {
		return fmt.Errorf("snapshotting logical volume %q as %q: %w", p.lvRef(originLV), snapLV, err)
	}
	return nil
}

// lvRemove deletes a logical volume.
func (p *Provider) lvRemove(ctx context.Context, lv string) error {
	_, err := p.runner.Run(ctx, binLVRemove, "--force", p.lvRef(lv))
	if err != nil {
		return fmt.Errorf("removing logical volume %q: %w", p.lvRef(lv), err)
	}
	return nil
}

// lvExtend grows a logical volume to an absolute size.
func (p *Provider) lvExtend(ctx context.Context, lv string, sizeBytes int64) error {
	_, err := p.runner.Run(ctx, binLVExtend,
		"--size", strconv.FormatInt(sizeBytes, 10)+"b",
		p.lvRef(lv),
	)
	if err != nil {
		return fmt.Errorf("extending logical volume %q: %w", p.lvRef(lv), err)
	}
	return nil
}
