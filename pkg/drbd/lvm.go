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

// snapSeparator joins a volume and snapshot name into one LV name; names cannot contain it.
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

// snapshotID renders the caller-facing snapshot ID, including the volume group.
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

// originSizeBytes parses origin_size, a backing size (DRBD metadata included); empty for a non-snapshot LV.
func (e *lvEntry) originSizeBytes() int64 { return parseLVMInt(e.OriginSize) }

// usedBytes is the space a CoW snapshot occupies: its CoW area times data_percent; 0 for an inactive snapshot, an error for an unreadable active one.
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

// parseLVMPercent reads data_percent, refusing anything but a finite percentage from 0 to 100.
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

// extentSizeBytes parses vg_extent_size, the volume group's allocation unit.
func (e *lvEntry) extentSizeBytes() int64 { return parseLVMInt(e.ExtentSize) }

// roundUpTo rounds n up to the next multiple of unit. A unit of zero or less
// means the granularity is unknown, and n is returned unchanged.
func roundUpTo(n, unit int64) int64 {
	if unit <= 0 {
		return n
	}
	return (n + unit - 1) / unit * unit
}

// parseLVMInt reads a byte count from an lvs field, dropping any decimal fraction and parsing the integer exactly.
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

// lvmTimeLayouts are the shapes lv_time takes; an unmatched value yields the zero time.
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

// lvActivate gives a logical volume a device node; --yes answers lvchange's prompt.
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
