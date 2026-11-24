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
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// lvFields is the -o column list requested from lvs. The parser below reads
// exactly these, so the two move together.
const lvFields = "lv_name,lv_size,lv_attr,origin,lv_time,data_percent,origin_size,lv_tags"

// lvsReport is the shape of `lvs --reportformat json`. LVM reports every value
// as a string, including the numeric ones.
type lvsReport struct {
	Report []struct {
		LV []struct {
			Name        string `json:"lv_name"`
			Size        string `json:"lv_size"`
			Attr        string `json:"lv_attr"`
			Origin      string `json:"origin"`
			Time        string `json:"lv_time"`
			DataPercent string `json:"data_percent"`
			OriginSize  string `json:"origin_size"`
			Tags        string `json:"lv_tags"`
		} `json:"lv"`
	} `json:"report"`
}

// lvInfo is one logical volume as this provider cares about it.
type lvInfo struct {
	// Name is the logical volume name, which for a provisioned volume is also
	// its volume ID and for a snapshot is also its SnapshotID.
	Name string

	// SizeBytes is the logical volume's size. For a copy-on-write snapshot this
	// is the size of the CoW area, not the size of the origin.
	SizeBytes int64

	// Attr is the lv_attr string. Its fifth character is the state field, where
	// 'a' means active.
	Attr string

	// Origin names the logical volume this one is a snapshot of, empty for a
	// volume that is not a snapshot.
	Origin string

	// CreatedAt is the creation time, zero when lvs reported it in a format
	// this parser does not recognize.
	CreatedAt time.Time

	// DataPercent is how much of a snapshot's CoW area is in use, 0 for a
	// volume that is not a snapshot.
	DataPercent float64

	// Tags are the LVM tags set on the logical volume. This provider sets one,
	// the header tag described on encryptedTagPrefix; anything else here
	// belongs to the operator or to other tooling sharing the volume group, and
	// is read past rather than touched.
	Tags []string

	// OriginSizeBytes is, on a SNAPSHOT, the size its origin had when the
	// snapshot was taken — the size of the image the snapshot presents. It is 0
	// on a volume that is not a snapshot.
	//
	// It is not the origin's current size and must not be confused with it. LVM
	// allows an origin with snapshots to be grown while it is inactive, which is
	// the state this provider leaves volumes in, so the two diverge in ordinary
	// use: measured, growing a 64 MiB origin to 192 MiB left the snapshot
	// reporting an origin_size of 67108864 while the origin's own lv_size read
	// 201326592, and the snapshot device kept presenting 64 MiB.
	OriginSizeBytes int64
}

// active reports whether the logical volume is active on this host.
func (l lvInfo) active() bool {
	return len(l.Attr) >= 5 && l.Attr[4] == 'a'
}

// luksHeaderTags returns every tag on the volume that records a LUKS header
// size. There should be at most one; LVM will happily hold several, so the
// caller decides what to do about it rather than this silently picking.
func (l lvInfo) luksHeaderTags() []string {
	var found []string
	for _, t := range l.Tags {
		if strings.HasPrefix(t, encryptedTagPrefix) {
			found = append(found, t)
		}
	}
	return found
}

// luksHeaderFromTags returns the tagged header size, distinguishing untagged from unreadable or conflicting tags.
func (l lvInfo) luksHeaderFromTags() (headerBytes int64, tagged bool, err error) {
	found := l.luksHeaderTags()
	switch len(found) {
	case 0:
		return 0, false, nil
	case 1:
		raw := strings.TrimPrefix(found[0], encryptedTagPrefix)
		size, parseErr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if parseErr != nil {
			return 0, true, fmt.Errorf("tag %q does not record a number", found[0])
		}
		if size <= 0 {
			return 0, true, fmt.Errorf("tag %q records a header of %d bytes", found[0], size)
		}
		return size, true, nil
	default:
		return 0, true, fmt.Errorf("the volume carries %d disagreeing header tags: %s",
			len(found), strings.Join(found, ", "))
	}
}

// isSnapshot reports whether the logical volume is a snapshot of another.
func (l lvInfo) isSnapshot() bool {
	return l.Origin != ""
}

// usedBytes is a snapshot's occupied CoW space, or 0 when inactive.
func (l lvInfo) usedBytes() int64 {
	return int64(float64(l.SizeBytes) * l.DataPercent / 100)
}

// lvTimeLayouts are lv_time formats; CreatedAt stays zero if none fit.
var lvTimeLayouts = []string{
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05 Z0700",
	"2006-01-02T15:04:05-0700",
	time.RFC3339,
}

// parseLVTags splits the comma-separated lv_tags column, dropping empty entries.
func parseLVTags(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	var tags []string
	for _, tag := range strings.Split(trimmed, ",") {
		if tag = strings.TrimSpace(tag); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func parseLVTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range lvTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// listLVs returns every LV in the volume group, so absence is an empty result rather than an exit code.
func (p *Provider) listLVs(ctx context.Context) ([]lvInfo, error) {
	out, err := p.runner.Run(ctx, nil, "lvs",
		"--reportformat", "json",
		"--units", "b",
		"--nosuffix",
		"-o", lvFields,
		p.volumeGroup,
	)
	if err != nil {
		return nil, fmt.Errorf("go-blockstore/local: listing logical volumes in %q: %w", p.volumeGroup, err)
	}

	var report lvsReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("go-blockstore/local: parsing lvs report: %w", err)
	}

	var infos []lvInfo
	for _, r := range report.Report {
		// Indexed rather than ranged by value: one lvs row is several strings
		// and copying each one per iteration is what gocritic's rangeValCopy is
		// about. Nothing below mutates the row.
		for i := range r.LV {
			lv := &r.LV[i]
			info := lvInfo{
				Name:      lv.Name,
				Attr:      lv.Attr,
				Origin:    lv.Origin,
				CreatedAt: parseLVTime(lv.Time),
				Tags:      parseLVTags(lv.Tags),
			}

			size, err := parseLVNumber(lv.Size)
			if err != nil {
				return nil, fmt.Errorf("go-blockstore/local: lvs reported lv_size %q for %s/%s: %w",
					lv.Size, p.volumeGroup, lv.Name, err)
			}
			info.SizeBytes = int64(size)

			// data_percent is empty for plain volumes and inactive snapshots; empty on an active snapshot is malformed.
			if raw := strings.TrimSpace(lv.DataPercent); raw != "" {
				pct, pctErr := parseLVNumber(raw)
				if pctErr != nil {
					return nil, fmt.Errorf("go-blockstore/local: lvs reported data_percent %q for %s/%s: %w",
						lv.DataPercent, p.volumeGroup, lv.Name, pctErr)
				}
				if pct > 100 {
					return nil, fmt.Errorf("go-blockstore/local: lvs reported data_percent %q for %s/%s: above 100",
						lv.DataPercent, p.volumeGroup, lv.Name)
				}
				info.DataPercent = pct
			} else if info.isSnapshot() && info.active() {
				return nil, fmt.Errorf("go-blockstore/local: lvs reported no data_percent for active snapshot %s/%s",
					p.volumeGroup, lv.Name)
			}

			// origin_size is required on a snapshot and ignored elsewhere.
			if raw := strings.TrimSpace(lv.OriginSize); raw != "" {
				originSize, sizeErr := parseLVNumber(raw)
				if sizeErr != nil {
					return nil, fmt.Errorf("go-blockstore/local: lvs reported origin_size %q for %s/%s: %w",
						lv.OriginSize, p.volumeGroup, lv.Name, sizeErr)
				}
				info.OriginSizeBytes = int64(originSize)
			} else if info.isSnapshot() {
				return nil, fmt.Errorf("go-blockstore/local: lvs reported no origin_size for snapshot %s/%s",
					p.volumeGroup, lv.Name)
			}

			infos = append(infos, info)
		}
	}
	return infos, nil
}

// parseLVNumber reads a numeric lvs column, refusing anything not finite and non-negative; maxInt64Float is 2^63, refused rather than converted.
const maxInt64Float = float64(math.MaxInt64)

func parseLVNumber(raw string) (float64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("value is empty")
	}
	v, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, fmt.Errorf("not a number")
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("not finite")
	}
	if v < 0 {
		return 0, fmt.Errorf("negative")
	}
	if v >= maxInt64Float {
		return 0, fmt.Errorf("too large to represent as a byte count")
	}
	return v, nil
}

// vgsReport is the shape of `vgs --reportformat json`.
type vgsReport struct {
	Report []struct {
		VG []struct {
			ExtentSize string `json:"vg_extent_size"`
		} `json:"vg"`
	} `json:"report"`
}

// extentSize returns the volume group's extent size, so Resize can tell a shrink from a rounded repeat.
func (p *Provider) extentSize(ctx context.Context) (int64, error) {
	out, err := p.runner.Run(ctx, nil, "vgs",
		"--reportformat", "json",
		"--units", "b",
		"--nosuffix",
		"-o", "vg_extent_size",
		p.volumeGroup,
	)
	if err != nil {
		return 0, fmt.Errorf("go-blockstore/local: reading extent size of %q: %w", p.volumeGroup, err)
	}

	var report vgsReport
	if err := json.Unmarshal(out, &report); err != nil {
		return 0, fmt.Errorf("go-blockstore/local: parsing vgs report: %w", err)
	}
	for _, r := range report.Report {
		for _, vg := range r.VG {
			size, err := parseLVNumber(vg.ExtentSize)
			if err == nil && size > 0 {
				return int64(size), nil
			}
		}
	}
	return 0, fmt.Errorf("go-blockstore/local: vgs reported no extent size for %q", p.volumeGroup)
}

// maxRoundableBytes is the largest byte count roundUpToExtent can take for a
// given extent size without the addition inside it overflowing.
func maxRoundableBytes(extent int64) int64 {
	if extent <= 1 {
		return math.MaxInt64
	}
	return math.MaxInt64 - (extent - 1)
}

// maxUsableBytes is the largest usable capacity whose overhead addition and extent rounding do not overflow.
func maxUsableBytes(extent, overhead int64) int64 {
	limit := maxRoundableBytes(extent)
	if overhead >= limit {
		return 0
	}
	return limit - overhead
}

// usableBytes is backing minus overhead, floored at zero.
func usableBytes(backing, overhead int64) int64 {
	if backing <= overhead {
		return 0
	}
	return backing - overhead
}

// roundUpToExtent rounds bytes up to whole extents; bytes must not exceed maxRoundableBytes(extent).
func roundUpToExtent(bytes, extent int64) int64 {
	if extent <= 0 {
		return bytes
	}
	if bytes > maxRoundableBytes(extent) {
		return bytes
	}
	return ((bytes + extent - 1) / extent) * extent
}

// lookupLV finds one logical volume by name in a listing.
func lookupLV(lvs []lvInfo, name string) (lvInfo, bool) {
	for _, lv := range lvs {
		if lv.Name == name {
			return lv, true
		}
	}
	return lvInfo{}, false
}

// lvPath is the device path LVM creates for a logical volume.
func (p *Provider) lvPath(name string) string {
	return "/dev/" + p.volumeGroup + "/" + name
}

// lvRef is the "vg/lv" reference the lvm tools take as an argument.
func (p *Provider) lvRef(name string) string {
	return p.volumeGroup + "/" + name
}

// activate makes an LV's device node available; --yes answers lvchange's snapshot prompt.
func (p *Provider) activate(ctx context.Context, name string) error {
	if _, err := p.runner.Run(ctx, nil, "lvchange", "--activate", "y", "--yes", p.lvRef(name)); err != nil {
		return fmt.Errorf("go-blockstore/local: activating %s: %w", p.lvRef(name), err)
	}
	return nil
}

// deactivate withdraws a logical volume's device node.
func (p *Provider) deactivate(ctx context.Context, name string) error {
	if _, err := p.runner.Run(ctx, nil, "lvchange", "--activate", "n", "--yes", p.lvRef(name)); err != nil {
		return fmt.Errorf("go-blockstore/local: deactivating %s: %w", p.lvRef(name), err)
	}
	return nil
}

// autoActivationOff keeps udev and boot from reactivating detached volumes; needs LVM 2.03.12 or newer.
var autoActivationOff = []string{"--setautoactivation", "n"}

// addTag records a tag on an LV; adding an existing tag is a no-op.
func (p *Provider) addTag(ctx context.Context, name, tag string) error {
	if _, err := p.runner.Run(ctx, nil, "lvchange", "--addtag", tag, p.lvRef(name)); err != nil {
		return fmt.Errorf("go-blockstore/local: tagging %s with %q: %w", p.lvRef(name), tag, err)
	}
	return nil
}

// deleteHeaderTags removes every header tag from a volume; --deltag of an absent tag exits 0.
func (p *Provider) deleteHeaderTags(ctx context.Context, name string, tags []string) error {
	args := make([]string, 0, 2*len(tags)+1)
	for _, tag := range tags {
		args = append(args, "--deltag", tag)
	}
	args = append(args, p.lvRef(name))

	if _, err := p.runner.Run(ctx, nil, "lvchange", args...); err != nil {
		return fmt.Errorf("go-blockstore/local: removing %s from %s: %w",
			strings.Join(tags, ", "), p.lvRef(name), err)
	}
	return nil
}

// retagLUKSHeader sets the header tag to want in one lvchange (--deltag then --addtag), so the volume is never untagged or double-tagged.
func (p *Provider) retagLUKSHeader(ctx context.Context, name string, stale []string, want string) error {
	args := make([]string, 0, 2*len(stale)+3)
	for _, tag := range stale {
		if tag != want {
			args = append(args, "--deltag", tag)
		}
	}
	args = append(args, "--addtag", want, p.lvRef(name))

	if _, err := p.runner.Run(ctx, nil, "lvchange", args...); err != nil {
		return fmt.Errorf("go-blockstore/local: recording %q on %s: %w", want, p.lvRef(name), err)
	}
	return nil
}

// createLV creates an LV of the given size in bytes; LVM rounds up to whole extents.
func (p *Provider) createLV(ctx context.Context, name string, sizeBytes int64) error {
	args := append([]string{
		"--yes",
		"--name", name,
		"--size", strconv.FormatInt(sizeBytes, 10) + "b",
	}, autoActivationOff...)
	args = append(args, p.volumeGroup)

	if _, err := p.runner.Run(ctx, nil, "lvcreate", args...); err != nil {
		return fmt.Errorf("go-blockstore/local: creating %s: %w", p.lvRef(name), err)
	}
	return nil
}

// removeLV destroys a logical volume.
func (p *Provider) removeLV(ctx context.Context, name string) error {
	if _, err := p.runner.Run(ctx, nil, "lvremove", "--force", p.lvRef(name)); err != nil {
		return fmt.Errorf("go-blockstore/local: removing %s: %w", p.lvRef(name), err)
	}
	return nil
}

// blkidNoSignature is blkid's exit status for no signature or no device; other non-zero statuses are failures.
const blkidNoSignature = 2

// probeFSType returns blkid's TYPE for a device, "" only for blkid's no-signature status, and an error otherwise.
func (p *Provider) probeFSType(ctx context.Context, device string) (string, error) {
	out, err := p.runner.Run(ctx, nil, "blkid", "-o", "export", device)
	if err != nil {
		if exitErr, ok := asExitError(err); ok && exitErr.Code == blkidNoSignature {
			return "", nil
		}
		return "", fmt.Errorf("go-blockstore/local: probing %s: %w", device, err)
	}
	// A zero exit must carry a TYPE; output without one is an error, not a raw device.
	var types []string
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found && key == "TYPE" && value != "" {
			types = append(types, value)
		}
	}
	switch len(types) {
	case 1:
		return types[0], nil
	case 0:
		return "", fmt.Errorf("go-blockstore/local: blkid identified %s but reported no TYPE", device)
	default:
		return "", fmt.Errorf("go-blockstore/local: blkid reported %d TYPE values for %s: %s",
			len(types), device, strings.Join(types, ", "))
	}
}

// dmName composes LVM's device-mapper name, doubling hyphens in each component ("bs-p9"/"my-vol" -> "bs--p9-my--vol").
func dmName(vg, lv string) string {
	return strings.ReplaceAll(vg, "-", "--") + "-" + strings.ReplaceAll(lv, "-", "--")
}

// mountpointsFor returns every path the volume is mounted at, matched by major:minor; an unreadable mount table is an error.
func (p *Provider) mountpointsFor(ctx context.Context, device string) ([]string, error) {
	if device == "" {
		return nil, nil
	}
	return p.mountTable.MountPointsFor(ctx, device)
}

// visibleMountpointsFor returns the paths where the volume is the visible filesystem, the set safe to unmount by path.
func (p *Provider) visibleMountpointsFor(ctx context.Context, device string) ([]string, error) {
	if device == "" {
		return nil, nil
	}
	return p.mountTable.VisibleMountPointsFor(ctx, device)
}
