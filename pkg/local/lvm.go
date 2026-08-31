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
	"bytes"
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

// luksHeaderFromTags reads the header size this volume was tagged with.
//
// The three answers are distinct on purpose. NOT TAGGED is a volume provisioned
// before the tag existed, and is a legitimate state with a documented fallback.
// TAGGED WITH SOMETHING UNREADABLE — a value that is not a positive number, or
// several disagreeing tags — is not: it means the tag was hand-edited or two
// writers disagreed, and answering with a number anyway would put a
// plausible-looking figure where an unreadable one was, which is the one thing
// this package refuses everywhere it reads a value back from a tool.
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

// usedBytes is the space a snapshot currently occupies: its CoW area scaled by
// how much of that area has been written. SnapshotInfo.SizeBytes is defined as
// this occupancy rather than the origin's capacity.
//
// It is 0 for an INACTIVE snapshot, which is what this provider leaves them as.
// LVM reports occupancy only while the kernel has the device mapped, and the
// figure is not worth activating a snapshot to obtain — activating one activates
// its origin too, which would move a volume the caller is using.
func (l lvInfo) usedBytes() int64 {
	return int64(float64(l.SizeBytes) * l.DataPercent / 100)
}

// lvTimeLayouts are the formats lvs has used for lv_time. The first two are
// what LVM emits with its default and ISO time formats; the parser tries each
// and leaves CreatedAt zero if none fit, because a creation timestamp is
// reporting detail and not worth failing a listing over.
var lvTimeLayouts = []string{
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05 Z0700",
	"2006-01-02T15:04:05-0700",
	time.RFC3339,
}

// parseLVTags splits the lv_tags column, which lvs renders as a comma-separated
// list and leaves EMPTY for an untagged volume — measured on LVM 2.03.16,
// including through the JSON report, where the field is the empty string rather
// than absent or null. Splitting "" yields one EMPTY tag rather than none, which
// would make a volume with no tags look like a volume with one, so empties are
// dropped both at the front and inside the loop.
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

// listLVs returns every logical volume in the provider's volume group.
//
// The provider queries the whole group in one call and searches the result,
// rather than asking lvs about a single volume, because lvs signals "no such
// logical volume" with an exit status shared by real failures. A full listing
// makes absence an ordinary empty result and keeps every lifecycle method's
// ErrNotFound decision a matter of reading a slice, not decoding exit codes.
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

			// data_percent is reported only where the kernel is tracking it:
			// for a snapshot that is ACTIVE. Measured on LVM 2.03.16, a plain
			// volume reports empty always, and so does an inactive snapshot —
			// which is the ordinary state here, since this provider leaves
			// snapshots deactivated. Empty is a real answer in both cases and
			// only a malformed one for a snapshot that IS active, where the
			// kernel has a figure and lvs failed to render it.
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

			// origin_size is reported for a snapshot and for an origin that has
			// one, and left empty for an ordinary volume. Only the snapshot's
			// value is used, and a snapshot without one cannot be restored from
			// safely — the copy's length and the zeroing offset both come from
			// it — so it is required there and ignored everywhere else.
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

// parseLVNumber reads one of lvs's numeric columns, refusing anything that is
// not a finite, non-negative number.
//
// The alternative — the zero value on a parse failure, which is what this used
// to do — puts a plausible-looking number where an unreadable one was, and these
// feed decisions rather than reports: a zero lv_size makes Resize read every
// request as a grow and makes a restore's "is the target big enough" check pass
// for any size at all. Failing the listing means an operation over a volume
// group this provider cannot read stops instead of acting on invented numbers.
// maxInt64Float is 2^63 exactly, the first float64 that does not fit in an
// int64. Converting a float at or above it is implementation-specific in Go and
// yields a nonsense value on amd64 — a negative one — so it is refused rather
// than converted.
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

// extentSize returns the volume group's allocation unit in bytes.
//
// Resize needs it to tell a genuine shrink from a repeat of a request LVM has
// already rounded up. Asking for 100000000 bytes yields a 100663296-byte volume
// on a 4 MiB-extent group, and without knowing the extent size the identical
// second request looks like a shrink and comes back ErrUnsupported.
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

// maxUsableBytes is the largest USABLE capacity a caller can ask for on a
// volume carrying overhead bytes of per-volume overhead, given a volume group
// with this extent size.
//
// Both steps that turn a usable capacity into a backing size can overflow: the
// addition of the overhead, and the rounding up to a whole extent inside
// roundUpToExtent. This is the bound past which either of them would, so the
// callers check once against it rather than each guarding half the arithmetic.
//
// The subtraction cannot itself go negative: maxRoundableBytes never returns
// less than the extent size, and the guard below covers the degenerate case of
// an overhead larger than the whole representable range.
func maxUsableBytes(extent, overhead int64) int64 {
	limit := maxRoundableBytes(extent)
	if overhead >= limit {
		return 0
	}
	return limit - overhead
}

// usableBytes is the capacity a caller can write to on a backing device of
// backing bytes carrying overhead bytes of per-volume overhead.
//
// It floors at zero rather than going negative. A backing device smaller than
// its own overhead is not a volume with negative capacity, it is a volume with
// none — and a negative size reported through VolumeStatus would be read as a
// number rather than as the nonsense it is.
func usableBytes(backing, overhead int64) int64 {
	if backing <= overhead {
		return 0
	}
	return backing - overhead
}

// roundUpToExtent rounds a byte count up to a whole number of extents, the way
// lvcreate and lvextend do.
//
// bytes must not exceed maxRoundableBytes(extent). The addition below overflows
// past that, and a signed overflow in Go wraps rather than trapping: the result
// comes back NEGATIVE, which then reads as a smaller size than the volume
// already has. A caller that skipped the check would have a request to grow a
// volume to an enormous size reported back as an unsupported SHRINK — the wrong
// answer, arrived at silently, to a question nobody would think to re-ask.
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

// activate makes a logical volume's device node available on this host.
//
// --yes answers the confirmation lvchange raises for a snapshot, where changing
// the snapshot's activation changes its origin's too. There is nobody to answer
// it from inside a library call, and the operation is one the caller asked for.
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

// autoActivationOff is what keeps Detach meaning anything.
//
// LVM autoactivation is on by default, and udev reactivates a whole volume
// group in response to unrelated device events — a mkfs on a sibling volume is
// enough. A deactivated volume therefore comes back on its own within seconds,
// which would make Detach a suggestion and Status a coin flip. Marking a volume
// as not auto-activated leaves activation entirely to this provider: explicit
// lvchange still works, boot and udev leave it alone.
//
// The flag needs LVM 2.03.12 (2021) or newer.
var autoActivationOff = []string{"--setautoactivation", "n"}

// addTag records a tag on a logical volume.
//
// It is idempotent: measured on LVM 2.03.16, adding a tag the volume already
// carries exits 0 and leaves one copy of it, so a repeated call is a no-op
// rather than something callers have to guard against.
func (p *Provider) addTag(ctx context.Context, name, tag string) error {
	if _, err := p.runner.Run(ctx, nil, "lvchange", "--addtag", tag, p.lvRef(name)); err != nil {
		return fmt.Errorf("go-blockstore/local: tagging %s with %q: %w", p.lvRef(name), tag, err)
	}
	return nil
}

// deleteHeaderTags removes every header tag from a volume, for the case where
// the probe says there should not be one at all.
//
// --deltag of a tag the volume does not carry exits 0 — measured — so this is
// idempotent and needs no read-back to confirm what it removed.
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

// retagLUKSHeader makes the volume's recorded header size be exactly want,
// removing any header tag that says something else.
//
// Both halves go to ONE lvchange — measured on LVM 2.03.16, --deltag and
// --addtag are accepted together and applied in that order — so the volume is
// never briefly untagged, and never briefly carrying two tags that disagree.
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

// createLV creates a logical volume of the given size.
//
// The size reaches lvcreate in bytes with an explicit "b" suffix. LVM rounds it
// up to a whole number of extents, so the volume can come back marginally
// larger than requested and never smaller.
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

// blkidNoSignature is the exit status blkid uses for "no information about this
// device", which covers both a device with no recognizable signature and one
// that does not exist. Its other non-zero statuses are failures: a usage error,
// or the exit 8 that means low-level probing found an ambivalent result.
const blkidNoSignature = 2

// probeFSType asks blkid what is on a device, returning "" for a device with no
// recognizable signature — a freshly created raw volume, most often.
//
// Only blkid's "nothing here" status becomes an empty answer. Every other
// failure is returned, because the alternative is reporting "no filesystem" for
// a device blkid could not read, or found two conflicting signatures on, and the
// caller acting on that would attach an encrypted volume as though it were
// plain, or skip growing a filesystem that is really there.
func (p *Provider) probeFSType(ctx context.Context, device string) (string, error) {
	out, err := p.runner.Run(ctx, nil, "blkid", "-o", "export", device)
	if err != nil {
		if exitErr, ok := asExitError(err); ok && exitErr.Code == blkidNoSignature {
			return "", nil
		}
		return "", fmt.Errorf("go-blockstore/local: probing %s: %w", device, err)
	}
	// A zero exit means blkid identified the device, so it owes us a TYPE.
	// Returning "" here — the authoritative "this is a raw device" answer —
	// for output that simply did not contain one would let truncated or
	// unexpected output pass as fact, and callers act on that answer: Attach
	// would hand back a LUKS container as a plain device, and Mount would try
	// to mount one.
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

// findmntReport is the shape of `findmnt --list --json`.
type findmntReport struct {
	Filesystems []struct {
		Target string `json:"target"`
		Source string `json:"source"`
	} `json:"filesystems"`
}

// dmName composes the device-mapper name LVM gives a logical volume.
//
// Each component has its hyphens doubled, which is what lets the single-hyphen
// join between them stay unambiguous. Measured on LVM 2.03.16: volume group
// "bs-p9" and logical volume "my-vol" appear as "bs--p9-my--vol".
func dmName(vg, lv string) string {
	return strings.ReplaceAll(vg, "-", "--") + "-" + strings.ReplaceAll(lv, "-", "--")
}

// sourceAliases lists the spellings findmnt may report for the device a volume
// is reachable at.
//
// A volume is reachable under several names — /dev/<vg>/<lv>, the dm-mangled
// /dev/mapper/<vg>-<lv>, and the /dev/dm-N underneath — and findmnt reports the
// one it resolves to rather than the one a mount was issued with. Matching a
// single spelling would miss a mount that is plainly there, and a missed mount
// is what turns Unmount into a silent no-op and lets Delete remove a volume out
// from under a live filesystem.
//
// Measured on util-linux 2.39.3, findmnt CANONICALIZES a device-mapper source to
// /dev/mapper/<dm-name> however the filesystem was mounted — mounting
// /dev/bs-p9/my-vol reports /dev/mapper/bs--p9-my--vol, and so does mounting
// /dev/dm-3 directly. So that spelling plus the caller's own is the whole set,
// and /dev/dm-N is deliberately absent rather than forgotten: findmnt was never
// observed to report it. Should a util-linux appear that does, the robust fix is
// to match on the MAJ:MIN column instead of on names at all.
//
// An unlocked encrypted volume needs no alias: its plaintext mapping is a
// device-mapper name in its own right, and /dev/mapper/<that name> is what
// findmnt reports.
func (p *Provider) sourceAliases(volID, device string) []string {
	aliases := []string{device}
	if device == p.lvPath(volID) {
		aliases = append(aliases, "/dev/mapper/"+dmName(p.volumeGroup, volID))
	}
	return aliases
}

// mountpointsFor returns every path the volume is currently mounted at, given
// the spellings its device may be reported under.
//
// The WHOLE mount table is enumerated and filtered here rather than handed to
// findmnt as a --source filter, because a filtered query cannot say why it came
// back empty. findmnt has exactly one non-zero status and its manual gives that
// status to "no filesystem matched" and "any other error" alike, so a findmnt
// that could not read the mount table at all was indistinguishable from a
// volume that is not mounted — and "not mounted" is the answer Delete acts on
// immediately before a forced lvremove. Unfiltered, a readable mount table is
// an exit of zero and a report that parses; anything else is a failure and is
// returned as one. Only a report that parsed, and holds no row for this device,
// means the volume is unmounted.
//
// --list rather than the default, which nests submounts under "children" and
// would hide any mount below another. The report is read as JSON because
// findmnt's column output escapes some characters in a path and not others,
// depending on flags and util-linux version — measured here, the default prints
// a space literally while --raw renders it \x20 — and a target that comes back
// spelled differently than it went in silently fails to match.
func (p *Provider) mountpointsFor(ctx context.Context, aliases []string) ([]string, error) {
	if len(aliases) == 0 {
		return nil, nil
	}

	out, err := p.runner.Run(ctx, nil, "findmnt", "--list", "--json", "--output", "TARGET,SOURCE")
	if err != nil {
		return nil, fmt.Errorf("go-blockstore/local: reading the mount table: %w", err)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("go-blockstore/local: reading the mount table: findmnt produced no report")
	}

	var report findmntReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("go-blockstore/local: parsing the mount table: %w", err)
	}

	var targets []string
	for _, fs := range report.Filesystems {
		if fs.Target != "" && contains(aliases, fs.Source) {
			targets = append(targets, fs.Target)
		}
	}
	return targets, nil
}
