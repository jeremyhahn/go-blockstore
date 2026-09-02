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
	"os"
	"strings"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// unlockedByTagPrefix records which node unlocked a volume, and on which boot
// of that node.
//
// It is written BEFORE the plaintext mapping is created, which is the whole
// point: a record written afterwards is missing for exactly the mappings that
// outlived the thing that should have torn them down, and those are the ones
// this exists to identify. A record with no mapping behind it is harmless — the
// reaper finds no mapping and says nothing — while a mapping with no record is
// unattributable, and unattributable means reported, never removed.
//
// It is an LVM tag rather than a file because it has to survive a reboot and
// travel with the volume. The lock directory cannot serve: DefaultLockDir is
// /run/lock, which is tmpfs on a systemd host and deliberately does NOT survive
// a reboot — and a reboot is precisely the event this record has to be readable
// across.
const unlockedByTagPrefix = "blockstore.unlocked-by="

// unlockedByTagSeparator divides the node from the boot inside the tag value.
//
// A colon, because LVM permits it in a tag and neither a hostname nor a boot
// ID can contain one, so the two halves can never be confused for each other.
const unlockedByTagSeparator = ":"

// mappingOwner is the record: which node unlocked this volume, and on which
// boot of that node.
type mappingOwner struct {
	// Node is the node ID that created the mapping.
	Node string

	// Boot identifies that node's boot. A mapping cannot outlive the boot it
	// was made on, so a record naming a boot that has ended describes something
	// no live holder can be using.
	Boot string
}

// String renders the record as it is stored.
func (o mappingOwner) String() string { return o.Node + unlockedByTagSeparator + o.Boot }

// tag renders the whole LVM tag.
func (o mappingOwner) tag() string { return unlockedByTagPrefix + o.String() }

// errUnreadableOwnerTag reports a record that is present and cannot be read.
//
// It fails closed for the reason every other read-back in this package does: a
// tag that does not decompose into a node and a boot was written by something
// other than this code or edited by hand, and answering with half of it would
// put a plausible-looking owner where an unreadable one is — on a decision that
// tears down a decrypted volume.
var errUnreadableOwnerTag = errors.New("the unlocked-by tag does not record a node and a boot")

// tagSafe reports whether a value can be stored in an LVM tag.
//
// LVM accepts A-Za-z0-9 and a small set of punctuation; this is the
// conservative subset that covers every hostname and UUID and nothing that
// could be mistaken for the separator. A value outside it is refused rather
// than mangled into something storable, because a mangled record attributes a
// mapping to a node that does not exist.
func tagSafe(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '+':
		default:
			return false
		}
	}
	return true
}

// parseMappingOwner reads the record off a volume's tags.
//
// The three answers are the same three the header tag uses, for the same
// reason. NO TAG is a volume unlocked before this record existed, or one this
// provider never unlocked — legitimate, and it makes the mapping
// unattributable rather than orphaned. ONE TAG is the answer. SEVERAL, or one
// that does not decompose, is a refusal.
func (l lvInfo) mappingOwner() (owner mappingOwner, recorded bool, err error) {
	var found []string
	for _, t := range l.Tags {
		if strings.HasPrefix(t, unlockedByTagPrefix) {
			found = append(found, t)
		}
	}

	switch len(found) {
	case 0:
		return mappingOwner{}, false, nil
	case 1:
		raw := strings.TrimPrefix(found[0], unlockedByTagPrefix)
		node, boot, ok := strings.Cut(raw, unlockedByTagSeparator)
		// Both halves must be exactly what this code writes. strings.Cut splits
		// at the FIRST separator, so "node:boot:x" would otherwise parse with a
		// Boot of "boot:x" — a value that matches no real boot, which under
		// that makes a mapping made on the CURRENT boot look like one from a
		// boot that ended. A record that is not exactly a record is not
		// a weaker record; it is no record.
		if !ok || !tagSafe(node) || !tagSafe(boot) {
			return mappingOwner{}, true, fmt.Errorf("%w: %q", errUnreadableOwnerTag, found[0])
		}
		return mappingOwner{Node: node, Boot: boot}, true, nil
	default:
		return mappingOwner{}, true, fmt.Errorf("%w: the volume carries %d of them: %s",
			errUnreadableOwnerTag, len(found), strings.Join(found, ", "))
	}
}

// unlockedByTags returns every ownership tag on the volume, for removal.
func (l lvInfo) unlockedByTags() []string {
	var found []string
	for _, t := range l.Tags {
		if strings.HasPrefix(t, unlockedByTagPrefix) {
			found = append(found, t)
		}
	}
	return found
}

// bootIDPath is where Linux publishes an identifier regenerated on every boot.
const bootIDPath = "/proc/sys/kernel/random/boot_id"

// readBootID returns this boot's identifier.
//
// It is read once per call rather than cached at construction so that a
// provider built before something remounted /proc still reports the truth
// rather than a value from a namespace it has left.
func readBootID() (string, error) {
	raw, err := os.ReadFile(bootIDPath)
	if err != nil {
		return "", fmt.Errorf("go-blockstore/local: reading %s: %w", bootIDPath, err)
	}
	id := strings.TrimSpace(string(raw))
	if !tagSafe(id) {
		return "", fmt.Errorf("go-blockstore/local: %s holds %q, which cannot be recorded", bootIDPath, id)
	}
	return id, nil
}

// owner returns the record this provider would write right now.
func (p *Provider) owner() (mappingOwner, error) {
	boot, err := p.bootID()
	if err != nil {
		return mappingOwner{}, err
	}
	node := string(p.nodeID)
	if !tagSafe(node) {
		return mappingOwner{}, fmt.Errorf("%w: node ID %q cannot be recorded on a volume, so a mapping made here could not be attributed to it",
			common.ErrInvalidArgument, node)
	}
	return mappingOwner{Node: node, Boot: boot}, nil
}

// recordMappingOwner writes the ownership record BEFORE a mapping is created.
//
// It is BEST EFFORT, and that is a deliberate trade rather than laziness. The
// tempting stance is to refuse the unlock when the record cannot be written —
// a mapping nothing can attribute is a mapping nothing may ever clean up. But
// the configuration where a tag write fails on its own is a volume group whose
// metadata is read-only, which still ACTIVATES volumes; mounting existing
// volumes out of such a group is a normal recovery, and refusing it to record
// bookkeeping would be the same wrong trade this package already declined for
// the header tag (TestAttachSurvivesAFailedTagRepair).
//
// The cost is bounded by the reaper's own rule ONLY when there is no record to
// begin with. A mapping with no record is UNATTRIBUTABLE, which is reported and
// never removed, so a failed FIRST write costs a mapping cleaned up by hand
// rather than one destroyed by mistake.
//
// A failed REFRESH is a different matter, and it is why this reports whether it
// succeeded. A stale record that is still readable does not read as
// unattributable — it reads as ORPHANED — so the report will name a live
// mapping as an orphan until the record can be written again. That is a
// misleading line in a report and nothing more, because nothing acts on it;
// were anything ever to act on it (issue #41), this is the first thing that
// would have to be reconsidered.
//
// It skips the write when the volume already carries exactly this record, so a
// re-attach on the same boot does not rewrite metadata it agrees with.
func (p *Provider) recordMappingOwner(ctx context.Context, volID string, lv lvInfo) bool {
	owner, err := p.owner()
	if err != nil {
		return false
	}
	if existing, recorded, readErr := lv.mappingOwner(); readErr == nil && recorded && existing == owner {
		return true
	}

	// Any record already on the volume is REPLACED rather than joined. A stale
	// one can survive — an unlock that failed after the tag was written, a
	// close whose tag removal did not land — and simply adding beside it leaves
	// the volume carrying two, which reads as unreadable from then on. That
	// would not merely lose the record: it would make every future orphan of
	// this volume permanently unattributable, so the guard would go quiet on
	// exactly the volume that already went wrong once.
	//
	// --deltag and --addtag ride in one lvchange, so the replacement is a
	// single metadata write rather than a window with no record at all.
	args := make([]string, 0, 2*len(lv.unlockedByTags())+3)
	for _, stale := range lv.unlockedByTags() {
		args = append(args, "--deltag", stale)
	}
	args = append(args, "--addtag", owner.tag(), p.lvRef(volID))

	// Discarded deliberately: see the doc comment. A record that cannot be
	// written costs a mapping the reaper reports and never removes, which is
	// strictly safer than refusing to attach.
	//nolint:errcheck // best effort by design; the failure mode is documented above
	_, writeErr := p.runner.Run(ctx, nil, "lvchange", args...)
	return writeErr == nil
}

// clearMappingOwner removes the record once the mapping is gone.
//
// It runs AFTER the mapping is closed, mirroring the write: between the close
// and this, the volume carries a record for a mapping that no longer exists,
// which the reaper reads as nothing to do. The reverse order would leave a
// window where a live mapping has no record and is therefore unattributable.
func (p *Provider) clearMappingOwner(ctx context.Context, volID string, lv lvInfo) error {
	tags := lv.unlockedByTags()
	if len(tags) == 0 {
		return nil
	}
	return p.deleteHeaderTags(ctx, volID, tags)
}
