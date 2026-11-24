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

// unlockedByTagPrefix records which node and boot unlocked a volume, as an LVM tag written before the mapping is created.
const unlockedByTagPrefix = "blockstore.unlocked-by="

// unlockedByTagSeparator divides node from boot; neither can contain a colon.
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
var errUnreadableOwnerTag = errors.New("the unlocked-by tag does not record a node and a boot")

// tagSafe reports whether a value can be stored in an LVM tag, refusing rather than mangling.
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

// parseMappingOwner reads the record off a volume's tags: none is unattributable, one is the answer, more or malformed is an error.
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
		// Both halves must be exactly what this code writes.
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

// readBootID returns this boot's identifier, read on each call.
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

// recordMappingOwner writes the ownership record before a mapping is created, best effort, and reports whether it succeeded; an identical record is not rewritten.
func (p *Provider) recordMappingOwner(ctx context.Context, volID string, lv lvInfo) bool {
	owner, err := p.owner()
	if err != nil {
		return false
	}
	if existing, recorded, readErr := lv.mappingOwner(); readErr == nil && recorded && existing == owner {
		return true
	}

	// Replace any existing record in one lvchange, so the volume never carries two.
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

// clearMappingOwner removes the record after the mapping is closed.
func (p *Provider) clearMappingOwner(ctx context.Context, volID string, lv lvInfo) error {
	tags := lv.unlockedByTags()
	if len(tags) == 0 {
		return nil
	}
	return p.deleteHeaderTags(ctx, volID, tags)
}
