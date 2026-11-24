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
	"fmt"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// MappingVerdict is what the reaper concluded about one plaintext mapping.
type MappingVerdict string

const (
	// VerdictLive means the mapping was made by this node on this boot, so
	// something may be using it right now. Never touched.
	VerdictLive MappingVerdict = "live"

	// VerdictForeignNode means the record names a different node; on shared storage that is not an orphan.
	VerdictForeignNode MappingVerdict = "another node's"

	// VerdictOrphaned means this node made the mapping on a boot that has
	// ended. Nothing live can be holding it: a holder cannot survive the reboot
	// of the host it was running on.
	VerdictOrphaned MappingVerdict = "orphaned"

	// VerdictUnattributable means ownership could not be established — no
	// record, an unreadable one, or a mapping whose backing device is not the
	// volume its name claims. Reported, never removed.
	VerdictUnattributable MappingVerdict = "unattributable"

	// VerdictLivenessUnknown means this node and running boot own the mapping and the liveness oracle could not answer.
	VerdictLivenessUnknown MappingVerdict = "liveness unknown"
)

// MappingFinding is one plaintext mapping and what was concluded about it.
type MappingFinding struct {
	// VolumeID is the volume the mapping's name encodes.
	VolumeID string

	// Mapping is the device-mapper name.
	Mapping string

	// Backing is the most legible path to the device the mapping decrypts, and
	// BackingID is that device's major:minor — the identity ownership rests on.
	Backing   string
	BackingID string

	// Owner is the record found on the volume, when there was a readable one.
	Owner    mappingOwner
	Recorded bool
	Verdict  MappingVerdict
	Reason   string
}

// String renders one finding as an audit line.
func (f MappingFinding) String() string {
	var b strings.Builder
	b.WriteString(f.Mapping)
	b.WriteString(" over ")
	if f.Backing != "" {
		b.WriteString(f.Backing)
	} else {
		b.WriteString("an unestablished device")
	}
	if f.BackingID != "" {
		b.WriteString(" (")
		b.WriteString(f.BackingID)
		b.WriteString(")")
	}
	b.WriteString(": ")
	b.WriteString(string(f.Verdict))
	if f.Recorded {
		b.WriteString(", unlocked by ")
		b.WriteString(f.Owner.String())
	}
	if f.Reason != "" {
		b.WriteString(" — ")
		b.WriteString(f.Reason)
	}
	return b.String()
}

// Orphaned returns the findings that are proven orphans.
func Orphaned(findings []MappingFinding) []MappingFinding {
	var orphans []MappingFinding
	for i := range findings {
		if findings[i].Verdict == VerdictOrphaned {
			orphans = append(orphans, findings[i])
		}
	}
	return orphans
}

// InspectMappings reports every plaintext mapping this provider owns, by name and backing device, without changing anything; it never enumerates device-mapper.
func (p *Provider) InspectMappings(ctx context.Context) ([]MappingFinding, error) {
	lvs, err := p.listLVs(ctx)
	if err != nil {
		return nil, err
	}

	owner, ownerErr := p.owner()
	if ownerErr != nil {
		// Without knowing who and when we are, no verdict is possible. That is
		// a refusal rather than an empty report: an empty report reads as "no
		// orphans", which is the fail-open this whole guard exists to remove.
		return nil, ownerErr
	}

	var findings []MappingFinding
	for i := range lvs {
		if lvs[i].isSnapshot() {
			continue
		}
		finding, found, err := p.inspectMapping(ctx, &lvs[i], owner)
		if err != nil {
			return findings, err
		}
		if found {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Mapping < findings[j].Mapping })
	return findings, nil
}

// inspectMapping decides about one volume's mapping, if it has one.
func (p *Provider) inspectMapping(ctx context.Context, lv *lvInfo, self mappingOwner) (MappingFinding, bool, error) {
	name := p.mappingName(lv.Name)

	info, open, err := p.luks.Mapping(ctx, name)
	if err != nil {
		// Unattributable; reported without aborting the sweep.
		return MappingFinding{
			VolumeID: lv.Name,
			Mapping:  name,
			Verdict:  VerdictUnattributable,
			Reason:   "the mapping's backing device could not be established: " + err.Error(),
		}, true, nil
	}
	if !open {
		return MappingFinding{}, false, nil
	}

	finding := MappingFinding{
		VolumeID:  lv.Name,
		Mapping:   name,
		Backing:   info.Backing,
		BackingID: info.BackingID,
	}

	// The mapping must decrypt this volume.
	wantID, idErr := p.luks.Identity(ctx, p.lvPath(lv.Name))
	switch {
	case idErr != nil:
		finding.Verdict = VerdictUnattributable
		finding.Reason = "the volume's own device identity could not be read: " + idErr.Error()
		return finding, true, nil
	case info.BackingID != wantID:
		finding.Verdict = VerdictUnattributable
		finding.Reason = fmt.Sprintf("the mapping decrypts %s, not this volume (%s)", info.BackingID, wantID)
		return finding, true, nil
	}

	// Nothing here tears anything down; the verdicts are a classification. VerdictOrphaned needs this node and an ended boot; the oracle is consulted only for this node's running boot.
	owner, recorded, ownerErr := lv.mappingOwner()
	finding.Owner, finding.Recorded = owner, recorded
	switch {
	case ownerErr != nil:
		finding.Verdict = VerdictUnattributable
		finding.Reason = ownerErr.Error()
	case !recorded:
		finding.Verdict = VerdictUnattributable
		finding.Reason = "the volume carries no record of who unlocked it, so nothing establishes that this provider created the mapping"
	case owner.Node != self.Node:
		finding.Verdict = VerdictForeignNode
		finding.Reason = "the volume group is reachable from more than one node and this mapping belongs to " + owner.Node
	case owner.Boot == self.Boot:
		finding.Verdict, finding.Reason = p.sameBootVerdict(ctx, lv.Name)
	default:
		finding.Verdict = VerdictOrphaned
		finding.Reason = "made by this node on a boot that has ended, so nothing holding it can still exist"
	}
	return finding, true, nil
}

// madeOnThisBoot is the half of every same-boot reason that is established
// without asking anybody.
const madeOnThisBoot = "made by this node on the boot that is still running"

// sameBootVerdict decides a mapping from this node's running boot: live without an oracle, otherwise the oracle's answer or VerdictLivenessUnknown.
func (p *Provider) sameBootVerdict(ctx context.Context, volID string) (MappingVerdict, string) {
	if p.liveness == nil {
		return VerdictLive, madeOnThisBoot
	}

	state, err := common.LivenessOf(ctx, p.liveness, volID)
	switch {
	case err != nil:
		return VerdictLivenessUnknown, madeOnThisBoot +
			", and the liveness oracle could not establish whether its owner is still there: " + err.Error()
	case state == common.LivenessReleased:
		return VerdictOrphaned, madeOnThisBoot +
			", and the liveness oracle reports that the owner of the attachment has gone"
	default:
		return VerdictLive, madeOnThisBoot +
			", and the liveness oracle reports that the attachment still has a live owner"
	}
}

// RunReaper sweeps once per tick until ctx is done, sending findings to report; a failed sweep does not stop the loop.
func (p *Provider) RunReaper(ctx context.Context, tick <-chan struct{}, report func([]MappingFinding, error)) error {
	sweep := func() {
		findings, err := p.InspectMappings(ctx)
		if report != nil {
			report(findings, err)
		}
	}

	// Sweep once at startup, before the first tick.
	sweep()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-tick:
			if !ok {
				return nil
			}
			sweep()
		}
	}
}
