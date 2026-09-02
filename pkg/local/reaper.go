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
)

// MappingVerdict is what the reaper concluded about one plaintext mapping.
type MappingVerdict string

const (
	// VerdictLive means the mapping was made by this node on this boot, so
	// something may be using it right now. Never touched.
	VerdictLive MappingVerdict = "live"

	// VerdictForeignNode means the record names a DIFFERENT node.
	//
	// On shared storage the volume group is visible to every node, so this is
	// an ordinary state and emphatically not an orphan: the other node's
	// workload is using it. Reaping on the boot ID alone would tear it down,
	// because another node's live boot never matches this node's.
	VerdictForeignNode MappingVerdict = "another node's"

	// VerdictOrphaned means this node made the mapping on a boot that has
	// ended. Nothing live can be holding it: a holder cannot survive the reboot
	// of the host it was running on.
	VerdictOrphaned MappingVerdict = "orphaned"

	// VerdictUnattributable means ownership could not be established — no
	// record, an unreadable one, or a mapping whose backing device is not the
	// volume its name claims. Reported, never removed.
	VerdictUnattributable MappingVerdict = "unattributable"
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

// InspectMappings finds every plaintext mapping this provider owns and says
// what it concluded about each, without changing anything.
//
// It never enumerates device-mapper. The candidate set is derived from the
// volumes in THIS provider's own volume group, and for each one it asks whether
// a mapping exists under the name this provider itself would have chosen. A
// mapping belonging to anything else is not in the candidate set at all, which
// is a stronger property than filtering an enumeration by a name pattern: a
// name is not evidence of ownership, and treating it as such is how a reaper
// destroys state it did not create (go-luks2 #96).
//
// Ownership then has to be POSITIVE and it takes two independent facts that
// agree: the deterministic name, and the mapping's backing device being the
// very volume that name encodes. Both come from mechanisms that already fail
// closed — Mapping and Identity refuse a mapping whose backing device cannot be
// established rather than guessing.
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
		// The mapping exists and its identity could not be established. That is
		// the unattributable case in its purest form, and it is reported rather
		// than allowed to abort the sweep: one unreadable mapping must not hide
		// the others.
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

	// The second of the two facts: this mapping must decrypt THIS volume, not
	// merely carry the name this provider would have given it.
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

	// ─────────────────────────────────────────────────────────────────────────
	// THE CRITERION. Read this before changing any case below it.
	//
	// Nothing here tears anything down. This provider REPORTS what it finds and
	// removes nothing, because the fact that would make removal safe does not
	// exist yet (issue #41). The verdicts below are a classification, and this
	// comment is about what happens when somebody gives them teeth.
	//
	// VerdictOrphaned is deliberately almost unreachable. A device-mapper
	// mapping is kernel state and does not survive a reboot — nothing recreates
	// a bs-* mapping at boot — so "the record names a boot that has ended AND
	// the mapping is still open" describes a state the kernel does not normally
	// produce. The abandoned-init-container case that motivates all of this
	// happens while the host STAYS UP, and this criterion cannot see it.
	//
	// Somebody will eventually notice that and loosen the predicate. Every
	// available way to loosen it would, if anything acted on the result, take
	// down a LIVE attachment:
	//
	//   - Dropping the NODE conjunct. On shared storage the volume group is
	//     visible to every node, and another node's live mapping was made on
	//     that node's boot — which never matches this one's. That reads as
	//     orphaned while somebody's workload is using it. This is the one that
	//     does not look dangerous.
	//   - Accepting "the dm device's open count is 0". Retracted upstream:
	//     go-luks2 #96 measured it identical for a live job mid-run.
	//   - Accepting "the volume is not mounted anywhere". A workload can hold
	//     the block device open raw, without ever mounting it.
	//
	// The missing ingredient is a LIVENESS FACT — something that says the
	// attachment's owner is gone — and this provider has none: it holds no
	// lease and writes no attachment record beyond this one, by design. Issue
	// #41 is where that is decided, and it is an architecture decision rather
	// than a loosening of this switch. Until it lands, an orphan is a line in a
	// report and nothing else.
	//
	// The tests below pin each conjunct and go red if one is removed. They tell
	// you WHAT broke; this comment is the one that tells you why not to.
	// ─────────────────────────────────────────────────────────────────────────
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
		finding.Verdict = VerdictLive
		finding.Reason = "made by this node on the boot that is still running"
	default:
		finding.Verdict = VerdictOrphaned
		finding.Reason = "made by this node on a boot that has ended, so nothing holding it can still exist"
	}
	return finding, true, nil
}

// RunReaper sweeps once for every tick, until the context is done.
//
// The caller supplies the tick, so this holds no timer of its own and never
// sleeps: a test drives it by sending on a channel and gets a deterministic
// sweep rather than a wall-clock wait, and a component in production supplies a
// time.Ticker. Each sweep's findings go to report, which is what makes a reaped
// mapping an audit event rather than a silent removal.
//
// A sweep that fails is reported and does not stop the loop. The condition that
// broke one sweep — an LVM tool that failed, a mapping whose identity could not
// be read — is very often gone by the next, and a reaper that exits on the
// first failure stops being a guard at the moment something is wrong.
func (p *Provider) RunReaper(ctx context.Context, tick <-chan struct{}, report func([]MappingFinding, error)) error {
	sweep := func() {
		findings, err := p.InspectMappings(ctx)
		if report != nil {
			report(findings, err)
		}
	}

	// A sweep at startup, before the first tick: the orphans this exists to
	// find are made by something that ALREADY died, so they are present the
	// moment the process starts and waiting a whole interval to look would be
	// waiting for nothing.
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
