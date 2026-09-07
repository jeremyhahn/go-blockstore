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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// fakeOracle is a liveness oracle a test can make answer, refuse, or answer
// nonsense — and that records what it was asked, so a test can prove it was NOT
// asked as well as that it was.
type fakeOracle struct {
	state Liveness
	err   error
	asked []string
}

func (o *fakeOracle) AttachmentLiveness(_ context.Context, volID string) (Liveness, error) {
	o.asked = append(o.asked, volID)
	return o.state, o.err
}

// Liveness is aliased here for the same reason the oracle itself is: a test in
// this package should be able to write the type it is configuring.
type Liveness = common.Liveness

// withOracle installs a liveness oracle on a test provider.
func withOracle(o LivenessOracle) func(*Options) {
	return func(opts *Options) { opts.LivenessOracle = o }
}

// TestOracleTurnsAnAbandonedSameBootMappingIntoAnOrphan is the case the whole
// seam exists for, and the one the boot ID cannot see: an init container
// attached, mounted, exited, and the HOST STAYED UP. The record names this node
// and the boot that is still running, so every fact this provider can observe
// on its own says "live".
func TestOracleTurnsAnAbandonedSameBootMappingIntoAnOrphan(t *testing.T) {
	oracle := &fakeOracle{state: common.LivenessReleased}
	p, runner := mappedProvider(t, []string{unlockedBy(thisNode, thisBoot)}, withOracle(oracle))

	finding := findingFor(t, mustInspect(t, p))
	if finding.Verdict != VerdictOrphaned {
		t.Fatalf("verdict = %q, want %q: %s", finding.Verdict, VerdictOrphaned, finding)
	}
	if !strings.Contains(finding.Reason, "owner of the attachment has gone") {
		t.Errorf("the reason does not say the oracle is what decided it: %s", finding.Reason)
	}
	if len(oracle.asked) != 1 || oracle.asked[0] != "data" {
		t.Errorf("the oracle was asked %v, want exactly [data]", oracle.asked)
	}
	// The finding is still only a finding. Nothing in this package acts.
	assertNothingClosed(t, runner)
}

// TestOracleKeepsALiveSameBootMappingLive is the answer that must not become an
// orphan however loudly the rest of the report reads: something holds this
// attachment right now.
func TestOracleKeepsALiveSameBootMappingLive(t *testing.T) {
	oracle := &fakeOracle{state: common.LivenessHeld}
	p, runner := mappedProvider(t, []string{unlockedBy(thisNode, thisBoot)}, withOracle(oracle))

	finding := findingFor(t, mustInspect(t, p))
	if finding.Verdict != VerdictLive {
		t.Fatalf("verdict = %q, want %q: %s", finding.Verdict, VerdictLive, finding)
	}
	if !strings.Contains(finding.Reason, "still has a live owner") {
		t.Errorf("the reason does not say the oracle answered: %s", finding.Reason)
	}
	assertNothingClosed(t, runner)
}

// TestAnOracleThatCannotAnswerIsNeitherOfTheTwoAnswers is the indeterminate
// case, and it is the one worth being strict about.
//
// A guard that cannot see must not report what a passing guard reports. Folded
// into "live", an oracle outage makes a fleet of abandoned mappings look
// healthy; folded into "orphaned", it points anything acting on these verdicts
// at volumes live workloads are using. Both are the check's own failure
// disguised as its result.
func TestAnOracleThatCannotAnswerIsNeitherOfTheTwoAnswers(t *testing.T) {
	backendDown := errors.New("the coordinator is unreachable")

	cases := map[string]*fakeOracle{
		"an oracle that failed":             {err: backendDown},
		"an oracle that answered nothing":   {},
		"an oracle that answered otherwise": {state: Liveness("maybe")},
		"a value returned beside an error":  {state: common.LivenessReleased, err: backendDown},
	}

	for name, oracle := range cases {
		t.Run(name, func(t *testing.T) {
			p, runner := mappedProvider(t, []string{unlockedBy(thisNode, thisBoot)}, withOracle(oracle))

			finding := findingFor(t, mustInspect(t, p))
			if finding.Verdict != VerdictLivenessUnknown {
				t.Fatalf("verdict = %q, want %q: %s", finding.Verdict, VerdictLivenessUnknown, finding)
			}
			// Spelled out rather than left to the verdict alone: these two are
			// the readings that turn a broken instrument into a clean bill of
			// health and into a teardown, and a future change that collapses the
			// third state has to fail here.
			if finding.Verdict == VerdictLive || finding.Verdict == VerdictOrphaned {
				t.Fatal("an oracle that could not answer was read as an answer")
			}
			if !strings.Contains(finding.Reason, "could not establish") {
				t.Errorf("the reason does not say the check itself failed: %s", finding.Reason)
			}
			// The whole sweep survives it. One mapping whose liveness cannot be
			// established must not hide the others, on the same reasoning as an
			// unreadable mapping.
			assertNothingClosed(t, runner)
		})
	}
}

// TestAnOracleThatCannotAnswerDoesNotFailTheSweep pins that the indeterminate
// case is a FINDING and not a returned error. A sweep that aborted would report
// nothing about the volumes it had not reached yet, and an empty report reads as
// "no orphans" — the fail-open this guard exists to remove.
func TestAnOracleThatCannotAnswerDoesNotFailTheSweep(t *testing.T) {
	oracle := &fakeOracle{err: errors.New("the coordinator is unreachable")}
	runner := newFakeRunner().
		withLVs(
			lvFixture{Name: "data", SizeBytes: gib, Active: true, Tags: []string{unlockedBy(thisNode, thisBoot)}},
			lvFixture{Name: "logs", SizeBytes: gib, Active: true, Tags: []string{unlockedBy(thisNode, priorBoot)}},
		).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS, "/dev/vg0/logs": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data", "bs-vg0_logs")
	p := newTestProvider(t, runner, onBoot(thisBoot), withOracle(oracle))

	findings, err := p.InspectMappings(context.Background())
	if err != nil {
		t.Fatalf("InspectMappings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want both volumes reported: %+v", len(findings), findings)
	}
	if len(Orphaned(findings)) != 1 {
		t.Errorf("the ended-boot orphan was lost when the other volume's oracle failed: %+v", findings)
	}
}

// TestTheOracleIsNotAskedWhereTheBootIDAlreadyDecides pins the seam's
// PLACEMENT, which is the whole of its authority.
//
// The oracle refines exactly one case: this node, the boot that is still
// running. On an ended boot the verdict is already proof — a holder cannot
// survive the reboot of the host it was running on — and routing that through a
// call that can fail would let an oracle outage erase findings that need no
// oracle. Another node's mapping is not this node's to reclaim however dead its
// owner is. Both oracles here would REFUSE if asked, so a verdict that survives
// is a verdict reached without them.
func TestTheOracleIsNotAskedWhereTheBootIDAlreadyDecides(t *testing.T) {
	cases := map[string]struct {
		tags []string
		want MappingVerdict
	}{
		"a boot that has ended": {
			tags: []string{unlockedBy(thisNode, priorBoot)},
			want: VerdictOrphaned,
		},
		"another node's mapping": {
			tags: []string{unlockedBy(otherNode, priorBoot)},
			want: VerdictForeignNode,
		},
		"a mapping with no record": {
			tags: nil,
			want: VerdictUnattributable,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			oracle := &fakeOracle{err: errors.New("the coordinator is unreachable")}
			p, runner := mappedProvider(t, tc.tags, withOracle(oracle))

			finding := findingFor(t, mustInspect(t, p))
			if finding.Verdict != tc.want {
				t.Fatalf("verdict = %q, want %q: %s", finding.Verdict, tc.want, finding)
			}
			if len(oracle.asked) != 0 {
				t.Errorf("the oracle was asked about %v, and this case is decided without it", oracle.asked)
			}
			assertNothingClosed(t, runner)
		})
	}
}

// TestWithoutAnOracleTheVerdictIsWhatItWasBefore pins the default, which is a
// deliberate choice and not a gap left open.
//
// A deployment where an attachment has no owner to outlive has nothing to
// inject, and turning its every mapping into a warning would make the report
// unreadable for the deployments that are behaving correctly. The absence is
// made legible through Posture instead — see TestPostureSaysWhenNothingAsks.
func TestWithoutAnOracleTheVerdictIsWhatItWasBefore(t *testing.T) {
	p, runner := mappedProvider(t, []string{unlockedBy(thisNode, thisBoot)})

	finding := findingFor(t, mustInspect(t, p))
	if finding.Verdict != VerdictLive {
		t.Fatalf("verdict = %q, want %q with no oracle configured", finding.Verdict, VerdictLive)
	}
	if finding.Reason != madeOnThisBoot {
		t.Errorf("reason = %q, want the unqualified %q: no oracle was consulted, so none should be claimed",
			finding.Reason, madeOnThisBoot)
	}
	assertNothingClosed(t, runner)
}

// TestTheAuditLineSaysWhichVerdictIsWhich covers the artifact somebody actually
// reads. A finding whose rendering does not distinguish "unknown" from "live" is
// the same silence one level up.
func TestTheAuditLineSaysWhichVerdictIsWhich(t *testing.T) {
	oracle := &fakeOracle{err: errors.New("the coordinator is unreachable")}
	p, _ := mappedProvider(t, []string{unlockedBy(thisNode, thisBoot)}, withOracle(oracle))

	line := findingFor(t, mustInspect(t, p)).String()
	for _, want := range []string{"bs-vg0_data", string(VerdictLivenessUnknown), "the coordinator is unreachable"} {
		if !strings.Contains(line, want) {
			t.Errorf("the audit line does not mention %q: %s", want, line)
		}
	}
}

// TestPostureSaysWhenNothingAsks is where the absent oracle stops being
// invisible.
//
// It is the second guard in this provider that an operator can leave off
// without ever seeing a symptom, and the symptom when it comes is a report full
// of "live" lines over mappings nothing has held for weeks. So the line names
// the consequence, not merely the configuration.
func TestPostureSaysWhenNothingAsks(t *testing.T) {
	absent := newTestProvider(t, newFakeRunner()).Posture()

	rendered := absent.String()
	if !strings.Contains(rendered, "attachment liveness: NOT CHECKED") {
		t.Errorf("the posture does not report the missing oracle:\n%s", rendered)
	}
	for _, want := range []string{"NO ORACLE", "init container", "Options.LivenessOracle"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the posture does not say %q:\n%s", want, rendered)
		}
	}

	var listed bool
	for _, g := range absent.Unchecked() {
		if g.Name == "attachment liveness" {
			listed = true
		}
	}
	if !listed {
		t.Error("the missing oracle is not in Unchecked(), which is the part a component acts on")
	}

	configured := newTestProvider(t, newFakeRunner(), withOracle(&fakeOracle{state: common.LivenessHeld})).Posture()
	if !strings.Contains(configured.String(), "attachment liveness: checked") {
		t.Errorf("a configured oracle is not reported as checked:\n%s", configured.String())
	}
	for _, g := range configured.Unchecked() {
		if g.Name == "attachment liveness" {
			t.Error("a configured oracle is listed as unchecked")
		}
	}
}
