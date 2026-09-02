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
)

const (
	thisBoot  = "11111111-1111-1111-1111-111111111111"
	priorBoot = "22222222-2222-2222-2222-222222222222"
	thisNode  = "node-a"
	otherNode = "node-b"
)

// onBoot fixes which boot the provider believes it is running on, so a test can
// make a boot END — the one fact the orphan verdict rests on and the one thing
// a test cannot otherwise arrange.
func onBoot(id string) func(*Options) {
	return func(o *Options) { o.bootID = func() (string, error) { return id, nil } }
}

// unlockedBy renders the record a volume would carry.
func unlockedBy(node, boot string) string {
	return mappingOwner{Node: node, Boot: boot}.tag()
}

// mappedProvider builds a provider over one encrypted volume whose plaintext
// mapping is open, tagged with the given ownership record.
func mappedProvider(t *testing.T, tags []string, mutate ...func(*Options)) (*Provider, *fakeRunner) {
	t.Helper()
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true, Tags: tags}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data")

	opts := append([]func(*Options){onBoot(thisBoot)}, mutate...)
	return newTestProvider(t, runner, opts...), runner
}

// findingFor returns the single finding for the one volume these tests use.
func findingFor(t *testing.T, findings []MappingFinding) MappingFinding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly one: %+v", len(findings), findings)
	}
	return findings[0]
}

// TestReaperFindsAMappingFromAnEndedBoot is the case the reaper exists for: an
// init container attached, exited without tearing down, and the host has since
// rebooted. Nothing live can be holding the mapping, because a holder cannot
// survive the reboot of the host it was running on.
func TestReaperFindsAMappingFromAnEndedBoot(t *testing.T) {
	p, _ := mappedProvider(t, []string{unlockedBy(thisNode, priorBoot)})

	finding := findingFor(t, mustInspect(t, p))
	if finding.Verdict != VerdictOrphaned {
		t.Fatalf("verdict = %q, want %q: %s", finding.Verdict, VerdictOrphaned, finding)
	}
	if finding.BackingID == "" {
		t.Error("the finding does not carry the identity ownership rests on")
	}
	// The audit line has to say what it is and why, because a reaped mapping is
	// an event somebody reads afterwards rather than watches happen.
	for _, want := range []string{"bs-vg0_data", string(VerdictOrphaned), thisNode, priorBoot} {
		if !strings.Contains(finding.String(), want) {
			t.Errorf("the audit line does not mention %q: %s", want, finding)
		}
	}
}

// TestReaperLeavesThisBootsMappingAlone is the live case. The same node, the
// same boot: something may be using it this second.
func TestReaperLeavesThisBootsMappingAlone(t *testing.T) {
	p, runner := mappedProvider(t, []string{unlockedBy(thisNode, thisBoot)})

	finding := findingFor(t, mustInspect(t, p))
	if finding.Verdict != VerdictLive {
		t.Fatalf("verdict = %q, want %q", finding.Verdict, VerdictLive)
	}
	assertNothingClosed(t, runner)
}

// TestReaperLeavesAnotherNodesMappingAlone is the conjunct that turns a
// catastrophe into a no-op, and it is the reason the record carries a node at
// all.
//
// On shared storage the volume group is visible to every node. Another node's
// LIVE mapping was made on that node's boot, which never matches this node's —
// so a criterion resting on the boot alone would call it orphaned and tear down
// a volume somebody else's workload is using. Requiring the record to name THIS
// node first makes that unreachable.
func TestReaperLeavesAnotherNodesMappingAlone(t *testing.T) {
	p, runner := mappedProvider(t, []string{unlockedBy(otherNode, priorBoot)})

	finding := findingFor(t, mustInspect(t, p))
	if finding.Verdict != VerdictForeignNode {
		t.Fatalf("verdict = %q, want %q: %s", finding.Verdict, VerdictForeignNode, finding)
	}
	if !strings.Contains(finding.String(), otherNode) {
		t.Errorf("the finding does not name the node it belongs to: %s", finding)
	}
	assertNothingClosed(t, runner)
}

// TestReaperReportsWhatItCannotAttribute covers every way ownership fails to be
// established. None of them is an orphan, and none of them is touched:
// destroying a mapping this code cannot prove it created is worse than leaving
// one behind.
func TestReaperReportsWhatItCannotAttribute(t *testing.T) {
	cases := map[string]struct {
		tags   []string
		expect string
	}{
		"no record at all": {
			tags:   nil,
			expect: "no record of who unlocked it",
		},
		"a record that does not decompose": {
			tags:   []string{unlockedByTagPrefix + "garbage"},
			expect: "does not record a node and a boot",
		},
		"two records that disagree": {
			tags: []string{
				unlockedBy(thisNode, priorBoot),
				unlockedBy(otherNode, priorBoot),
			},
			expect: "carries 2 of them",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, runner := mappedProvider(t, tc.tags)

			finding := findingFor(t, mustInspect(t, p))
			if finding.Verdict != VerdictUnattributable {
				t.Fatalf("verdict = %q, want %q: %s", finding.Verdict, VerdictUnattributable, finding)
			}
			if !strings.Contains(finding.Reason, tc.expect) {
				t.Errorf("the reason does not say %q: %s", tc.expect, finding.Reason)
			}
			assertNothingClosed(t, runner)
		})
	}
}

// TestReaperRefusesAMappingOverAnotherDevice is the second of the two facts
// ownership needs. The name is the one this provider would have chosen, and the
// mapping decrypts something else — which is precisely the state a name-based
// reaper cannot see, and the reason a name is not evidence (go-luks2 #96).
func TestReaperRefusesAMappingOverAnotherDevice(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{unlockedBy(thisNode, priorBoot)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		// This provider's deterministic name, over somebody else's device.
		withMappingsBackedBy(map[string]string{"bs-vg0_data": "/dev/sdb1"})
	p := newTestProvider(t, runner, onBoot(thisBoot))

	finding := findingFor(t, mustInspect(t, p))
	if finding.Verdict != VerdictUnattributable {
		t.Fatalf("verdict = %q, want %q: %s", finding.Verdict, VerdictUnattributable, finding)
	}
	if !strings.Contains(finding.Reason, "not this volume") {
		t.Errorf("the reason does not say the mapping decrypts something else: %s", finding.Reason)
	}
	assertNothingClosed(t, runner)
}

// TestReaperReportsButDoesNotRemoveByDefault pins the default. Reporting is
// useful on its own and cannot destroy anything; removal is opt-in.
func TestReaperReportsButDoesNotRemoveByDefault(t *testing.T) {
	p, runner := mappedProvider(t, []string{unlockedBy(thisNode, priorBoot)})

	finding := findingFor(t, mustInspect(t, p))
	if finding.Verdict != VerdictOrphaned {
		t.Fatalf("verdict = %q, want the orphan to be FOUND", finding.Verdict)
	}
	assertNothingClosed(t, runner)
}

// TestReaperSaysNothingAboutAVolumeWithNoMapping is the ordinary state of most
// volumes and must not appear in a report at all — a report full of healthy
// rows is one nobody reads.
func TestReaperSaysNothingAboutAVolumeWithNoMapping(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": "ext4"})
	p := newTestProvider(t, runner, onBoot(thisBoot))

	findings := mustInspect(t, p)
	if len(findings) != 0 {
		t.Fatalf("got %d findings for a volume with no mapping: %+v", len(findings), findings)
	}
}

// TestReaperRefusesToSweepWithoutKnowingWhoItIs is the fail-closed direction on
// the reaper's own inputs. Without a boot ID there is no verdict to reach, and
// an empty report would read as "no orphans" — the fail-open this whole guard
// exists to remove.
func TestReaperRefusesToSweepWithoutKnowingWhoItIs(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, func(o *Options) {
		o.bootID = func() (string, error) { return "", errors.New("/proc is not mounted") }
	})

	if _, err := p.InspectMappings(context.Background()); err == nil {
		t.Fatal("the reaper swept without knowing which boot it is on")
	}
}

// TestRunReaperSweepsOnceBeforeTheFirstTick covers the startup sweep. The
// orphans this finds were made by something that already died, so they are
// present the moment the process starts; waiting a whole interval to look would
// be waiting for nothing.
func TestRunReaperSweepsOnceBeforeTheFirstTick(t *testing.T) {
	p, _ := mappedProvider(t, []string{unlockedBy(thisNode, priorBoot)})

	ctx, cancel := context.WithCancel(context.Background())
	sweeps := make(chan []MappingFinding, 4)
	tick := make(chan struct{})

	done := make(chan error, 1)
	go func() {
		done <- p.RunReaper(ctx, tick, func(f []MappingFinding, _ error) { sweeps <- f })
	}()

	first := <-sweeps
	if len(Orphaned(first)) != 1 {
		t.Errorf("the startup sweep found %d orphans, want 1", len(Orphaned(first)))
	}

	tick <- struct{}{}
	if len(Orphaned(<-sweeps)) != 1 {
		t.Error("the sweep after a tick found no orphan")
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("RunReaper = %v, want it to stop on the context", err)
	}
}

// TestRunReaperStopsWhenTheTickerIsClosed covers the other way a component
// shuts it down.
func TestRunReaperStopsWhenTheTickerIsClosed(t *testing.T) {
	p, _ := mappedProvider(t, []string{unlockedBy(thisNode, thisBoot)})

	tick := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- p.RunReaper(context.Background(), tick, nil) }()

	close(tick)
	if err := <-done; err != nil {
		t.Errorf("RunReaper = %v, want nil when the ticker is closed", err)
	}
}

// TestAttachRecordsWhoUnlockedIt is the write half of the record, and the
// ORDER is the property: the record has to exist before the mapping does, or it
// is missing for exactly the mappings that outlive their owner.
func TestAttachRecordsWhoUnlockedIt(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	p := newTestProvider(t, runner, withKey, onBoot(thisBoot))

	if _, err := p.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	lines := runner.lines()
	recordAt, openAt := -1, -1
	for i, line := range lines {
		if strings.Contains(line, unlockedByTagPrefix) {
			recordAt = i
		}
		if strings.HasPrefix(line, luksBinary+" open ") {
			openAt = i
		}
	}
	if recordAt < 0 {
		t.Fatalf("no ownership record was written; ran:\n  %s", strings.Join(lines, "\n  "))
	}
	if openAt < 0 || recordAt > openAt {
		t.Errorf("the record must be written BEFORE the mapping; record at %d, open at %d", recordAt, openAt)
	}
}

func mustInspect(t *testing.T, p *Provider) []MappingFinding {
	t.Helper()
	findings, err := p.InspectMappings(context.Background())
	if err != nil {
		t.Fatalf("InspectMappings: %v", err)
	}
	return findings
}

// assertNothingClosed is the assertion most of this file rests on: whatever the
// reaper concluded, it removed nothing.
func assertNothingClosed(t *testing.T, runner *fakeRunner) {
	t.Helper()
	for _, line := range runner.lines() {
		if strings.HasPrefix(line, luksBinary+" close ") {
			t.Fatalf("a mapping was closed: %q", line)
		}
	}
}

// TestARecordIsReplacedRatherThanJoined covers the state that would silence the
// guard permanently. A stale record can survive — an unlock that failed after
// the tag was written, a close whose removal did not land — and a second record
// beside it reads as unreadable from then on, so every future orphan of this
// volume would be unattributable and never reaped.
func TestARecordIsReplacedRatherThanJoined(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{unlockedBy(thisNode, priorBoot)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	p := newTestProvider(t, runner, withKey, onBoot(thisBoot))

	if _, err := p.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// One lvchange that removes the stale record and writes the new one, rather
	// than an --addtag that leaves two behind.
	assertLine(t, runner, "lvchange --deltag "+unlockedBy(thisNode, priorBoot)+
		" --addtag "+unlockedBy(thisNode, thisBoot)+" vg0/data")
}

// TestARecordWithAnExtraSeparatorIsNotARecord is the parse that would make a
// LIVE mapping look reapable. strings.Cut splits at the first separator, so
// "node:boot:x" would yield a Boot of "boot:x" — matching no real boot, which
// reads as a boot that has ended.
func TestARecordWithAnExtraSeparatorIsNotARecord(t *testing.T) {
	malformed := unlockedByTagPrefix + thisNode + unlockedByTagSeparator +
		thisBoot + unlockedByTagSeparator + "x"
	p, runner := mappedProvider(t, []string{malformed})

	finding := findingFor(t, mustInspect(t, p))
	if finding.Verdict != VerdictUnattributable {
		t.Fatalf("verdict = %q, want %q: %s", finding.Verdict, VerdictUnattributable, finding)
	}
	assertNothingClosed(t, runner)
}

// TestAttachRefreshesTheRecordWhenItAdoptsAnOpenMapping closes the hole the
// locked recheck alone leaves.
//
// The recheck reads the RECORD. An Attach that finds a mapping already open and
// hands it to a workload without refreshing that record makes the mapping live
// while the volume still says it was unlocked on a boot that ended — and the
// reaper, reading the record, closes it. The attach is what makes a mapping
// live, so the attach is what has to say so.
func TestAttachRefreshesTheRecordWhenItAdoptsAnOpenMapping(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{unlockedBy(thisNode, priorBoot)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		// Already open: the attach adopts it rather than unlocking.
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey, onBoot(thisBoot))

	if _, err := p.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	assertNoLine(t, runner, luksBinary+" open /dev/vg0/data bs-vg0_data")
	assertLine(t, runner, "lvchange --deltag "+unlockedBy(thisNode, priorBoot)+
		" --addtag "+unlockedBy(thisNode, thisBoot)+" vg0/data")
}

// TestAttachSurvivesAFailedFirstRecord keeps the ordinary degradation intact: a
// volume with NO record that cannot be given one attaches, and the mapping is
// simply unattributable — reported, never reaped.
func TestAttachSurvivesAFailedFirstRecord(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS})
	runner.on("lvchange", func(args []string, _ []byte) ([]byte, error) {
		if contains(args, "--addtag") {
			return nil, &ExitError{Name: "lvchange", Args: args, Code: 5,
				Stderr: "Volume group \"vg0\" metadata is read-only"}
		}
		return nil, nil
	})
	p := newTestProvider(t, runner, withKey, onBoot(thisBoot))

	if _, err := p.Attach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Attach = %v, want nil: no record is unattributable, which is safe", err)
	}
}

// TestDetachClearsTheOwnershipRecord covers the ORDINARY teardown path, which
// is where the record is cleared almost every time it is cleared at all.
//
// The reaper's own teardown clears it too, and that path had a test while this
// one did not — so a regression here would have been invisible until it
// mattered: a clean detach leaving a stale record makes the reaper misclassify
// that volume's next mapping — reporting a live one as an orphan.
func TestDetachClearsTheOwnershipRecord(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{unlockedBy(thisNode, thisBoot)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey, onBoot(thisBoot))

	if err := p.Detach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	assertLine(t, runner, luksBinary+" close bs-vg0_data")
	assertLine(t, runner, "lvchange --deltag "+unlockedBy(thisNode, thisBoot)+" vg0/data")
}

// TestDeleteClearsTheOwnershipRecord covers the other caller of the same close.
//
// Delete removes the volume, so a leftover tag has nothing to mislead — but it
// reaches the clearing through the same code as Detach, and a test that pins
// only one of the two callers leaves the shared path half covered.
func TestDeleteClearsTheOwnershipRecord(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{
			Name: "data", SizeBytes: gib, Active: true,
			Tags: []string{unlockedBy(thisNode, thisBoot)},
		}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey, onBoot(thisBoot))

	if err := p.Delete(context.Background(), "data"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertLine(t, runner, "lvchange --deltag "+unlockedBy(thisNode, thisBoot)+" vg0/data")
}

// TestDetachLeavesNoRecordToClearAlone keeps the clearing idempotent: a volume
// with no record must not produce an empty --deltag, which lvchange would
// refuse and which would turn a clean detach into a failure.
func TestDetachLeavesNoRecordToClearAlone(t *testing.T) {
	runner := newFakeRunner().
		withLVs(lvFixture{Name: "data", SizeBytes: gib, Active: true}).
		withBlkid(map[string]string{"/dev/vg0/data": fsTypeLUKS}).
		withOpenMappings("bs-vg0_data")
	p := newTestProvider(t, runner, withKey, onBoot(thisBoot))

	if err := p.Detach(context.Background(), "data", "node-a"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	for _, line := range runner.lines() {
		if strings.Contains(line, "--deltag") && strings.Contains(line, unlockedByTagPrefix) {
			t.Errorf("a volume with no record still had one removed: %q", line)
		}
	}
}
