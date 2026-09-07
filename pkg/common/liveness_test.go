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

package common

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// oracleFunc adapts a function to the seam, so a test can describe one answer
// without a type per case.
type oracleFunc func(ctx context.Context, volID string) (Liveness, error)

func (f oracleFunc) AttachmentLiveness(ctx context.Context, volID string) (Liveness, error) {
	return f(ctx, volID)
}

// silentOracle is an implementation that answers nothing at all — a method with
// a bare return, which is what a half-written or an unimplemented case looks
// like. It is the zero value this type exists to make safe.
type silentOracle struct{}

func (silentOracle) AttachmentLiveness(context.Context, string) (Liveness, error) { return "", nil }

// TestLivenessOfRefusesEveryAnswerThatIsNotOne is the whole contract in one
// table: exactly two values are answers, and every other way an oracle can
// respond is a failure that matches ErrLivenessIndeterminate.
//
// The rows that matter most are the last two. An implementation that returns
// nothing, and one that returns a value BESIDE an error, are the two ways a
// zero value reaches a caller by accident — and the zero value must never
// arrive as "released", the answer somebody may act on by tearing a live
// workload's mapping down.
func TestLivenessOfRefusesEveryAnswerThatIsNotOne(t *testing.T) {
	backendDown := errors.New("the coordinator is unreachable")

	cases := map[string]struct {
		oracle LivenessOracle
		want   Liveness
		wantIn string // substring the refusal must carry, when it refuses
	}{
		"a live owner": {
			oracle: oracleFunc(func(context.Context, string) (Liveness, error) { return LivenessHeld, nil }),
			want:   LivenessHeld,
		},
		"an owner that has gone": {
			oracle: oracleFunc(func(context.Context, string) (Liveness, error) { return LivenessReleased, nil }),
			want:   LivenessReleased,
		},
		"no oracle at all": {
			oracle: nil,
			wantIn: "no liveness oracle is configured",
		},
		"an oracle that failed": {
			oracle: oracleFunc(func(context.Context, string) (Liveness, error) { return "", backendDown }),
			wantIn: backendDown.Error(),
		},
		"an oracle that answered nothing": {
			oracle: silentOracle{},
			wantIn: `answered ""`,
		},
		"an oracle that answered something else": {
			oracle: oracleFunc(func(context.Context, string) (Liveness, error) { return "probably", nil }),
			wantIn: `answered "probably"`,
		},
		"a value returned beside an error": {
			// The dangerous shape: an implementation whose failure path fills in
			// the reclaimable answer. The error wins and the value is dropped.
			oracle: oracleFunc(func(context.Context, string) (Liveness, error) {
				return LivenessReleased, backendDown
			}),
			wantIn: backendDown.Error(),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := LivenessOf(context.Background(), tc.oracle, "data")

			if tc.want != "" {
				if err != nil {
					t.Fatalf("LivenessOf: %v", err)
				}
				if got != tc.want {
					t.Fatalf("liveness = %q, want %q", got, tc.want)
				}
				return
			}

			if err == nil {
				t.Fatalf("LivenessOf returned %q and no error; not answering must be a failure", got)
			}
			if !errors.Is(err, ErrLivenessIndeterminate) {
				t.Errorf("the refusal does not match ErrLivenessIndeterminate: %v", err)
			}
			if got != "" {
				t.Errorf("a refusal carried the answer %q; a failed oracle answered nothing", got)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("the refusal does not say %q: %v", tc.wantIn, err)
			}
		})
	}
}

// TestLivenessOfKeepsTheOraclesOwnError pins that the wrapping preserves what an
// operator has to act on. The sentinel says the check broke; the wrapped error
// names the coordinator that was unreachable, and that is what gets fixed.
func TestLivenessOfKeepsTheOraclesOwnError(t *testing.T) {
	backendDown := errors.New("the coordinator is unreachable")
	oracle := oracleFunc(func(context.Context, string) (Liveness, error) { return "", backendDown })

	_, err := LivenessOf(context.Background(), oracle, "data")
	if !errors.Is(err, backendDown) {
		t.Errorf("the oracle's own error did not survive the wrapping: %v", err)
	}
	if !errors.Is(err, ErrLivenessIndeterminate) {
		t.Errorf("the refusal does not match the sentinel: %v", err)
	}
}

// TestLivenessOfDoesNotDoubleWrapItsOwnSentinel covers an oracle that already
// speaks this vocabulary — the expected case for one built on a Coordinator,
// which knows perfectly well that an unreachable backend is indeterminate. Its
// message is passed through rather than prefixed with the same sentence twice.
func TestLivenessOfDoesNotDoubleWrapItsOwnSentinel(t *testing.T) {
	own := errors.New("wrapped")
	oracle := oracleFunc(func(context.Context, string) (Liveness, error) {
		return "", errors.Join(ErrLivenessIndeterminate, own)
	})

	_, err := LivenessOf(context.Background(), oracle, "data")
	if !errors.Is(err, ErrLivenessIndeterminate) || !errors.Is(err, own) {
		t.Fatalf("the refusal lost one of its halves: %v", err)
	}
	if n := strings.Count(err.Error(), ErrLivenessIndeterminate.Error()); n != 1 {
		t.Errorf("the sentinel's text appears %d times, want 1: %v", n, err)
	}
}

// TestLivenessOfPassesTheVolumeThrough pins the one argument the seam carries.
// An oracle keyed by volume cannot answer about a volume it was never told.
func TestLivenessOfPassesTheVolumeThrough(t *testing.T) {
	var asked string
	oracle := oracleFunc(func(_ context.Context, volID string) (Liveness, error) {
		asked = volID
		return LivenessHeld, nil
	})

	if _, err := LivenessOf(context.Background(), oracle, "data"); err != nil {
		t.Fatalf("LivenessOf: %v", err)
	}
	if asked != "data" {
		t.Errorf("the oracle was asked about %q, want %q", asked, "data")
	}
}

// TestLivenessValidRejectsTheZeroValue is the property the enumeration was
// chosen for. A bool's zero value is a decision; this one's is not an answer.
func TestLivenessValidRejectsTheZeroValue(t *testing.T) {
	var zero Liveness
	if zero.Valid() {
		t.Error("the zero value is a valid answer; the type has lost the property it exists for")
	}
	for _, l := range []Liveness{LivenessHeld, LivenessReleased} {
		if !l.Valid() {
			t.Errorf("%q is not valid", l)
		}
	}
	if Liveness("released ").Valid() {
		t.Error("a near miss is accepted as an answer")
	}
}
