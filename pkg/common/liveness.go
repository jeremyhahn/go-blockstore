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
	"fmt"
)

// Liveness is an oracle's answer about one attachment: whether the thing that
// attached the volume is still there.
//
// It is a two-valued enumeration and NOT a bool, for a reason that is about the
// zero value rather than about style. The dangerous answer is "no owner" —
// that is the one a caller may act on by tearing a mapping down — and with a
// bool it is exactly what an implementation returns when it returns nothing:
// a method with a bare `return` on some path, a struct with an unimplemented
// case, a value decoded from an empty record. The zero value of this type is
// "", which is neither answer, and every path here refuses it. The direction
// that costs a live workload its volume therefore has to be written out on
// purpose.
type Liveness string

const (
	// LivenessHeld means the attachment still has an owner and that owner is
	// alive. Whatever the deployment counts as an owner — a lease holder, a pod
	// that has not been deleted — it exists right now.
	LivenessHeld Liveness = "held"

	// LivenessReleased means the attachment's owner is gone: it existed and it
	// does not any more, or the deployment can prove there never was one.
	//
	// This is the only answer that makes an attachment reclaimable, so an
	// implementation returns it only from a POSITIVE observation. "I looked and
	// found nothing" is an observation; "I could not look" is not, and belongs
	// in the error return.
	LivenessReleased Liveness = "released"
)

// Valid reports whether l is one of the two answers this library recognizes.
//
// Anything else — the zero value most of all — is indeterminate, and callers
// route it to ErrLivenessIndeterminate rather than picking whichever branch it
// falls into.
func (l Liveness) Valid() bool { return l == LivenessHeld || l == LivenessReleased }

// ErrLivenessIndeterminate reports that an oracle could not establish whether
// an attachment's owner is still there.
//
// It is a FAILURE and not a shrug, on the same reasoning package preflight
// applies to its own probes: a guard that reports success when its own check
// broke converts an unknown into a green light. "Could not determine" is
// therefore never folded into LivenessReleased — the answer that permits
// reclaiming an attachment — and never quietly into LivenessHeld either, which
// would make an outage of the oracle look like a fleet with no orphans.
var ErrLivenessIndeterminate = errors.New("go-blockstore: whether an attachment's owner is still alive could not be determined")

// LivenessOracle answers whether the attachment of a volume still has a live
// owner.
//
// It is a SEAM, not a mechanism. Whether an attachment has a liveness owner at
// all is a property of how a system is DEPLOYED and not of what a block
// provider does: pkg/ha holds a per-volume lease and can answer from it; a CSI
// node plugin answers from the pod that consumes the staged volume; a provider
// driving local disks on a host that runs nothing else has no such notion and
// supplies no oracle. Deciding the question inside a provider would bake one
// deployment's assumption into a library every deployment consumes, so the
// provider exposes the question and the deployment answers it — the same shape
// as Coordinator, which is declared here and implemented by whatever consensus
// store the deployment happens to run.
//
// Implementations MUST fail closed. An oracle that cannot reach its coordinator,
// cannot read its API server, or does not recognize the volume returns an error
// — wrapping ErrLivenessIndeterminate where the distinction is worth
// preserving — rather than reporting LivenessReleased, which a caller may act
// on by tearing down a mapping a live workload is using.
//
// volID is the provider's own volume identifier, the same string passed to
// Attach. An implementation that keys its records by something else maps it,
// and answers with an error for an identifier it cannot map rather than
// treating an unrecognized volume as unowned.
type LivenessOracle interface {
	AttachmentLiveness(ctx context.Context, volID string) (Liveness, error)
}

// LivenessOf asks oracle about volID and returns an answer that is safe to
// branch on, or an error matching ErrLivenessIndeterminate.
//
// It exists so that "indeterminate is a failure" is enforced in ONE place
// rather than re-derived by every consumer, and it collapses the three ways an
// oracle can decline to answer into that single condition:
//
//   - a nil oracle, so a caller that forgot to check gets a refusal rather than
//     a panic or an accidental zero value;
//   - a non-nil error, whatever the returned Liveness beside it says — a value
//     accompanying an error is not an answer, and returning it would let an
//     implementation's zero value through on its failure path;
//   - a value outside the two this package defines, the zero value included.
func LivenessOf(ctx context.Context, oracle LivenessOracle, volID string) (Liveness, error) {
	if oracle == nil {
		return "", fmt.Errorf("%w: no liveness oracle is configured", ErrLivenessIndeterminate)
	}

	state, err := oracle.AttachmentLiveness(ctx, volID)
	if err != nil {
		// The oracle's own error is wrapped rather than replaced: it names the
		// coordinator that was unreachable or the record that would not parse,
		// and that is what somebody fixes. Any state returned beside it is
		// dropped, because an implementation that failed had nothing to report.
		if errors.Is(err, ErrLivenessIndeterminate) {
			return "", err
		}
		return "", fmt.Errorf("%w: %w", ErrLivenessIndeterminate, err)
	}
	if !state.Valid() {
		return "", fmt.Errorf("%w: the oracle answered %q, which is neither %q nor %q",
			ErrLivenessIndeterminate, string(state), string(LivenessHeld), string(LivenessReleased))
	}
	return state, nil
}
