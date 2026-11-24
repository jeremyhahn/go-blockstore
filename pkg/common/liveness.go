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

// Liveness is an oracle's answer about one attachment; its zero value is neither answer and is refused.
type Liveness string

const (
	// LivenessHeld means the attachment still has an owner and that owner is
	// alive. Whatever the deployment counts as an owner — a lease holder, a pod
	// that has not been deleted — it exists right now.
	LivenessHeld Liveness = "held"

	// LivenessReleased means the owner is gone; return it only from a positive observation.
	LivenessReleased Liveness = "released"
)

// Valid reports whether l is one of the two answers; anything else is indeterminate.
func (l Liveness) Valid() bool { return l == LivenessHeld || l == LivenessReleased }

// ErrLivenessIndeterminate reports that an oracle could not establish whether an attachment's owner is still there.
var ErrLivenessIndeterminate = errors.New("go-blockstore: whether an attachment's owner is still alive could not be determined")

// LivenessOracle answers whether a volume's attachment still has a live owner; the deployment supplies it.
// Implementations must fail closed: an error, never LivenessReleased, when they cannot tell. volID is the provider's volume ID.
type LivenessOracle interface {
	AttachmentLiveness(ctx context.Context, volID string) (Liveness, error)
}

// LivenessOf asks oracle about volID and returns a safe answer or an error matching ErrLivenessIndeterminate (nil oracle, an error, or an unknown value).
func LivenessOf(ctx context.Context, oracle LivenessOracle, volID string) (Liveness, error) {
	if oracle == nil {
		return "", fmt.Errorf("%w: no liveness oracle is configured", ErrLivenessIndeterminate)
	}

	state, err := oracle.AttachmentLiveness(ctx, volID)
	if err != nil {
		// Wrap the oracle's error, which names what to fix, and drop any state returned beside it.
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
