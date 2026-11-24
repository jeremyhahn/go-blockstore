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

package mountinfo

import (
	"strings"
	"testing"
)

// unsupportedReason separates UNSUPPORTED child failures from wrong answers and returns the child's message.
func unsupportedReason(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if i := strings.Index(line, "UNSUPPORTED: "); i >= 0 {
			return strings.TrimSpace(line[i+len("UNSUPPORTED: "):])
		}
	}
	switch {
	case strings.TrimSpace(output) == "":
		return "the child produced no output at all, which is what a kernel refusing CLONE_NEWUSER looks like"
	case strings.Contains(output, "operation not permitted"),
		strings.Contains(output, "permission denied"):
		return "creating a user or mount namespace was not permitted"
	}
	return ""
}

// TestUnsupportedReasonNamesTheRefusedStep checks the classification on the child's real output shapes; untagged because it needs no kernel.
func TestUnsupportedReasonNamesTheRefusedStep(t *testing.T) {
	cases := map[string]struct {
		output string
		want   string
	}{
		"a mount the namespace would not permit": {
			output: "=== RUN   TestX\n    f_test.go:1: UNSUPPORTED: mounting tmpfs at /tmp/x: operation not permitted\n--- FAIL: TestX\n",
			want:   "mounting tmpfs at /tmp/x: operation not permitted",
		},
		"a child that never started": {
			output: "",
			want:   "the child produced no output at all, which is what a kernel refusing CLONE_NEWUSER looks like",
		},
		"a clone refused before any test ran": {
			output: "fork/exec /proc/self/exe: operation not permitted\n",
			want:   "creating a user or mount namespace was not permitted",
		},
		"a genuine wrong answer is NOT a skip": {
			output: "=== RUN   TestX\n    f_test.go:1: VisibleMountPointsFor(0:87) = [/tmp/x], want none\n--- FAIL: TestX\n",
			want:   "",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := unsupportedReason(c.output); got != c.want {
				t.Errorf("unsupportedReason = %q, want %q", got, c.want)
			}
		})
	}
}
