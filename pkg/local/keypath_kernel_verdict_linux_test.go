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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// The live-kernel check in keypath_kernel_linux_test.go re-execs itself into a
// user + mount namespace. It can fail to produce an answer two ways, and they
// must stay distinguishable:
//
//   - THE HOST REFUSED THE NAMESPACE — the capability the kernel_keypath tag
//     says this host has, it does not have;
//   - IT RAN AND THE ANSWER WAS WRONG — the substitution behaved differently
//     from what the guard is built on.
//
// Both are failures. Selecting the tag is a statement that this host provides
// the capability, so a refusal is a broken claim rather than an excuse, and
// NEITHER reports success (conventions/testing-guidelines.md §No Skip Guards;
// `internal/guards` refuses a runtime skip anywhere in the tree).
//
// THIS FILE IS DELIBERATELY UNTAGGED. The decision above is ordinary logic that
// needs no privilege to exercise, and it is the part that shipped broken: the
// classifier read only the child's OUTPUT, so a runner that refuses the
// namespace at exec — producing no output at all — was reported as a check that
// had FAILED rather than as a host that had refused. Every developer host
// permits the re-exec, so no local run could reach that branch. Gating these
// tests behind the tag too would put them back out of reach of exactly the
// environment that found the defect.

// requireKernelChecksTag names the build tag that selects the live-kernel
// check, so the refusal message can tell an operator what they asked for.
const requireKernelChecksTag = "kernel_keypath"

// kernelCheckReporter is the part of *testing.T the relaunch reports through,
// so the choice between the two failure messages is itself testable.
//
// Driving *testing.T directly means the only way to exercise that choice is to
// BE on a host that makes it, which is how the wrong branch shipped.
type kernelCheckReporter interface {
	Helper()
	Logf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// hostRefusedTheNamespace reports why the host would not run the check, or ""
// when the child ran and gave a real answer.
//
// THE DISCRIMINATOR IS WHETHER THE CHILD RAN, and it is taken from the error's
// TYPE, not from its text. exec returns *exec.ExitError only when a process
// started and exited non-zero. A namespace refused at clone/exec time never
// starts one: os.StartProcess hands back the syscall error and there is NO
// OUTPUT AT ALL to classify.
//
// That is the defect this replaced. The previous version read only the child's
// OUTPUT, so a container that refuses CLONE_NEWUSER|CLONE_NEWNS at exec
// produced an empty string to classify and fell through to "the kernel check
// failed" — reporting a host that would not run the check as a check that had
// failed. The classifier was narrower than the condition it classified, and its
// own doc comment named the case it did not handle.
//
// Both shapes measured on this host:
//
//	CLONE_NEWNS as uid 1000 -> output "", err *fs.PathError
//	    "fork/exec /bin/true: operation not permitted"
//	    errors.As(*exec.ExitError) = false, errors.Is(EPERM) = true
//	a child that ran and exited 1 -> output present, err *exec.ExitError
//
// A child that RAN and failed keeps its own message. An *exec.ExitError counts
// as a refusal only when the child MARKED the step it was denied with
// UNSUPPORTED, which it does for the mounts it makes once already inside the
// namespace.
func hostRefusedTheNamespace(err error, output string) string {
	if err == nil {
		return ""
	}

	// The child started, reached a step it was not permitted, and said so.
	for _, line := range strings.Split(output, "\n") {
		if i := strings.Index(line, "UNSUPPORTED: "); i >= 0 {
			return strings.TrimSpace(line[i+len("UNSUPPORTED: "):])
		}
	}

	// The child ran. A failure it did not mark is a real answer, wrong.
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		return ""
	}

	// The child never started. Only the REFUSAL shapes count: a harness broken
	// some other way — the binary missing, a bad path — must be reported as the
	// check failing rather than excused as an unsupported host. ENOSPC is here
	// because that is what clone(2) returns when the user-namespace limit is
	// exhausted, a refusal wearing an unlikely name.
	for _, refusal := range []error{
		os.ErrPermission, syscall.EPERM, syscall.EACCES,
		syscall.EINVAL, syscall.ENOSYS, syscall.ENOSPC,
	} {
		if errors.Is(err, refusal) {
			return "the test binary could not be re-executed in a new user + mount namespace: " + err.Error()
		}
	}
	return ""
}

// reportKernelChildResult turns the child's outcome into a verdict.
//
// Neither failure path reports success, and they carry different messages so an
// operator can tell "this host cannot do what the tag claims" from "the kernel
// behaved differently from what the guard assumes". Every branch returns
// explicitly: with a real *testing.T Fatalf does not return, but this is driven
// by a recording reporter in its own tests, where a missing return would run
// two branches for one outcome.
func reportKernelChildResult(t kernelCheckReporter, output string, err error) {
	t.Helper()

	if err == nil {
		t.Logf("child ran in a user + mount namespace on this kernel:\n%s", indentChildOutput(output))
		return
	}

	if reason := hostRefusedTheNamespace(err, output); reason != "" {
		t.Fatalf("this host refused the namespace the %s tag says it provides: %s\n"+
			"THE SUBSTITUTION WAS NOT MEASURED. Either run this where an unprivileged user + mount "+
			"namespace can be created, or do not select the tag — do not report it as a pass "+
			"(conventions/testing-guidelines.md §No Skip Guards).\nchild output:\n%s",
			requireKernelChecksTag, reason, indentChildOutput(output))
		return
	}
	t.Fatalf("the kernel check failed: %v\n%s", err, indentChildOutput(output))
}

// indentChildOutput sets the child's output apart from the parent's, so a
// failure reads as two reports rather than one run together.
func indentChildOutput(output string) string {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	for i := range lines {
		lines[i] = "    | " + lines[i]
	}
	return strings.Join(lines, "\n")
}

// recordingReporter captures a verdict instead of acting on it, so a test can
// assert which branch fired without itself failing.
type recordingReporter struct {
	failed  bool
	logged  bool
	message string
}

func (r *recordingReporter) Helper() {}

func (r *recordingReporter) Logf(format string, args ...any) {
	r.logged, r.message = true, fmt.Sprintf(format, args...)
}

func (r *recordingReporter) Fatalf(format string, args ...any) {
	r.failed, r.message = true, fmt.Sprintf(format, args...)
}

func (r *recordingReporter) verdict() string {
	switch {
	case r.failed:
		return "FAIL"
	case r.logged:
		return "PASS"
	}
	return "none"
}

// execRefusedEPERM is the error shape a host that refuses the namespace hands
// back, reproduced exactly as measured: os.StartProcess never starts a process,
// so it is an *fs.PathError wrapping EPERM and NOT an *exec.ExitError.
//
// TestTheMeasuredRefusalHasTheShapeThisFileAssumes checks that against the
// kernel, so the table below is not a guess about it.
func execRefusedEPERM() error {
	return &fs.PathError{Op: "fork/exec", Path: "/tmp/go-build/local.test", Err: syscall.EPERM}
}

// ranAndFailed builds a REAL *exec.ExitError from a child that started, wrote
// something and exited non-zero — the shape of a kernel check whose assertion
// was wrong.
func ranAndFailed(t *testing.T, childOutput string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "cat; exit 1")
	cmd.Stdin = strings.NewReader(childOutput)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the fixture child exited 0; it must fail for this to be the failure case")
	}
	var exited *exec.ExitError
	if !errors.As(err, &exited) {
		t.Fatalf("the fixture child produced %T, want *exec.ExitError: this test needs a child that RAN", err)
	}
	return string(output), err
}

// TestTheVerdictOnEachChildOutcome pins every outcome, and pins that the two
// failures stay distinguishable.
func TestTheVerdictOnEachChildOutcome(t *testing.T) {
	realFailureOutput, realFailureErr := ranAndFailed(t,
		"keypath_kernel_linux_test.go:200: after the mount the check = <nil>, want ErrKeyFileInsideVolume\n")
	markedOutput, markedErr := ranAndFailed(t,
		"    keypath_kernel_linux_test.go:169: UNSUPPORTED: mounting tmpfs at /tmp/x/mnt: operation not permitted\n")

	cases := map[string]struct {
		output  string
		err     error
		want    string
		mustSay string
		mustNot string
	}{
		// The case CI took, and the one the old classifier got wrong: it must
		// be reported as the HOST refusing, not as the check having failed.
		"the host refused the re-exec": {
			output: "", err: execRefusedEPERM(),
			want: "FAIL", mustSay: "refused the namespace the kernel_keypath tag says it provides",
			mustNot: "the kernel check failed",
		},
		// THE CONTROL. The child ran and the answer was wrong: it keeps its own
		// message and must not be dressed up as an unsupported host, which
		// would excuse a real defect.
		"the check ran and the answer was wrong": {
			output: realFailureOutput, err: realFailureErr,
			want: "FAIL", mustSay: "the kernel check failed",
			mustNot: "refused the namespace",
		},
		// The child got inside the namespace and was denied a step there. It
		// marks that itself, and the refusal repeats its words.
		"the child marked its own refusal": {
			output: markedOutput, err: markedErr,
			want: "FAIL", mustSay: "mounting tmpfs",
			mustNot: "the kernel check failed",
		},
		// A harness broken some other way is not an unsupported host.
		"the test binary is missing": {
			output: "", err: &fs.PathError{Op: "fork/exec", Path: "/nope", Err: syscall.ENOENT},
			want: "FAIL", mustSay: "the kernel check failed",
			mustNot: "refused the namespace",
		},
		"the child ran and passed": {
			output: "PASS\n", err: nil,
			want: "PASS", mustSay: "child ran in a user + mount namespace",
			mustNot: "the kernel check failed",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := &recordingReporter{}
			reportKernelChildResult(r, tc.output, tc.err)
			if got := r.verdict(); got != tc.want {
				t.Fatalf("verdict = %s, want %s\nmessage: %s", got, tc.want, r.message)
			}
			if !strings.Contains(r.message, tc.mustSay) {
				t.Errorf("the message does not say %q: %s", tc.mustSay, r.message)
			}
			if strings.Contains(r.message, tc.mustNot) {
				t.Errorf("the message says %q, which is the other failure mode: %s", tc.mustNot, r.message)
			}
		})
	}
}

// TestARefusalSaysTheMeasurementDidNotHappen keeps a refused host from reading
// as a check that ran.
//
// It has to name what was NOT measured and what the operator asked for by
// selecting the tag. A refusal that only says "operation not permitted" leaves
// the reader to work out that the substitution went unchecked.
func TestARefusalSaysTheMeasurementDidNotHappen(t *testing.T) {
	r := &recordingReporter{}
	reportKernelChildResult(r, "", execRefusedEPERM())

	if !r.failed {
		t.Fatalf("verdict = %s, want FAIL", r.verdict())
	}
	for _, want := range []string{
		"THE SUBSTITUTION WAS NOT MEASURED",
		requireKernelChecksTag,
		"No Skip Guards",
	} {
		if !strings.Contains(r.message, want) {
			t.Errorf("the refusal does not say %q: %s", want, r.message)
		}
	}
}

// TestTheMeasuredRefusalHasTheShapeThisFileAssumes checks the instrument.
//
// Everything above rests on one claim about the kernel: a namespace refused at
// clone/exec time produces NO OUTPUT and an error that is not an
// *exec.ExitError. That claim is exactly what the previous classifier got
// wrong, so it is asserted against the kernel rather than assumed — by asking
// for CLONE_NEWNS without CLONE_NEWUSER as an unprivileged user, which is
// refused at the same moment a container refuses CLONE_NEWUSER|CLONE_NEWNS.
//
// Running as root the request SUCCEEDS and there is no refusal here to measure.
// That is not a skip: the test still runs and still asserts the branch it can
// see — that a success is not classified as a refusal — and says which half it
// took, so a reader is never left thinking the shape was re-measured when it
// was not.
func TestTheMeasuredRefusalHasTheShapeThisFileAssumes(t *testing.T) {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	output, err := cmd.CombinedOutput()

	if err == nil {
		if reason := hostRefusedTheNamespace(nil, ""); reason != "" {
			t.Errorf("a successful re-exec was classified as a refusal (%q)", reason)
		}
		t.Logf("this host permits CLONE_NEWNS unprivileged (uid %d), so the REFUSAL shape was not "+
			"re-measured here; the table above still pins the classification", syscall.Getuid())
		return
	}

	if len(output) != 0 {
		t.Errorf("a refused re-exec produced %q; this file classifies it as having no output", string(output))
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		t.Errorf("a refused re-exec produced an *exec.ExitError (%v); the discriminator between "+
			"'would not run' and 'ran and failed' is exactly that it does not", err)
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("a refused re-exec produced %v, which is not EPERM; the refusal list needs its shape", err)
	}

	// And the verdict on the REAL error, not only on the reproduction of it.
	r := &recordingReporter{}
	reportKernelChildResult(r, string(output), err)
	if !r.failed || !strings.Contains(r.message, "refused the namespace") {
		t.Fatalf("the real refusal got %s / %q, want the host-refused failure", r.verdict(), r.message)
	}
	t.Logf("measured refusal: %T %v -> host-refused", err, err)
}
