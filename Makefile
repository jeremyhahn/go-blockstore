# Makefile for go-blockstore
# Embedded block/volume storage library with pluggable providers.
#
# devops.md §4 — "the Makefile is the contract": CI runs the same targets a
# developer runs. Every check in .github/workflows/ci.yml has a target here
# that reproduces it locally with the same flags. When one changes, change
# both.

# ==============================================================================
# Configuration
# ==============================================================================

# Build tags applied to every go invocation below, COMMA-separated. EMPTY by
# default: the scaffold and the `local` provider carry no tag, so a bare
# `make test` builds the whole tree today.
#
# Networked/kernel-backed providers are tag-gated (README,
# conventions/build-tags.md), so the tagged packages are exercised by SETTING
# this rather than by editing recipes:
#
#     make test TAGS=drbd
#     make ci   TAGS=drbd,cephrbd
#
# CI threads the same value through the BUILD_TAGS workflow env, which is what
# lets issue #3 turn on the drbd provider without rewriting a workflow file.
# Commas, not spaces, for the same reason CI uses them: the value stays a
# single word everywhere it is passed, and gosec accepts no other form.
#
# Two other places must follow a new tag: `run.build-tags` in .golangci.yml —
# a tag the linter does not know about is a package the linter does not read —
# and BUILD_TAGS in .github/workflows/ci.yml.
#
# `drbd` since #3, matching what CI runs. Override with TAGS= to reproduce the
# untagged build, which is the one the tag convention promises still compiles.
TAGS ?= drbd

comma := ,
TAG_FLAGS := $(if $(strip $(TAGS)),-tags=$(strip $(TAGS)),)

GO := go
GOBUILD := $(GO) build $(TAG_FLAGS)
GOTEST := $(GO) test $(TAG_FLAGS)
GOVET := $(GO) vet $(TAG_FLAGS)
GOMOD := $(GO) mod
GOCLEAN := $(GO) clean

PROJECT_NAME := go-blockstore
MODULE := github.com/jeremyhahn/go-blockstore

# Release identity, for `release-alpha` below. All three exist because the
# alternatives are wrong in ways that do not announce themselves:
#
# REPO_NAME is the LITERAL repo name and must never become $(notdir $(CURDIR)),
# which derives the SIGNING IDENTITY from the checkout directory — a worktree,
# CI workspace or clone named anything else then signs and attributes the
# release as the wrong agent (measured in go-enclave, 2026-08-26: a directory
# named `mk` signed as agent-mk). This repo is developed in worktrees named
# `go-blockstore-<issue>`, so that failure mode is not theoretical here.
#
# RELEASE_REMOTE is a DEVIATION from release-alpha-template v2.2, which
# hardcodes `dev`. No repository on this workstation has a remote by that name:
# go-blockstore, go-objstore, go-qrdb, go-quicbaas and go-xkms all reach Gitea
# through `origin` (checked 2026-08-27). The template's own duplicate-tag check
# is `! git ls-remote --exit-code --tags dev ...`, which SUCCEEDS when the
# remote does not exist — so with the hardcoded name the guard silently
# evaporates and the push fails afterward, having already committed VERSION.
# The remote is therefore named once, defaulted to what is actually configured,
# and its existence is asserted before it is trusted. Override for a checkout
# that does follow version-control.md's naming: RELEASE_REMOTE=dev.
AGENT_GIT ?= /home/jhahn/sources/automatethethings/software/scripts/agent-git.sh
REPO_NAME ?= go-blockstore
RELEASE_REMOTE ?= origin

COVERAGE_DIR := coverage
COVERAGE_PROFILE := $(COVERAGE_DIR)/unit.out

# Kept identical to COVERAGE_THRESHOLD in .github/workflows/ci.yml. The tree is
# at 100% today (pkg/common is declarations only and contributes no
# statements); 90 is the fleet floor from the CI template, and a provider
# landing under-tested is meant to fail here.
COVERAGE_THRESHOLD := 90

# Unit tests get a generous but finite bound. The lease/coordinator contract
# tests use real timers, so a deadlock shows up as a timeout rather than a
# hung runner.
TEST_TIMEOUT := 900s

# The trivy the security suite expects, read from the ONE place it is declared.
# .github/workflows/nightly.yml reads the same file, so the scanner in CI and
# the scanner on a developer's machine are the same build. Bump it there, not
# here.
#
# Read as ONE bare token, not scrubbed. The prior `tr -d ' \t\n\r'` DELETED all
# whitespace, so a malformed `.trivy-version` holding `0.74 .0` — or a stray
# second line — silently normalised to a plausible-looking version instead of
# being caught. A version string does not tolerate embedded whitespace: awk
# counts every whitespace-delimited token in the file and emits the value ONLY
# when there is exactly one, trimming surrounding whitespace as a side effect.
# An internally-spaced or multi-token file yields empty, which the trivy target
# then surfaces as a mismatch against whatever is installed rather than acting
# on a scrubbed guess. (scripts/install-trivy.sh independently re-validates the
# file as a strict semver before it fetches anything, so install fails loud too.)
TRIVY_VERSION := $(shell awk '{for(i=1;i<=NF;i++){n++;v=$$i}} END{if(n==1)print v}' .trivy-version 2>/dev/null)

# THE ANALYSER VERSIONS, IN ONE PLACE (#30). These are the SAME numbers the
# ci-runner image bakes (infra/gitea/ci-runner/Dockerfile) and the same ones
# .github/workflows/ci.yml carries as its floors — devops.md §8 makes `make
# security` and `make lint` the contract CI mirrors, so a developer's tools and
# CI's tools must not be different builds.
#
# golangci-lint must not lag the image. golangci-lint refuses to load a config
# when the Go it was BUILT with is older than the module's target, and `go
# install` builds it with whatever Go is on the developer's box. v2.14.0 is what
# the image ships, built against the portfolio maximum. A developer left on an
# older build gets no local lint signal at all on a 1.27 module — it fails to
# start rather than degrading — while CI stays green, which is how a misspell
# shipped twice in go-enclave. Pins track the upstream latest, never below it.
#
# The rest were `@latest`, which made scans unreproducible: the same commit gets
# a different analyser on a different day (go-luks2 #21).
GOLANGCI_LINT_VERSION := v2.14.0
GOSEC_VERSION         := v2.29.0
GOVULNCHECK_VERSION   := v1.8.0
ACTIONLINT_VERSION    := v1.7.12

RESET := \033[0m
BOLD := \033[1m
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
CYAN := \033[36m

.DEFAULT_GOAL := help

# ==============================================================================
# Dependencies
# ==============================================================================

.PHONY: deps
## deps: Download and tidy module dependencies
deps:
	@echo "$(CYAN)$(BOLD)→ Downloading dependencies...$(RESET)"
	@$(GOMOD) download
	@$(GOMOD) tidy
	@echo "$(GREEN)✓ Dependencies ready$(RESET)"

.PHONY: deps-latest
## deps-latest: Update first-party deps to their newest tags (dependency-resolution.md §3)
deps-latest:
	@echo "$(CYAN)$(BOLD)→ Updating first-party dependencies...$(RESET)"
	@if ! ALL_MODS=$$($(GO) list -m -f '{{.Path}}' all); then \
		echo "$(RED)✗ go list -m failed — cannot determine dependencies$(RESET)"; \
		exit 1; \
	fi; \
	: "guard:fail-open grep exits 1 on no match, and a repo with no first-party deps is valid; the -z test below is what handles it"; \
	FIRST_PARTY=$$(printf '%s\n' "$$ALL_MODS" | grep '^github.com/jeremyhahn/' | grep -v '^$(MODULE)$$' || true); \
	if [ -z "$$FIRST_PARTY" ]; then \
		echo "$(YELLOW)  No first-party dependencies yet — nothing to update$(RESET)"; \
	else \
		for m in $$FIRST_PARTY; do \
			echo "$(CYAN)  $$m$(RESET)"; \
			$(GO) get "$$m@latest" || exit 1; \
		done; \
		$(GOMOD) tidy; \
	fi
	@echo "$(GREEN)✓ Dependencies current$(RESET)"

# ==============================================================================
# Build
# ==============================================================================

.PHONY: build
## build: Build every package
build:
	@echo "$(CYAN)$(BOLD)→ Building packages...$(RESET)"
	$(GOBUILD) ./...
	@echo "$(GREEN)✓ Build complete$(RESET)"

# ==============================================================================
# Test
# ==============================================================================

.PHONY: test
## test: Run unit tests with the race detector and coverage
# -race is part of `make test` itself, not a separate opt-in (devops.md §4).
# `race` below is the same detector without coverage instrumentation, for when
# a suspected data race should be reproduced on uninstrumented code.
test:
	@echo "$(CYAN)$(BOLD)→ Running unit tests (race detector, coverage)...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -race -count=1 -timeout=$(TEST_TIMEOUT) -covermode=atomic -coverprofile=$(COVERAGE_PROFILE) ./...
	@echo ""
# guard:fail-open a display line only — the coverage THRESHOLD is enforced by the `coverage` target, which does not swallow
	@$(GO) tool cover -func=$(COVERAGE_PROFILE) | tail -1 | awk '{print "  $(GREEN)Total coverage: " $$NF "$(RESET)"}' || true
	@echo "$(GREEN)✓ Unit tests complete$(RESET)"

.PHONY: race
## race: Run the race detector without coverage instrumentation
race:
	@echo "$(CYAN)$(BOLD)→ Running race detector...$(RESET)"
	$(GOTEST) -race -count=1 -timeout=$(TEST_TIMEOUT) ./...
	@echo "$(GREEN)✓ No races detected$(RESET)"

.PHONY: integration-test
## integration-test: Run the integration suite (build tag: integration)
# TWO real-provider suites are deliberately NOT in here, each behind its own
# second build tag because each creates and destroys storage on the host it runs
# on — under `integration` they would run from `make ci`, on every machine,
# either doing that or hard-failing on their own destructive-operation guard:
#
#   drbd  → pkg/drbd, tag `drbd_integration`      (logical volumes + DRBD resources)
#   local → pkg/local, tag `local_integration`    (loop devices + VGs + LUKS volumes)
#
# The cost of that separation is that a green run of THIS target says nothing
# about either real provider, so the banner names both rather than letting a
# developer assume otherwise. Each is operator-run and needs root:
#
#     make integration-test-drbd     # needs a configured two-node pair
#     make integration-test-local    # needs loop devices and root
#
integration-test:
	@echo "$(CYAN)$(BOLD)→ Running integration tests...$(RESET)"
	$(GO) test -tags=integration$(if $(strip $(TAGS)),$(comma)$(strip $(TAGS)),) -count=1 -timeout=$(TEST_TIMEOUT) ./...
	@echo "$(YELLOW)  note: the destructive real-provider suites are NOT included:$(RESET)"
	@echo "$(YELLOW)        drbd real-cluster    → make integration-test-drbd$(RESET)"
	@echo "$(YELLOW)        local real LVM/LUKS  → make integration-test-local$(RESET)"
	@echo "$(GREEN)✓ Integration tests complete$(RESET)"

.PHONY: integration-test-drbd
## integration-test-drbd: Run the drbd real-cluster suite (DESTRUCTIVE, needs root + a configured pair)
# Separate from `integration-test` on purpose: this creates and destroys logical
# volumes and DRBD resources on the host. It refuses to run without
# GO_BLOCKSTORE_DRBD_ALLOW_DESTRUCTIVE=1 and the GO_BLOCKSTORE_DRBD_* settings
# naming the pair, so an accidental invocation stops rather than starting.
integration-test-drbd:
	@echo "$(CYAN)$(BOLD)→ Running the drbd real-cluster suite...$(RESET)"
	@echo "$(YELLOW)  DESTRUCTIVE: creates and destroys LVs and DRBD resources on this host$(RESET)"
	$(GO) test -tags=drbd,drbd_integration -count=1 -timeout=$(TEST_TIMEOUT) -run Integration ./pkg/drbd/
	@echo "$(GREEN)✓ drbd real-cluster suite complete$(RESET)"

.PHONY: integration-test-local
## integration-test-local: Run the local provider's real LVM/LUKS suite (DESTRUCTIVE, needs root + loopback)
# The exact mirror of integration-test-drbd, for the local provider. Its suite
# (~20 tests, incl. #11's sizing/restore/tag proofs) drives real LVM, LUKS and
# filesystems over a loopback file, so it creates and destroys loop devices,
# volume groups and LUKS volumes on THIS host. It is tag-gated (local_integration)
# so an ordinary `make integration-test` never compiles it, and — matching the
# drbd convention exactly — it refuses to run without
# GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1, so an accidental invocation stops
# rather than starting. Set that and run as root:
#
#     sudo -E GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1 make integration-test-local
#
# `sudo -E` preserves the variable across the privilege change; without -E the
# environment is scrubbed and the in-test guard fails as designed.
#
# NOT wired into `make ci` or the CI unit lane, same as the drbd suite: it needs
# root, loop devices and device-mapper, which the shared runner does not grant.
# It is operator-run.
integration-test-local:
	@echo "$(CYAN)$(BOLD)→ Running the local provider real LVM/LUKS suite...$(RESET)"
	@echo "$(YELLOW)  DESTRUCTIVE: creates and destroys loop devices, VGs and LUKS volumes on this host$(RESET)"
	$(GO) test -tags=local_integration -count=1 -timeout=$(TEST_TIMEOUT) -run Integration ./pkg/local/
	@echo "$(GREEN)✓ local provider real suite complete$(RESET)"

.PHONY: integration-clean-local
## integration-clean-local: Remove state a KILLED local integration run left behind
# The suite cleans up after itself on every exit path Go can see — pass, fail
# and panic all run t.Cleanup. This is the backstop for the one it cannot: a
# SIGKILL, or a container torn down mid-run, where no deferred code executes at
# all and a live dm-crypt mapping is simply abandoned.
#
# It is SCOPED, and the scoping is the whole point. It touches only names this
# suite generates — mappings `bs-bsit<pid>x<n>_*` and volume groups
# `bsit<pid>x<n>` — and never `dmsetup remove_all` or `losetup -D`, which is how
# a cleanup destroys a developer's own encrypted root. go-luks2 PR #85 removed
# exactly those two commands from that repo after an unrelated host was found
# with test litter and a LIVE system volume in the same `dmsetup ls`.
#
# The LOOP DEVICES go too, and they are the reason this matters more than tidiness.
# A killed run skips the detach as well as the close, and loop devices are a
# finite pool: enough killed runs and the suite cannot allocate one at all, at
# which point every branch's verification fails for a reason that looks nothing
# like its cause. They are found through the volume group rather than by
# pattern — `pvs --select vg_name=<vg>` names the device backing a volume group
# this suite created — and captured BEFORE the vgremove that would otherwise
# make them unfindable. Most of the time the kernel releases the loop device on
# its own when the last thing holding it goes — the suite attaches with
# autoclear — so the usual outcome is a line saying it was already released,
# which is worth printing rather than a warning that reads like a failure.
#
# It prints what it would remove before removing it, so an operator sees whether
# the pattern matched something it should not have.
integration-clean-local:
	@echo "$(CYAN)$(BOLD)→ Removing state a killed local integration run left behind...$(RESET)"
	@mappings=$$(dmsetup ls 2>/dev/null | awk '$$1 ~ /^bs-bsit[0-9]+x[0-9]+_/ {print $$1}'); \
	: "guard:fail-open grep exits 1 when no bsit group is left, which is the normal case. RESIDUAL, stated rather than hidden: a FAILING vgs is swallowed here too, so an unreadable answer looks like a clean one. Harm is bounded because this target CLEANS debris — a false empty leaves debris rather than destroying anything — but it is the same shape as the dmsetup guard that once reported no mappings because the read failed."; \
	vgs=$$(vgs --noheadings -o vg_name 2>/dev/null | tr -d ' ' | grep -E '^bsit[0-9]+x[0-9]+$$' || true); \
	loops=""; \
	for v in $$vgs; do \
		loops="$$loops $$(pvs --noheadings -o pv_name --select vg_name=$$v 2>/dev/null | tr -d ' ')"; \
	done; \
	if [ -z "$$mappings" ] && [ -z "$$vgs" ] && [ -z "$$(echo $$loops)" ]; then \
		echo "  nothing to clean"; \
	else \
		for m in $$mappings; do echo "  mapping $$m"; dmsetup remove "$$m" || echo "$(YELLOW)    still busy: $$m$(RESET)"; done; \
		for v in $$vgs; do echo "  volume group $$v"; vgremove --force "$$v" >/dev/null || echo "$(YELLOW)    could not remove: $$v$(RESET)"; done; \
		for l in $$loops; do \
			if ! losetup "$$l" >/dev/null 2>&1; then echo "  loop device $$l (already released with its volume group)"; continue; fi; \
			echo "  loop device $$l"; losetup -d "$$l" || echo "$(YELLOW)    could not detach: $$l$(RESET)"; \
		done; \
	fi
	@echo "$(GREEN)✓ scoped cleanup complete$(RESET)"

# The Go toolchain the container suite runs under, read from go.mod so it cannot
# drift from what this module declares.
GO_VERSION := $(shell awk '/^go /{print $$2}' go.mod)

.PHONY: test-container
## test-container: Run the unit suite inside a container, where CI runs it
# NOT redundant with `make test`, and this target exists because the difference
# cost a review round. Several tests assert what the guard says on a machine
# that CANNOT do something — a blocked kernel keyring, an absent device node —
# and a developer host can do all of it, so those branches never execute there.
# A suite that is green on a desk and red in CI is the same false evidence this
# repo's preflight work exists to remove, so the container run is a target
# rather than a thing to remember.
#
# It carries $(TAG_FLAGS), the SAME tags `make test` uses. Without them this
# target compiles none of the tag-gated packages and reports success anyway —
# which is the build-tag half of the same trap: a partial-tag run is
# indistinguishable from a clean one. Measured: the first version of this target
# ran untagged and never compiled pkg/drbd at all, while printing ok for
# everything it did compile.
#
# The module cache is mounted read-only; nothing is fetched.
test-container:
	@echo "$(CYAN)$(BOLD)→ Running the unit suite inside a container...$(RESET)"
	docker run --rm \
		-v "$(CURDIR):/src:ro" -v "$$(go env GOMODCACHE):/gomod:ro" \
		-w /src --user 0 \
		-e GOFLAGS=-mod=mod -e GOPATH=/tmp/gopath -e GOMODCACHE=/gomod \
		-e GOPROXY=off -e GOCACHE=/tmp/gocache \
		golang:$(GO_VERSION) go test $(TAG_FLAGS) -count=1 -timeout=$(TEST_TIMEOUT) ./...
	@echo "$(GREEN)✓ Container suite complete$(RESET)"

.PHONY: integration-test-cryptsetup
## integration-test-cryptsetup: The one suite needing the cryptsetup binary (DESTRUCTIVE, needs root + loopback + cryptsetup)
# Separate from integration-test-local because that suite's documented tooling
# is lvm2, e2fsprogs and util-linux and deliberately NOT cryptsetup — nothing
# else in it shells out to one. This is the pre-go-luks2 migration gate: it
# reproduces a container the OLD implementation wrote, which only cryptsetup can
# produce, and then proves this package still opens it.
#
# It used to live in the local suite behind a RUNTIME SKIP, so on any host
# without cryptsetup — including CI — the migration gate for every encrypted
# volume in the fleet reported success without running. Selecting this tag is an
# operator declaring cryptsetup is present, so its absence is now a hard failure
# of a suite that promised to have it (conventions/testing-guidelines.md
# §No Skip Guards; found by `make guards`).
integration-test-cryptsetup:
	@echo "$(CYAN)$(BOLD)→ Running the cryptsetup compatibility gate...$(RESET)"
	@echo "$(YELLOW)  DESTRUCTIVE: creates and destroys loop devices, VGs and LUKS volumes on this host$(RESET)"
	@echo "$(YELLOW)  REQUIRES: root, loop devices, lvm2 AND the cryptsetup binary$(RESET)"
	$(GO) test -tags=local_integration,cryptsetup_compat -count=1 -timeout=$(TEST_TIMEOUT) -run Integration ./pkg/local/
	@echo "$(GREEN)✓ cryptsetup compatibility gate complete$(RESET)"

.PHONY: guards
## guards: Run the whole-tree scanners (internal/guards)
# Whole-TREE, so they read files rather than compiling them: a build tag cannot
# blind them, which matters because a tag-gated file is exactly where a skip
# hides. Each scanner reports what it EXAMINED as well as what it found, and an
# empty examined set is a failure — an empty file list and a clean tree
# otherwise produce the same verdict, which is the defect that prompted #47.
#
# TWO COMMANDS, ANSWERING DIFFERENT QUESTIONS. The binary asks whether the tree
# is clean; the package tests ask whether the scanners can still FIRE at all,
# against fixtures that contain each violation. A green sweep from scanners
# nobody has watched fail is the defect this target exists to prevent.
#
# Neither carries a `-run` filter, and that is deliberate. The first version of
# this target ran `go test -run TestGuards`, which is the same defect in a
# different coat: a `-run` pattern matching nothing prints `ok` and exits 0.
guards:
	@echo "$(CYAN)$(BOLD)→ Running the whole-tree guards...$(RESET)"
	$(GO) run ./internal/guards/cmd/guards
	@echo "$(CYAN)  …and proving each one can still fire:$(RESET)"
	$(GO) test -count=1 ./internal/guards/
	@echo "$(GREEN)✓ Guards passed$(RESET)"

.PHONY: test-kernel-mountinfo
## test-kernel-mountinfo: Check internal/mountinfo against a LIVE kernel (needs unprivileged user namespaces)
# Behind the kernel_mountinfo tag because these three tests re-exec themselves
# in a user + mount namespace, and a host that will not create one cannot run
# them. They used to SKIP there instead — measured 2026-09-04: inside
# golang:$(GO_VERSION), the image `make test-container` uses, all three skipped
# and the package printed ok in 0.002s, so the only tests checking this package
# against a real kernel had silently stopped running in the shape CI runs in.
#
# Selecting the tag is a statement that this host provides the capability, so a
# refusal is now a hard failure (conventions/testing-guidelines.md
# §No Skip Guards; found by `make guards`).
test-kernel-mountinfo:
	@echo "$(CYAN)$(BOLD)→ Checking internal/mountinfo against this kernel...$(RESET)"
	@echo "$(YELLOW)  REQUIRES: a host that permits unprivileged user + mount namespaces$(RESET)"
	$(GO) test -tags=kernel_mountinfo -count=1 -timeout=$(TEST_TIMEOUT) -run TestAgainstARunningKernel -v ./internal/mountinfo/
	@echo "$(GREEN)✓ Live-kernel mountinfo checks complete$(RESET)"

.PHONY: test-kernel-keypath
## test-kernel-keypath: Check the key-path guard against a LIVE kernel (needs unprivileged user namespaces)
# Behind the kernel_keypath tag for the reason test-kernel-mountinfo is behind
# its own: the test re-execs itself in a user + mount namespace, and a host that
# will not create one cannot run it.
#
# It is the measurement the whole guard rests on. pkg/local's key-path check
# asks its question of the filesystem AFTER mount(2) rather than predicting it,
# and the case that makes prediction impossible — a key path through a symlink
# whose destination does not exist until the volume is mounted — can only be
# built with a real mount. Everywhere else in the package that substitution is
# imitated by a fake whose Mount is a recording, which is exactly the instrument
# that cannot tell a check running before the mount from one running after it.
#
# This started as a runtime SKIP and CI reported it as a failure, which is how
# the tag got chosen. Measured 2026-09-04: `go test` without -v prints nothing
# at all for a passing package, and the CI Test job runs without -v — so the
# skip would not have been quiet there, it would have been invisible. Selecting
# the tag is a statement that this host provides the capability, so a refusal is
# a hard failure (conventions/testing-guidelines.md §No Skip Guards).
test-kernel-keypath:
	@echo "$(CYAN)$(BOLD)→ Checking the key-path guard against this kernel...$(RESET)"
	@echo "$(YELLOW)  REQUIRES: a host that permits unprivileged user + mount namespaces$(RESET)"
	$(GO) test -tags=kernel_keypath -count=1 -timeout=$(TEST_TIMEOUT) -run TestAgainstARunningKernel -v ./pkg/local/
	@echo "$(GREEN)✓ Live-kernel key-path checks complete$(RESET)"

.PHONY: preflight-matrix
## preflight-matrix: Prove the startup privilege guard fires (and does not) in real containers
# NOT in `make ci`, and not because it is optional. The condition the guard
# exists to catch is a property of how the PROCESS WAS STARTED — CAP_SYS_ADMIN
# granted, /dev/mapper/control passed in, and the runtime's DEFAULT seccomp
# profile still denying add_key — which nothing inside `go test` can reproduce.
# It needs a Docker-capable host, which the shared runner is not, so it is run
# here and by an operator. It ASSERTS rather than prints: a row that does not
# behave as pkg/preflight claims exits non-zero.
preflight-matrix:
	@echo "$(CYAN)$(BOLD)→ Running the preflight container matrix...$(RESET)"
	./scripts/preflight-container-matrix.sh
	@echo "$(GREEN)✓ preflight container matrix complete$(RESET)"

.PHONY: coverage
## coverage: Enforce the coverage threshold and write an HTML report
coverage: test
	@COVERAGE=$$($(GO) tool cover -func=$(COVERAGE_PROFILE) | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "  Coverage: $${COVERAGE}% (threshold: $(COVERAGE_THRESHOLD)%)"; \
	if awk "BEGIN{exit !($${COVERAGE} < $(COVERAGE_THRESHOLD))}"; then \
		echo "$(RED)✗ Coverage $${COVERAGE}% is below threshold $(COVERAGE_THRESHOLD)%$(RESET)"; \
		exit 1; \
	fi
	@$(GO) tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_DIR)/coverage.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/coverage.html$(RESET)"

.PHONY: bench
## bench: Run benchmarks
bench:
	@echo "$(CYAN)$(BOLD)→ Running benchmarks...$(RESET)"
	$(GOTEST) -run='^$$' -bench=. -benchmem ./...

# ==============================================================================
# Static analysis
# ==============================================================================

.PHONY: fmt
## fmt: Format all Go source
fmt:
	@echo "$(CYAN)$(BOLD)→ Formatting...$(RESET)"
	@$(GO) fmt ./...
	@echo "$(GREEN)✓ Formatted$(RESET)"

.PHONY: fmt-check
## fmt-check: Fail if any file is unformatted (mirrors the CI lint job)
fmt-check:
	@UNFORMATTED=$$(gofmt -l .); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "$(RED)✗ Files not formatted:$(RESET)"; echo "$$UNFORMATTED"; \
		echo "$(YELLOW)  Fix with: make fmt$(RESET)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ All files formatted$(RESET)"

.PHONY: vet
## vet: Run go vet
vet:
	@echo "$(CYAN)$(BOLD)→ Running go vet...$(RESET)"
	$(GOVET) ./...
	@echo "$(GREEN)✓ Vet passed$(RESET)"

.PHONY: lint
## lint: gofmt, vet, golangci-lint and actionlint (devops.md §4)
lint: fmt-check vet golangci-lint actionlint guards

.PHONY: golangci-lint
## golangci-lint: Run golangci-lint (config is version "2" — needs the v2 binary)
# The probe demands a MINIMUM VERSION, not merely "major 2" (#30). GOPATH/bin is
# searched first, so on a box that has ever run `make install-tools` an old
# binary there SHADOWS the newer one the ci-runner image ships at
# /usr/local/bin — silently, because both are v2. That is the local half of the
# defect this target's CI counterpart had: the developer lints with one tool and
# CI with another, and past the 1.27 wave the old one does not lint at all.
# Anything below the floor is now named and refused rather than selected.
golangci-lint:
	@echo "$(CYAN)$(BOLD)→ Running golangci-lint...$(RESET)"
	@GOPATH=$$($(GO) env GOPATH); \
	MIN="$(GOLANGCI_LINT_VERSION)"; MIN="$${MIN#v}"; \
	BIN=""; FOUND=""; SEEN=""; \
	for cand in "$$GOPATH/bin/golangci-lint" $$(command -v golangci-lint 2>/dev/null) /usr/local/bin/golangci-lint /usr/bin/golangci-lint; do \
		[ -x "$$cand" ] || continue; \
		ver=$$("$$cand" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1); \
		[ -n "$$ver" ] || continue; \
		SEEN="$$SEEN $$cand($$ver)"; \
		if [ "$$(printf '%s\n%s\n' "$$MIN" "$$ver" | sort -V | head -1)" = "$$MIN" ]; then \
			BIN="$$cand"; FOUND="$$ver"; break; \
		fi; \
	done; \
	if [ -z "$$BIN" ]; then \
		echo "$(RED)✗ no golangci-lint >= $$MIN found (.golangci.yml is version: \"2\")$(RESET)"; \
		echo "$(YELLOW)  probed:$${SEEN:- none}$(RESET)"; \
		echo "$(YELLOW)  Install the pinned version: make install-tools$(RESET)"; \
		exit 1; \
	fi; \
	echo "$(CYAN)  Using $$BIN ($$FOUND)$(RESET)"; \
	"$$BIN" run --timeout=5m ./...
	@echo "$(GREEN)✓ golangci-lint passed$(RESET)"

.PHONY: actionlint
## actionlint: Lint the workflow files (requires shellcheck for the SC* rules)
# A missing actionlint FAILS this target. It used to warn and return 0, which is
# the same fail-open the trivy target carried: `make lint` would report success
# with a declared check never run, and on a machine without the binary it would
# report success forever. `lint` is part of `ci`, so that silence propagated
# straight into the pipeline's exit code.
#
# A missing SHELLCHECK fails it for the same reason, and this one is subtler.
# actionlint delegates every SC-prefixed rule to shellcheck, invoking it BY NAME
# from PATH. With shellcheck not on PATH it DISABLES those rules and still EXITS
# 0 at default verbosity — only `-verbose` prints "Rule shellcheck was
# disabled". So actionlint appearing to pass says nothing about the shell inside
# `run:` steps: a real SC2046 reached main that way (fixed in #21). The check is
# `command -v shellcheck` and not a GOPATH/bin probe ON PURPOSE — actionlint
# spawns whatever `shellcheck` PATH resolves, so a binary installed to GOPATH/bin
# that is not on PATH is invisible to it, and asserting the wrong location would
# be a check narrower than what it verifies. `make install-tools` installs it;
# put GOPATH/bin on PATH.
#
# The runner labels it must accept live in .github/actionlint.yaml — without
# that file every self-hosted label reads as an unknown runner; with it, a
# MISSPELLED label is still caught.
actionlint:
	@if ! command -v shellcheck > /dev/null 2>&1; then \
		echo "$(RED)✗ shellcheck not on PATH — actionlint would SILENTLY skip every SC* rule and still exit 0$(RESET)"; \
		echo "$(YELLOW)  Install: make install-tools (then put \$$(go env GOPATH)/bin on PATH)$(RESET)"; \
		exit 1; \
	fi
	@GOPATH=$$($(GO) env GOPATH); \
	BIN=""; \
	for cand in "$$GOPATH/bin/actionlint" $$(command -v actionlint 2>/dev/null); do \
		[ -x "$$cand" ] && BIN="$$cand" && break; \
	done; \
	if [ -z "$$BIN" ]; then \
		echo "$(RED)✗ actionlint not found — the workflow lint cannot run$(RESET)"; \
		echo "$(YELLOW)  Install: make install-tools$(RESET)"; \
		exit 1; \
	fi; \
	"$$BIN"
	@echo "$(GREEN)✓ actionlint passed (shellcheck present; SC* rules live)$(RESET)"

# ==============================================================================
# Security (devops.md §8)
# ==============================================================================

.PHONY: install-tools
## install-tools: Install the pinned linter and the security scanners
# trivy and shellcheck are not `go install` targets, so they come from
# scripts/install-trivy.sh and scripts/install-shellcheck.sh — the same scripts
# CI runs (nightly.yml for trivy, the lint job for shellcheck), each of which
# downloads the PINNED release artifact and verifies its SHA-256 before
# executing anything. Nothing here pipes a fetched script into a shell. One
# installer per tool for both call sites, so the binary on a dev box and the one
# in CI cannot drift apart. shellcheck backs actionlint's SC* rules; without it
# actionlint disables those rules and exits 0, which is the fail-open the lint
# target now refuses (see the actionlint target).
#
# It writes into GOPATH/bin and needs no root, and it lives in this
# explicitly-invoked target so nothing mutates a developer's machine as a side
# effect of a build or test (devops.md §4).
install-tools:
	@echo "$(CYAN)$(BOLD)→ Installing tools...$(RESET)"
	@echo "$(CYAN)  golangci-lint $(GOLANGCI_LINT_VERSION) (pinned — see the versions block above)$(RESET)"
	@$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@echo "$(CYAN)  gosec $(GOSEC_VERSION)$(RESET)"
	@# -ldflags is not decoration: without it gosec reports "Version: dev" and no
	@# log — here or in CI — can say which analyser produced a finding.
	@$(GO) install -ldflags "-X main.Version=$(GOSEC_VERSION)" github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	@echo "$(CYAN)  govulncheck $(GOVULNCHECK_VERSION)$(RESET)"
	@$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@echo "$(CYAN)  actionlint $(ACTIONLINT_VERSION)$(RESET)"
	@$(GO) install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	@echo "$(CYAN)  shellcheck (pinned, checksum-verified)$(RESET)"
	@./scripts/install-shellcheck.sh "$$($(GO) env GOPATH)/bin"
	@echo "$(CYAN)  trivy $(TRIVY_VERSION) (pinned, checksum-verified)$(RESET)"
	@# Pass the STRICTLY-parsed version through, and refuse to install without it.
	@# TRIVY_VERSION above resolves to empty on a malformed .trivy-version (embedded
	@# whitespace or multiple tokens); without this guard install-trivy.sh would
	@# then fall back to reading the file ITSELF with `tr -d`, scrub `0.74 .0` to
	@# `0.75.0` and install that — the exact normalize-not-verify hole the read was
	@# hardened to close, reopened one layer down. Failing here keeps the parsed
	@# value the single source and never lets the scrubbing fallback run.
	@test -n "$(TRIVY_VERSION)" || { echo "$(RED)✗ .trivy-version is malformed (empty, whitespace, or multi-token) — refusing to install a scrubbed guess$(RESET)"; exit 1; }
	@./scripts/install-trivy.sh "$$($(GO) env GOPATH)/bin" "$(TRIVY_VERSION)"
	@echo "$(GREEN)✓ Tools installed to $$($(GO) env GOPATH)/bin$(RESET)"
	@echo '$(YELLOW)  Put that directory on your PATH, or the security targets will not find them.$(RESET)'

# Kept identical to the gosec step in .github/workflows/ci.yml — devops.md §8
# makes `make security` the contract, so the two must not drift. There are
# deliberately NO -exclude rules: every exclusion needs a written, code-checked
# justification here and in the workflow, and this tree has earned none.
#
# -concurrency 4 is the memory bound that actually works (ci-template v1.7):
# gosec sizes its worker pool from runtime.NumCPU(), which reports the HOST's
# cores regardless of GOMAXPROCS, and the live SSA of that many concurrent
# packages is not something GOMEMLIMIT can collect.
# These must stay ANALYSIS-identical to the gosec step in ci.yml: same rules,
# same directory scope, same severity and confidence thresholds. The only
# difference CI carries is `-fmt=sarif -out=gosec.sarif`, which is a reporting
# artifact for the upload step and changes nothing about what is scanned.
#
# NOT `-exclude-generated`, deliberately. The Makefile carried it and CI did
# not, which meant the day someone adds a generated .go file, this target would
# pass locally and the same commit would fail in CI — a local target that
# promises to reproduce CI has to actually do it. Scanning generated code is
# also the safer direction: a generated file can carry a real finding.
GOSEC_ARGS = -concurrency 4 -stdout -verbose=text \
	-exclude-dir=test -exclude-dir=examples \
	-severity=medium -confidence=medium

# gosec spells the flag the same way but parses it itself; TAGS is already
# comma-separated, so it passes straight through.
GOSEC_TAG_FLAGS := $(if $(strip $(TAGS)),-tags=$(strip $(TAGS)),)

.PHONY: security
## security: The full devops.md §8 suite — gosec, govulncheck, go mod verify, trivy fs
# EVERY scanner in this target is MANDATORY. A missing binary is a hard failure,
# never a warning: a target named `security` that returns 0 with a scan skipped
# lets a developer — or a script reading the exit code — believe the declared
# suite passed when its vulnerability and secret scan never ran. That is
# fail-open, and it is worse than having no target, because it manufactures
# false confidence. If a tool is missing, install it (`make install-tools`);
# do not reach for a variant of this target that runs less.
#
# `security-go` below is the honest narrower claim, for the case where only the
# Go-toolchain scanners are wanted. It is not a fallback for a broken install.
security: security-go trivy
	@echo "$(GREEN)$(BOLD)✓ Security suite complete (gosec, govulncheck, go mod verify, trivy fs)$(RESET)"

.PHONY: security-go
## security-go: The Go-toolchain scanners only — what the CI security job runs
# Named for what it actually covers. This is the analysis mirror of the
# `security` job in .github/workflows/ci.yml, which does NOT run trivy —
# ci-template v1.9 moved trivy to nightly.yml. Reproducing a CI failure is what
# this is for; `security` above is the devops.md §4 contract and is what `ci`
# runs.
#
# Both scanners triage their own exit code (ci-template v1.8). A shell reports
# a signal death as 128+N, so an OOM kill leaves 137 — indistinguishable from a
# real finding when the log holds none, which is how a phantom CVE hunt starts
# (measured on go-quicbaas). Fail-closed either way; this only says which.
security-go:
	@echo "$(CYAN)$(BOLD)→ Running Go security scanners...$(RESET)"
	@echo "$(CYAN)  gosec...$(RESET)"
	@BIN=$$(command -v gosec 2>/dev/null || echo "$$($(GO) env GOPATH)/bin/gosec"); \
	if [ ! -x "$$BIN" ]; then \
		echo "$(RED)✗ gosec not found$(RESET)"; \
		echo "$(YELLOW)  Install: make install-tools$(RESET)"; \
		exit 1; \
	fi; \
	set +e; "$$BIN" $(GOSEC_ARGS) $(GOSEC_TAG_FLAGS) ./...; rc=$$?; set -e; \
	if [ "$$rc" -gt 128 ]; then \
		echo "$(RED)✗ gosec was KILLED by signal $$((rc - 128)) — NOT a security finding.$(RESET)"; \
		echo "$(YELLOW)  Memory pressure. Re-run when the machine is quieter.$(RESET)"; \
	fi; \
	if [ "$$rc" -ne 0 ]; then exit "$$rc"; fi; \
	echo "$(GREEN)✓ gosec passed$(RESET)"
	@echo "$(CYAN)  govulncheck...$(RESET)"
	@BIN=$$(command -v govulncheck 2>/dev/null || echo "$$($(GO) env GOPATH)/bin/govulncheck"); \
	if [ ! -x "$$BIN" ]; then \
		echo "$(RED)✗ govulncheck not found$(RESET)"; \
		echo "$(YELLOW)  Install: make install-tools$(RESET)"; \
		exit 1; \
	fi; \
	set +e; GOFLAGS="$(TAG_FLAGS)" "$$BIN" ./...; rc=$$?; set -e; \
	if [ "$$rc" -gt 128 ]; then \
		echo "$(RED)✗ govulncheck was KILLED by signal $$((rc - 128)) — NOT a vulnerability finding.$(RESET)"; \
		echo "$(YELLOW)  Memory pressure, not a CVE. Confirm with an uncapped run before believing it.$(RESET)"; \
	fi; \
	if [ "$$rc" -ne 0 ]; then exit "$$rc"; fi; \
	echo "$(GREEN)✓ govulncheck passed$(RESET)"
	@echo "$(CYAN)  go mod verify...$(RESET)"
	@$(GOMOD) verify
	@echo "$(GREEN)✓ Module integrity verified$(RESET)"

.PHONY: trivy
## trivy: Trivy filesystem scan — the gates nightly.yml runs, reproduced locally
# A missing trivy FAILS this target. It does not warn and return 0: the whole
# point of the target is the scan, so "trivy is not installed" and "the scan
# found nothing" must never produce the same exit code.
#
# The version actually in use is reported against the pin in .trivy-version.
# That report is INFORMATIONAL and never gates: the scan still runs and still
# fails closed, and findings move with trivy's vulnerability DB as much as with
# its version, so demanding exact-version equality would be false precision. It
# is printed because a mismatch is the usual reason a local result and a CI
# result disagree.
#
# The blocking gate is kept string-identical to the `Trivy gate (Gitea)` step in
# .github/workflows/nightly.yml so the same failure reproduces here. The
# misconfiguration pass mirrors that workflow's advisory step — exit code 0 by
# design (devops.md §8 promises misconfig scanning portfolio-wide; it is not yet
# a blocking finding class). It cannot affect this target's exit status.
trivy:
	@echo "$(CYAN)$(BOLD)→ Running trivy filesystem scan...$(RESET)"
	@if ! command -v trivy > /dev/null 2>&1; then \
		echo "$(RED)✗ trivy not found — the filesystem scan cannot run$(RESET)"; \
		echo "$(YELLOW)  Install: make install-tools$(RESET)"; \
		exit 1; \
	fi
	@INSTALLED=$$(trivy --version 2>/dev/null | head -1 | sed -n 's/^Version: \([0-9.]*\).*/\1/p'); \
	if [ "$$INSTALLED" != "$(TRIVY_VERSION)" ]; then \
		echo "$(YELLOW)  note: using trivy $$INSTALLED; this repo pins $(TRIVY_VERSION) (.trivy-version)$(RESET)"; \
		echo "$(YELLOW)        run 'make install-tools' to match CI exactly$(RESET)"; \
	else \
		echo "$(CYAN)  trivy $$INSTALLED (matches the pin)$(RESET)"; \
	fi
	trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 --format table --skip-dirs test,examples --ignorefile .trivyignore .
	@echo "$(GREEN)✓ trivy vuln/secret gate passed$(RESET)"
	@echo "$(CYAN)  misconfiguration scan (advisory)...$(RESET)"
	@trivy fs --scanners misconfig --exit-code 0 --format table --skip-dirs test,examples --ignorefile .trivyignore .
	@echo "$(GREEN)✓ trivy complete$(RESET)"

# ==============================================================================
# Pipelines
# ==============================================================================

.PHONY: ci
## ci: Everything a pull request must pass (devops.md §4)
# This runs the FULL §8 security suite, so it is deliberately a superset of the
# PR gate in .github/workflows/ci.yml: ci-template v1.9 moved trivy off the push
# path into nightly.yml, so a pull request is not blocked on it, but §4 defines
# `make ci` as including `make security` and §4 defines that as the full suite.
# Erring toward the superset is the right direction — a developer sees the
# nightly finding before it fires rather than after.
#
# To reproduce the PR gate EXACTLY — no trivy — run: lint, build, security-go,
# coverage. `security-go` exists precisely so that mirror has an honest name
# instead of being spelled as a weakened `security`.
ci: ci-fast integration-test
	@echo "$(GREEN)$(BOLD)========================================$(RESET)"
	@echo "$(GREEN)$(BOLD)  ✓ CI pipeline passed$(RESET)"
	@echo "$(GREEN)$(BOLD)========================================$(RESET)"

.PHONY: ci-fast
## ci-fast: The CI subset that needs no Docker or external services
# Ordered as the workflow stages it: the fast tier (lint, build) first, so a
# tree that cannot lint or compile says so before the expensive tier runs.
ci-fast:
	@echo "$(CYAN)$(BOLD)[1/4] Lint$(RESET)"
	@$(MAKE) --no-print-directory lint
	@echo "$(CYAN)$(BOLD)[2/4] Build$(RESET)"
	@$(MAKE) --no-print-directory build
	@echo "$(CYAN)$(BOLD)[3/4] Security$(RESET)"
	@$(MAKE) --no-print-directory security
	@echo "$(CYAN)$(BOLD)[4/4] Test + coverage$(RESET)"
	@$(MAKE) --no-print-directory coverage

# ==============================================================================
# Release
# ==============================================================================

# release-alpha-template: v2.2, copied from
# software/templates/make/release-alpha.mk in the automatethethings repo. That
# file carries the full rationale; the short form is that it replaces a v1
# recipe which auto-incremented PATCH only (an API addition shipped labelled a
# bugfix), created LIGHTWEIGHT UNSIGNED tags under the owner's identity, pushed
# every local tag, and `|| true`-swallowed a failed VERSION commit so a tag
# could disagree with its own VERSION file. None of that failed loudly.
#
# The v2 contract, unchanged here:
#   - The version is EXPLICIT. No auto-increment: whoever cuts the release
#     decides patch-vs-minor-vs-major per release-versioning.md and says so.
#     Pre-1.0 that decision matters more than usual, because MINOR is where
#     breakage lives — an auto-incremented PATCH cannot express it.
#   - Every git write goes through agent-git.sh (identity + SSH signing as
#     agent-go-blockstore); the tag is ANNOTATED and signed.
#   - Pushes ONLY the release commit and the named tag. Never --tags.
#     ATOMICALLY: `--atomic` is load-bearing and is NOT a synonym for listing
#     both refs on one command line. Without it git sends the two updates
#     independently and the server applies each on its own, so a protected
#     `main` can reject the commit while the TAG still lands — and a published
#     tag cannot be retracted, so the recipe's nonzero exit arrives after the
#     irreversible half already happened. It fails the other way too: the tag
#     rejected, main advanced, and VERSION now claims a release that has no
#     tag. Same lesson go-qrdb's release-lockstep header records. Verified
#     against a hook-rejecting bare remote, both with and without the flag.
#   - Cut from `main` ONLY, since `push <remote> HEAD` publishes whatever
#     branch is checked out.
#   - Fail-closed end to end: no `|| true`; any failing step aborts before the
#     tag exists.
#   - Error messages are SINGLE-quoted, deliberately. A double-quoted `echo` is
#     a live command-substitution context, and error strings are exactly what
#     people edit casually — a backtick or $(...) added there gets EXECUTED at
#     the moment a release is already failing.
#
# THREE DEVIATIONS from the template. The first two settle a conflict between
# the template and conventions/release-versioning.md, which is normative; the
# third closes a hole in the template's own fail-closed contract:
#
#   1. The VERSION file is written UNPREFIXED. The template writes $(VERSION)
#      verbatim, i.e. `v0.3.2-alpha`. §2 of release-versioning.md states the
#      opposite in a table — VERSION is unprefixed, the tag carries the `v` —
#      and every repo in the portfolio follows it. It also breaks the standard
#      reconciliation `VERSION=$${GITHUB_REF#refs/tags/v}`, which is what
#      .github/workflows/release.yml validates against.
#   2. The CHANGELOG section guard anchors on the unprefixed heading and
#      matches it LITERALLY. Two problems with the template's
#      `^#+ +\[?v0.3.2-alpha\]?`: it wants the v-prefix, which no Keep a
#      Changelog heading carries, so left as-is it would refuse every
#      well-formed release; and it is a REGEX, in which the dots of a version
#      are wildcards and `#+ +\[?` accepts heading shapes the release workflow
#      does not. So `## [0x3x2-alpha]` — or `### 0.3.2-alpha` — passes this
#      guard, the tag gets cut and pushed, and only then does the workflow's
#      literal lookup fail, on a tag that can no longer be retracted. This
#      guard is now the SAME predicate the workflow uses, because a
#      pre-flight check that is not identical to the thing it clears for is
#      not a check.
#   3. The remote duplicate-tag check reads the EXIT CODE instead of inverting
#      it with `!`. `git ls-remote --exit-code` answers three different things
#      and the template's `! ... || { error }` collapses them to two: 0 = the
#      tag exists, 2 = it does not, anything else (128 on an unreachable or
#      unauthenticated remote) = the question was never answered. Under `!`
#      that third case reads as "absent" and the recipe proceeds to commit
#      VERSION and create the tag before the push fails — which is the exact
#      half-released state the check exists to prevent. Codes verified against
#      this remote on 2026-08-27, not assumed.
#
# The fourth deviation, RELEASE_REMOTE, is documented at its definition above.
# All four are reported upstream for the template; do not "fix" them back.
#
# STANDING INVARIANT, and the one to check when editing either file: the
# version grammar accepted HERE must be a strict SUBSET of the one
# .github/workflows/release.yml accepts. This target's job is to fail BEFORE a
# tag exists; the workflow's is to fail after, when nothing can be taken back.
# So the target may be stricter (it is — it demands `-alpha`, where the
# workflow also accepts a stable release), but it must never be LOOSER on any
# axis. It briefly was: tightening the workflow to full SemVer left this guard
# accepting `v01.2.3-alpha`, which the target would happily tag and the
# workflow would then reject on an unretractable tag — the same
# check-does-not-match-what-it-clears-for defect the CHANGELOG guard had.
# THE MAKE -> SHELL CROSSING HAPPENS EXACTLY ONCE, HERE.
#
# Every value below can be set from the command line, which makes it attacker
# input the moment anyone pastes a release command. A `$(VAR)` written in a
# recipe BODY is not a shell parameter — make splices the value into the recipe
# TEXT and the shell then parses the result as source. Quoting is no defence,
# because the quotes are in the template while the value becomes syntax inside
# them: `make release-alpha 'VERSION=v0.3.2-alpha`touch /tmp/pwn`'` runs the
# backticks at the FIRST guard line, before any check can reject the string.
# Measured, both vectors, before this was written: backticks execute, and so
# does a value carrying an embedded double quote, which closes the guard's own
# quoting and appends a command. (`$(...)` and `;` happen not to fire — make
# eats the former as a variable reference and the latter stays inside the
# quotes — which is exactly the kind of partial immunity that makes this look
# safe when spot-checked.)
#
# Target-specific `export` moves each value into the recipe's ENVIRONMENT
# instead. It reaches the shell through execve as data, never through the
# parser, so a backtick in it is a byte. The recipe body below therefore
# references ONLY shell parameters — "$$REL_VERSION" and friends — and never
# `$(VERSION)`. Keep it that way: reintroducing a single `$(...)` carrying a
# settable value reopens this.
#
# Note the corollary, which is the part that reads wrong at first glance:
# `echo "ERROR: $$REL_VERSION"` in double quotes is SAFE, because the shell
# does not re-scan the result of a parameter expansion for command
# substitution. The v2.2 rule about single-quoting error messages was aimed at
# a different hazard — a backtick typed into the literal message text — and
# that still holds for the literal parts.
#
# The colour variables are exported for the same reason, which is easy to miss:
# a command-line assignment overrides even a `:=` set in this file, so `$(GREEN)`
# spliced into the last line would be one more splice point. It is a far less
# plausible vector than VERSION — a pasted `GREEN=...` looks wrong where a
# pasted `VERSION=...` looks routine — but leaving it would make the rule above
# untrue, and a rule with one exception is not checkable. (The colour variables
# are used this way throughout the rest of this Makefile; those recipes neither
# sign nor push, so they are out of scope here rather than fixed silently.)
#
# `$(value VERSION)` rather than `$(VERSION)`: it yields the variable's RAW
# text without expanding it, so a make FUNCTION smuggled into the value —
# `VERSION='$(shell ...)v0.3.2-alpha'` — is not evaluated by this assignment,
# and REL_VERSION ends up holding the literal `$(shell ...)` text, which the
# grammar guard then rejects.
#
# BE CLEAR ABOUT WHAT THAT DOES AND DOES NOT BUY, because the honest limit
# matters more than the mitigation. It does NOT close the make-function vector.
# Measured three ways: with `:=$(VERSION)`, with `:=$(value VERSION)`, and with
# a Makefile that never mentions the variable at all, `$(shell touch canary)`
# RAN IN ALL THREE. Make expands a command-line variable while exporting it to
# the recipe environment whether or not any rule references it, so no Makefile
# can prevent it — a one-line Makefile with an empty target is equally exposed.
# `$(value)` only stops the SECOND evaluation this assignment would add (an
# `$(info)` payload printed twice without it, once with).
#
# So: the shell-metacharacter vector below is ours and is closed. The
# make-function vector belongs to `make` itself and is out of reach from here;
# it is why a release command line is only ever pasted from a trusted source.
release-alpha: export REL_VERSION   := $(value VERSION)
release-alpha: export REL_REMOTE    := $(RELEASE_REMOTE)
release-alpha: export REL_REPO      := $(REPO_NAME)
release-alpha: export REL_AGENT_GIT := $(AGENT_GIT)
release-alpha: export REL_GREEN     := $(GREEN)
release-alpha: export REL_RESET     := $(RESET)
.PHONY: release-alpha
## release-alpha: Cut and push a signed release tag (VERSION=vX.Y.Z-alpha)
release-alpha:
	@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (release-versioning.md decides patch/minor/major — the recipe refuses to guess)'; exit 1; }
	@printf '%s' "$$REL_VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha$$' || { echo 'ERROR: VERSION is not of the form vX.Y.Z-alpha, with no leading zeros in X, Y or Z (SemVer rule 9 — and release.yml refuses what this would otherwise let you tag)'; exit 1; }
	@test -n "$$REL_REPO" || { echo 'ERROR: REPO_NAME is empty — set it to the literal repo name in the Makefile, never $$(notdir $$(CURDIR))'; exit 1; }
	@test -x "$$REL_AGENT_GIT" || { echo 'ERROR: AGENT_GIT does not point at an executable agent-git.sh — every git write in this recipe signs through it'; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = main || { echo "ERROR: releases are cut from main; you are on $$(git rev-parse --abbrev-ref HEAD). Pushing HEAD would publish this branch."; exit 1; }
	@git remote get-url "$$REL_REMOTE" >/dev/null 2>&1 || { echo "ERROR: no git remote named $$REL_REMOTE. Set RELEASE_REMOTE to the Gitea remote; the duplicate-tag check below FAILS OPEN without it"; exit 1; }
	@! git rev-parse -q --verify "refs/tags/$$REL_VERSION" >/dev/null || { echo "ERROR: tag $$REL_VERSION already exists locally"; exit 1; }
	@rc=0; git ls-remote --exit-code --tags "$$REL_REMOTE" "refs/tags/$$REL_VERSION" >/dev/null 2>&1 || rc=$$?; \
	case "$$rc" in \
	  0) echo "ERROR: tag $$REL_VERSION already exists on $$REL_REMOTE (a local check alone would miss this and fail the push AFTER committing VERSION)"; exit 1 ;; \
	  2) : ;; \
	  *) echo "ERROR: could not reach $$REL_REMOTE to check whether tag $$REL_VERSION exists. Refusing to continue: an unreachable remote is not an absent tag"; exit 1 ;; \
	esac
	@test -z "$$(git status --porcelain)" || { echo 'ERROR: working tree not clean'; exit 1; }
	@ver="## [$${REL_VERSION#v}]"; awk -v ver="$$ver" 'index($$0, ver) == 1 { f = 1 } END { exit f ? 0 : 1 }' CHANGELOG.md || { echo "ERROR: CHANGELOG.md has no '$$ver' section heading. Matched LITERALLY and anchored at the line start, exactly as .github/workflows/release.yml matches it — an unanchored prose mention does not count, and neither does a near-miss heading"; exit 1; }
	@printf '%s\n' "$${REL_VERSION#v}" > VERSION
	"$$REL_AGENT_GIT" "$$REL_REPO" add VERSION
	"$$REL_AGENT_GIT" "$$REL_REPO" commit -m "chore(release): $$REL_VERSION"
	"$$REL_AGENT_GIT" "$$REL_REPO" tag -a "$$REL_VERSION" -m "$$REL_VERSION"
	"$$REL_AGENT_GIT" "$$REL_REPO" push --atomic "$$REL_REMOTE" HEAD "refs/tags/$$REL_VERSION"
	@printf '%b✓ Released %s (signed, annotated, single tag pushed)%b\n' "$$REL_GREEN" "$$REL_VERSION" "$$REL_RESET"

.PHONY: clean
## clean: Remove build and test output
clean:
	@echo "$(CYAN)$(BOLD)→ Cleaning...$(RESET)"
# guard:fail-open clean is best-effort; an absent cache is the normal case and nothing downstream reads this
	@$(GOCLEAN) -testcache 2>/dev/null || true
	@rm -rf $(COVERAGE_DIR)
	@rm -f gosec-results.json trivy-results.sarif
	@echo "$(GREEN)✓ Clean$(RESET)"

# ==============================================================================
# Help
# ==============================================================================

.PHONY: help
## help: Show this help
help:
	@echo "$(BOLD)$(PROJECT_NAME)$(RESET) — make targets"
	@echo ""
	@grep -E '^## [a-zA-Z0-9_-]+:' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk 'match($$0, /: /) {printf "  $(CYAN)%-18s$(RESET) %s\n", substr($$0, 1, RSTART - 1), substr($$0, RSTART + 2)}'
	@echo ""
	@echo "$(BOLD)Variables$(RESET)"
	@echo "  $(CYAN)TAGS$(RESET)               build tags for every go invocation (default: none)"
	@echo "                     e.g. make test TAGS=drbd"
	@echo "  $(CYAN)VERSION$(RESET)            the release tag, required by release-alpha; no default"
	@echo "                     e.g. make release-alpha VERSION=v0.3.2-alpha"
	@echo "  $(CYAN)RELEASE_REMOTE$(RESET)     git remote the release is pushed to (default: origin)"
