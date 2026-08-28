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
TRIVY_VERSION := $(shell tr -d ' \t\n\r' < .trivy-version 2>/dev/null)

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
# The drbd provider's real-cluster suite is NOT in here, and that is deliberate.
# It carries `drbd_integration` as a second tag because it creates and destroys
# logical volumes and DRBD resources on the host it runs on: under `integration`
# it would run from `make ci`, on every machine, either doing that or hard
# failing on its own destructive-operation guard.
#
# The cost of that separation is that a green run of THIS target says nothing
# about the drbd provider, so the banner says so rather than letting a developer
# assume otherwise. Running it needs a configured two-node pair and root:
#
#     make integration-test-drbd
#
integration-test:
	@echo "$(CYAN)$(BOLD)→ Running integration tests...$(RESET)"
	$(GO) test -tags=integration$(if $(strip $(TAGS)),$(comma)$(strip $(TAGS)),) -count=1 -timeout=$(TEST_TIMEOUT) ./...
	@echo "$(YELLOW)  note: the drbd real-cluster suite is not included; see integration-test-drbd$(RESET)"
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
lint: fmt-check vet golangci-lint actionlint

.PHONY: golangci-lint
## golangci-lint: Run golangci-lint (config is version "2" — needs the v2 binary)
golangci-lint:
	@echo "$(CYAN)$(BOLD)→ Running golangci-lint...$(RESET)"
	@GOPATH=$$($(GO) env GOPATH); \
	BIN=""; \
	for cand in "$$GOPATH/bin/golangci-lint" $$(command -v golangci-lint 2>/dev/null) /usr/local/bin/golangci-lint /usr/bin/golangci-lint; do \
		[ -x "$$cand" ] || continue; \
		ver=$$("$$cand" version 2>/dev/null | grep -oE 'version v?[0-9]+' | grep -oE '[0-9]+' | head -1); \
		if [ "$$ver" = "2" ]; then BIN="$$cand"; break; fi; \
	done; \
	if [ -z "$$BIN" ]; then \
		echo "$(RED)✗ golangci-lint v2 not found (.golangci.yml is version: \"2\")$(RESET)"; \
		echo "$(YELLOW)  Install the pinned version: make install-tools$(RESET)"; \
		exit 1; \
	fi; \
	echo "$(CYAN)  Using $$BIN$(RESET)"; \
	"$$BIN" run --timeout=5m ./...
	@echo "$(GREEN)✓ golangci-lint passed$(RESET)"

.PHONY: actionlint
## actionlint: Lint the workflow files
# A missing actionlint FAILS this target. It used to warn and return 0, which is
# the same fail-open the trivy target carried: `make lint` would report success
# with a declared check never run, and on a machine without the binary it would
# report success forever. `lint` is part of `ci`, so that silence propagated
# straight into the pipeline's exit code.
#
# The runner labels it must accept live in .github/actionlint.yaml — without
# that file every self-hosted label reads as an unknown runner; with it, a
# MISSPELLED label is still caught.
actionlint:
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
	@echo "$(GREEN)✓ actionlint passed$(RESET)"

# ==============================================================================
# Security (devops.md §8)
# ==============================================================================

.PHONY: install-tools
## install-tools: Install the pinned linter and the security scanners
# trivy is not a `go install` target, so it comes from scripts/install-trivy.sh
# — the same script .github/workflows/nightly.yml runs, which downloads the
# PINNED release artifact and verifies its published SHA-256 before executing
# anything. Nothing here pipes a fetched script into a shell. One installer for
# both call sites, so the scanner on a dev box and the scanner in CI cannot
# drift apart.
#
# It writes into GOPATH/bin and needs no root, and it lives in this
# explicitly-invoked target so nothing mutates a developer's machine as a side
# effect of a build or test (devops.md §4).
install-tools:
	@echo "$(CYAN)$(BOLD)→ Installing tools...$(RESET)"
	@echo "$(CYAN)  golangci-lint v2.12.2 (pinned — see .github/workflows/ci.yml)$(RESET)"
	@$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
	@echo "$(CYAN)  gosec$(RESET)"
	@$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest
	@echo "$(CYAN)  govulncheck$(RESET)"
	@$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "$(CYAN)  actionlint$(RESET)"
	@$(GO) install github.com/rhysd/actionlint/cmd/actionlint@latest
	@echo "$(CYAN)  trivy $(TRIVY_VERSION) (pinned, checksum-verified)$(RESET)"
	@./scripts/install-trivy.sh "$$($(GO) env GOPATH)/bin"
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
