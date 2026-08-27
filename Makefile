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
TAGS ?=

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
# No integration suite exists yet — the providers that need one ship in #2/#3/#4.
# The target exists so the contract in devops.md §4 is real from the start and
# the first suite is added by writing tests, not by inventing a target.
integration-test:
	@echo "$(CYAN)$(BOLD)→ Running integration tests...$(RESET)"
	$(GO) test -tags=integration$(if $(strip $(TAGS)),$(comma)$(strip $(TAGS)),) -count=1 -timeout=$(TEST_TIMEOUT) ./...
	@echo "$(GREEN)✓ Integration tests complete$(RESET)"

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
