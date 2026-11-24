# Makefile for go-blockstore, an embedded block and volume storage library. CI runs these same targets.

# ==============================================================================
# Configuration
# ==============================================================================

# Comma-separated build tags for every go invocation; also update run.build-tags in .golangci.yml and BUILD_TAGS in ci.yml.
TAGS ?= drbd

comma := ,
empty :=
space := $(empty) $(empty)

# GO_BUILD_TAGS (space-separated) is added to each target's tags, never replaces them; tags_flag merges and dedupes.
GO_BUILD_TAGS ?=
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))
tag_csv = $(subst $(space),$(comma),$(strip $(call uniq,$(subst $(comma),$(space),$1))))
tags_flag = $(if $(strip $(call tag_csv,$1)),-tags=$(call tag_csv,$1),)
# With GO_BUILD_TAGS, never without: a target's fixed tags plus the CI set.
with_ci_tags = $(call tags_flag,$1 $(GO_BUILD_TAGS))

BUILD_TAGS_LIST := $(TAGS) $(GO_BUILD_TAGS)
TAG_FLAGS := $(call tags_flag,$(BUILD_TAGS_LIST))

# --build-tags replaces .golangci.yml run.build-tags, so pass it only with GO_BUILD_TAGS; check-build-tags.sh catches drift.
GOLANGCI_CONFIG_TAGS := drbd
LINT_TAG_FLAGS := $(if $(strip $(GO_BUILD_TAGS)),--build-tags=$(call tag_csv,$(GOLANGCI_CONFIG_TAGS) $(BUILD_TAGS_LIST)),)

GO := go
GOBUILD := $(GO) build $(TAG_FLAGS)
GOTEST := $(GO) test $(TAG_FLAGS)
GOVET := $(GO) vet $(TAG_FLAGS)
GOMOD := $(GO) mod
GOCLEAN := $(GO) clean

PROJECT_NAME := go-blockstore
MODULE := github.com/jeremyhahn/go-blockstore

# REPO_NAME is literal (it sets the signing identity); RELEASE_REMOTE defaults to the configured remote and is checked before use.
AGENT_GIT ?= /home/jhahn/sources/automatethethings/software/scripts/agent-git.sh
REPO_NAME ?= go-blockstore
RELEASE_REMOTE ?= origin

COVERAGE_DIR := coverage
COVERAGE_PROFILE := $(COVERAGE_DIR)/unit.out

# Must match COVERAGE_THRESHOLD in ci.yml.
COVERAGE_THRESHOLD := 90

# Finite bound: lease tests use real timers, so a deadlock shows as a timeout.
TEST_TIMEOUT := 900s

# The trivy version from .trivy-version; awk emits it only when the file holds exactly one token.
TRIVY_VERSION := $(shell awk '{for(i=1;i<=NF;i++){n++;v=$$i}} END{if(n==1)print v}' .trivy-version 2>/dev/null)

# Analyser versions, identical to the CI runner image and the ci.yml floors.
GOLANGCI_LINT_VERSION := v2.14.0
GOSEC_VERSION         := v2.29.0
# x/tools in gosec v2.29.0's go.mod cannot read Go 1.27 export data; remove
# this when the gosec pin names an x/tools that can.
XTOOLS_VERSION        := v0.52.0
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
# -race is part of make test; race below runs the detector without coverage.
test: check-build-tags
	@echo "$(CYAN)$(BOLD)→ Running unit tests (race detector, coverage)...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -race -count=1 -timeout=$(TEST_TIMEOUT) -covermode=atomic -coverprofile=$(COVERAGE_PROFILE) ./...
	@echo ""
# guard:fail-open a display line only — the coverage THRESHOLD is enforced by the `coverage` target, which does not swallow
	@$(GO) tool cover -func=$(COVERAGE_PROFILE) | tail -1 | awk '{print "  $(GREEN)Total coverage: " $$NF "$(RESET)"}' || true
	@echo "$(GREEN)✓ Unit tests complete$(RESET)"

.PHONY: check-build-tags
## check-build-tags: Prove GO_BUILD_TAGS reaches every template target, and empty is a no-op (#98)
# Reads make -n, compiles nothing; a target that drops GO_BUILD_TAGS would otherwise pass on the wrong tags.
check-build-tags:
	@./scripts/check-build-tags.sh

.PHONY: race
## race: Run the race detector without coverage instrumentation
race:
	@echo "$(CYAN)$(BOLD)→ Running race detector...$(RESET)"
	$(GOTEST) -race -count=1 -timeout=$(TEST_TIMEOUT) ./...
	@echo "$(GREEN)✓ No races detected$(RESET)"

.PHONY: integration-test
## integration-test: Run the integration suite (build tag: integration)
# The destructive drbd and local suites have their own tags and targets: integration-test-drbd, integration-test-local (root).
integration-test:
	@echo "$(CYAN)$(BOLD)→ Running integration tests...$(RESET)"
	$(GO) test $(call tags_flag,integration $(BUILD_TAGS_LIST)) -count=1 -timeout=$(TEST_TIMEOUT) ./...
	@echo "$(YELLOW)  note: the destructive real-provider suites are NOT included:$(RESET)"
	@echo "$(YELLOW)        drbd real-cluster    → make integration-test-drbd$(RESET)"
	@echo "$(YELLOW)        local real LVM/LUKS  → make integration-test-local$(RESET)"
	@echo "$(GREEN)✓ Integration tests complete$(RESET)"

.PHONY: integration-test-drbd
## integration-test-drbd: Run the drbd real-cluster suite (DESTRUCTIVE, needs root + a configured pair)
# Creates and destroys LVs and DRBD resources; refuses without GO_BLOCKSTORE_DRBD_ALLOW_DESTRUCTIVE=1 and the GO_BLOCKSTORE_DRBD_* settings.
integration-test-drbd:
	@echo "$(CYAN)$(BOLD)→ Running the drbd real-cluster suite...$(RESET)"
	@echo "$(YELLOW)  DESTRUCTIVE: creates and destroys LVs and DRBD resources on this host$(RESET)"
	$(GO) test $(call with_ci_tags,drbd drbd_integration) -count=1 -timeout=$(TEST_TIMEOUT) -run Integration ./pkg/drbd/
	@echo "$(GREEN)✓ drbd real-cluster suite complete$(RESET)"

.PHONY: integration-test-local
## integration-test-local: Run the local provider's real LVM/LUKS suite (DESTRUCTIVE, needs root + loopback)
# Creates and destroys loop devices, VGs and LUKS volumes; run as: sudo -E GO_BLOCKSTORE_LOCAL_ALLOW_DESTRUCTIVE=1 make integration-test-local
integration-test-local:
	@echo "$(CYAN)$(BOLD)→ Running the local provider real LVM/LUKS suite...$(RESET)"
	@echo "$(YELLOW)  DESTRUCTIVE: creates and destroys loop devices, VGs and LUKS volumes on this host$(RESET)"
	$(GO) test $(call with_ci_tags,local_integration) -count=1 -timeout=$(TEST_TIMEOUT) -run Integration ./pkg/local/
	@echo "$(GREEN)✓ local provider real suite complete$(RESET)"

.PHONY: integration-clean-local
## integration-clean-local: Remove state a KILLED local integration run left behind
# Removes only this suite's mappings (bs-bsit<pid>x<n>_*), VGs (bsit<pid>x<n>) and their loop devices, printing each first.
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
# Runs the unit suite in a container with the same tags, so branches a developer host never takes still run; module cache read-only.
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
# Opens a container written by cryptsetup; selecting the tag declares cryptsetup present, so its absence fails.
integration-test-cryptsetup:
	@echo "$(CYAN)$(BOLD)→ Running the cryptsetup compatibility gate...$(RESET)"
	@echo "$(YELLOW)  DESTRUCTIVE: creates and destroys loop devices, VGs and LUKS volumes on this host$(RESET)"
	@echo "$(YELLOW)  REQUIRES: root, loop devices, lvm2 AND the cryptsetup binary$(RESET)"
	$(GO) test $(call with_ci_tags,local_integration cryptsetup_compat) -count=1 -timeout=$(TEST_TIMEOUT) -run Integration ./pkg/local/
	@echo "$(GREEN)✓ cryptsetup compatibility gate complete$(RESET)"

.PHONY: guards
## guards: Run the whole-tree scanners (internal/guards)
# The binary checks the tree; the package tests prove each scanner still fires. No -run filter.
guards:
	@echo "$(CYAN)$(BOLD)→ Running the whole-tree guards...$(RESET)"
	$(GO) run ./internal/guards/cmd/guards
	@echo "$(CYAN)  …and proving each one can still fire:$(RESET)"
	$(GO) test -count=1 ./internal/guards/
	@echo "$(GREEN)✓ Guards passed$(RESET)"

.PHONY: test-kernel-mountinfo
## test-kernel-mountinfo: Check internal/mountinfo against a LIVE kernel (needs unprivileged user namespaces)
# The tests re-exec in a user and mount namespace; selecting the tag declares the capability, so a refusal fails.
test-kernel-mountinfo:
	@echo "$(CYAN)$(BOLD)→ Checking internal/mountinfo against this kernel...$(RESET)"
	@echo "$(YELLOW)  REQUIRES: a host that permits unprivileged user + mount namespaces$(RESET)"
	$(GO) test $(call with_ci_tags,kernel_mountinfo) -count=1 -timeout=$(TEST_TIMEOUT) -run TestAgainstARunningKernel -v ./internal/mountinfo/
	@echo "$(GREEN)✓ Live-kernel mountinfo checks complete$(RESET)"

.PHONY: test-kernel-dm
## test-kernel-dm: Check internal/luks against a LIVE device-mapper (needs /dev/mapper/control)
# Needs /dev/mapper/control; selecting the tag declares it, so its absence fails.
test-kernel-dm:
	@echo "$(CYAN)$(BOLD)→ Checking internal/luks against this kernel's device-mapper...$(RESET)"
	@echo "$(YELLOW)  REQUIRES: /dev/mapper/control, readable by this user$(RESET)"
	$(GO) test $(call with_ci_tags,kernel_dm) -count=1 -timeout=$(TEST_TIMEOUT) -run TestNativeMapping -v ./internal/luks/
	@echo "$(GREEN)✓ Live device-mapper checks complete$(RESET)"

.PHONY: test-kernel-keypath
## test-kernel-keypath: Check the key-path guard against a LIVE kernel (needs unprivileged user namespaces)
# Proves the key-path check runs after mount(2), using a real mount in a user namespace; a refusal fails.
test-kernel-keypath:
	@echo "$(CYAN)$(BOLD)→ Checking the key-path guard against this kernel...$(RESET)"
	@echo "$(YELLOW)  REQUIRES: a host that permits unprivileged user + mount namespaces$(RESET)"
	$(GO) test $(call with_ci_tags,kernel_keypath) -count=1 -timeout=$(TEST_TIMEOUT) -run TestAgainstARunningKernel -v ./pkg/local/
	@echo "$(GREEN)✓ Live-kernel key-path checks complete$(RESET)"

.PHONY: preflight-matrix
## preflight-matrix: Prove the startup privilege guard fires (and does not) in real containers
# Needs a Docker-capable host, not in make ci; each row asserts and a mismatch exits non-zero.
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
# Demands a minimum v2 version, so an older binary shadowing the image's is refused.
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
	"$$BIN" run $(strip --timeout=5m $(LINT_TAG_FLAGS)) ./...
	@echo "$(GREEN)✓ golangci-lint passed$(RESET)"

.PHONY: actionlint
## actionlint: Lint the workflow files (requires shellcheck for the SC* rules)
# Fails without actionlint, or without shellcheck on PATH (actionlint silently disables the SC rules); labels are in .github/actionlint.yaml.
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
# trivy and shellcheck come from the same checksum-verifying installers CI runs; they install into GOPATH/bin without root.
install-tools:
	@echo "$(CYAN)$(BOLD)→ Installing tools...$(RESET)"
	@echo "$(CYAN)  golangci-lint $(GOLANGCI_LINT_VERSION) (pinned — see the versions block above)$(RESET)"
	@$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@echo "$(CYAN)  gosec $(GOSEC_VERSION)$(RESET)"
	@# -ldflags is not decoration: without it gosec reports "Version: dev" and no
	@# log — here or in CI — can say which analyser produced a finding.
	@# Built in a throwaway module so it links XTOOLS_VERSION (handbook devcontainer form).
	@d=$$(mktemp -d); (cd "$$d" && export GOWORK=off && $(GO) mod init gosec-build && $(GO) get github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) golang.org/x/tools@$(XTOOLS_VERSION) && $(GO) install -ldflags "-X main.Version=$(GOSEC_VERSION)" github.com/securego/gosec/v2/cmd/gosec); rc=$$?; rm -rf "$$d"; exit $$rc
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

# Analysis-identical to the gosec step in ci.yml (rules, scope, thresholds); -concurrency 4 bounds memory; no -exclude rules.
GOSEC_ARGS = -concurrency 4 -stdout -verbose=text \
	-exclude-dir=test -exclude-dir=examples \
	-severity=medium -confidence=medium

# TAG_FLAGS is already comma-separated, as gosec expects.
GOSEC_TAG_FLAGS := $(TAG_FLAGS)

.PHONY: security
## security: The full devops.md §8 suite — gosec, govulncheck, go mod verify, trivy fs
# Every scanner is mandatory: a missing binary fails. security-go is the narrower Go-only set.
security: security-go trivy
	@echo "$(GREEN)$(BOLD)✓ Security suite complete (gosec, govulncheck, go mod verify, trivy fs)$(RESET)"

.PHONY: security-go
## security-go: The Go-toolchain scanners only — what the CI security job runs
# Mirrors the CI security job (no trivy); each scanner tells a signal death (128+N) from a finding.
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
# A missing trivy fails; the version check against .trivy-version is informational. The gate matches nightly.yml; the misconfiguration pass is advisory.
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
# Superset of the PR gate (adds trivy); the exact PR gate is lint, build, security-go, coverage.
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

# Signed, annotated release tag via agent-git.sh: explicit version, from main only, atomic push of commit and tag, fail-closed.
# VERSION is written unprefixed; the CHANGELOG and version checks match release.yml literally and must stay no looser than it.
# Settable values reach the recipe only through the exported environment, never spliced into recipe text.
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
	@echo "  $(CYAN)GO_BUILD_TAGS$(RESET)      extra tags added to every target's own (space-separated)"
	@echo "                     e.g. make build GO_BUILD_TAGS='cephrbd'"
	@echo "  $(CYAN)VERSION$(RESET)            the release tag, required by release-alpha; no default"
	@echo "                     e.g. make release-alpha VERSION=v0.3.2-alpha"
	@echo "  $(CYAN)RELEASE_REMOTE$(RESET)     git remote the release is pushed to (default: origin)"
