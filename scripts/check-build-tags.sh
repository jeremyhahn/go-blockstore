#!/bin/sh
# check-build-tags.sh — prove the Makefile honours GO_BUILD_TAGS (#98).
#
# ci-template v1.21+ calls every stage as `make <target> GO_BUILD_TAGS='a b'`.
# A target that ignores the variable still goes green, just on the wrong tag
# set, so nothing else would notice. This reads the commands `make -n` would
# run and asserts:
#
#   - a non-empty GO_BUILD_TAGS reaches build, test, the integration targets
#     and golangci-lint, comma-joined after the tags each already uses;
#   - an empty GO_BUILD_TAGS prints exactly the commands an unset one does,
#     and those are the commands the Makefile ran before #98;
#   - GOLANGCI_CONFIG_TAGS in the Makefile still equals run.build-tags in
#     .golangci.yml, since the lint flag replaces that list.
#
# Run by `make test` (check-build-tags). Plain sh, no grep: the substring tests
# are `case` patterns.
set -eu

cd "$(dirname "$0")/.."

MAKE_BIN=${MAKE:-make}
fail=0

# The caller's own TAGS / GO_BUILD_TAGS (and any inherited through MAKEFLAGS
# when this runs under `make test GO_BUILD_TAGS=...`) must not leak in: every
# assertion below is against the repository defaults.
dry() {
	env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u TAGS -u GO_BUILD_TAGS \
		"$MAKE_BIN" --no-print-directory -n "$@" 2>&1
}

expect() { # target, description, needle, make args...
	target=$1 what=$2 needle=$3
	shift 3
	out=$(dry "$target" "$@")
	case $out in
	*"$needle"*) echo "  ok   $target $what" ;;
	*)
		echo "  FAIL $target $what: no '$needle' in make -n output:" >&2
		printf '%s\n' "$out" >&2
		fail=1
		;;
	esac
}

refuse() { # target, description, needle, make args...
	target=$1 what=$2 needle=$3
	shift 3
	out=$(dry "$target" "$@")
	case $out in
	*"$needle"*)
		echo "  FAIL $target $what: unexpected '$needle' in make -n output" >&2
		fail=1
		;;
	*) echo "  ok   $target $what" ;;
	esac
}

same() { # target: empty GO_BUILD_TAGS prints what unset does
	if [ "$(dry "$1")" = "$(dry "$1" GO_BUILD_TAGS=)" ]; then
		echo "  ok   $1 empty GO_BUILD_TAGS is a no-op"
	else
		echo "  FAIL $1: GO_BUILD_TAGS= changes the command" >&2
		fail=1
	fi
}

echo "→ GO_BUILD_TAGS reaches every template target"
expect build "GO_BUILD_TAGS=x" "go build -tags=drbd,x ./..." GO_BUILD_TAGS=x
expect test "GO_BUILD_TAGS=x" "go test -tags=drbd,x -race" GO_BUILD_TAGS=x
expect test "GO_BUILD_TAGS='x y'" "go test -tags=drbd,x,y -race" "GO_BUILD_TAGS=x y"
expect test "GO_BUILD_TAGS=drbd (no repeat)" "go test -tags=drbd -race" GO_BUILD_TAGS=drbd
expect coverage "GO_BUILD_TAGS=x" "go test -tags=drbd,x -race" GO_BUILD_TAGS=x
expect integration-test "GO_BUILD_TAGS=x" "go test -tags=integration,drbd,x -count=1" GO_BUILD_TAGS=x
expect integration-test-drbd "GO_BUILD_TAGS=x" "go test -tags=drbd,drbd_integration,x -count=1" GO_BUILD_TAGS=x
expect integration-test-local "GO_BUILD_TAGS=x" "go test -tags=local_integration,x -count=1" GO_BUILD_TAGS=x
expect security-go "GO_BUILD_TAGS=x" "-severity=medium -confidence=medium -tags=drbd,x ./..." GO_BUILD_TAGS=x
expect security-go "GO_BUILD_TAGS=x (govulncheck)" 'GOFLAGS="-tags=drbd,x"' GO_BUILD_TAGS=x
expect golangci-lint "GO_BUILD_TAGS='x y'" "run --timeout=5m --build-tags=drbd,x,y ./..." "GO_BUILD_TAGS=x y"
expect build "TAGS= GO_BUILD_TAGS=x" "go build -tags=x ./..." TAGS= GO_BUILD_TAGS=x

echo "→ an empty GO_BUILD_TAGS changes nothing"
for t in build test coverage integration-test integration-test-drbd integration-test-local security-go golangci-lint; do
	same "$t"
done
expect build "unset" "go build -tags=drbd ./..."
expect test "unset" "go test -tags=drbd -race -count=1"
expect integration-test "unset" "go test -tags=integration,drbd -count=1"
expect integration-test-drbd "unset" "go test -tags=drbd,drbd_integration -count=1"
expect golangci-lint "unset" "run --timeout=5m ./..."
refuse golangci-lint "unset" "--build-tags"
expect build "TAGS= (untagged build)" "go build  ./..." TAGS=

echo "→ GOLANGCI_CONFIG_TAGS matches .golangci.yml run.build-tags"
# Collect the `- tag` items under `build-tags:` (the list ends at the first
# line that is not one).
yml="" inlist=0
while IFS= read -r line; do
	trimmed=$(printf '%s' "$line" | tr -d ' \t')
	if [ "$inlist" = 1 ]; then
		case $trimmed in
		-*) yml="$yml${yml:+,}${trimmed#-}" ;;
		*) break ;;
		esac
	elif [ "$trimmed" = "build-tags:" ]; then
		inlist=1
	fi
done < .golangci.yml
expect golangci-lint "config tags = .golangci.yml ($yml)" "--build-tags=$yml,zz ./..." TAGS= GO_BUILD_TAGS=zz

if [ "$fail" -ne 0 ]; then
	echo "✗ GO_BUILD_TAGS check failed" >&2
	exit 1
fi
echo "✓ GO_BUILD_TAGS reaches every target, and an empty value is a no-op"
