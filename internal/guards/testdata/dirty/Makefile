# A fixture for the fail-open scanner, which reads Makefile recipes as well as
# CI YAML — the swallowed exit in this repository's own `clean` target lives in
# one. Every recipe line below swallows an exit status with no stated reason,
# which is the violation: one line per SPELLING the scanner recognizes, so
# dropping any one of them from failOpenPatterns fails the golden test rather
# than passing on the strength of the others. The last line carries a trailing
# comment, which does not excuse the construction before it.
.PHONY: fixture-clean
fixture-clean:
	@rm -rf build || true
	vgs --noheadings ||true
	pvs --noheadings || :
	lvs --noheadings ||:
	blkid /dev/sda1 || true   # a trailing comment stating no reason is not an exemption
