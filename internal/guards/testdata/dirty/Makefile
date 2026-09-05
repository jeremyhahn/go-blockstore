# A fixture proving the fail-open scanner reads Makefiles too, not only .sh —
# the swallowed exit in this repository's own `clean` target lives in one.
.PHONY: fixture-clean
fixture-clean:
	@rm -rf build || true
