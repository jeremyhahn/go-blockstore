#!/bin/sh
# A fixture for the fail-open scanner. Every line below swallows an exit status
# with no stated reason, which is the violation — one line per SPELLING the
# scanner recognizes, so dropping any one of them from failOpenPatterns fails
# the golden test rather than passing on the strength of the others.
set -eu

dmsetup ls | grep -c 'bs-' || true

vgs --noheadings ||true

pvs --noheadings || :

lvs --noheadings ||:

# A trailing comment does not excuse the construction before it.
blkid /dev/sda1 || true   # a trailing comment stating no reason is not an exemption

echo "done"
