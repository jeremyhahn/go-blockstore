#!/bin/sh
# A fixture proving the fail-open scanner accepts a STATED reason and ignores
# prose about the construction.
set -eu

# This comment discusses `|| true` and `|| :` at length without using either,
# the way the incident notes in this repository do.

vgs --noheadings || true  # guard:fail-open an absent vgs means no volume groups, which is the normal case

# guard:fail-open the marker may also sit on the line above
dmsetup ls || :

# A trailing comment that merely MENTIONS the construction is not one. Only what
# precedes the "#" is executed, and a scanner that missed that would fire on
# every incident note in this repository that explains the bug.
lsblk --noheadings   # do not write `|| true` here; handle the failure instead

echo "done"
