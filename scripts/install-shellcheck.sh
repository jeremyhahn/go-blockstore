#!/bin/sh
# Install a PINNED, checksum-verified shellcheck.
#
#   usage: scripts/install-shellcheck.sh <install-dir> [version]
#
# The ONE installer for shellcheck in this repo. `make install-tools` calls it
# and the Gitea CI lint job runs the same script, so the shellcheck that backs
# actionlint's SC* rules on a developer's machine and the one in CI are the same
# binary and cannot drift.
#
# WHY shellcheck HAS TO BE INSTALLED AT ALL
# -----------------------------------------
# actionlint delegates every SC-prefixed rule to shellcheck. With shellcheck NOT
# on PATH it DISABLES those rules and still EXITS 0 at default verbosity — only
# `actionlint -verbose` prints "Rule shellcheck was disabled". So `make lint`
# and the CI lint job were a paper gate for shell findings on a box that lacks
# the tool; that is what let a real SC2046 reach main (fixed in #21). The lint
# target now asserts this binary is present, but an assertion with no way to
# satisfy it is just a red an agent cannot clear — hence this installer lands
# with it.
#
# WHY NOT `apt-get install shellcheck` OR `curl ... | sh`
# -------------------------------------------------------
# The distro package floats to whatever the archive ships (version drift between
# CI and a dev box is exactly what the SC gate cannot tolerate), and piping a
# fetched script into a shell runs unread, unverified code as the build user.
# This downloads the PINNED release artifact and checks its bytes before
# anything is executed. Nothing from the download is ever run as a script.
#
# HOW THIS PINS, AND WHY IT IS STRONGER THAN scripts/install-trivy.sh
# -------------------------------------------------------------------
# Upstream (koalaman/shellcheck) publishes NO checksums file next to its release
# artifacts, so — unlike install-trivy.sh, which fetches trivy's published
# checksums from the same origin as the tarball — the expected SHA-256 is PINNED
# HERE, in the repo, under code review. That is the property install-trivy.sh
# documents it does NOT have: a hash committed to the tree is not fetched from
# the same place as the bytes it guards, so a compromised release that rewrites
# the artifact cannot also rewrite the expectation without a reviewed commit to
# this file. The cost is that bumping the version REQUIRES updating the pinned
# hash below in the same commit; a version with no embedded checksum is refused
# rather than downloaded on trust.
#
# To bump shellcheck: change PINNED_VERSION, add the new artifacts' SHA-256 to
# the checksum table, run this, and re-run `make lint`.

set -eu

# The pinned version. Its per-artifact SHA-256 lives in the checksum table
# below; the two move together, in one reviewed commit, or not at all.
PINNED_VERSION=0.10.0

INSTALL_DIR=${1:-}
if [ -z "${INSTALL_DIR}" ]; then
	echo "usage: $0 <install-dir> [version]" >&2
	exit 2
fi

VERSION=${2:-${PINNED_VERSION}}
if [ -z "${VERSION}" ]; then
	echo "error: shellcheck version resolved to empty" >&2
	exit 1
fi

# Refuse a version string that is not a plain semver. It is interpolated into a
# download URL and an artifact name, and a pinned installer that will fetch
# whatever it is handed is not pinned.
if ! printf '%s' "${VERSION}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "error: shellcheck version '${VERSION}' is not a bare semver (expected e.g. 0.10.0)" >&2
	exit 1
fi

# xz is required: shellcheck ships .tar.xz, not .tar.gz.
for tool in curl tar xz sha256sum; do
	command -v "${tool}" > /dev/null 2>&1 || {
		echo "error: ${tool} is required and was not found" >&2
		exit 1
	}
done

OS=$(uname -s)
ARCH=$(uname -m)
case "${OS}:${ARCH}" in
	Linux:x86_64)              ARTIFACT="shellcheck-v${VERSION}.linux.x86_64.tar.xz" ;;
	Linux:aarch64|Linux:arm64) ARTIFACT="shellcheck-v${VERSION}.linux.aarch64.tar.xz" ;;
	*)
		# Deliberately not guessing. A wrong artifact name would fail the
		# checksum step anyway, but failing here says why.
		echo "error: unsupported platform ${OS}/${ARCH} — add its artifact name and checksum here" >&2
		exit 1
		;;
esac

# The pinned SHA-256 for each artifact, keyed by "version:artifact". Upstream
# publishes none, so these are recorded here from the release and verified in
# the same reviewed commit that sets PINNED_VERSION. A version/artifact with no
# entry is refused, never downloaded on trust.
#
# TWO hashes per artifact, because they guard two different bytes:
#   EXPECTED_SHA256      — the TARBALL (.tar.xz). Checked before anything is
#                          extracted, so a tampered archive is never even opened.
#   EXPECTED_BIN_SHA256  — the EXTRACTED shellcheck binary. This is the anchor
#                          the idempotency fast path needs: an on-disk binary is
#                          trusted only if ITS OWN bytes hash to this, never
#                          because it self-reports the pinned --version (a
#                          corrupted or malicious binary can print any version).
#                          It also re-verifies what we just extracted and install.
EXPECTED_SHA256=
EXPECTED_BIN_SHA256=
case "${VERSION}:${ARTIFACT}" in
	"0.10.0:shellcheck-v0.10.0.linux.x86_64.tar.xz")
		EXPECTED_SHA256=6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87
		EXPECTED_BIN_SHA256=f35ae15a4677945428bdfe61ccc297490d89dd1e544cc06317102637638c6deb ;;
	"0.10.0:shellcheck-v0.10.0.linux.aarch64.tar.xz")
		EXPECTED_SHA256=324a7e89de8fa2aed0d0c28f3dab59cf84c6d74264022c00c22af665ed1a09bb
		EXPECTED_BIN_SHA256=4111c09318d10b93653a42179381273f31061b34987978346fbd19a6e81a74c3 ;;
	*)
		echo "error: no pinned SHA-256 for ${ARTIFACT} at version ${VERSION}" >&2
		echo "       Add it to the checksum table in $0 in the same commit that bumps the version." >&2
		exit 1
		;;
esac

# Already the pinned binary? Skip — but decide that by HASHING the on-disk file,
# never by its self-reported --version. A `--version` string is output the
# binary chooses to print: a corrupted or planted `shellcheck` can claim 0.10.0
# and this fast path would then bless it and exit 0, having verified nothing.
# The trust anchor is EXPECTED_BIN_SHA256 (the reviewed artifact's extracted
# bytes). If the file on disk hashes to it, it IS the pinned binary and there is
# nothing to do; anything else — wrong version, corruption, tampering — falls
# through to the verified download+install below.
if [ -x "${INSTALL_DIR}/shellcheck" ]; then
	ON_DISK_SHA=$(sha256sum "${INSTALL_DIR}/shellcheck" 2>/dev/null | cut -d' ' -f1)
	if [ "${ON_DISK_SHA}" = "${EXPECTED_BIN_SHA256}" ]; then
		echo "shellcheck ${VERSION} already installed at ${INSTALL_DIR}/shellcheck (binary hash verified)"
		exit 0
	fi
fi

BASE_URL="https://github.com/koalaman/shellcheck/releases/download/v${VERSION}"
TMP=$(mktemp -d)
# shellcheck disable=SC2064  # expand TMP now, on purpose: it must not change
trap "rm -rf '${TMP}'" EXIT INT TERM

echo "→ downloading shellcheck ${VERSION} (${ARTIFACT})"
curl -sSfL --proto '=https' --tlsv1.2 -o "${TMP}/${ARTIFACT}" "${BASE_URL}/${ARTIFACT}"

echo "→ verifying SHA-256 (pinned in-repo)"
printf '%s  %s\n' "${EXPECTED_SHA256}" "${ARTIFACT}" > "${TMP}/expected.sha256"
if ! (cd "${TMP}" && sha256sum -c expected.sha256); then
	echo "error: CHECKSUM MISMATCH for ${ARTIFACT} — refusing to install" >&2
	echo "       The download does not match the SHA-256 pinned for v${VERSION}." >&2
	echo "       Do not work around this. Re-run; if it persists, treat it as a" >&2
	echo "       supply-chain event and escalate before installing anything." >&2
	exit 1
fi

echo "→ installing to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
# The binary sits at "shellcheck-v<version>/shellcheck" inside the tarball (a
# versioned top-level directory) — extract exactly that one entry.
tar -xJf "${TMP}/${ARTIFACT}" -C "${TMP}" "shellcheck-v${VERSION}/shellcheck"

# Verify the EXTRACTED binary against its own pin before installing it. The
# tarball hash already cleared the archive, so this is defence in depth — but it
# is also what proves EXPECTED_BIN_SHA256 (the value the fast path trusts) really
# is this artifact's binary, so the two pins can never silently disagree.
echo "→ verifying extracted binary SHA-256 (pinned in-repo)"
printf '%s  %s\n' "${EXPECTED_BIN_SHA256}" "shellcheck-v${VERSION}/shellcheck" > "${TMP}/expected-bin.sha256"
if ! (cd "${TMP}" && sha256sum -c expected-bin.sha256); then
	echo "error: extracted shellcheck binary does not match its pinned SHA-256 — refusing to install" >&2
	echo "       The pinned tarball and binary hashes disagree; do not work around this." >&2
	exit 1
fi

install -m 0755 "${TMP}/shellcheck-v${VERSION}/shellcheck" "${INSTALL_DIR}/shellcheck"

"${INSTALL_DIR}/shellcheck" --version | sed -n '2p'
echo "✓ shellcheck ${VERSION} installed at ${INSTALL_DIR}/shellcheck (binary hash verified)"
