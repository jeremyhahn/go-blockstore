#!/bin/sh
# Install a pinned, checksum-verified shellcheck; actionlint disables its SC rules without it.
#
#   usage: scripts/install-shellcheck.sh <install-dir> [version]
#
# Upstream publishes no checksums, so the SHA-256s are pinned below. To bump: change PINNED_VERSION, add the artifacts' hashes and re-run `make lint`.

set -eu

# The pinned version. Its per-artifact SHA-256 lives in the checksum table
# below; the two move together, in one reviewed commit, or not at all.
PINNED_VERSION=0.11.0

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
	echo "error: shellcheck version '${VERSION}' is not a bare semver (expected e.g. 0.11.0)" >&2
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

# Pinned SHA-256s keyed by "version:artifact": EXPECTED_SHA256 for the tarball, EXPECTED_BIN_SHA256 for the extracted binary. A missing entry is refused.
EXPECTED_SHA256=
EXPECTED_BIN_SHA256=
case "${VERSION}:${ARTIFACT}" in
	"0.11.0:shellcheck-v0.11.0.linux.x86_64.tar.xz")
		EXPECTED_SHA256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
		EXPECTED_BIN_SHA256=4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b ;;
	"0.11.0:shellcheck-v0.11.0.linux.aarch64.tar.xz")
		EXPECTED_SHA256=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
		EXPECTED_BIN_SHA256=127f13925eadd52c341bca0ebaf9ab0dbd78c6468f30a8f262a528bf8de47546 ;;
	*)
		echo "error: no pinned SHA-256 for ${ARTIFACT} at version ${VERSION}" >&2
		echo "       Add it to the checksum table in $0 in the same commit that bumps the version." >&2
		exit 1
		;;
esac

# Skip when the on-disk binary hashes to EXPECTED_BIN_SHA256.
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

# Verify the extracted binary against its own pin before installing.
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
