#!/bin/sh
# Install a PINNED, checksum-verified trivy.
#
#   usage: scripts/install-trivy.sh <install-dir> [version]
#
# The ONE installer for trivy in this repo. Both `make install-tools` and the
# Gitea path of .github/workflows/nightly.yml call it, so the scanner on a
# developer's machine and the scanner in CI are the same binary — and neither
# can drift from the other by editing one of them.
#
# WHY NOT `curl .../install.sh | sh`
# ---------------------------------
# That is what this replaces, in both call sites. It fetched a script from a
# MUTABLE ref (contrib/install.sh on `main`) and executed it, unread and
# unverified, as the build user. Anyone who could change that file — upstream
# compromise, account takeover, a MITM on the fetch — would get arbitrary code
# execution on the runner, and in nightly.yml that runner holds a token with
# security-events: write. Pulling the security scanner itself through an
# unverified channel inverts the point of running it.
#
# WHAT THIS GUARANTEES, AND WHAT IT DOES NOT
# ------------------------------------------
# Guarantees: the version is fixed (no silent upgrade to whatever shipped
# today), the bytes are checked against the release's published SHA-256 before
# anything is executed, and nothing from the download is ever run as a script.
# A corrupted or tampered-in-transit tarball is refused.
#
# Does NOT guarantee: the checksums file is fetched from the same origin as the
# tarball, so this is not a signature check and does not defend against a
# compromised release where an attacker rewrites both. Upstream publishes a
# sigstore bundle next to each artifact (trivy_<ver>_checksums.txt.sigstore.json);
# verifying that with cosign is the next hardening step and needs cosign on the
# runners first. Stated here rather than implied, so nobody reads "verified" as
# more than it is.
#
# To bump trivy: edit .trivy-version, run this, and re-run `make security`. The
# same file feeds the trivy-action `version:` input in nightly.yml, so the
# GitHub and Gitea paths move together.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)

INSTALL_DIR=${1:-}
if [ -z "${INSTALL_DIR}" ]; then
	echo "usage: $0 <install-dir> [version]" >&2
	exit 2
fi

VERSION=${2:-}
if [ -z "${VERSION}" ]; then
	if [ ! -f "${REPO_ROOT}/.trivy-version" ]; then
		echo "error: no version given and ${REPO_ROOT}/.trivy-version is missing" >&2
		exit 1
	fi
	VERSION=$(tr -d ' \t\n\r' < "${REPO_ROOT}/.trivy-version")
fi
if [ -z "${VERSION}" ]; then
	echo "error: trivy version resolved to empty" >&2
	exit 1
fi

# Refuse a version string that is not a plain semver. It is interpolated into a
# download URL, and a pinned installer that will fetch whatever it is handed is
# not pinned.
if ! printf '%s' "${VERSION}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "error: trivy version '${VERSION}' is not a bare semver (expected e.g. 0.74.0)" >&2
	exit 1
fi

for tool in curl tar sha256sum; do
	command -v "${tool}" > /dev/null 2>&1 || {
		echo "error: ${tool} is required and was not found" >&2
		exit 1
	}
done

OS=$(uname -s)
ARCH=$(uname -m)
case "${OS}:${ARCH}" in
	Linux:x86_64)          ARTIFACT="trivy_${VERSION}_Linux-64bit.tar.gz" ;;
	Linux:aarch64|Linux:arm64) ARTIFACT="trivy_${VERSION}_Linux-ARM64.tar.gz" ;;
	*)
		# Deliberately not guessing. A wrong artifact name would fail the
		# checksum step anyway, but failing here says why.
		echo "error: unsupported platform ${OS}/${ARCH} — add its artifact name here" >&2
		exit 1
		;;
esac

# Already at the pinned version? Nothing to do. Note this compares against the
# PIN, not against "some trivy exists": a box carrying a different version is
# reinstalled, which is the whole point of pinning.
if [ -x "${INSTALL_DIR}/trivy" ]; then
	CURRENT=$("${INSTALL_DIR}/trivy" --version 2>/dev/null | head -1 | sed -n 's/^Version: \([0-9.]*\).*/\1/p')
	if [ "${CURRENT}" = "${VERSION}" ]; then
		echo "trivy ${VERSION} already installed at ${INSTALL_DIR}/trivy"
		exit 0
	fi
fi

BASE_URL="https://github.com/aquasecurity/trivy/releases/download/v${VERSION}"
TMP=$(mktemp -d)
# shellcheck disable=SC2064  # expand TMP now, on purpose: it must not change
trap "rm -rf '${TMP}'" EXIT INT TERM

echo "→ downloading trivy ${VERSION} (${ARTIFACT})"
curl -sSfL --proto '=https' --tlsv1.2 -o "${TMP}/${ARTIFACT}" "${BASE_URL}/${ARTIFACT}"
curl -sSfL --proto '=https' --tlsv1.2 -o "${TMP}/checksums.txt" "${BASE_URL}/trivy_${VERSION}_checksums.txt"

echo "→ verifying SHA-256"
# Reduce the published list to the ONE line for our artifact and check that.
# Feeding the whole file to `sha256sum -c` would report every other artifact as
# missing and exit non-zero even on a good download.
if ! grep -F " ${ARTIFACT}" "${TMP}/checksums.txt" > "${TMP}/expected.sha256"; then
	echo "error: ${ARTIFACT} is not listed in the published checksums file" >&2
	exit 1
fi
# One line, exactly. More than one means the grep matched something unexpected.
if [ "$(wc -l < "${TMP}/expected.sha256")" -ne 1 ]; then
	echo "error: expected exactly one checksum line for ${ARTIFACT}" >&2
	exit 1
fi
if ! (cd "${TMP}" && sha256sum -c expected.sha256); then
	echo "error: CHECKSUM MISMATCH for ${ARTIFACT} — refusing to install" >&2
	echo "       The download does not match the checksum published for v${VERSION}." >&2
	echo "       Do not work around this. Re-run; if it persists, treat it as a" >&2
	echo "       supply-chain event and escalate before installing anything." >&2
	exit 1
fi

echo "→ installing to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
tar -xzf "${TMP}/${ARTIFACT}" -C "${TMP}" trivy
install -m 0755 "${TMP}/trivy" "${INSTALL_DIR}/trivy"

"${INSTALL_DIR}/trivy" --version | head -1
echo "✓ trivy ${VERSION} installed at ${INSTALL_DIR}/trivy"
