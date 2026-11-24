#!/bin/sh
# Installs a pinned, SHA-256-verified trivy (usage: scripts/install-trivy.sh <install-dir> [version]); version from .trivy-version.

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
	# Read .trivy-version as exactly one token; anything else yields empty and is refused below.
	VERSION=$(awk '{for(i=1;i<=NF;i++){n++;v=$i}} END{if(n==1)print v}' "${REPO_ROOT}/.trivy-version")
fi
if [ -z "${VERSION}" ]; then
	echo "error: trivy version resolved to empty (missing, whitespace-only, or malformed .trivy-version)" >&2
	exit 1
fi

# Refuse a version string that is not a plain semver. It is interpolated into a
# download URL, and a pinned installer that will fetch whatever it is handed is
# not pinned.
if ! printf '%s' "${VERSION}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "error: trivy version '${VERSION}' is not a bare semver (expected e.g. 0.75.0)" >&2
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

# Always download and verify; an installed binary's self-reported version is not trusted.

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
