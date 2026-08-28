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
	# Read as ONE bare token, not scrubbed. `tr -d ' \t\n\r'` DELETED all
	# whitespace, so a malformed `0.74 .0` (or a stray second line) was silently
	# normalised to a plausible-looking version and then passed the semver check
	# below — verify-not-normalise, at the source. awk emits the value only when
	# the file holds exactly one whitespace-delimited token; anything else yields
	# empty, caught by the "resolved to empty" guard immediately after. This keeps
	# EVERY call site strict (Makefile, nightly.yml, a bare direct invocation),
	# not just the one that passes $2.
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

# NO version-based idempotency fast path — deliberately removed.
#
# It used to `exit 0` when an existing ${INSTALL_DIR}/trivy self-reported the
# pinned version. That trusted the binary's own `--version` string, which any
# corrupted or planted binary can print: the skip blessed a file it never
# verified, so a security scanner could be silently swapped and this installer
# would still report success. Self-reported version is not a trust anchor.
#
# A trustworthy skip would hash the on-disk binary against the pinned EXTRACTED
# binary's SHA-256 (as scripts/install-shellcheck.sh now does). trivy cannot pin
# that in-repo the same way: its checksums are FETCHED from the release origin,
# not committed here, and its version is data-driven from .trivy-version — so a
# per-version binary hash in this script would break the single-source
# "bump = edit .trivy-version only" workflow and would not scale across the many
# versions the fleet pins. The honest fix is therefore to ALWAYS run the
# verified path below: download, check the tarball against the published SHA-256,
# extract, install. The cost is one download per explicit invocation (this is an
# explicitly-invoked install step, not a per-build hook), and correctness is
# absolute — the installed binary is always one whose bytes were just verified.

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
