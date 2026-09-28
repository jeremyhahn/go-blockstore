// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-blockstore.
//
// go-blockstore is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package toolinstall

import "strconv"

// VersionError reports a version string that is not a bare semver.
type VersionError struct {
	Tool    string
	Version string
}

func (e *VersionError) Error() string {
	return "toolinstall: " + e.Tool + " version " + quote(e.Version) + " is not a bare semver (expected e.g. 1.2.3)"
}

// VersionFileError reports a version file that is missing, or that does not
// hold exactly one token.
type VersionFileError struct {
	Path string
	Err  error
}

func (e *VersionFileError) Error() string {
	if e.Err != nil {
		return "toolinstall: reading " + e.Path + ": " + e.Err.Error()
	}
	return "toolinstall: " + e.Path + " must hold exactly one version token (it is empty, whitespace or several tokens); refusing to guess"
}

func (e *VersionFileError) Unwrap() error { return e.Err }

// PlatformError reports a platform the tool table has no artifact for. It is
// refused rather than guessed: a wrong artifact would fail its checksum anyway,
// but failing here says why.
type PlatformError struct {
	Tool     string
	Platform string
}

func (e *PlatformError) Error() string {
	return "toolinstall: " + e.Tool + " has no artifact for " + e.Platform + "; add its artifact name (and pins) to the tool table"
}

// NoPinError reports a version/artifact with no in-repo hash. It is refused,
// never downloaded on trust.
type NoPinError struct {
	Tool     string
	Version  string
	Artifact string
}

func (e *NoPinError) Error() string {
	return "toolinstall: no pinned SHA-256 for " + e.Artifact + " at " + e.Tool + " " + e.Version +
		"; add it to the pin table in the same commit that bumps the version"
}

// ChecksumListError reports a published checksum list that does not name the
// artifact exactly once.
type ChecksumListError struct {
	Artifact string
	Matches  int
}

func (e *ChecksumListError) Error() string {
	return "toolinstall: the published checksums name " + e.Artifact + " " + itoa(e.Matches) + " time(s), not exactly once"
}

// ChecksumError reports bytes that do not match their expected SHA-256. Do not
// work around it: re-run, and if it persists treat it as a supply-chain event.
type ChecksumError struct {
	Tool string
	File string
	Want string
	Got  string
}

func (e *ChecksumError) Error() string {
	return "toolinstall: CHECKSUM MISMATCH for " + e.Tool + " " + e.File + " (want " + e.Want + ", got " + e.Got +
		") — refusing to install; if a re-run does not clear it, treat it as a supply-chain event and escalate"
}

// HTTPStatusError reports a download that did not answer 200.
type HTTPStatusError struct {
	URL    string
	Status string
}

func (e *HTTPStatusError) Error() string {
	return "toolinstall: GET " + e.URL + ": " + e.Status
}

// RedirectError reports a redirect the installer refused to follow.
type RedirectError struct {
	URL string
}

func (e *RedirectError) Error() string {
	return "toolinstall: refusing a redirect to " + e.URL + " (not https, or too many hops)"
}

// ExtractError reports a failed tar extraction.
type ExtractError struct {
	Output string
	Err    error
}

func (e *ExtractError) Error() string {
	msg := "toolinstall: tar: " + e.Err.Error()
	if e.Output != "" {
		msg += ": " + e.Output
	}
	return msg
}

func (e *ExtractError) Unwrap() error { return e.Err }

// InstallError wraps a failure at one named step.
type InstallError struct {
	Tool string
	Step string
	Err  error
}

func (e *InstallError) Error() string {
	return "toolinstall: " + e.Tool + ": " + e.Step + ": " + e.Err.Error()
}

func (e *InstallError) Unwrap() error { return e.Err }

func quote(s string) string { return strconv.Quote(s) }

func itoa(n int) string { return strconv.Itoa(n) }
