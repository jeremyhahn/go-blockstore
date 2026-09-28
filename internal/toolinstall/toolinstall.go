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

// Package toolinstall installs the two analysers that are not `go install`
// targets — shellcheck and trivy — as PINNED, checksum-verified release
// binaries. `make install-tools` and CI run the same code, so the binary on a
// developer's machine and the one in CI cannot drift apart.
//
// # Why not a distro package, or `curl ... | sh`
//
// A distro package floats to whatever the archive ships, and piping a fetched
// script into a shell runs unread, unverified code as the build user — on a CI
// runner that holds a token with security-events: write. This downloads the
// pinned release artifact and checks its bytes before anything is extracted,
// and nothing from the download is ever run as a script.
//
// # The two pinning strengths, stated rather than implied
//
// shellcheck publishes NO checksums, so its SHA-256 values are pinned HERE, in
// the repository, under review: a compromised release that rewrites the
// artifact cannot also rewrite the expectation. Two hashes per artifact — the
// archive, checked before extraction, and the extracted binary, which is the
// only thing the already-installed fast path trusts. A binary's self-reported
// --version is output it chooses to print, and is never a trust anchor.
//
// trivy's checksums are FETCHED from the same release as the archive. That
// catches corruption and tampering in transit; it does not defend against a
// compromised release that rewrites both, which a sigstore verification of the
// published bundle would. Because the binary hash is not pinned, there is no
// fast path: every install downloads and verifies.
//
// To bump shellcheck: change ShellcheckVersion and add the new artifacts' two
// hashes to the table, in one commit. To bump trivy: edit .trivy-version.
package toolinstall

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// ShellcheckVersion is the pinned shellcheck. Its per-artifact hashes are in
// Shellcheck().Pins; the two move together, in one reviewed commit, or not at
// all.
const ShellcheckVersion = "0.10.0"

// Compression names how an archive is compressed, as tar's flag spells it.
type Compression string

const (
	// Gzip is a .tar.gz archive.
	Gzip Compression = "z"

	// XZ is a .tar.xz archive. Extracting one needs xz on the host.
	XZ Compression = "J"
)

// Pin is the reviewed SHA-256 of one release artifact and of the binary inside
// it.
type Pin struct {
	// Archive is the hash of the downloaded archive.
	Archive string

	// Binary is the hash of the extracted binary.
	Binary string
}

// Tool describes one installable release binary.
type Tool struct {
	// Name is the binary's name, and the file it is installed as.
	Name string

	// Repo is the GitHub owner/name the releases are published under.
	Repo string

	// Artifacts maps "GOOS/GOARCH" to the archive name for a version.
	Artifacts map[string]func(version string) string

	// Member is the binary's path inside the archive for a version.
	Member func(version string) string

	// Compression is how the archive is compressed.
	Compression Compression

	// Pins holds the in-repo hashes, keyed by "version:artifact". A tool
	// with Pins installs nothing that is not in the table.
	Pins map[string]Pin

	// ChecksumsFile names the release's published checksum list for a
	// version. It is used only when Pins is nil.
	ChecksumsFile func(version string) string
}

// Shellcheck is shellcheck, pinned in-repo because upstream publishes no
// checksums.
func Shellcheck() Tool {
	return Tool{
		Name: "shellcheck",
		Repo: "koalaman/shellcheck",
		Artifacts: map[string]func(string) string{
			"linux/amd64": func(v string) string { return "shellcheck-v" + v + ".linux.x86_64.tar.xz" },
			"linux/arm64": func(v string) string { return "shellcheck-v" + v + ".linux.aarch64.tar.xz" },
		},
		Member:      func(v string) string { return "shellcheck-v" + v + "/shellcheck" },
		Compression: XZ,
		Pins: map[string]Pin{
			"0.10.0:shellcheck-v0.10.0.linux.x86_64.tar.xz": {
				Archive: "6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87",
				Binary:  "f35ae15a4677945428bdfe61ccc297490d89dd1e544cc06317102637638c6deb",
			},
			"0.10.0:shellcheck-v0.10.0.linux.aarch64.tar.xz": {
				Archive: "324a7e89de8fa2aed0d0c28f3dab59cf84c6d74264022c00c22af665ed1a09bb",
				Binary:  "4111c09318d10b93653a42179381273f31061b34987978346fbd19a6e81a74c3",
			},
		},
	}
}

// Trivy is trivy, verified against the checksums its release publishes.
func Trivy() Tool {
	return Tool{
		Name: "trivy",
		Repo: "aquasecurity/trivy",
		Artifacts: map[string]func(string) string{
			"linux/amd64": func(v string) string { return "trivy_" + v + "_Linux-64bit.tar.gz" },
			"linux/arm64": func(v string) string { return "trivy_" + v + "_Linux-ARM64.tar.gz" },
		},
		Member:        func(string) string { return "trivy" },
		Compression:   Gzip,
		ChecksumsFile: func(v string) string { return "trivy_" + v + "_checksums.txt" },
	}
}

// semver is the only version shape accepted. The version is interpolated into
// a download URL and an artifact name, and an installer that fetches whatever
// it is handed is not pinned.
var semver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// runtimePlatform is the platform this binary runs on, in Artifacts' form.
const runtimePlatform = runtime.GOOS + "/" + runtime.GOARCH

// maxDownload bounds what is read from the network. Both archives are tens of
// megabytes.
const maxDownload = 512 << 20

// Installer fetches, verifies and installs a Tool.
type Installer struct {
	// Client performs the downloads. Nil uses a client that refuses any
	// redirect off https and times out after ten minutes.
	Client *http.Client

	// BaseURL is prefixed to "/<repo>/releases/download/v<version>/<file>".
	// Empty means https://github.com.
	BaseURL string

	// Platform is "GOOS/GOARCH". Empty means the running platform.
	Platform string

	// Extract unpacks one member of a verified archive into dir. Nil runs
	// tar, which is what an .xz archive needs.
	Extract func(ctx context.Context, archive, dir, member string, compression Compression) error

	// Log receives progress lines. Nil discards them.
	Log io.Writer
}

// Install puts the pinned tool at dir/<name>, verified. An existing binary is
// kept only when the tool pins its binary hash and the file on disk has it.
func (in Installer) Install(ctx context.Context, tool Tool, version, dir string) error {
	if !semver.MatchString(version) {
		return &VersionError{Tool: tool.Name, Version: version}
	}
	platform := in.Platform
	if platform == "" {
		platform = runtimePlatform
	}
	artifactFor, ok := tool.Artifacts[platform]
	if !ok {
		return &PlatformError{Tool: tool.Name, Platform: platform}
	}
	artifact := artifactFor(version)
	target := filepath.Join(dir, tool.Name)

	var pin Pin
	if tool.Pins != nil {
		pin, ok = tool.Pins[version+":"+artifact]
		if !ok {
			return &NoPinError{Tool: tool.Name, Version: version, Artifact: artifact}
		}
		if sum, err := fileSHA256(target); err == nil && sum == pin.Binary {
			in.logf("%s %s already installed at %s (binary hash verified)\n", tool.Name, version, target)
			return nil
		}
	}

	work, err := os.MkdirTemp("", "toolinstall-")
	if err != nil {
		return &InstallError{Tool: tool.Name, Step: "creating a work directory", Err: err}
	}
	defer func() { _ = os.RemoveAll(work) }()

	base := in.baseURL() + "/" + tool.Repo + "/releases/download/v" + version + "/"
	if tool.Pins == nil {
		in.logf("→ fetching the published checksums for %s %s\n", tool.Name, version)
		list, fetchErr := in.fetch(ctx, base+tool.ChecksumsFile(version))
		if fetchErr != nil {
			return &InstallError{Tool: tool.Name, Step: "downloading the checksums", Err: fetchErr}
		}
		archiveSum, listErr := checksumFor(list, artifact)
		if listErr != nil {
			return listErr
		}
		pin.Archive = archiveSum
	}

	in.logf("→ downloading %s %s (%s)\n", tool.Name, version, artifact)
	archive := filepath.Join(work, artifact)
	sum, err := in.download(ctx, base+artifact, archive)
	if err != nil {
		return &InstallError{Tool: tool.Name, Step: "downloading " + artifact, Err: err}
	}
	if !strings.EqualFold(sum, pin.Archive) {
		return &ChecksumError{Tool: tool.Name, File: artifact, Want: pin.Archive, Got: sum}
	}
	in.logf("→ archive SHA-256 verified\n")

	extract := in.Extract
	if extract == nil {
		extract = tarExtract
	}
	member := tool.Member(version)
	if err := extract(ctx, archive, work, member, tool.Compression); err != nil {
		return &InstallError{Tool: tool.Name, Step: "extracting " + member, Err: err}
	}
	extracted := filepath.Join(work, filepath.FromSlash(member))
	if pin.Binary != "" {
		got, err := fileSHA256(extracted)
		if err != nil {
			return &InstallError{Tool: tool.Name, Step: "hashing the extracted binary", Err: err}
		}
		if got != pin.Binary {
			return &ChecksumError{Tool: tool.Name, File: member, Want: pin.Binary, Got: got}
		}
		in.logf("→ extracted binary SHA-256 verified\n")
	}

	if err := place(extracted, dir, target); err != nil {
		return &InstallError{Tool: tool.Name, Step: "installing to " + dir, Err: err}
	}
	in.logf("✓ %s %s installed at %s\n", tool.Name, version, target)
	return nil
}

// ReadVersionFile reads a version file holding exactly ONE whitespace-delimited
// token. It is read strictly, not scrubbed: deleting whitespace would turn a
// malformed "0.74 .0" into a plausible "0.74.0" nobody pinned.
func ReadVersionFile(path string) (string, error) {
	// #nosec G304 -- the caller names the repository's own version file.
	content, err := os.ReadFile(path)
	if err != nil {
		return "", &VersionFileError{Path: path, Err: err}
	}
	fields := strings.Fields(string(content))
	if len(fields) != 1 {
		return "", &VersionFileError{Path: path}
	}
	return fields[0], nil
}

func (in Installer) logf(format string, args ...any) {
	if in.Log != nil {
		fmt.Fprintf(in.Log, format, args...)
	}
}

func (in Installer) baseURL() string {
	if in.BaseURL != "" {
		return strings.TrimSuffix(in.BaseURL, "/")
	}
	return "https://github.com"
}

func (in Installer) client() *http.Client {
	if in.Client != nil {
		return in.Client
	}
	return &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return &RedirectError{URL: req.URL.Redacted()}
			}
			if len(via) >= 10 {
				return &RedirectError{URL: req.URL.Redacted()}
			}
			return nil
		},
	}
}

// open issues a GET and returns the body of a 200 response.
func (in Installer) open(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := in.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, &HTTPStatusError{URL: url, Status: resp.Status}
	}
	return resp.Body, nil
}

// fetch reads a small response whole.
func (in Installer) fetch(ctx context.Context, url string) ([]byte, error) {
	body, err := in.open(ctx, url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	return io.ReadAll(io.LimitReader(body, 1<<20))
}

// download streams a response to path and returns its SHA-256.
func (in Installer) download(ctx context.Context, url, path string) (string, error) {
	body, err := in.open(ctx, url)
	if err != nil {
		return "", err
	}
	defer func() { _ = body.Close() }()

	// #nosec G304 -- path is inside the installer's own temporary directory.
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, hash), io.LimitReader(body, maxDownload))
	closeErr := out.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// checksumFor finds the ONE line of a published checksum list that names
// artifact exactly. Matching on the whole second field, not a substring, keeps
// a longer artifact name from answering for a shorter one.
func checksumFor(list []byte, artifact string) (string, error) {
	var found []string
	scanner := bufio.NewScanner(strings.NewReader(string(list)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == artifact {
			found = append(found, fields[0])
		}
	}
	if len(found) != 1 {
		return "", &ChecksumListError{Artifact: artifact, Matches: len(found)}
	}
	return found[0], nil
}

// fileSHA256 hashes a file.
func fileSHA256(path string) (string, error) {
	// #nosec G304 -- path is the install target or the installer's own work file.
	handle, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = handle.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, handle); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// tarExtract unpacks exactly one member with the host's tar. Only a verified
// archive reaches it, and the member is named, so nothing else is written.
func tarExtract(ctx context.Context, archive, dir, member string, compression Compression) error {
	// #nosec G204 -- fixed binary; the arguments are the verified archive, the
	// installer's own directory and a member name from the tool table.
	cmd := exec.CommandContext(ctx, "tar", "-x"+string(compression)+"f", archive, "-C", dir, member)
	if out, err := cmd.CombinedOutput(); err != nil {
		return &ExtractError{Output: strings.TrimSpace(string(out)), Err: err}
	}
	return nil
}

// place copies the verified binary into dir and renames it over target, so a
// half-written binary is never on PATH under the tool's name.
func place(src, dir, target string) error {
	// #nosec G301 -- an install directory on PATH is world-readable by design.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// #nosec G304 -- src is the verified binary in the installer's work directory.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".tmp-")
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(tmp, in)
	closeErr := tmp.Close()
	// #nosec G302 -- an installed executable must be executable by its users.
	chmodErr := os.Chmod(tmp.Name(), 0o755)
	if err := errors.Join(copyErr, closeErr, chmodErr); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}
