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

package releasability

import (
	"net/netip"
	"path"
	"regexp"
	"strings"
)

// Rule names what a finding is about. It is a string so a report, a test name
// and the documentation all spell it the same way.
type Rule string

const (
	// RuleLabAddress is an IP address, or a CIDR, on a private network: every
	// RFC 1918 range, and the lab's own public prefixes. A public reader cannot
	// reach one, so an example carrying it is broken documentation, and it
	// publishes the operator's network layout.
	RuleLabAddress Rule = "lab-address"

	// RuleInternalDomain is a name under a TLD that only resolves inside a
	// private network (.internal, .lan, .home.arpa, .localdomain).
	RuleInternalDomain Rule = "internal-domain"

	// RuleLabHost is the hostname of a machine in the development fleet.
	RuleLabHost Rule = "lab-host"

	// RuleOwnerPath is a path, or the account name, that exists only on the
	// owner's machines.
	RuleOwnerPath Rule = "owner-path"

	// RuleShellScript is a shell script, recognized by its extension or by
	// its shebang. The public release is Go only.
	RuleShellScript Rule = "shell-script"

	// RuleAgentFile is an AI agent's instruction or state file.
	RuleAgentFile Rule = "agent-file"

	// RuleCertTooling is certificate or key material, or the tooling that
	// mints it.
	RuleCertTooling Rule = "cert-tooling"

	// RuleSymlinkEscape is a symlink whose target leaves the tree: it names a
	// path on the machine it was made on, and it dangles everywhere else.
	RuleSymlinkEscape Rule = "symlink-escape"

	// RuleUnreadable is a tracked file the gate could not read as text — a
	// binary, a file over the size cap, a submodule, a file missing from the
	// working tree — and that is not listed in ExemptFile. The gate fails
	// closed on what it cannot see.
	RuleUnreadable Rule = "unreadable"

	// RuleStaleExemption is an ExemptFile entry that exempts nothing: the path
	// is not tracked, or the file is readable text the gate scans anyway. The
	// list is meant to shrink, and an entry nobody needs hides the next file
	// that lands at that path.
	RuleStaleExemption Rule = "stale-exemption"
)

// contentRule is one pattern applied to every line of every text file and to
// every symlink target.
type contentRule struct {
	rule     Rule
	expr     *regexp.Regexp
	guidance string
}

// The patterns below are written so their OWN source text does not match
// them: a leading \b, a character class, or an escape sits inside each literal
// the gate hunts for. The gate scans this file like any other, so a pattern
// that matched itself would fail the tree; and a waiver mechanism to excuse it
// would be a hole in the gate for everything else too.
var contentRules = []contentRule{
	{
		rule:     RuleInternalDomain,
		expr:     regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:internal|lan|home\.arpa|localdomain)\b`),
		guidance: "use an RFC 2606 name: example.com, *.example, *.invalid",
	},
	{
		rule:     RuleLabHost,
		expr:     regexp.MustCompile(`(?i)\b(?:v[s]tation|d[e]llemc)(?:-?\d+)?\b`),
		guidance: "name the role, not the machine: node-a, ci-runner-01, host.example.com",
	},
	{
		rule:     RuleLabHost,
		expr:     regexp.MustCompile(`(?i)\b(?:g[o]dlike|m[o]n0|m[i]ni-0\d|r[a]ck\d+sw[a-z]*)\b`),
		guidance: "name the role, not the machine: node-a, ci-runner-01, host.example.com",
	},
	{
		rule:     RuleLabAddress,
		expr:     regexp.MustCompile(`(?i)\b2602:0*f5bb(?:\b|:)`),
		guidance: "use an RFC 3849 documentation address (2001:db8::/32)",
	},
	{
		rule:     RuleOwnerPath,
		expr:     regexp.MustCompile(`(?i)(?:/mnt/v[s]tation|\bj[h]ahn\b)`),
		guidance: "make the path relative to the repository root, or use /var/lib, /srv, /home/user",
	},
}

// dottedRun is a maximal run of dot-separated digit groups. Taking the whole
// run first, and judging it after, is what keeps an OID or a four-part version
// string from being read as an address: "1.3.6.10.0.0.1" is one seven-part run,
// not an address with a prefix.
var dottedRun = regexp.MustCompile(`\d+(?:\.\d+)+`)

// labPrefixes are the ranges a published address may not fall in. Every RFC
// 1918 range is listed, not just the ones the lab happens to use today: a
// private address in a public tree is either the lab's, or indistinguishable
// from it to a reader, and RFC 5737 exists so neither is ever needed.
//
// They are built from octets rather than parsed from dotted strings so that
// this file does not itself carry a dotted lab address for the gate to find.
var labPrefixes = []netip.Prefix{
	netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 0}), 8),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16, 0, 0}), 12),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 0}), 16),
	// The lab's own public allocation. Routable, but it is still the lab.
	netip.PrefixFrom(netip.AddrFrom4([4]byte{23, 143, 36, 0}), 24),
}

// addressGuidance is what a lab-address finding tells the engineer to do.
const addressGuidance = "use an RFC 5737 documentation address: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24"

// labAddresses returns every dotted IPv4 value in line that falls in a lab
// prefix. A three-part run beginning 192.168 is reported too: "192.168.N.x" is
// how a subnet is written in prose, and it names the subnet just as well.
func labAddresses(line string) []string {
	var found []string
	for _, run := range dottedRun.FindAllString(line, -1) {
		parts := strings.Split(run, ".")
		switch len(parts) {
		case 3:
			if parts[0] == "192" && parts[1] == "168" {
				found = append(found, run)
			}
		case 4:
			addr, err := netip.ParseAddr(run)
			if err != nil {
				// An octet over 255, or a leading zero: a version
				// string, not an address.
				continue
			}
			for _, prefix := range labPrefixes {
				if prefix.Contains(addr) {
					found = append(found, run)
					break
				}
			}
		}
	}
	return found
}

// shellExtensions are the file extensions of shell scripts, lowercased.
var shellExtensions = map[string]bool{
	".sh": true, ".bash": true, ".zsh": true, ".ksh": true, ".csh": true,
	".tcsh": true, ".fish": true, ".dash": true, ".ash": true,
}

// shellInterpreters are the interpreters a shebang may name that make the file
// a shell script, whatever it is called.
var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "ksh": true, "mksh": true, "csh": true,
	"tcsh": true, "fish": true, "dash": true, "ash": true, "yash": true,
}

// shebangShell returns the shell a file's first line hands it to, or "" when
// it names none. It understands the three spellings in use: a direct path
// (#!/bin/sh), env (#!/usr/bin/env -S bash -eu, including VAR=value
// assignments before the program) and busybox (#!/bin/busybox sh).
func shebangShell(content []byte) string {
	if len(content) < 2 || content[0] != '#' || content[1] != '!' {
		return ""
	}
	first := string(content[2:])
	if nl := strings.IndexByte(first, '\n'); nl >= 0 {
		first = first[:nl]
	}
	fields := strings.Fields(first)
	for len(fields) > 0 {
		name := path.Base(fields[0])
		switch {
		case name == "env" || name == "busybox":
			fields = fields[1:]
			for len(fields) > 0 && (strings.HasPrefix(fields[0], "-") || strings.Contains(fields[0], "=")) {
				fields = fields[1:]
			}
		case shellInterpreters[strings.ToLower(name)]:
			return name
		default:
			return ""
		}
	}
	return ""
}

// agentDirs and agentFiles name what an AI coding agent reads or writes. They
// are development-time state for one operator's tooling, not part of the
// product, and several carry machine-local permissions and paths. Matched
// case-insensitively against every path component.
var (
	agentDirs = map[string]bool{
		".claude": true, ".serena": true, ".cursor": true, ".codex": true, ".gemini": true,
	}
	agentFiles = map[string]bool{
		"claude.md": true, "agents.md": true, "gemini.md": true, ".cursorrules": true,
	}
)

// isAgentFile reports whether a tracked path is agent state.
func isAgentFile(name string) bool {
	parts := strings.Split(strings.ToLower(name), "/")
	for _, dir := range parts[:len(parts)-1] {
		if agentDirs[dir] {
			return true
		}
	}
	return agentFiles[parts[len(parts)-1]]
}

// certExtensions are key and certificate containers, lowercased. Material
// minted for a test belongs in the test, generated at run time; material
// minted for a deployment never belongs in a public tree.
var certExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".csr": true, ".key": true,
	".p12": true, ".pfx": true, ".der": true, ".jks": true, ".srl": true,
}

// certFiles are the configuration files of certificate tooling.
var certFiles = map[string]bool{"openssl.cnf": true, "openssl.conf": true}

// pemArmor is the header of PEM-encoded key or certificate material, in any
// file. The class is written so that this line does not contain one.
var pemArmor = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE(?: REQUEST)?)-----`)

// isCertTooling reports whether a tracked path is key material or the
// tooling that mints it, by name alone.
func isCertTooling(name string) bool {
	base := strings.ToLower(path.Base(name))
	return certExtensions[path.Ext(base)] || certFiles[base]
}
