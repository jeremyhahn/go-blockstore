# Public releasability

This repository ships publicly. Everything tracked here is published: the
module zip a `go get` downloads, and the source tree on the public mirror. This
page is the rule that keeps that true, and the gate that enforces it.

## The rule

No tracked file may carry any of the following. Each has a public equivalent,
so none ever needs to be kept.

| Rule | What it covers | Use instead |
|---|---|---|
| `lab-address` | An IPv4 address or CIDR in any RFC 1918 range (`10/8`, `172.16/12`, `192.168/16`), or in the lab's own public allocations | RFC 5737 documentation addresses — `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; RFC 3849 `2001:db8::/32` for IPv6 |
| `internal-domain` | A name under `.internal`, `.lan`, `.home.arpa` or `.localdomain` | RFC 2606 names — `example.com`, `*.example`, `*.invalid` |
| `lab-host` | A development-fleet hostname | The role, not the machine — `node-a`, `host-01`, `ci-runner-01` |
| `owner-path` | A path, or the account name, that exists only on the owner's machines | A repository-relative path, or `/var/lib`, `/srv`, `/home/user` |
| `shell-script` | A shell script, by extension (`.sh`, `.bash`, …) **or** by a shell shebang, whatever the file is called | A Go program under `internal/…/cmd/`, or a Makefile recipe |
| `agent-file` | An AI agent's instructions or state: `.claude/`, `.serena/`, `.cursor/`, `.codex/`, `.gemini/`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules` | Nothing — keep it untracked; `.gitignore` already excludes the common ones |
| `cert-tooling` | Key or certificate material (`.pem`, `.crt`, `.key`, `.p12`, … or a PEM `BEGIN … PRIVATE KEY` / `CERTIFICATE` block in any file) and OpenSSL configuration | Generate test material at run time, in the test |
| `symlink-escape` | A symlink whose target is absolute or leaves the repository | Commit the content, or point inside the tree |
| `unreadable` | A tracked file the gate could not read as text — see below | Make it text, or exempt it with a reason |
| `stale-exemption` | An exemption that exempts nothing | Delete the entry |

The lab's own subnets, hostnames and path prefixes are written down in exactly
one place: `contentRules` and `labPrefixes` in
`internal/releasability/rules.go`. Read them there rather than repeating them
here — repeating them would be the leak this page exists to prevent.

Everything is matched **case-insensitively**, line by line. A symlink's target
text is scanned as if it were the file's content, and the link is never
followed: the target is what is published, and following it would read a file
on whatever machine the gate runs on.

Local configuration — node configs, deployment tooling, the fleet's addresses —
belongs in the private infrastructure repository, not here.

## The gate

```
make releasability                                  # also part of `make lint`
go run ./internal/releasability/cmd/releasability   # what the target runs
```

It runs in the CI Lint job as the **Public releasability** step. It lists the
git index — a file is published because it is tracked — and reads each one from
the working tree. Resolution is textual: no build tags, no module loading, no
parser, so it covers Go, Markdown, YAML, Makefiles and testdata alike, and it
runs on a tree that does not compile.

It prints how many files it examined on every run, passing or not: a pass over
zero files is not a pass, and the gate refuses one.

A finding names the file, the line, the rule, the matched text and what to use
instead:

```
pkg/example/example_test.go:12: [lab-address] "<the address>" -- use an RFC 5737 documentation address: ...
```

### It fails closed

A tracked file the gate cannot read as text **fails** it:

- a binary — a NUL byte in its first 8 KiB, git's own test;
- a file over 1 MiB;
- a submodule, a special file, or a file missing from the working tree.

There are no silent skips. A file the gate did not read is a file nobody has
checked, and "unread" must not be reported the same way as "clean".

The only way to ship such a file is an entry in the committed
[`releasability-exempt.txt`](../../releasability-exempt.txt): the path,
whitespace, and a one-line reason. An entry exempts **only** the file being
unreadable — a shell script, an agent file or key material fails whatever the
list says. An entry with no reason, a duplicate, and an entry that exempts
nothing (the path is untracked, or it is text the gate reads anyway) each fail
the gate, so the list can only shrink. It is empty today.

There is deliberately **no inline waiver**. Every refused value has a public
equivalent, so a waiver would only ever be a hole.

### How the gate avoids flagging itself

`internal/releasability/rules.go` has to name what it looks for. Each pattern
is written so its own source text does not match it — a leading `\b`, a
one-character class or an escape sits inside every literal — and the address
ranges are built from octets rather than parsed from dotted strings. Tests build
their samples by concatenation for the same reason. The gate scans its own
package like every other file, so a pattern that matched itself fails the tree
at once.

### Adding a value to the rule set

One entry in `contentRules` (or one prefix in `labPrefixes`), written so it does
not match itself, and a sample in `TestContentRulesFire` proving it fires. Run
`make releasability` to confirm the tree is still clean.

## Known limits — follow-ups, not blockers

The gate is a textual scan. It does not decode encodings (base64, URL-escaped,
hex or decimal-integer IPv4, IPv4-mapped IPv6), follow a fleet name spelled in a
new syntax, or parse every `env` option in a shebang. Findings of that kind
belong in a `priority:low` follow-up issue and do not hold a release. Generic words
that also happen to be fleet hostnames are not matched by name at all: a rule
that fired on ordinary English would be switched off within a week.

## What #75 removed

- `scripts/install-shellcheck.sh`, `scripts/install-trivy.sh` and
  `scripts/preflight-container-matrix.sh`, replaced by `internal/toolinstall`
  and `internal/preflightmatrix`; the guards' `run.sh` fixtures, replaced by
  Makefile fixtures.
- The owner-workstation default for `AGENT_GIT` in the Makefile.
- Private addresses, internal domains and fleet hostnames in the DRBD and
  factory test fixtures, and fleet hostnames in `CHANGELOG.md`.
