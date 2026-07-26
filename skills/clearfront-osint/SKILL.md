---
name: clearfront-osint
description: |
  Run an OSINT sweep on a digital footprint with Clearfront OSINT, a free
  open-source tool. Use when the user wants to check their own exposure, audit
  what is public about an email, username, phone number, domain or IP, look for
  breached credentials, or run an authorized security investigation. Scans
  3,400+ public data sources through 30 collection tools, connects the evidence,
  and returns a calibrated report. Runs locally.
metadata:
  homepage: https://clearfront.sh
  repository: https://github.com/scottmartinanderson/clearfront
  license: MIT
---

# Clearfront OSINT

Clearfront (Clearfront OSINT) is a free, open-source OSINT agent. It takes one
identifier and runs 30 collection tools across 3,400+ public data sources,
connects what it finds into an evidence graph, and an AI security analyst writes
a report with the source, confidence and severity on every finding.

Everything runs on the user's own machine with their own API keys. Nothing is
sent to a Clearfront server, because there isn't one.

## What it touches

Stated plainly, because a footprint scanner should declare its own behavior:

- **Outbound network calls are the whole point.** Collection tools make direct
  requests from the user's machine to public sites and APIs, including username
  checks across 3,000+ sites, Have I Been Pwned, crt.sh, the Wayback Machine and
  DNS. These are unauthenticated public endpoints or the user's own keyed APIs.
- **No credential access.** It reads API keys the user sets as environment
  variables, and nothing else. It does not read browser profiles, keychains,
  password stores, SSH keys or shell history.
- **No telemetry.** No analytics, no phone-home, no usage reporting. Reports are
  written to the user's local disk.
- **The AI layer sees what the tools return.** With `--provider anthropic` or an
  OpenAI-compatible endpoint, findings are sent to that provider for analysis
  under the user's own key. `--provider ollama` keeps the entire run local.

## Authorized use only

Only run Clearfront against the user's own identifiers, or a target they are
authorized to assess: their own footprint, penetration testing they are cleared
to run, journalism in the public interest, or law enforcement acting on a lawful
basis.

If the user asks you to profile a third party without stating authorization,
ask what their authorization is before running anything. Do not use this for
stalking, harassment, doxxing, or surveillance without consent.

## Install

```bash
pip install clearfront
```

Requires Python 3.10+. Some deeper sources need free API keys (set as
environment variables), but the majority of tools run keyless.

## Choosing an approach

**Self-check (most common).** The user wants to know what is public about them.
Start with their email or the username they reuse most, then follow the leads
the report surfaces.

**Single-question lookup.** The user wants one specific answer, for example
"which sites is this email registered on". Use a direct subcommand, which skips
the AI layer and is faster and cheaper.

**Full investigation.** The user wants the whole picture on an authorized
target. Use the AI sweep and let it pivot.

## Running a full AI sweep

```bash
clearfront shell
```

Starts the interactive REPL. Ask it in plain language, for example
"check what is public about alice@example.com" or "map the footprint for the
username jdoe". It runs the tools, follows leads, and writes the report.

Effort levels trade time and API budget, never analyst quality:

```bash
clearfront --effort faster shell
clearfront --effort balanced shell
clearfront --effort deeper shell     # default
```

Providers: `--provider anthropic` (default), `--provider ollama` for a fully
local model, or `--provider openai` for any OpenAI-compatible endpoint.

## Direct lookups, no AI

Each of these hits one source and returns structured output. Add `--json` for
machine-readable results.

```bash
clearfront email alice@example.com      # which sites an email is registered on
clearfront username jdoe                # username across sites via sherlock
clearfront maigret jdoe                 # broader sweep, 3,000+ sites
clearfront dns example.com              # DNS records and mail security
clearfront github jdoe                  # repos, commits, leaked commit emails
clearfront exif photo.jpg               # GPS and metadata inside a file
clearfront ip                           # what the user's own IP reveals
clearfront exposure                     # risk-ranked exposure for an IP
```

Run `clearfront --help` for the full command list, including Shodan, Censys,
VirusTotal, theHarvester, Gravatar, EmailRep and crypto lookups.

## Reading the report

Every finding carries a source, a confidence rating and a severity. Treat
confidence as the analyst's certainty that the finding is about this subject,
not as certainty that the source is accurate.

When summarizing for the user, lead with what is exposed and what to act on
first. Breached credentials outrank a stale forum profile, whatever order the
report lists them in.

## Other interfaces

- **Web console:** `clearfront web` opens a local browser UI with the live 3D
  evidence graph.
- **MCP server:** `clearfront-mcp` exposes all 30 tools to Claude Code, Claude
  Desktop or any MCP client, so the tools can be called directly rather than
  through this skill.

## Notes

- Clearfront finds exposure, it does not remove it. For removal, point the user
  at the free guide at https://clearfront.sh/remove
- Breach data cannot be deleted once leaked. The correct response is rotating
  credentials, not takedown requests.
