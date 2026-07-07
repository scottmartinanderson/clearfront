# Changelog

All notable changes to Clearfront are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.0], 2026-07-02

### Added
- **`search_crt`** (27th tool), keyless, passive subdomain discovery from certificate transparency logs (crt.sh). Exposed on the REPL/CLI, MCP, and web console, and routed into the auto-pivot evidence graph for domains.
- **Footprint-enrichment tools** now reach the terminal agent (tool count 22 -> 27):
  - `search_gravatar`, public Gravatar profile for an email (avatar, display name, linked/verified accounts).
  - `search_emailrep`, EmailRep.io reputation and footprint summary (keyed: `EMAILREP_API_KEY`, free/approval-gated).
  - `search_crypto`, keyless on-chain summary for a Bitcoin or Ethereum address (balance, transaction count, total received).
  - `search_harvester`, passive organisation/domain recon via theHarvester (emails, people, subdomains; passive sources only).
- **`search_github` public code/secret search**, reports leaked-secret exposure (repository, path, and secret type only, never the value or the raw file). Requires `GITHUB_TOKEN`.
- **`search_hudsonrock`** (30th tool), keyless infostealer-exposure check via Hudson Rock's free Cavalier index. For an email or username it reports whether the identifier appears in malware-stolen credential logs plus the defensive infection metadata (count, dates, OS, antivirus, malware file name, affected-service counts). Authorized-use only, and deliberately narrower than the source: it uses only the free (masked) tier, never Hudson Rock's paid API, and never echoes even the masked passwords/logins or identifying machine strings, so it can never surface a working credential. Analyst-invoked, never auto-pivoted.
- **Report export in the web console**, copy, Markdown, and PDF download of the intelligence report (`POST /api/report/export`, reusing the existing PDF path).
- **Evidence-graph export.** New `clearfront graph TARGET` CLI command auto-pivots from a target and writes the entity correlation graph as GraphML/JSON/Mermaid artifacts, and the web console's evidence-graph panel gains `.graphml` / `.json` / `.mmd` download controls (`POST /api/graph/export`). Output is deterministic (sorted nodes and links) so the same graph always exports identically; GraphML opens in Gephi, yEd, and Maltego.
- `search_username` now also queries a WhatsMyName subset (+231 modern/niche sites maigret/sherlock miss; dataset CC BY-SA 4.0, attributed), merged into its verified results.

### Performance
- **Per-run tool cache.** Agentic runs (web console, REPL/CLI, multi-target) memoize `(tool, args) -> result` for the lifetime of a single investigation, so a repeated tool call with the same target across the multi-round loop is served from memory instead of re-hitting the network. Scoped strictly per run: results never persist across targets, requests, or REPL turns.

### Analysis
- **Cross-tool corroboration notes.** When several tools surface the same profile in one investigation (holehe, sherlock, maigret, and footprint routinely overlap), the analyst now sees a `[corroboration]` note flagging which profiles were independently reported by more than one tool, so genuine agreement reads as higher confidence. It is strictly additive: the raw tool output is never merged, deduped, reordered, or altered, and extraction is conservative (host + handle only) so two different people never read as corroborating each other.

### Changed
- **Unified tool registry and analyst prompt across all surfaces.** The REPL, CLI, and multi-target agent now expose the full tool set and produce the calibrated ICD-203 intelligence report that previously existed only in the web console (shared `clearfront/prompts.py`). Tool-surface parity is enforced by tests.
- **Free-tier auto-pivot.** `search_footprint` is no longer gated behind Bright Data keys (it runs free on DuckDuckGo), and `search_maigret` / `search_gravatar` are now routed and extracted into the evidence graph, enabling the email -> real name -> footprint loop for keyless users.
- Multi-target investigations honour the selected AI provider (`--provider ollama|openai`) instead of always using Anthropic.
- Every MCP tool description now carries an authorized-use / passive-collection clause so the safety posture travels into MCP clients.

---

## [2.4.0], 2026-06-25

A rebrand to **CLEARFRONT**, plus four feature waves of new capability.

### Changed
- **Institutional rebrand to CLEARFRONT** across the web UI, CLI and server
  banner, and PDF reports.
- **Institutional web-UI redesign**, monochrome "console" theme (greyscale tokens,
  warm-paper light mode, colour reserved for semantic severity), ANSI-Shadow ASCII
  hero, command-list empty state, command-bar header, WCAG-AA pass.
- **Monochrome grayscale-satellite** IP-geolocation map; Settings field for the
  Maps Embed key.
- Web chat model bumped to **Claude Sonnet 4.6**.
- **Analyst voice** rewritten to ICD-203 intelligence-community tradecraft
  (calibrated estimative language, analytic confidence, no em dashes).
- Header wordmark restyled (lowercase JetBrains Mono + version); chat-input focus
  cue moved to a quiet shell hairline (no focus-ring box).

### Added
- **Exposure verdict band** (RISK / WATCH / CLEAR) on `search_exposure` reports.
- **Interactive force-directed evidence graph**, Obsidian-style link analysis
  below the report: entity mesh, edge pulses, click-to-detail, in-place pivot
  merge, live theme re-skin.
- **Always-on local server** via a launchd agent at `127.0.0.1:8080`.

## [0.1.0], 2026-06-21

Initial release of **Clearfront**, an AI-driven OSINT
agent, MCP server, and CLI for authorized security research and personal
exposure checks.

### Added

#### Interfaces
- **Interactive REPL** (`clearfront`), the default mode; an AI agent that chains tools,
  with built-in commands (`tools`, `save`, `config`, `clear`, `help`, `exit`) and
  auto-saved reports under `reports/`.
- **CLI**, direct subcommands for every tool (e.g. `clearfront email`, `clearfront username`,
  `clearfront exif FILE`, `clearfront scrape URL`).
- **MCP server** (`clearfront-mcp`), exposes all 20 tools plus multi-target investigation
  to MCP-compatible clients (Claude Code, Claude Desktop) over standard I/O.
- **Web UI** (`clearfront web`), a localhost dashboard with a tool catalog and key-availability
  indicators.

#### AI agent
- Anthropic Claude native tool-use loop, with OpenAI-compatible (`--provider openai`)
  and local Ollama backends for offline use.

#### OSINT tools (20), passive, public-data
- **Email & accounts:** `search_email` (holehe), `search_username` (Sherlock),
  `search_github`.
- **Domain & network infrastructure:** `search_domain` (sublist3r), `search_dns`,
  `search_whois`, `search_ip` (ipinfo), `search_ip2location`, `search_abuseipdb`,
  `search_shodan`, `search_censys`, `search_virustotal`.
- **Files & content:** `search_exif` (exiftool metadata extraction with GPS flagging),
  `search_paste` (Pastebin dumps).
- **Phone:** `search_phone` (phoneinfoga).
- **Breaches:** `search_breach` (Have I Been Pwned).
- **Search / SERP:** `generate_dorks` (offline Google dork templates),
  `search_dorks_live` and `search_footprint` (entity-aware live SERP via the
  Bright Data API), `scrape_url` (fetch blocked pages via the Bright Data Web
  Unlocker, returned as Markdown).

#### Output & analysis
- Structured JSON output, PDF report export, cross-entity correlation and pivoting,
  multi-target investigations, and session history.

#### Security
- Web server binds `127.0.0.1` by default and warns when bound to `0.0.0.0`;
  same-origin CORS policy.
- SSRF guard in `scrape_url`; argument-injection guards on the holehe / Sherlock /
  phoneinfoga / sublist3r binary wrappers.


### Ethics & licensing
- Passive, public-data, authorized-use-only posture, see [`DISCLAIMER.md`](DISCLAIMER.md).
- Released under the MIT license; see [`LICENSE`](LICENSE).

[2.5.0]: https://github.com/scottmartinanderson/clearfront/releases/tag/v2.5.0
[2.4.0]: https://github.com/scottmartinanderson/clearfront/releases/tag/v2.4.0
[0.1.0]: https://github.com/scottmartinanderson/clearfront/releases/tag/v0.1.0
