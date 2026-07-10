# clearfront/mcp_server.py
"""
Clearfront MCP Server, v2.6.0

Exposes all 30 OSINT tool capabilities plus multi-target investigation
to MCP-compliant AI clients over standard I/O. Tools include:
search_email, search_username, search_maigret, search_breach, search_whois,
search_ip, search_domain, generate_dorks, search_paste, search_phone,
search_shodan, search_virustotal, search_censys, search_ip2location,
search_abuseipdb, search_github, search_dns, search_dorks_live, scrape_url,
search_footprint, search_exif, search_exposure.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from clearfront.json_output import to_json
from clearfront.tools.generate_dorks import run_dork_osint
from clearfront.tools.scrape_url import run_scrape_url_osint
from clearfront.tools.search_abuseipdb import run_abuseipdb_osint
from clearfront.tools.search_breach import run_breach_osint
from clearfront.tools.search_censys import run_censys_osint
from clearfront.tools.search_dns import run_dns_osint
from clearfront.tools.search_exif import run_exif_osint
from clearfront.tools.search_domain import run_domain_osint
from clearfront.tools.search_dorks_live import run_dorks_live_osint
from clearfront.tools.search_email import run_email_osint
from clearfront.tools.search_gravatar import run_gravatar_osint
from clearfront.tools.search_emailrep import run_emailrep_osint
from clearfront.tools.search_crypto import run_crypto_osint
from clearfront.tools.search_harvester import run_harvester_osint
from clearfront.tools.search_crt import run_crt_osint
from clearfront.tools.search_wayback import run_wayback_osint
from clearfront.tools.search_greynoise import run_greynoise_osint
from clearfront.tools.search_hudsonrock import run_hudsonrock_osint
from clearfront.tools.search_github import run_github_osint
from clearfront.tools.search_exposure import run_exposure_osint
from clearfront.tools.search_ip import run_ip_osint
from clearfront.tools.search_ip2location import run_ip2location_osint
from clearfront.tools.search_paste import run_paste_osint
from clearfront.tools.search_phone import run_phone_osint
from clearfront.tools.search_shodan import run_shodan_osint
from clearfront.tools.search_username import run_username_osint
from clearfront.tools.search_maigret import run_maigret_osint
from clearfront.tools.search_virustotal import run_virustotal_osint
from clearfront.tools.search_whois import run_whois_osint
from clearfront.tools.search_footprint import run_footprint_osint

logging.basicConfig(level=logging.INFO, format="[MCP] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)
app = Server("clearfront")

# Appended to every tool description. In an MCP client (Claude Desktop, Cursor,
# Windsurf, …) Clearfront's own safety chrome is absent, so the authorized-use
# posture has to travel with each tool.
_AUTHORIZED_USE_NOTE = (
    " Authorized use only: your own assets or a target you are authorized to assess. "
    "Passive, public-source collection."
)

_JSON_PROP = {
    "json_output": {"type": "boolean", "description": "Return result as structured JSON."}
}


def _with_json(schema: dict) -> dict:
    """Return a copy of *schema* with the optional json_output property added."""
    props = dict(schema.get("properties", {}))
    props.update(_JSON_PROP)
    return {**schema, "properties": props}


@app.list_tools()
async def list_tools() -> list[Tool]:
    tools = [
        Tool(
            name="search_email",
            description="Enumerate accounts linked to an email using holehe.",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"email": {"type": "string"}},
                    "required": ["email"],
                }
            ),
        ),
        Tool(
            name="search_username",
            description="Enumerate and verify platforms where a username is registered, using sherlock plus a WhatsMyName subset of modern/niche sites.",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"username": {"type": "string"}},
                    "required": ["username"],
                }
            ),
        ),
        Tool(
            name="search_maigret",
            description="Broad username/identity discovery across 3,000+ sites via maigret (also extracts profile details).",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"username": {"type": "string"}},
                    "required": ["username"],
                }
            ),
        ),
        Tool(
            name="search_breach",
            description="Check if an email appears in data breaches via HaveIBeenPwned. Requires HIBP_API_KEY env var.",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"email": {"type": "string"}},
                    "required": ["email"],
                }
            ),
        ),
        Tool(
            name="search_gravatar",
            description="Look up an email's public Gravatar profile: avatar, display name, bio, location, and linked/verified accounts.",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"email": {"type": "string"}},
                    "required": ["email"],
                }
            ),
        ),
        Tool(
            name="search_emailrep",
            description="Email reputation and footprint summary via EmailRep.io (profiles seen, breach/abuse flags). Requires EMAILREP_API_KEY.",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"email": {"type": "string"}},
                    "required": ["email"],
                }
            ),
        ),
        Tool(
            name="search_crypto",
            description="Validate a Bitcoin or Ethereum address and return a keyless on-chain summary (balance, transactions, total received).",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"address": {"type": "string"}},
                    "required": ["address"],
                }
            ),
        ),
        Tool(
            name="search_harvester",
            description="Passive organisation/domain recon via theHarvester: emails, people, and subdomains from public sources (passive only, no active probing).",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"],
                }
            ),
        ),
        Tool(
            name="search_whois",
            description="Retrieve WHOIS registration data for a domain.",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"],
                }
            ),
        ),
        Tool(
            name="search_ip",
            description=(
                "Retrieve geolocation and ASN data for an IP address via ipinfo.io. "
                "Omit 'ip' (or pass 'me') to auto-detect the caller's own public IP."
            ),
            inputSchema=_with_json(
                {"type": "object", "properties": {"ip": {"type": "string"}}, "required": []}
            ),
        ),
        Tool(
            name="search_exposure",
            description=(
                "Risk-ranked IP exposure report (geolocation, ASN, reverse-DNS, DNS blocklists, "
                "VPN/Tor flags). Omit 'ip' (or pass 'me') to check the caller's own public IP."
            ),
            inputSchema=_with_json(
                {"type": "object", "properties": {"ip": {"type": "string"}}, "required": []}
            ),
        ),
        Tool(
            name="search_domain",
            description="Enumerate subdomains of a target domain using sublist3r.",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"],
                }
            ),
        ),
        Tool(
            name="search_crt",
            description=(
                "Enumerate subdomains from certificate transparency logs via crt.sh. Keyless "
                "and purely passive (public CA logs), surfaces internal/staging hosts that never "
                "resolve publicly."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"],
                }
            ),
        ),
        Tool(
            name="search_wayback",
            description=(
                "List URLs archived under a domain in the Internet Archive (Wayback Machine) via "
                "the keyless CDX API. Passive; recovers deleted, forgotten, or historical pages. "
                "Pairs with scrape_url to fetch a recovered page."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                }
            ),
        ),
        Tool(
            name="search_greynoise",
            description=(
                "Check an IP against the GreyNoise Community API: internet background noise (mass "
                "scanner) vs. potentially targeted actor. Returns classification, noise/RIOT "
                "flags, org, and last-seen. Community tier is 50 lookups/week, so use selectively."
            ),
            inputSchema=_with_json(
                {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}
            ),
        ),
        Tool(
            name="search_hudsonrock",
            description=(
                "Check whether an email or username appears in Hudson Rock's free Cavalier "
                "infostealer index (malware-stolen credentials). Reports exposure yes/no plus "
                "infection metadata (count, dates, OS, antivirus, malware file, affected-service "
                "counts). AUTHORIZED-USE ONLY: for your own or an authorized identifier's exposure "
                "so credentials can be rotated. Uses only the free masked tier; never returns "
                "passwords or login URLs. Keyless."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                }
            ),
        ),
        Tool(
            name="generate_dorks",
            description="Generate targeted Google dork URLs for any target (name, email, username, domain).",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                }
            ),
        ),
        Tool(
            name="search_paste",
            description="Search public paste sites for an email or username (HIBP paste index + search-engine dorking).",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                }
            ),
        ),
        Tool(
            name="search_phone",
            description="Gather carrier and geolocation data for a phone number using phoneinfoga. Use E.164 format.",
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"phone": {"type": "string"}},
                    "required": ["phone"],
                }
            ),
        ),
        Tool(
            name="search_shodan",
            description=(
                "Query Shodan for host intelligence or banner search. "
                "IP address → host lookup (open ports, org, CVEs). "
                "Any other string → keyword/service search. "
                "Requires SHODAN_API_KEY env var."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                }
            ),
        ),
        Tool(
            name="search_virustotal",
            description=(
                "Check IP, domain, URL, or file hash against VirusTotal's 70+ antivirus "
                "engines and threat intelligence. Auto-detects input type. "
                "Requires VIRUSTOTAL_API_KEY env var."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                }
            ),
        ),
        Tool(
            name="search_censys",
            description=(
                "Search Censys for internet-facing infrastructure data. "
                "IP address → open ports, services, ASN, country. "
                "Domain → certificate history, SANs, issuer, first/last seen. "
                "Requires CENSYS_PAT (free plan = IP lookups; domain search is paid)."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                }
            ),
        ),
        Tool(
            name="search_ip2location",
            description=(
                "Enhanced IP intelligence using IP2Location Security Plan. "
                "Returns geolocation, ISP, ASN, and detects VPN, proxy, Tor exit nodes, "
                "and datacenter hosting. Sponsored integration. "
                "Requires IP2LOCATION_API_KEY env var."
            ),
            inputSchema=_with_json(
                {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}
            ),
        ),
        Tool(
            name="search_abuseipdb",
            description=(
                "Check an IP address against the AbuseIPDB v2 API for abuse reputation. "
                "Returns abuse confidence score (0–100%), total reports, country, ISP, domain, "
                "and last reported timestamp. Shows a warning when score exceeds 50%. "
                "Requires ABUSEIPDB_API_KEY env var."
            ),
            inputSchema=_with_json(
                {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}
            ),
        ),
        Tool(
            name="search_github",
            description=(
                "Search GitHub for a username, email, or keyword. "
                "For exact username matches: returns full profile, recent repos, and emails "
                "discovered from commit history. For other queries: top 5 matching accounts. "
                "With a GITHUB_TOKEN it also searches public code for secrets/keys tied to the "
                "target, reported as exposure (location and type only, never the value). "
                "Optional GITHUB_TOKEN env var raises rate limit from 60 to 5000 req/h."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                }
            ),
        ),
        Tool(
            name="search_dns",
            description=(
                "Comprehensive DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA). "
                "Highlights email security misconfigurations: missing SPF, weak SPF policy, "
                "missing or unenforced DMARC, and absent DKIM across common selectors. "
                "No external API or credentials required."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"],
                }
            ),
        ),
        Tool(
            name="search_exif",
            description=(
                "Extract embedded metadata (EXIF/IPTC/XMP) from a local file via exiftool, "
                "camera make/model, software, timestamps, author, and GPS coordinates. "
                "Flags embedded GPS location. Input is a local file path."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"file": {"type": "string"}},
                    "required": ["file"],
                }
            ),
        ),
        Tool(
            name="search_dorks_live",
            description=(
                "Execute Google dork queries for a target via the Bright Data SERP API, "
                "returning live structured results (title, URL, snippet). "
                "Runs up to 5 dorks by default, each is a billable API call. "
                "Requires BRIGHTDATA_API_KEY and BRIGHTDATA_SERP_ZONE env vars."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                }
            ),
        ),
        Tool(
            name="scrape_url",
            description=(
                "Fetch any public URL through the Bright Data Web Unlocker API, bypassing "
                "Cloudflare, CAPTCHA, and bot-protection. Returns the page as clean Markdown. "
                "Requires BRIGHTDATA_API_KEY and BRIGHTDATA_UNLOCKER_ZONE env vars."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                }
            ),
        ),
        Tool(
            name="search_footprint",
            description=(
                "Find a target's real public profiles by searching the web (entity-type-aware: "
                "email, username, domain, phone, full name). Returns structured results and Entity "
                "Correlation Graph nodes/edges. Works free via DuckDuckGo; uses Bright Data SERP "
                "(Google) automatically if configured."
            ),
            inputSchema=_with_json(
                {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "max_queries": {
                            "type": "integer",
                            "description": "Max SERP queries (default 3, each is billable).",
                        },
                    },
                    "required": ["target"],
                }
            ),
        ),
        Tool(
            name="investigate_multi",
            description=(
                "Investigate multiple targets in parallel using the full OSINT tool chain. "
                "Each target gets its own report file. A summary report is also generated. "
                "Maximum 10 targets. Requires ANTHROPIC_API_KEY env var."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of OSINT targets (emails, usernames, domains, IPs). Max 10.",
                    }
                },
                "required": ["targets"],
            },
        ),
    ]

    return [
        t.model_copy(update={"description": (t.description or "") + _AUTHORIZED_USE_NOTE})
        for t in tools
    ]


# Map tool name → (coroutine factory, target key for JSON export)
_HANDLERS: dict[str, tuple] = {
    "search_email": (
        lambda a: run_email_osint(a["email"], timeout_seconds=120),
        lambda a: a["email"],
    ),
    "search_username": (
        lambda a: run_username_osint(a["username"], timeout_seconds=180),
        lambda a: a["username"],
    ),
    "search_maigret": (
        lambda a: run_maigret_osint(a["username"], timeout_seconds=100),
        lambda a: a["username"],
    ),
    "search_breach": (
        lambda a: run_breach_osint(a["email"], timeout_seconds=15),
        lambda a: a["email"],
    ),
    "search_gravatar": (
        lambda a: run_gravatar_osint(a["email"], timeout_seconds=10),
        lambda a: a["email"],
    ),
    "search_emailrep": (
        lambda a: run_emailrep_osint(a["email"], timeout_seconds=15),
        lambda a: a["email"],
    ),
    "search_crypto": (
        lambda a: run_crypto_osint(a["address"], timeout_seconds=15),
        lambda a: a["address"],
    ),
    "search_harvester": (
        lambda a: run_harvester_osint(a["domain"], timeout_seconds=180),
        lambda a: a["domain"],
    ),
    "search_whois": (
        lambda a: run_whois_osint(a["domain"], timeout_seconds=15),
        lambda a: a["domain"],
    ),
    "search_ip": (lambda a: run_ip_osint(a.get("ip", ""), timeout_seconds=10), lambda a: a.get("ip") or "self"),
    "search_exposure": (lambda a: run_exposure_osint(a.get("ip", ""), timeout_seconds=20), lambda a: a.get("ip") or "self"),
    "search_domain": (
        lambda a: run_domain_osint(a["domain"], timeout_seconds=120),
        lambda a: a["domain"],
    ),
    "search_crt": (
        lambda a: run_crt_osint(a["domain"], timeout_seconds=30),
        lambda a: a["domain"],
    ),
    "search_wayback": (
        lambda a: run_wayback_osint(a["target"], timeout_seconds=30),
        lambda a: a["target"],
    ),
    "search_greynoise": (
        lambda a: run_greynoise_osint(a["ip"], timeout_seconds=30),
        lambda a: a["ip"],
    ),
    "search_hudsonrock": (
        lambda a: run_hudsonrock_osint(a["target"], timeout_seconds=30),
        lambda a: a["target"],
    ),
    "generate_dorks": (lambda a: run_dork_osint(a["target"]), lambda a: a["target"]),
    "search_paste": (
        lambda a: run_paste_osint(a["query"], timeout_seconds=15),
        lambda a: a["query"],
    ),
    "search_phone": (
        lambda a: run_phone_osint(a["phone"], timeout_seconds=60),
        lambda a: a["phone"],
    ),
    "search_shodan": (
        lambda a: run_shodan_osint(a["query"], timeout_seconds=30),
        lambda a: a["query"],
    ),
    "search_virustotal": (
        lambda a: run_virustotal_osint(a["target"], timeout_seconds=30),
        lambda a: a["target"],
    ),
    "search_censys": (
        lambda a: run_censys_osint(a["target"], timeout_seconds=30),
        lambda a: a["target"],
    ),
    "search_ip2location": (
        lambda a: run_ip2location_osint(a["ip"], timeout_seconds=30),
        lambda a: a["ip"],
    ),
    "search_abuseipdb": (
        lambda a: run_abuseipdb_osint(a["ip"], timeout_seconds=30),
        lambda a: a["ip"],
    ),
    "search_github": (
        lambda a: run_github_osint(a["query"], timeout_seconds=30),
        lambda a: a["query"],
    ),
    "search_dns": (
        lambda a: run_dns_osint(a["domain"], timeout_seconds=10),
        lambda a: a["domain"],
    ),
    "search_exif": (
        lambda a: run_exif_osint(a["file"], timeout_seconds=30),
        lambda a: a["file"],
    ),
    "search_dorks_live": (
        lambda a: run_dorks_live_osint(a["target"], timeout_seconds=30),
        lambda a: a["target"],
    ),
    "scrape_url": (
        lambda a: run_scrape_url_osint(a["url"], timeout_seconds=60),
        lambda a: a["url"],
    ),
    "search_footprint": (
        lambda a: run_footprint_osint(
            a["target"],
            max_queries=int(a.get("max_queries", 3)),
            timeout_seconds=30,
        ),
        lambda a: a["target"],
    ),
}


# No per-run tool cache here (unlike the web console and the agent loops). Each MCP
# call_tool is an independent request against a long-lived server process, so there is
# no single "run" to scope a cache to; a process-wide cache would serve stale results
# across unrelated investigations. The MCP host does its own turn management instead.
@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    logger.info("Tool: %s | args: %s", name, arguments)
    should_use_json = bool(arguments.get("json_output", False))

    # Special handler for multi-target investigation
    if name == "investigate_multi":
        return await _call_investigate_multi(arguments)

    try:
        if name not in _HANDLERS:
            raise ValueError(f"Unknown tool: '{name}'")
        handler, target_fn = _HANDLERS[name]
        result = await handler(arguments)
        if should_use_json:
            target = target_fn(arguments)
            text = to_json(name, target, result)
        else:
            text = result
        return CallToolResult(content=[TextContent(type="text", text=text)], isError=False)
    except (KeyError, ValueError) as exc:
        logger.error("Validation error: %s", exc)
        return CallToolResult(content=[TextContent(type="text", text=str(exc))], isError=True)
    except Exception as exc:
        logger.exception("Unhandled error in tool '%s'.", name)
        return CallToolResult(
            content=[TextContent(type="text", text=f"Internal error: {exc}")],
            isError=True,
        )


async def _call_investigate_multi(arguments: dict[str, Any]) -> CallToolResult:
    from clearfront.multi_target import MAX_TARGETS, run_multi_target

    targets = arguments.get("targets", [])
    if not isinstance(targets, list) or not targets:
        return CallToolResult(
            content=[TextContent(type="text", text="'targets' must be a non-empty list.")],
            isError=True,
        )
    if len(targets) > MAX_TARGETS:
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Too many targets ({len(targets)}). Maximum is {MAX_TARGETS}.",
                )
            ],
            isError=True,
        )
    try:
        summary = await run_multi_target(targets, is_pdf_disabled=True)
        return CallToolResult(content=[TextContent(type="text", text=summary)], isError=False)
    except Exception as exc:
        logger.exception("Error in investigate_multi.")
        return CallToolResult(
            content=[TextContent(type="text", text=f"Internal error: {exc}")],
            isError=True,
        )


async def _serve() -> None:
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())


def main() -> None:
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
