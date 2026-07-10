# clearfront/cli.py
"""
Clearfront command-line interface.

Default behaviour  : launches the interactive REPL (Claude Code style).
Subcommands        : direct tool execution without AI (email, username,
                     shodan, multi).

Usage:
    clearfront                                   # interactive REPL
    clearfront email target@example.com          # direct, no AI
    clearfront username johndoe99                # direct, no AI
    clearfront shodan 8.8.8.8                    # Shodan lookup, no AI
    clearfront multi targets.txt                 # multi-target (file)
    clearfront multi email1,email2,email3        # multi-target (inline)
    clearfront --parallel email target@example.com
    clearfront --json email target@example.com
    clearfront --provider ollama                 # use local Ollama
"""

from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

import argparse  # noqa: E402
import asyncio  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402

from clearfront.json_output import format_tool_result  # noqa: E402
from clearfront.tools.scrape_url import run_scrape_url_osint  # noqa: E402
from clearfront.tools.search_footprint import run_footprint_osint  # noqa: E402
from clearfront.tools.search_abuseipdb import run_abuseipdb_osint  # noqa: E402
from clearfront.tools.search_breach import run_breach_osint  # noqa: E402
from clearfront.tools.search_censys import run_censys_osint  # noqa: E402
from clearfront.tools.search_dns import run_dns_osint  # noqa: E402
from clearfront.tools.search_exif import run_exif_osint  # noqa: E402
from clearfront.tools.search_exposure import run_exposure_osint  # noqa: E402
from clearfront.tools.search_dorks_live import run_dorks_live_osint  # noqa: E402
from clearfront.tools.search_email import run_email_osint  # noqa: E402
from clearfront.tools.search_gravatar import run_gravatar_osint  # noqa: E402
from clearfront.tools.search_emailrep import run_emailrep_osint  # noqa: E402
from clearfront.tools.search_crypto import run_crypto_osint  # noqa: E402
from clearfront.tools.search_harvester import run_harvester_osint  # noqa: E402
from clearfront.tools.search_github import run_github_osint  # noqa: E402
from clearfront.tools.search_ip import run_ip_osint  # noqa: E402
from clearfront.tools.search_ip2location import run_ip2location_osint  # noqa: E402
from clearfront.tools.search_paste import run_paste_osint  # noqa: E402
from clearfront.tools.search_shodan import run_shodan_osint  # noqa: E402
from clearfront.tools.search_username import run_username_osint  # noqa: E402
from clearfront.tools.search_maigret import run_maigret_osint  # noqa: E402
from clearfront.tools.search_virustotal import run_virustotal_osint  # noqa: E402

_DIVIDER = "=" * 60


# ---------------------------------------------------------------------------
# Ollama pre-flight check
# ---------------------------------------------------------------------------


def _check_ollama_server(host: str) -> bool:
    """Return True if the Ollama HTTP server is accepting connections."""
    import socket
    import urllib.parse

    parsed = urllib.parse.urlparse(host)
    hostname = parsed.hostname or "localhost"
    port = parsed.port or 11434
    try:
        with socket.create_connection((hostname, port), timeout=3):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="[%(levelname)s] %(name)s: %(message)s")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clearfront",
        description=(
            "Clearfront, AI-powered OSINT framework.\n"
            "Run without arguments to start the interactive REPL."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  clearfront                                   # interactive AI session\n"
            "  clearfront email target@example.com          # direct email scan\n"
            "  clearfront username johndoe99                # direct username scan\n"
            "  clearfront shodan 8.8.8.8                    # Shodan host lookup\n"
            "  clearfront censys 8.8.8.8                   # Censys host lookup\n"
            "  clearfront censys example.com               # Censys certificate search\n"
            "  clearfront ip2location 8.8.8.8              # IP2Location lookup\n"
            "  clearfront multi targets.txt                 # multi-target from file\n"
            "  clearfront multi a@x.com,b@y.com             # multi-target inline\n"
            "  clearfront --parallel email target@example.com\n"
            "  clearfront --json email target@example.com\n"
            "  clearfront --provider ollama                 # use local Ollama\n"
            "  clearfront --provider ollama --ollama-model mistral\n"
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        metavar="KEY",
        help="Anthropic API key (overrides ANTHROPIC_API_KEY env var).",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        dest="is_parallel",
        help=(
            "Run independent complementary tools concurrently using asyncio.gather(). "
            "For 'email': runs search_email + search_breach in parallel. "
            "For 'username': runs search_username + search_paste in parallel."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as structured JSON instead of formatted text.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        metavar="FILE",
        default=None,
        help="Write results to FILE instead of stdout (raw, no banner; combine with --json for a JSON file).",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default="anthropic",
        choices=["anthropic", "ollama", "openai"],
        help="AI provider for the interactive REPL (default: anthropic).",
    )
    parser.add_argument(
        "--ollama-model",
        type=str,
        default="llama3.2",
        metavar="MODEL",
        help="Ollama model name (default: llama3.2).  Used when --provider ollama.",
    )
    parser.add_argument(
        "--ollama-host",
        type=str,
        default="http://localhost:11434",
        metavar="URL",
        help="Ollama server URL (default: http://localhost:11434).",
    )
    parser.add_argument(
        "--openai-base-url",
        type=str,
        default=os.environ.get("OPENAI_BASE_URL", "http://localhost:8080/v1"),
        metavar="URL",
        help=(
            "Base URL of an OpenAI-compatible endpoint (LiteLLM, llama-swap, vLLM, …).  "
            "Used when --provider openai.  Default: $OPENAI_BASE_URL or "
            "http://localhost:8080/v1."
        ),
    )
    parser.add_argument(
        "--openai-model",
        type=str,
        default=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        metavar="MODEL",
        help=(
            "Model name to request from the OpenAI-compatible endpoint.  "
            "Used when --provider openai.  Default: $OPENAI_MODEL or gpt-4o-mini."
        ),
    )
    parser.add_argument(
        "--openai-api-key",
        type=str,
        default=None,
        metavar="KEY",
        help=(
            "API key for the OpenAI-compatible endpoint.  "
            "Falls back to $OPENAI_API_KEY (local servers may ignore it)."
        ),
    )
    parser.add_argument(
        "--no-pdf",
        action="store_true",
        dest="is_pdf_disabled",
        help="Disable automatic PDF generation alongside Markdown reports.",
    )
    parser.add_argument(
        "--depth",
        type=str,
        default="deeper",
        choices=["faster", "balanced", "deeper"],
        help=(
            "Sweep depth for the interactive analyst (default: deeper).  "
            "faster: fewer sources, quick pass.  balanced: main sources.  "
            "deeper: follows every lead.  Change it live with the 'depth' command."
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    # shell, explicit alias for REPL
    subparsers.add_parser(
        "shell",
        help="Start the interactive REPL (default when no command given).",
    )

    # email
    email_cmd = subparsers.add_parser(
        "email",
        help="Direct email scan via holehe (no AI).",
    )
    email_cmd.add_argument("target", type=str, metavar="ADDRESS")
    email_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=120,
        metavar="SECONDS",
        help="Maximum execution time (default: 120).",
    )

    # gravatar
    gravatar_cmd = subparsers.add_parser(
        "gravatar",
        help="Direct Gravatar profile lookup for an email (no AI).",
    )
    gravatar_cmd.add_argument("target", type=str, metavar="ADDRESS")
    gravatar_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="Maximum execution time (default: 10).",
    )

    # emailrep
    emailrep_cmd = subparsers.add_parser(
        "emailrep",
        help="Direct EmailRep.io reputation lookup for an email (no AI). Needs EMAILREP_API_KEY.",
    )
    emailrep_cmd.add_argument("target", type=str, metavar="ADDRESS")
    emailrep_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=15,
        metavar="SECONDS",
        help="Maximum execution time (default: 15).",
    )

    # crypto
    crypto_cmd = subparsers.add_parser(
        "crypto",
        help="Direct on-chain summary for a BTC/ETH address (no AI).",
    )
    crypto_cmd.add_argument("target", type=str, metavar="ADDRESS")
    crypto_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=15,
        metavar="SECONDS",
        help="Maximum execution time (default: 15).",
    )

    # harvester
    harvester_cmd = subparsers.add_parser(
        "harvester",
        help="Passive domain recon via theHarvester: emails, people, subdomains (no AI).",
    )
    harvester_cmd.add_argument("target", type=str, metavar="DOMAIN")
    harvester_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=180,
        metavar="SECONDS",
        help="Maximum execution time (default: 180).",
    )

    # username
    username_cmd = subparsers.add_parser(
        "username",
        help="Direct username scan via sherlock (no AI).",
    )
    username_cmd.add_argument("target", type=str, metavar="USERNAME")
    username_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=180,
        metavar="SECONDS",
        help="Maximum execution time (default: 180).",
    )

    # maigret
    maigret_cmd = subparsers.add_parser(
        "maigret",
        help="Broad username scan across 3,000+ sites via maigret (no AI).",
    )
    maigret_cmd.add_argument("target", type=str, metavar="USERNAME")
    maigret_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=100,
        metavar="SECONDS",
        help="Maximum execution time (default: 100).",
    )

    # shodan
    shodan_cmd = subparsers.add_parser(
        "shodan",
        help="Shodan host lookup or keyword search (no AI). Requires SHODAN_API_KEY.",
    )
    shodan_cmd.add_argument(
        "query",
        type=str,
        metavar="QUERY",
        help="IP address for host lookup, or any Shodan search query.",
    )
    shodan_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Request timeout (default: 30).",
    )

    # virustotal
    virustotal_cmd = subparsers.add_parser(
        "virustotal",
        help="VirusTotal lookup for IP, domain, URL, or file hash (no AI). Requires VIRUSTOTAL_API_KEY.",
    )
    virustotal_cmd.add_argument(
        "target",
        type=str,
        metavar="TARGET",
        help="IPv4 address, domain, full URL, or file hash (MD5/SHA-1/SHA-256).",
    )
    virustotal_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Request timeout (default: 30).",
    )

    # censys
    censys_cmd = subparsers.add_parser(
        "censys",
        help="Censys lookup for IP or domain (no AI). Requires CENSYS_PAT (domain search needs a paid plan).",
    )
    censys_cmd.add_argument(
        "target",
        type=str,
        metavar="TARGET",
        help="IPv4 address for host lookup, or domain for certificate search.",
    )
    censys_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Request timeout (default: 30).",
    )

    # github
    github_cmd = subparsers.add_parser(
        "github",
        help="GitHub OSINT: profile, repos, and commit-email discovery (no AI).",
    )
    github_cmd.add_argument(
        "query",
        type=str,
        metavar="QUERY",
        help="GitHub username, email address, or keyword.",
    )
    github_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Request timeout (default: 30).",
    )

    # dns
    dns_cmd = subparsers.add_parser(
        "dns",
        help="DNS record enumeration with email security analysis (no AI).",
    )
    dns_cmd.add_argument(
        "domain",
        type=str,
        metavar="DOMAIN",
        help="Target domain (e.g. example.com).",
    )
    dns_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="DNS query timeout (default: 10).",
    )

    # exif
    exif_cmd = subparsers.add_parser(
        "exif",
        help="Extract embedded file metadata (EXIF/GPS/author) via exiftool (no AI).",
    )
    exif_cmd.add_argument(
        "file",
        type=str,
        metavar="FILE",
        help="Path to a local image, PDF, or media file.",
    )
    exif_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="exiftool timeout (default: 30).",
    )

    # ip
    ip_cmd = subparsers.add_parser(
        "ip",
        help="IP geolocation, ASN & hostname via ipinfo.io (no AI). Omit IP to check your own public IP.",
    )
    ip_cmd.add_argument(
        "ip",
        type=str,
        nargs="?",
        default="",
        metavar="IP_ADDRESS",
        help="IPv4/IPv6 address to look up. Omit (or use 'me') to auto-detect your own public IP.",
    )
    ip_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="Request timeout (default: 10).",
    )

    # exposure
    exposure_cmd = subparsers.add_parser(
        "exposure",
        help="Risk-ranked IP exposure report (no AI). Omit IP to check your own public IP.",
    )
    exposure_cmd.add_argument(
        "ip",
        type=str,
        nargs="?",
        default="",
        metavar="IP_ADDRESS",
        help="IPv4/IPv6 address. Omit (or use 'me') to check your own public IP.",
    )
    exposure_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=20,
        metavar="SECONDS",
        help="Per-signal timeout (default: 20).",
    )

    # abuseipdb
    abuseipdb_cmd = subparsers.add_parser(
        "abuseipdb",
        help="AbuseIPDB reputation check for an IP address (no AI). Requires ABUSEIPDB_API_KEY.",
    )
    abuseipdb_cmd.add_argument(
        "ip",
        type=str,
        metavar="IP_ADDRESS",
        help="IPv4 or IPv6 address to check.",
    )
    abuseipdb_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Request timeout (default: 30).",
    )

    # ip2location
    ip2location_cmd = subparsers.add_parser(
        "ip2location",
        help="IP2Location lookup for geolocation, ISP, VPN/Proxy/Tor/Datacenter detection (no AI). Requires IP2LOCATION_API_KEY.",
    )
    ip2location_cmd.add_argument(
        "ip",
        type=str,
        metavar="IP_ADDRESS",
        help="IPv4 or IPv6 address to look up.",
    )
    ip2location_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Request timeout (default: 30).",
    )

    # search-dorks-live
    dorks_live_cmd = subparsers.add_parser(
        "search-dorks-live",
        help=(
            "Execute live Google dork searches via Bright Data SERP API (no AI). "
            "Requires BRIGHTDATA_API_KEY and BRIGHTDATA_SERP_ZONE."
        ),
    )
    dorks_live_cmd.add_argument(
        "target",
        type=str,
        metavar="TARGET",
        help="Any target: name, email, username, or domain.",
    )
    dorks_live_cmd.add_argument(
        "--max-dorks",
        type=int,
        default=5,
        metavar="N",
        dest="max_dorks",
        help="Number of dork queries to run (default: 5, max: 12).",
    )
    dorks_live_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Per-request timeout (default: 30).",
    )

    # scrape
    scrape_cmd = subparsers.add_parser(
        "scrape",
        help=(
            "Fetch a URL via Bright Data Web Unlocker and return clean Markdown (no AI). "
            "Bypasses Cloudflare/CAPTCHA. Requires BRIGHTDATA_API_KEY and BRIGHTDATA_UNLOCKER_ZONE."
        ),
    )
    scrape_cmd.add_argument(
        "url",
        type=str,
        metavar="URL",
        help="Full URL to fetch (must start with http:// or https://).",
    )
    scrape_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Request timeout (default: 60).",
    )

    # footprint
    footprint_cmd = subparsers.add_parser(
        "footprint",
        help=(
            "Entity-type-aware SERP footprint via Bright Data (no AI). "
            "Requires BRIGHTDATA_API_KEY and BRIGHTDATA_SERP_ZONE."
        ),
    )
    footprint_cmd.add_argument(
        "target",
        type=str,
        metavar="TARGET",
        help="Any OSINT target: email, username, domain, phone, or full name.",
    )
    footprint_cmd.add_argument(
        "--max-queries",
        type=int,
        default=3,
        metavar="N",
        dest="max_queries",
        help="Number of SERP queries to run (default: 3, each is billable).",
    )
    footprint_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Per-request timeout (default: 30).",
    )

    # graph
    graph_cmd = subparsers.add_parser(
        "graph",
        help=(
            "Auto-pivot from a target and export the entity correlation graph as "
            "GraphML/JSON/Mermaid artifacts (no AI)."
        ),
    )
    graph_cmd.add_argument(
        "target",
        type=str,
        metavar="TARGET",
        help="Seed target: email, username, domain, IP, phone, hash, or URL.",
    )
    graph_cmd.add_argument(
        "-o",
        "--output",
        dest="graph_output",
        metavar="PATH",
        default=None,
        help=(
            "Output path or prefix. With --format all, the .graphml/.json/.mmd suffixes "
            "are appended. Default: derived from TARGET. A single --format with no -o "
            "prints to stdout."
        ),
    )
    graph_cmd.add_argument(
        "--format",
        dest="graph_format",
        choices=["graphml", "json", "mermaid", "all"],
        default="all",
        help="Export format to write (default: all three).",
    )
    graph_cmd.add_argument(
        "--max-depth",
        dest="graph_max_depth",
        type=int,
        default=2,
        metavar="N",
        help="Maximum BFS hops from the seed (default: 2).",
    )
    graph_cmd.add_argument(
        "--max-entities",
        dest="graph_max_entities",
        type=int,
        default=40,
        metavar="N",
        help="Cap on distinct entities investigated (default: 40).",
    )
    graph_cmd.add_argument(
        "--max-tool-calls",
        dest="graph_max_tool_calls",
        type=int,
        default=60,
        metavar="N",
        help="Cap on total tool invocations across the run (default: 60).",
    )
    graph_cmd.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Per-tool-call timeout (default: 30).",
    )

    # multi
    multi_cmd = subparsers.add_parser(
        "multi",
        help="Investigate multiple targets in parallel (AI-powered).",
    )
    multi_cmd.add_argument(
        "targets",
        type=str,
        metavar="TARGETS",
        help=("Comma-separated list of targets, or path to a file with one target per line."),
    )

    # web
    web_cmd = subparsers.add_parser(
        "web",
        help="Start the web server (opens browser automatically).",
    )
    web_cmd.add_argument(
        "--port",
        type=int,
        default=8080,
        metavar="PORT",
        help="Port to listen on (default: 8080).",
    )
    web_cmd.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        metavar="HOST",
        help=(
            "Host/IP to bind to (default: 127.0.0.1, localhost-only). "
            "Use 0.0.0.0 to expose on your network, no auth, see startup warning."
        ),
    )
    web_cmd.add_argument(
        "--no-browser",
        action="store_true",
        dest="no_browser",
        help="Do not open a browser tab automatically.",
    )

    # history
    history_parser = subparsers.add_parser(
        "history",
        help="Browse saved REPL session history.",
    )
    history_parser.add_argument(
        "--all",
        action="store_true",
        dest="history_all",
        help="List all saved sessions (up to 50).",
    )
    history_parser.add_argument(
        "--last",
        type=int,
        metavar="N",
        dest="history_last",
        default=None,
        help="List last N sessions.",
    )
    history_sub = history_parser.add_subparsers(dest="history_action", metavar="action")

    history_open = history_sub.add_parser("open", help="Open session by number from the list.")
    history_open.add_argument("n", type=int, metavar="N", help="Session number (1-based).")

    history_sub.add_parser("clear", help="Delete all session history files.")

    # sponsors
    subparsers.add_parser(
        "sponsors",
        help="List current sponsors and featured integrations.",
    )

    # -o/--output is a global flag, but analysts expect to type it at the end
    # (`clearfront ip 8.8.8.8 -o out.json`), so also register it on every
    # subparser. SUPPRESS keeps the main-parser value when it is not repeated.
    # 'graph' is excluded: it defines its own -o as a multi-file path PREFIX
    # (dest=graph_output), not the raw single-file sink the others share.
    for _name, _sub in subparsers.choices.items():
        if _name == "graph":
            continue
        _sub.add_argument(
            "-o",
            "--output",
            dest="output",
            metavar="FILE",
            default=argparse.SUPPRESS,
            help="Write results to FILE instead of stdout (raw; combine with --json for JSON).",
        )

    return parser


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


# Set from --output. When present, tool results are appended here (raw, no
# banner) instead of printed to stdout, so an analyst can script Clearfront
# without shell redirection. The file is truncated once at startup.
_OUTPUT_FILE: str | None = None


def _write_output(text: str) -> None:
    """Append raw text to the --output file."""
    with open(_OUTPUT_FILE, "a", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def _print_result(result: str) -> None:
    if _OUTPUT_FILE:
        _write_output(result)
        return
    print(_DIVIDER)
    print(" SCAN RESULTS ".center(60, "="))
    print(_DIVIDER)
    print(result)
    print(_DIVIDER)


def _print_result_labeled(label: str, result: str) -> None:
    if _OUTPUT_FILE:
        _write_output(f"=== {label} ===\n{result}")
        return
    print(_DIVIDER)
    print(f" {label} ".center(60, "="))
    print(_DIVIDER)
    print(result)
    print(_DIVIDER)


def _emit_json(data: dict | list) -> None:
    text = json.dumps(data, indent=2)
    if _OUTPUT_FILE:
        _write_output(text)
        return
    print(text)


# ---------------------------------------------------------------------------
# Direct command handlers (no AI)
# ---------------------------------------------------------------------------


async def _handle_email(
    target: str,
    timeout: int,
    is_parallel: bool = False,
    json_output: bool = False,
) -> None:
    if is_parallel:
        print(f"[*] Email scan (parallel): {target}", file=sys.stderr)
        email_result, breach_result = await asyncio.gather(
            run_email_osint(email=target, timeout_seconds=timeout),
            run_breach_osint(email=target),
        )
        if json_output:
            _emit_json(
                [
                    format_tool_result("search_email", target, email_result),
                    format_tool_result("search_breach", target, breach_result),
                ]
            )
        else:
            _print_result_labeled("search_email", email_result)
            _print_result_labeled("search_breach", breach_result)
    else:
        print(f"[*] Email scan: {target}", file=sys.stderr)
        print(f"[*] Timeout: {timeout}s\n", file=sys.stderr)
        result = await run_email_osint(email=target, timeout_seconds=timeout)
        if json_output:
            _emit_json(format_tool_result("search_email", target, result))
        else:
            _print_result(result)


async def _handle_username(
    target: str,
    timeout: int,
    is_parallel: bool = False,
    json_output: bool = False,
) -> None:
    if is_parallel:
        print(f"[*] Username scan (parallel): {target}", file=sys.stderr)
        username_result, paste_result = await asyncio.gather(
            run_username_osint(username=target, timeout_seconds=timeout),
            run_paste_osint(query=target),
        )
        if json_output:
            _emit_json(
                [
                    format_tool_result("search_username", target, username_result),
                    format_tool_result("search_paste", target, paste_result),
                ]
            )
        else:
            _print_result_labeled("search_username", username_result)
            _print_result_labeled("search_paste", paste_result)
    else:
        print(f"[*] Username scan: {target}", file=sys.stderr)
        print(f"[*] Timeout: {timeout}s\n", file=sys.stderr)
        result = await run_username_osint(username=target, timeout_seconds=timeout)
        if json_output:
            _emit_json(format_tool_result("search_username", target, result))
        else:
            _print_result(result)


async def _handle_shodan(
    query: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] Shodan lookup: {query}", file=sys.stderr)
    result = await run_shodan_osint(query=query, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_shodan", query, result))
    else:
        _print_result(result)


async def _handle_virustotal(
    target: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] VirusTotal lookup: {target}", file=sys.stderr)
    result = await run_virustotal_osint(target=target, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_virustotal", target, result))
    else:
        _print_result(result)


async def _handle_censys(
    target: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] Censys lookup: {target}", file=sys.stderr)
    result = await run_censys_osint(target=target, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_censys", target, result))
    else:
        _print_result(result)


async def _handle_maigret(
    target: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] Maigret scan (3,000+ sites): {target}", file=sys.stderr)
    result = await run_maigret_osint(username=target, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_maigret", target, result))
    else:
        _print_result(result)


async def _handle_ip(
    ip: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    label = ip.strip() if ip.strip() else "your own public IP"
    print(f"[*] IP lookup: {label}", file=sys.stderr)
    result = await run_ip_osint(ip, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_ip", ip.strip() or "self", result))
    else:
        _print_result(result)


async def _handle_exposure(
    ip: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    label = ip.strip() if ip.strip() else "your own public IP"
    print(f"[*] Exposure report: {label}", file=sys.stderr)
    result = await run_exposure_osint(ip, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_exposure", ip.strip() or "self", result))
    else:
        _print_result(result)


async def _handle_abuseipdb(
    ip: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] AbuseIPDB lookup: {ip}", file=sys.stderr)
    result = await run_abuseipdb_osint(ip=ip, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_abuseipdb", ip, result))
    else:
        _print_result(result)


async def _handle_github(
    query: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] GitHub lookup: {query}", file=sys.stderr)
    result = await run_github_osint(query=query, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_github", query, result))
    else:
        _print_result(result)


async def _handle_gravatar(
    email: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] Gravatar lookup: {email}", file=sys.stderr)
    result = await run_gravatar_osint(email=email, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_gravatar", email, result))
    else:
        _print_result(result)


async def _handle_emailrep(
    email: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] EmailRep lookup: {email}", file=sys.stderr)
    result = await run_emailrep_osint(email=email, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_emailrep", email, result))
    else:
        _print_result(result)


async def _handle_crypto(
    address: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] Crypto lookup: {address}", file=sys.stderr)
    result = await run_crypto_osint(address=address, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_crypto", address, result))
    else:
        _print_result(result)


async def _handle_harvester(
    domain: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] Passive domain recon: {domain}", file=sys.stderr)
    result = await run_harvester_osint(domain=domain, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_harvester", domain, result))
    else:
        _print_result(result)


async def _handle_dns(
    domain: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] DNS lookup: {domain}", file=sys.stderr)
    result = await run_dns_osint(domain=domain, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_dns", domain, result))
    else:
        _print_result(result)


async def _handle_exif(
    file_path: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] Metadata extraction: {file_path}", file=sys.stderr)
    result = await run_exif_osint(file_path=file_path, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_exif", file_path, result))
    else:
        _print_result(result)


async def _handle_ip2location(
    ip: str,
    timeout: int,
    json_output: bool = False,
) -> None:
    print(f"[*] IP2Location lookup: {ip}", file=sys.stderr)
    result = await run_ip2location_osint(ip=ip, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_ip2location", ip, result))
    else:
        _print_result(result)


async def _handle_dorks_live(
    target: str,
    max_dorks: int = 5,
    timeout: int = 30,
    json_output: bool = False,
) -> None:
    print(f"[*] Live dork search: {target}", file=sys.stderr)
    result = await run_dorks_live_osint(target=target, max_dorks=max_dorks, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("search_dorks_live", target, result))
    else:
        _print_result(result)


async def _handle_scrape(
    url: str,
    timeout: int = 60,
    json_output: bool = False,
) -> None:
    print(f"[*] Web Unlocker scrape: {url}", file=sys.stderr)
    result = await run_scrape_url_osint(url=url, timeout_seconds=timeout)
    if json_output:
        _emit_json(format_tool_result("scrape_url", url, result))
    else:
        _print_result(result)


async def _handle_footprint(
    target: str,
    max_queries: int = 3,
    timeout: int = 30,
    json_output: bool = False,
) -> None:
    print(f"[*] Footprint search: {target}", file=sys.stderr)
    result = await run_footprint_osint(
        target=target, max_queries=max_queries, timeout_seconds=timeout
    )
    if json_output:
        _emit_json(format_tool_result("search_footprint", target, result))
    else:
        _print_result(result)


def _safe_graph_base(target: str) -> str:
    """Filesystem-safe base name derived from a target (no path separators)."""
    allowed = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    )
    base = "".join(c if c in allowed else "_" for c in target).strip("._-")
    return base or "clearfront-graph"


async def _handle_graph(
    target: str,
    *,
    output: str | None,
    fmt: str,
    max_depth: int,
    max_entities: int,
    max_tool_calls: int,
    timeout: int,
) -> None:
    """Auto-pivot from *target* and write the correlation graph as portable artifacts.

    Uses the same investigate_graph() BFS the pivot engine uses, then the deterministic
    EntityGraph exporters, so the same target always yields byte-identical artifacts.
    """
    from clearfront.pivot import investigate_graph

    print(f"[*] Building entity graph for: {target}", file=sys.stderr)
    graph = await investigate_graph(
        target,
        max_depth=max_depth,
        max_entities=max_entities,
        max_tool_calls=max_tool_calls,
        timeout_seconds=timeout,
    )
    print(f"[*] {graph.summary()}", file=sys.stderr)

    exporters = {
        "graphml": (graph.to_graphml, ".graphml"),
        "json": (graph.to_json, ".json"),
        "mermaid": (graph.to_mermaid, ".mmd"),
    }
    formats = ["graphml", "json", "mermaid"] if fmt == "all" else [fmt]

    # A single format with no -o prints to stdout, so it composes with pipes/redirects.
    if len(formats) == 1 and not output:
        render, _ext = exporters[formats[0]]
        print(render())
        return

    base = output or _safe_graph_base(target)
    for name in formats:
        render, ext = exporters[name]
        path = base if (len(formats) == 1 and base.endswith(ext)) else base + ext
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render())
        print(f"[*] Wrote {path}", file=sys.stderr)


async def _handle_multi(
    targets_arg: str,
    api_key: str | None = None,
    is_pdf_disabled: bool = False,
    provider: str = "anthropic",
    ollama_model: str = "llama3.2",
    ollama_host: str = "http://localhost:11434",
    openai_base_url: str = "http://localhost:8080/v1",
    openai_model: str = "gpt-4o-mini",
    openai_api_key: str | None = None,
) -> None:
    from clearfront.multi_target import MAX_TARGETS, parse_targets, run_multi_target

    targets = parse_targets(targets_arg)
    if not targets:
        print("[!] No targets found.", file=sys.stderr)
        sys.exit(1)
    if len(targets) > MAX_TARGETS:
        print(
            f"[!] Too many targets ({len(targets)}). Maximum is {MAX_TARGETS}.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[*] Multi-target investigation: {len(targets)} target(s)", file=sys.stderr)
    summary = await run_multi_target(
        targets,
        api_key=api_key,
        is_pdf_disabled=is_pdf_disabled,
        provider=provider,
        ollama_model=ollama_model,
        ollama_host=ollama_host,
        openai_base_url=openai_base_url,
        openai_model=openai_model,
        openai_api_key=openai_api_key,
    )
    _print_result(summary)


# ---------------------------------------------------------------------------
# Sponsors command handler
# ---------------------------------------------------------------------------


def _handle_sponsors() -> None:
    from clearfront.sponsors import SponsorsValidationError, load_sponsors

    try:
        sponsors = load_sponsors()
    except SponsorsValidationError as exc:
        print(f"[!] sponsors.json error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(_DIVIDER)
    print(" SPONSORS & FEATURED INTEGRATIONS ".center(60, "="))
    print(_DIVIDER)

    tier_order = [
        ("featured", "Featured Integrations"),
        ("integration", "Integrations"),
        ("supporter", "Supporters"),
    ]
    for tier_key, tier_label in tier_order:
        tier_sponsors = [s for s in sponsors if s["tier"] == tier_key]
        if not tier_sponsors:
            continue
        print(f"\n{tier_label}:")
        for s in tier_sponsors:
            tool_note = f"  [tool: {s['tool']}]" if s.get("tool") else ""
            print(f"  • {s['name']}{tool_note}")
            print(f"    {s['tagline']}")
            print(f"    {s['url']}")

    print("\n  Full prospectus: SPONSORSHIP.md")
    print(_DIVIDER)


# ---------------------------------------------------------------------------
# Web server handler
# ---------------------------------------------------------------------------


async def _handle_web(
    host: str = "0.0.0.0",
    port: int = 8080,
    no_browser: bool = False,
) -> None:
    import threading
    import webbrowser

    from clearfront.web_server import serve_async

    if not no_browser:
        display = "localhost" if host in ("0.0.0.0", "") else host
        url = f"http://{display}:{port}"
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    await serve_async(host=host, port=port)


# ---------------------------------------------------------------------------
# History command handler
# ---------------------------------------------------------------------------


def _handle_history(args: argparse.Namespace) -> None:
    import sys as _sys

    from rich.console import Console as _Console

    from clearfront.session_history import (
        clear_sessions,
        display_history_table,
        display_session_detail,
        load_sessions,
    )

    _console = _Console()
    action = getattr(args, "history_action", None)

    if action == "open":
        sessions = load_sessions()
        n = args.n
        if n < 1 or n > len(sessions):
            _console.print(
                f"[bold red]Error:[/] Session {n} not found (total saved: {len(sessions)})"
            )
            _sys.exit(1)
        display_session_detail(sessions[n - 1], n, _console)

    elif action == "clear":
        confirm = input("Delete all session history? [y/N] ").strip().lower()
        if confirm == "y":
            deleted = clear_sessions()
            noun = "file" if deleted == 1 else "files"
            _console.print(f"  [dim]✓ Deleted {deleted} session {noun}.[/]\n")
        else:
            _console.print("  [dim]Aborted.[/]\n")

    else:
        if getattr(args, "history_all", False):
            sessions = load_sessions()
        elif getattr(args, "history_last", None):
            sessions = load_sessions(limit=args.history_last)
        else:
            sessions = load_sessions(limit=10)
        display_history_table(sessions, _console)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


async def _async_main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    _configure_logging(args.verbose)

    # No subcommand or explicit 'shell' → launch REPL.
    # Await directly, run_repl() is a sync wrapper that calls asyncio.run()
    # internally, which raises RuntimeError when called from a running event loop.
    if args.command in (None, "shell"):
        if getattr(args, "provider", "anthropic") == "ollama":
            ollama_host = getattr(args, "ollama_host", "http://localhost:11434")
            if not _check_ollama_server(ollama_host):
                print(
                    f"[ERROR] Ollama server is not running at {ollama_host}.",
                    file=sys.stderr,
                )
                print(
                    "Make sure Ollama is installed (https://ollama.com) and running:",
                    file=sys.stderr,
                )
                print(
                    "  macOS/Linux:  curl -fsSL https://ollama.com/install.sh | sh",
                    file=sys.stderr,
                )
                print(
                    "  Windows:      https://ollama.com/download/windows",
                    file=sys.stderr,
                )
                print("", file=sys.stderr)
                print("  ollama serve          # start in terminal", file=sys.stderr)
                print("  ollama pull llama3.2  # pull a model first", file=sys.stderr)
                print("", file=sys.stderr)
                print("Then retry:  clearfront --provider ollama", file=sys.stderr)
                sys.exit(1)

        from clearfront.repl import OISRepl

        repl = OISRepl(
            api_key=getattr(args, "api_key", None),
            provider=getattr(args, "provider", "anthropic"),
            ollama_model=getattr(args, "ollama_model", "llama3.2"),
            ollama_host=getattr(args, "ollama_host", "http://localhost:11434"),
            openai_base_url=getattr(args, "openai_base_url", "http://localhost:8080/v1"),
            openai_model=getattr(args, "openai_model", "gpt-4o-mini"),
            openai_api_key=getattr(args, "openai_api_key", None),
            is_pdf_disabled=getattr(args, "is_pdf_disabled", False),
            depth=getattr(args, "depth", "deeper"),
        )
        await repl.run()
        return

    is_parallel = getattr(args, "is_parallel", False)
    json_output = getattr(args, "json_output", False)
    is_pdf_disabled = getattr(args, "is_pdf_disabled", False)

    global _OUTPUT_FILE
    _OUTPUT_FILE = getattr(args, "output", None)
    if _OUTPUT_FILE:
        try:
            open(_OUTPUT_FILE, "w", encoding="utf-8").close()  # truncate once
        except OSError as exc:
            print(f"[!] Cannot write to {_OUTPUT_FILE}: {exc}", file=sys.stderr)
            sys.exit(1)

    if args.command == "email":
        await _handle_email(
            args.target, args.timeout, is_parallel=is_parallel, json_output=json_output
        )
    elif args.command == "gravatar":
        await _handle_gravatar(args.target, args.timeout, json_output=json_output)
    elif args.command == "emailrep":
        await _handle_emailrep(args.target, args.timeout, json_output=json_output)
    elif args.command == "crypto":
        await _handle_crypto(args.target, args.timeout, json_output=json_output)
    elif args.command == "harvester":
        await _handle_harvester(args.target, args.timeout, json_output=json_output)
    elif args.command == "username":
        await _handle_username(
            args.target, args.timeout, is_parallel=is_parallel, json_output=json_output
        )
    elif args.command == "maigret":
        await _handle_maigret(args.target, args.timeout, json_output=json_output)
    elif args.command == "shodan":
        await _handle_shodan(args.query, args.timeout, json_output=json_output)
    elif args.command == "virustotal":
        await _handle_virustotal(args.target, args.timeout, json_output=json_output)
    elif args.command == "censys":
        await _handle_censys(args.target, args.timeout, json_output=json_output)
    elif args.command == "github":
        await _handle_github(args.query, args.timeout, json_output=json_output)
    elif args.command == "dns":
        await _handle_dns(args.domain, args.timeout, json_output=json_output)
    elif args.command == "exif":
        await _handle_exif(args.file, args.timeout, json_output=json_output)
    elif args.command == "abuseipdb":
        await _handle_abuseipdb(args.ip, args.timeout, json_output=json_output)
    elif args.command == "ip":
        await _handle_ip(args.ip, args.timeout, json_output=json_output)
    elif args.command == "exposure":
        await _handle_exposure(args.ip, args.timeout, json_output=json_output)
    elif args.command == "ip2location":
        await _handle_ip2location(args.ip, args.timeout, json_output=json_output)
    elif args.command == "search-dorks-live":
        await _handle_dorks_live(
            args.target,
            max_dorks=getattr(args, "max_dorks", 5),
            timeout=args.timeout,
            json_output=json_output,
        )
    elif args.command == "scrape":
        await _handle_scrape(args.url, timeout=args.timeout, json_output=json_output)
    elif args.command == "footprint":
        await _handle_footprint(
            args.target,
            max_queries=getattr(args, "max_queries", 3),
            timeout=args.timeout,
            json_output=json_output,
        )
    elif args.command == "graph":
        await _handle_graph(
            args.target,
            output=getattr(args, "graph_output", None),
            fmt=getattr(args, "graph_format", "all"),
            max_depth=getattr(args, "graph_max_depth", 2),
            max_entities=getattr(args, "graph_max_entities", 40),
            max_tool_calls=getattr(args, "graph_max_tool_calls", 60),
            timeout=getattr(args, "timeout", 30),
        )
    elif args.command == "multi":
        await _handle_multi(
            args.targets,
            api_key=getattr(args, "api_key", None),
            is_pdf_disabled=is_pdf_disabled,
            provider=getattr(args, "provider", "anthropic"),
            ollama_model=getattr(args, "ollama_model", "llama3.2"),
            ollama_host=getattr(args, "ollama_host", "http://localhost:11434"),
            openai_base_url=getattr(args, "openai_base_url", "http://localhost:8080/v1"),
            openai_model=getattr(args, "openai_model", "gpt-4o-mini"),
            openai_api_key=getattr(args, "openai_api_key", None),
        )
    elif args.command == "web":
        await _handle_web(
            host=getattr(args, "host", "0.0.0.0"),
            port=getattr(args, "port", 8080),
            no_browser=getattr(args, "no_browser", False),
        )
    elif args.command == "history":
        _handle_history(args)
    elif args.command == "sponsors":
        _handle_sponsors()
    else:
        parser.print_help()
        sys.exit(1)

    if _OUTPUT_FILE:
        try:
            if os.path.getsize(_OUTPUT_FILE) > 0:
                print(f"[*] Results written to {_OUTPUT_FILE}", file=sys.stderr)
        except OSError:
            pass


def main() -> None:
    """Synchronous entry point registered in pyproject.toml."""
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"[!] Fatal: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
