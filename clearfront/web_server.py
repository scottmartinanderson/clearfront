# clearfront/web_server.py
"""
CLEARFRONT Web Server, FastAPI REST + SSE backend.

Routes:
  GET  /                       serve web/index.html
  GET  /api/health             version + setup status
  GET  /api/tools              tool catalog with availability
  POST /api/run/{tool_name}    run tool, return full result
  GET  /api/stream/{tool_name} stream output via Server-Sent Events
  POST /api/chat               AI chat with tool_use (SSE)
  POST /api/setup              save API keys to .env
  GET  /docs/*                 docs/ static files (mounted)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import AsyncIterator

import requests as _requests

try:
    import httpx as _httpx
except ImportError:
    _httpx = None  # type: ignore

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from clearfront import effort as _effort
from clearfront.brightdata import BRIGHTDATA_LINK_WEB
from clearfront.corroboration import CorroborationLedger
from clearfront.utils import is_internal_url
from clearfront.tool_cache import ToolCache
from clearfront.tools.generate_dorks import run_dork_osint
from clearfront.tools.scrape_url import run_scrape_url_osint
from clearfront.tools.search_breach import run_breach_osint
from clearfront.tools.search_censys import run_censys_osint
from clearfront.tools.search_domain import run_domain_osint
from clearfront.tools.search_crt import run_crt_osint
from clearfront.tools.search_wayback import run_wayback_osint
from clearfront.tools.search_greynoise import run_greynoise_osint
from clearfront.tools.search_hudsonrock import run_hudsonrock_osint
from clearfront.tools.search_exif import run_exif_osint
from clearfront.tools.search_dorks_live import run_dorks_live_osint
from clearfront.tools.search_email import run_email_osint
from clearfront.tools.search_gravatar import run_gravatar_osint
from clearfront.tools.search_emailrep import run_emailrep_osint
from clearfront.tools.search_crypto import run_crypto_osint
from clearfront.tools.search_harvester import run_harvester_osint
from clearfront.tools.search_exposure import run_exposure_osint
from clearfront.tools.search_ip import run_ip_osint
from clearfront.tools.search_ip2location import run_ip2location_osint
from clearfront.tools.search_paste import run_paste_osint
from clearfront.tools.search_phone import run_phone_osint
from clearfront.tools.search_shodan import run_shodan_osint
from clearfront.tools.search_username import run_username_osint
from clearfront.tools.search_maigret import run_maigret_osint
from clearfront.tools.search_abuseipdb import run_abuseipdb_osint
from clearfront.tools.search_dns import run_dns_osint
from clearfront.tools.search_footprint import run_footprint_osint
from clearfront.tools.search_github import run_github_osint
from clearfront.tools.search_virustotal import run_virustotal_osint
from clearfront.tools.search_whois import run_whois_osint
from clearfront import __version__ as _VERSION
from clearfront.regexes import EMAIL_FIND_RE
_ROOT = Path(__file__).parent.parent

# Web assets: prefer the package-relative path (pip install) with project-root fallback (dev/editable)
_PACKAGE_WEB = Path(__file__).parent / "web"
_WEB_DIR = _PACKAGE_WEB if _PACKAGE_WEB.exists() else _ROOT / "web"

# Anthropic model for the web chat backend, single source of truth, also
# surfaced to the UI via /api/health so the status readout can never drift.
_CLAUDE_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6").strip()


def _pretty_model(model_id: str) -> str:
    """`claude-sonnet-4-5` -> `Claude Sonnet 4.5` (robust to model bumps)."""
    mid = (model_id or "").strip()
    if not mid.startswith("claude-"):
        return mid
    words, nums = [], []
    for part in mid.split("-"):
        (nums if part.isdigit() else words).append(part)
    label = " ".join(w.capitalize() for w in words)
    return f"{label} {'.'.join(nums)}".strip() if nums else label

# ---------------------------------------------------------------------------
# Tool catalog, drives both the REST API and the frontend sidebar
# ---------------------------------------------------------------------------

_TOOL_CATALOG: list[dict] = [
    {
        "name": "search_email",
        "description": "Enumerate accounts linked to an email via holehe.",
        "input_label": "Email address",
        "input_placeholder": "target@example.com",
        "category": "Identity",
        "icon": "📧",
        "requires_binary": ["holehe"],
        "requires_env": [],
        "binary_hints": {"holehe": "pip install holehe"},
    },
    {
        "name": "search_username",
        "description": "Enumerate and verify platforms where a username is registered, via sherlock plus a WhatsMyName subset covering modern/niche sites.",
        "input_label": "Username",
        "input_placeholder": "johndoe99",
        "category": "Identity",
        "icon": "👤",
        "requires_binary": ["sherlock"],
        "requires_env": [],
        "binary_hints": {"sherlock": "pip install sherlock-project"},
    },
    {
        "name": "search_maigret",
        "description": "Broad username discovery across 3,000+ sites via maigret (also extracts profile details).",
        "input_label": "Username",
        "input_placeholder": "johndoe99",
        "category": "Identity",
        "icon": "🕵️",
        "requires_binary": ["maigret"],
        "requires_env": [],
        "binary_hints": {"maigret": "pip install maigret"},
    },
    {
        "name": "search_breach",
        "description": "Check if an email appears in data breaches via HaveIBeenPwned.",
        "input_label": "Email address",
        "input_placeholder": "target@example.com",
        "category": "Identity",
        "icon": "🔓",
        "requires_binary": [],
        "requires_env": ["HIBP_API_KEY"],
        "env_hints": {"HIBP_API_KEY": "haveibeenpwned.com/API/Key"},
    },
    {
        "name": "search_gravatar",
        "description": "Look up an email's public Gravatar profile, avatar, display name, bio, location, and linked/verified accounts. Strong email-to-identity pivot.",
        "input_label": "Email address",
        "input_placeholder": "target@example.com",
        "category": "Identity",
        "icon": "🧑",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_emailrep",
        "description": "Email reputation and footprint summary via EmailRep.io: profiles seen, breach/credential-leak flags, suspicious/spam signals. Requires EMAILREP_API_KEY (free).",
        "input_label": "Email address",
        "input_placeholder": "target@example.com",
        "category": "Identity",
        "icon": "📨",
        "requires_binary": [],
        "requires_env": ["EMAILREP_API_KEY"],
        "env_hints": {"EMAILREP_API_KEY": "emailrep.io/free"},
    },
    {
        "name": "search_crypto",
        "description": "Validate a Bitcoin or Ethereum address and return a keyless on-chain summary (balance, transactions, total received).",
        "input_label": "BTC/ETH address",
        "input_placeholder": "bc1q... or 0x...",
        "category": "Recon",
        "icon": "🪙",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_ip",
        "description": "Retrieve geolocation and ASN data for an IP address via ipinfo.io.",
        "input_label": "IP address",
        "input_placeholder": "8.8.8.8",
        "category": "Network",
        "icon": "🌐",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_exposure",
        "description": "Risk-ranked exposure report for an IP, geolocation, reverse-DNS, blocklists, VPN/Tor flags. Leave blank to check your own public IP.",
        "input_label": "IP address (blank = your own)",
        "input_placeholder": "leave blank for your own IP",
        "category": "Network",
        "icon": "🚨",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_whois",
        "description": "Retrieve WHOIS registration data for a domain.",
        "input_label": "Domain",
        "input_placeholder": "example.com",
        "category": "Network",
        "icon": "🔍",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_domain",
        "description": "Enumerate subdomains of a target domain via sublist3r.",
        "input_label": "Domain",
        "input_placeholder": "example.com",
        "category": "Network",
        "icon": "🗺️",
        "requires_binary": ["sublist3r"],
        "requires_env": [],
        "binary_hints": {"sublist3r": "pip install sublist3r"},
    },
    {
        "name": "search_crt",
        "description": "Enumerate subdomains from certificate transparency logs via crt.sh. Keyless, passive, surfaces internal/staging hosts sublist3r misses.",
        "input_label": "Domain",
        "input_placeholder": "example.com",
        "category": "Network",
        "icon": "📜",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_wayback",
        "description": "List URLs archived under a domain in the Internet Archive (Wayback Machine). Keyless, passive; recovers deleted or historical pages.",
        "input_label": "Domain",
        "input_placeholder": "example.com",
        "category": "Network",
        "icon": "🏛️",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_greynoise",
        "description": "Check an IP against GreyNoise: internet background noise (mass scanner) vs. targeted actor. Community tier is free (50/week).",
        "input_label": "IP address",
        "input_placeholder": "8.8.8.8",
        "category": "Network",
        "icon": "📡",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_hudsonrock",
        "description": "Check whether an email or username appears in Hudson Rock's free infostealer index (malware-stolen credentials). Reports exposure + infection metadata; never returns passwords. Authorized-use only.",
        "input_label": "Email or username",
        "input_placeholder": "you@example.com",
        "category": "Identity",
        "icon": "🦠",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_harvester",
        "description": "Passive organisation/domain recon via theHarvester: emails, people, and subdomains aggregated from public sources. Passive only, no active probing.",
        "input_label": "Domain",
        "input_placeholder": "example.com",
        "category": "Network",
        "icon": "🌾",
        "requires_binary": ["theHarvester"],
        "requires_env": [],
        "binary_hints": {"theHarvester": "pip install git+https://github.com/laramies/theHarvester.git"},
    },
    {
        "name": "search_exif",
        "description": "Extract embedded metadata (EXIF/GPS/author) from a local file via exiftool.",
        "input_label": "File path",
        "input_placeholder": "/path/to/photo.jpg",
        "category": "Recon",
        "icon": "📷",
        "requires_binary": ["exiftool"],
        "requires_env": [],
        "binary_hints": {"exiftool": "brew install exiftool"},
    },
    {
        "name": "search_ip2location",
        "description": "Enhanced IP intelligence: geolocation, ISP, VPN/Proxy/Tor detection.",
        "input_label": "IP address",
        "input_placeholder": "8.8.8.8",
        "category": "Network",
        "icon": "📍",
        "requires_binary": [],
        "requires_env": ["IP2LOCATION_API_KEY"],
        "env_hints": {"IP2LOCATION_API_KEY": "ip2location.io/pricing"},
    },
    {
        "name": "generate_dorks",
        "description": "Generate targeted Google dork URLs for any target.",
        "input_label": "Target (name, email, username, domain)",
        "input_placeholder": "john doe",
        "category": "Recon",
        "icon": "🔎",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_paste",
        "description": "Search public paste sites for an email or username (HIBP paste index + search-engine dorking).",
        "input_label": "Email or username",
        "input_placeholder": "target@example.com",
        "category": "Recon",
        "icon": "📋",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_phone",
        "description": "Gather carrier and geolocation data for a phone number.",
        "input_label": "Phone number (E.164 format)",
        "input_placeholder": "+14155552671",
        "category": "Recon",
        "icon": "📱",
        "requires_binary": ["phoneinfoga"],
        "requires_env": [],
        "binary_hints": {"phoneinfoga": "github.com/sundowndev/phoneinfoga/releases"},
    },
    {
        "name": "search_censys",
        "description": "Search Censys for internet-facing infrastructure data.",
        "input_label": "IP address or domain",
        "input_placeholder": "example.com",
        "category": "Recon",
        "icon": "🔭",
        "requires_binary": [],
        "requires_env": ["CENSYS_PAT"],
        "env_hints": {
            "CENSYS_PAT": "accounts.censys.io → Personal Access Tokens",
        },
    },
    {
        "name": "search_shodan",
        "description": "Query Shodan for host intelligence or banner search.",
        "input_label": "IP address or search query",
        "input_placeholder": "8.8.8.8",
        "category": "Recon",
        "icon": "🛡️",
        "requires_binary": [],
        "requires_env": ["SHODAN_API_KEY"],
        "env_hints": {"SHODAN_API_KEY": "account.shodan.io"},
    },
    {
        "name": "search_virustotal",
        "description": "Check IP, domain, URL, or file hash against VirusTotal.",
        "input_label": "IP, domain, URL, or file hash",
        "input_placeholder": "8.8.8.8",
        "category": "Recon",
        "icon": "🦠",
        "requires_binary": [],
        "requires_env": ["VIRUSTOTAL_API_KEY"],
        "env_hints": {"VIRUSTOTAL_API_KEY": "virustotal.com/gui/my-apikey"},
    },
    {
        "name": "search_dorks_live",
        "description": (
            "Execute live Google dork searches via Bright Data SERP API. "
            "Returns structured results (title, URL, snippet) for each dork query."
        ),
        "input_label": "Target (name, email, username, domain)",
        "input_placeholder": "john doe",
        "category": "Recon",
        "icon": "🔎",
        "requires_binary": [],
        "requires_env": ["BRIGHTDATA_API_KEY", "BRIGHTDATA_SERP_ZONE"],
        "env_hints": {
            "BRIGHTDATA_API_KEY": BRIGHTDATA_LINK_WEB,
            "BRIGHTDATA_SERP_ZONE": "Your Bright Data SERP zone name",
        },
    },
    {
        "name": "scrape_url",
        "description": (
            "Fetch any public URL via Bright Data Web Unlocker, bypassing Cloudflare/CAPTCHA. "
            "Returns clean Markdown."
        ),
        "input_label": "URL to fetch",
        "input_placeholder": "https://example.com",
        "category": "Recon",
        "icon": "🌍",
        "requires_binary": [],
        "requires_env": ["BRIGHTDATA_API_KEY", "BRIGHTDATA_UNLOCKER_ZONE"],
        "env_hints": {
            "BRIGHTDATA_API_KEY": BRIGHTDATA_LINK_WEB,
            "BRIGHTDATA_UNLOCKER_ZONE": "Your Bright Data Web Unlocker zone name",
        },
    },
    {
        "name": "search_footprint",
        "description": (
            "Find a target's real public profiles by searching the web (entity-type-aware: "
            "email, username, domain, phone, full name). Free via DuckDuckGo; uses Bright Data "
            "SERP (Google) automatically if configured."
        ),
        "input_label": "Target (email, username, domain, phone, or full name)",
        "input_placeholder": "john doe",
        "category": "Recon",
        "icon": "👣",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_dns",
        "description": "Enumerate DNS records (A/MX/NS/TXT/CNAME/SOA) and flag SPF/DMARC/DKIM email-security gaps.",
        "input_label": "Domain",
        "input_placeholder": "example.com",
        "category": "Network",
        "icon": "📡",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_github",
        "description": "Retrieve GitHub profile, repos, and commit-discovered emails for a username. With GITHUB_TOKEN, also searches public code for exposed secrets/keys tied to the target.",
        "input_label": "GitHub username or handle",
        "input_placeholder": "octocat",
        "category": "Identity",
        "icon": "🐙",
        "requires_binary": [],
        "requires_env": [],
    },
    {
        "name": "search_abuseipdb",
        "description": "Check an IP's abuse reputation (confidence score, recent reports) via AbuseIPDB.",
        "input_label": "IP address",
        "input_placeholder": "8.8.8.8",
        "category": "Network",
        "icon": "🚫",
        "requires_binary": [],
        "requires_env": ["ABUSEIPDB_API_KEY"],
        "env_hints": {"ABUSEIPDB_API_KEY": "abuseipdb.com/account/api"},
    },
]

# Map tool name → async callable(input_value: str, timeout: int) -> str
_RUNNERS: dict[str, object] = {
    "search_email": lambda v, t: run_email_osint(v, timeout_seconds=t),
    "search_username": lambda v, t: run_username_osint(v, timeout_seconds=t),
    "search_maigret": lambda v, t: run_maigret_osint(v, timeout_seconds=t),
    "search_breach": lambda v, t: run_breach_osint(v, timeout_seconds=t),
    "search_gravatar": lambda v, t: run_gravatar_osint(v, timeout_seconds=t),
    "search_emailrep": lambda v, t: run_emailrep_osint(v, timeout_seconds=t),
    "search_crypto": lambda v, t: run_crypto_osint(v, timeout_seconds=t),
    "search_harvester": lambda v, t: run_harvester_osint(v, timeout_seconds=t),
    "search_whois": lambda v, t: run_whois_osint(v, timeout_seconds=t),
    "search_ip": lambda v, t: run_ip_osint(v, timeout_seconds=t),
    "search_exposure": lambda v, t: run_exposure_osint(v, timeout_seconds=t),
    "search_domain": lambda v, t: run_domain_osint(v, timeout_seconds=t),
    "search_crt": lambda v, t: run_crt_osint(v, timeout_seconds=t),
    "search_wayback": lambda v, t: run_wayback_osint(v, timeout_seconds=t),
    "search_greynoise": lambda v, t: run_greynoise_osint(v, timeout_seconds=t),
    "search_hudsonrock": lambda v, t: run_hudsonrock_osint(v, timeout_seconds=t),
    "search_exif": lambda v, t: run_exif_osint(v, timeout_seconds=t),
    "search_ip2location": lambda v, t: run_ip2location_osint(v, timeout_seconds=t),
    "generate_dorks": lambda v, _t: run_dork_osint(v),
    "search_paste": lambda v, t: run_paste_osint(v, timeout_seconds=t),
    "search_phone": lambda v, t: run_phone_osint(v, timeout_seconds=t),
    "search_shodan": lambda v, t: run_shodan_osint(v, timeout_seconds=t),
    "search_virustotal": lambda v, t: run_virustotal_osint(v, timeout_seconds=t),
    "search_censys": lambda v, t: run_censys_osint(v, timeout_seconds=t),
    "search_dorks_live": lambda v, t: run_dorks_live_osint(v, timeout_seconds=t),
    "scrape_url": lambda v, t: run_scrape_url_osint(v, timeout_seconds=t),
    "search_footprint": lambda v, t: run_footprint_osint(v, timeout_seconds=t),
    "search_dns": lambda v, t: run_dns_osint(v, timeout_seconds=t),
    "search_github": lambda v, t: run_github_osint(v, timeout_seconds=t),
    "search_abuseipdb": lambda v, t: run_abuseipdb_osint(v, timeout_seconds=t),
}

# Claude tool schemas (one string "input" param per tool)
# Tools that auto-detect the caller's own public IP when called with no input
# (self-lookup). For these, an empty input is valid, not an error.
_SELF_LOOKUP_TOOLS = {"search_ip", "search_exposure"}

_CLAUDE_TOOLS: list[dict] = [
    {
        "name": meta["name"],
        "description": meta["description"],
        "input_schema": {
            "type": "object",
            "properties": {
                "input": {
                    "type": "string",
                    "description": f"{meta['input_label']}, e.g. {meta['input_placeholder']}",
                }
            },
            # Self-lookup tools accept no input (they detect the caller's own IP).
            "required": [] if meta["name"] in _SELF_LOOKUP_TOOLS else ["input"],
        },
    }
    for meta in _TOOL_CATALOG
]


def _check_available(meta: dict) -> tuple[bool, str | None]:
    """Return (is_available, reason_if_not) for a tool."""
    for binary in meta.get("requires_binary", []):
        if not shutil.which(binary):
            hint = meta.get("binary_hints", {}).get(binary, f"install {binary}")
            return False, f"{binary} not in PATH, {hint}"
    for key in meta.get("requires_env", []):
        if not os.environ.get(key, "").strip():
            hint = meta.get("env_hints", {}).get(key, "")
            suffix = f", {hint}" if hint else ""
            return False, f"{key} not set{suffix}"
    return True, None


_KNOWN_ENV_KEYS = [
    "ANTHROPIC_API_KEY",
    "HIBP_API_KEY",
    "IPINFO_TOKEN",
    "IP2LOCATION_API_KEY",
    "CENSYS_PAT",
    "CENSYS_ORG_ID",
    "SHODAN_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "BRIGHTDATA_API_KEY",
    "BRIGHTDATA_SERP_ZONE",
    "BRIGHTDATA_UNLOCKER_ZONE",
]


def _is_setup_complete() -> bool:
    if (_ROOT / ".env").exists():
        return True
    return any(os.environ.get(k, "").strip() for k in _KNOWN_ENV_KEYS)


# ---------------------------------------------------------------------------
# Network-exposure hardening
#
# The console has no authentication by design: on the default 127.0.0.1 bind the
# only client is the local operator, so arbitrary local-file tools and localhost
# AI backends are a feature, not a risk. When the server is bound to a
# non-loopback address (the Docker image binds 0.0.0.0), untrusted network
# clients can reach it, so a few endpoints must refuse dangerous inputs.
# _PUBLIC_BIND records that mode; the entry points set it from the bind host.
# ---------------------------------------------------------------------------

_PUBLIC_BIND = False

_URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)

# Keys the Settings panel may persist via POST /api/setup. Anything else in the
# request body is ignored, so a caller cannot write arbitrary environment
# variables (e.g. PATH, LD_PRELOAD) into the server's .env.
_SETTABLE_ENV_KEYS = frozenset(_KNOWN_ENV_KEYS) | {
    "OPENAI_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "OLLAMA_HOST",
    "OLLAMA_MODEL",
    "GOOGLE_MAPS_API_KEY",
    "SERPER_API_KEY",
    "EMAILREP_API_KEY",
    "GITHUB_TOKEN",
}

# Tools that read the server's local filesystem. A feature for the local
# CLI/REPL user, but never reachable from a network-exposed console.
_LOCAL_FILE_TOOLS = frozenset({"search_exif"})

# Upper bound on the Markdown a single /api/report/export request may render, so
# one unauthenticated call cannot pin a PDF worker on a huge document.
_MAX_REPORT_MARKDOWN = 512 * 1024


def _set_public_bind(host: str) -> None:
    """Record whether the server is bound to a network-reachable address."""
    global _PUBLIC_BIND
    _PUBLIC_BIND = host not in ("127.0.0.1", "localhost", "")


def _reject_backend_url(url: str) -> str | None:
    """Validate a request-supplied AI-backend URL (OpenAI-compatible base or
    Ollama host). Returns an error string if it must be refused, else None.

    Always requires an http(s) scheme. On a network-exposed bind it also refuses
    internal/loopback/private/metadata targets (SSRF protection). On the default
    local bind the operator may legitimately point at their own localhost
    Ollama/LiteLLM, so internal addresses are allowed there.
    """
    url = (url or "").strip()
    if not url:
        return None
    if not _URL_SCHEME_RE.match(url):
        return "backend URL must start with http:// or https://"
    if _PUBLIC_BIND and is_internal_url(url):
        return "refusing an internal/private backend address (SSRF protection)"
    return None


def _blocked_local_tool(tool_name: str) -> str | None:
    """Return an error string if tool_name reads local files and the server is
    network-exposed; else None."""
    if _PUBLIC_BIND and tool_name in _LOCAL_FILE_TOOLS:
        return (
            f"{tool_name} is disabled on a network-exposed server because it reads "
            "local files. Run the console on 127.0.0.1 to use it."
        )
    return None


def _get_ai_backend() -> tuple[str, str | None, bool | None]:
    """Return (backend_name, ollama_host, ollama_reachable)."""
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return "claude", None, None
    # An OpenAI-compatible endpoint (LiteLLM, llama-swap, vLLM, …) takes
    # precedence over Ollama when configured.
    if os.environ.get("OPENAI_BASE_URL", "").strip():
        return "openai", None, None
    ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        resp = _requests.get(f"{ollama_host}/api/tags", timeout=2)
        reachable = resp.status_code == 200
    except Exception:
        reachable = False
    return ("ollama" if reachable else "none"), ollama_host, reachable


async def _probe_openai_endpoint(base_url: str, api_key: str) -> dict:
    """Probe an OpenAI-compatible endpoint server-side (no browser CORS / mixed-content).

    Distinguishes three states so the UI can give an accurate message:
      * unreachable     , connection failed / refused / timed out
      * reachable + auth_ok=False, server answered but rejected the key (401/403)
      * reachable + auth_ok=True , server answered and accepted the key

    A 401/403 still means the endpoint is *up* and usable once a valid key is
    supplied, so we must not report it as "not configured / unreachable", that
    was the old bug where a healthy LiteLLM/vLLM proxy showed as backend "none".
    """
    base = base_url.strip().rstrip("/")
    if not base:
        return {"reachable": False, "auth_ok": False, "status_code": None}
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        if _httpx is not None:
            async with _httpx.AsyncClient(timeout=2.5) as client:
                r = await client.get(f"{base}/models", headers=headers)
                status = r.status_code
        else:
            raw = await asyncio.to_thread(
                lambda: _requests.get(f"{base}/models", headers=headers, timeout=2.5)
            )
            status = raw.status_code
    except Exception:
        return {"reachable": False, "auth_ok": False, "status_code": None}
    return {
        "reachable": True,
        "auth_ok": status == 200,
        "status_code": status,
    }


class RunRequest(BaseModel):
    input: str
    timeout: int = 120


class ChatRequest(BaseModel):
    message: str
    history: list[dict] = []
    model: str = "claude"
    depth: str = "deeper"
    ollama_model: str = "llama3.2"
    ollama_host: str = "http://localhost:11434"
    openai_base_url: str = ""
    openai_model: str = ""
    openai_api_key: str = ""


class ReportExportRequest(BaseModel):
    """Body for POST /api/report/export. ``markdown`` is the user's own report
    text already rendered in the browser; ``title`` becomes the file name."""

    markdown: str
    title: str = "clearfront-report"


class GraphExportRequest(BaseModel):
    """Body for POST /api/graph/export. ``graph`` is the D3 node-link evidence
    graph already rendered in the browser; the endpoint only reformats it (no new
    collection). ``format`` is graphml | json | mermaid; ``title`` becomes the file name."""

    graph: dict
    format: str = "graphml"
    title: str = "clearfront-graph"


class OpenAITestRequest(BaseModel):
    """Body for POST /api/openai/test, all fields optional; blanks fall back
    to the server's OPENAI_BASE_URL / OPENAI_API_KEY env vars."""

    openai_base_url: str = ""
    openai_api_key: str = ""


def _select_chat_backend(req: "ChatRequest") -> str:
    """Resolve which AI backend to use for a chat request: openai | ollama | claude."""
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    openai_base = (req.openai_base_url or os.environ.get("OPENAI_BASE_URL", "")).strip()

    # Explicit selection from the UI takes priority.
    if req.model == "openai":
        return "openai"
    if req.model == "ollama":
        return "ollama"
    if req.model == "claude" and has_anthropic:
        return "claude"

    # Auto-detect when no explicit, usable selection was made.
    if has_anthropic:
        return "claude"
    if openai_base:
        return "openai"
    if req.ollama_host:
        return "ollama"
    return "claude"


# ---------------------------------------------------------------------------
# AI chat streaming helpers
# ---------------------------------------------------------------------------


async def _run_tool(
    tool_name: str,
    tool_input: str,
    timeout: int = 120,
    cache: ToolCache | None = None,
    ledger: CorroborationLedger | None = None,
) -> str:
    if tool_name not in _RUNNERS:
        return f"Unknown tool: {tool_name}"
    blocked = _blocked_local_tool(tool_name)
    if blocked:
        return f"Error: {blocked}"
    if not str(tool_input).strip() and tool_name not in _SELF_LOOKUP_TOOLS:
        return (
            f"Tool call error: 'input' is required for {tool_name} but was not provided. "
            "Retry with the target value as the 'input' parameter."
        )

    async def _invoke() -> str:
        try:
            return await _RUNNERS[tool_name](tool_input, timeout)
        except Exception as exc:
            return f"Error: {exc}"

    if cache is None:
        result = await _invoke()
    else:
        result, _was_cached = await cache.run(tool_name, tool_input, _invoke)
    if ledger is not None:
        # Additive only: appends a corroboration note, never alters the raw output.
        result = result + ledger.note(tool_name, result)
    return result


# Dedicated evidence-graph extractor. The graph is generated in its own pass after the
# report, so it is never truncated by the report's token budget and can include every
# entity the investigation surfaced (the inline approach dropped or trimmed it on long runs).
_GRAPH_SYSTEM_PROMPT = (
    "You build the evidence graph for an OSINT investigation. You are given the tool outputs "
    "and the analyst report. Output ONLY one fenced code block labelled graph containing JSON, "
    "and nothing else: no prose, no preamble, no trailing text.\n"
    "Shape: {\"nodes\":[{\"id\":\"unique-id\",\"label\":\"short label\",\"type\":\"SUBJECT|"
    "ACCOUNT|EMAIL|IP|ASN|HOSTNAME|DOMAIN|BREACH|PASTE|COMPANY|PERSON|PHONE\",\"value\":\"full "
    "value\",\"source\":\"tool name\",\"confidence\":\"verified|candidate|high|moderate|low\","
    "\"severity\":\"risk|watch|\"}],\"links\":[{\"source\":\"id-a\",\"target\":\"id-b\"}]}\n"
    "COMPLETENESS IS MANDATORY. Include EVERY distinct entity that appears anywhere in the tool "
    "outputs or the report: the subject, every account or profile, every email, every breach, "
    "every paste, every domain, every company, every real name, every phone, every IP/ASN/"
    "hostname. If the report names it, it MUST be a node. Give each distinct entity its own node; "
    "never group, merge, or collapse several accounts into one. Never summarise or omit entities.\n"
    "Build a dense connected web, not a star. Route links through shared pivots: link accounts to "
    "the email or identity they belong to, link each breach and paste to that email, link a domain "
    "to its registrant and company, link a company to the subject. A shared email, domain, company, "
    "or real name becomes a hub. Do not link everything only to the subject. Maximise defensible "
    "connections: link any two entities the evidence ties together (a shared email, real name, "
    "handle, domain, or company, or co-occurrence in the same source or profile), not only links "
    "back to a central pivot. Aim for a dense Obsidian-style mesh where well-connected hubs carry "
    "many edges, so the user can see how their whole footprint interconnects.\n"
    "Exactly one node has type SUBJECT (the seed target). Add every link the evidence supports, but "
    "never invent one it does not. severity is 'risk' for breaches and confirmed exposures, 'watch' "
    "for watchpoints, empty otherwise.\n"
    "Emit the JSON as compact, single-line JSON: no indentation, no newlines inside the JSON, "
    "no spaces after commas or colons. A compact graph stays well within the token budget so it "
    "is never truncated.\n"
    "Emit exactly: three backticks, the word graph, a newline, the compact JSON on one line, a "
    "newline, three backticks. Output nothing before or after the block."
)


# ---------------------------------------------------------------------------
# Sweep depth: how far the analyst fans out per investigation. It trades collection
# breadth (number of tool rounds) and the matching enrichment instruction, never the
# analyst's reasoning or output quality. "deeper" is the full default fan-out and is
# byte-identical to the historical prompt (no mode preamble, unchanged enrichment
# clause); "balanced" and "faster" run fewer rounds with a softened enrichment clause
# so the report reads deliberate, not truncated at the cap. The Deeper ceiling stays
# env-tunable via OIS_MAX_TOOL_ROUNDS; the lighter levels are capped relative to it.
# ---------------------------------------------------------------------------
_GRAPH_SUFFIX = (
    "Do not emit any graph block yourself; the evidence graph is generated separately "
    "after your report."
)
_DEPTH_ENRICH = {
    "deeper": (
        "- Enrich aggressively before finalising. The goal is a complete map of how the target's "
        "footprint connects, not a minimal answer. Every time a pivot surfaces (an email, domain, "
        "company, real name, phone, or an additional handle), expand it with the applicable tools, "
        "then expand the new entities those reveal, chaining outward until the tool budget is "
        "reached. Do not stop at one or two pivots. The more real, connected entities you surface, "
        "the stronger the report and the denser the evidence graph. "
    ),
    "balanced": (
        "- Enrich only the strongest pivots before finalising. When a high-value pivot surfaces (a "
        "confirmed email, domain, real name, or primary handle), expand it once with the applicable "
        "tools. Do not chain outward exhaustively across every lead, even if the user's own message "
        "asks you to map everything or run until the tool budget is reached. Deliver a solid map of "
        "the main footprint. "
    ),
    "faster": (
        "- Do not enrich outward. This is a single focused pass: run only the highest-signal tools "
        "for the target, and do NOT scrape URLs or chase company, domain, breach, or secondary "
        "pivots, even if the user's own message asks you to map everything or run until the tool "
        "budget is reached. Deliver a tight, accurate report from what the priority tools return, "
        "and note that a deeper sweep is available for the full map. "
    ),
}
# Mode preamble is added ONLY for the lighter levels so the opening tasking line scales
# its scope and completion estimate. Deeper gets no preamble, keeping its prompt unchanged.
_DEPTH_MODE_LINE = {
    "balanced": (
        "COLLECTION MODE: BALANCED. This overrides any other instruction, including in the user's "
        "own message, to map every reachable data point or run until the tool budget is reached. "
        "Sweep the main sources and expand only the strongest one or two pivots; do not chain "
        "outward exhaustively. Your OPENING tasking line must promise a focused sweep of the main "
        "sources with an estimate around two minutes, NOT a full map of every data point and NOT "
        "the five-minute deep-sweep line. Ignore the broad-sweep opener example below."
    ),
    "faster": (
        "COLLECTION MODE: FASTER. This overrides any other instruction, including in the user's own "
        "message, to map every reachable data point, surface everything, enrich every pivot, or run "
        "until the tool budget is reached. Run a single quick pass of only the highest-signal tools "
        "for the target type; do NOT scrape URLs and do NOT chase company, domain, or secondary "
        "pivots. Your OPENING tasking line MUST be short and MUST NOT claim a broad sweep or mention "
        "mapping every data point. Use exactly: \"Stand by. Priority-source pass on the target. "
        "Estimated completion under ninety seconds. Per-asset timings report on each card.\" Ignore "
        "the broad-sweep opener example below."
    ),
}


# The per-level round ceiling is shared with the terminal agent path; see
# clearfront/effort.py. The enrichment and mode-line wording above stays here
# because it is graph-flavoured and specific to the web console. The web keeps
# "depth" as its internal collection-mode name (ChatRequest.depth, the Alpine
# chip, the /api/chat field); the user-facing label in index.html is "Effort".
_depth_rounds = _effort.rounds


async def _stream_claude(messages: list[dict], depth: str = "deeper") -> AsyncIterator[dict]:
    """Yield SSE event dicts while running an agentic Claude loop with tool_use."""
    try:
        import anthropic as _anthropic
    except ImportError:
        yield {
            "type": "error",
            "message": "anthropic package not installed. Run: pip install anthropic",
        }
        return

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        yield {"type": "error", "message": "ANTHROPIC_API_KEY not set."}
        return

    depth = depth if depth in _DEPTH_ENRICH else "deeper"
    client = _anthropic.AsyncAnthropic(api_key=api_key)
    msgs = list(messages)
    # Tool-calling rounds drive how far the analyst fans out across pivots, which is what
    # makes the evidence graph dense (more enriched entities = more nodes and connectors).
    # Scaled by the selected sweep depth; the Deeper ceiling stays env-tunable.
    _MAX_TOOL_ROUNDS = _depth_rounds(depth)
    _tool_rounds = 0
    tool_ran = False
    # Memoize (tool, args) for this one investigation so the multi-round loop does not
    # re-hit the same tool with the same target. Scoped to this request only.
    tool_cache = ToolCache()
    # Cross-tool corroboration for this one investigation (additive notes only).
    corroboration_ledger = CorroborationLedger()

    # Deeper gets no preamble (prompt unchanged); lighter levels get a mode line up top.
    _preamble = f"{_DEPTH_MODE_LINE[depth]}\n\n" if depth in _DEPTH_MODE_LINE else ""
    system_prompt = _preamble + (
        "You are CLEARFRONT, an open-source intelligence (OSINT) analyst. You write to the analytic "
        "tradecraft of the intelligence community, the standard behind platforms like Palantir "
        "Gotham. When the user gives a target, use the available tools to gather intelligence, then "
        "deliver one structured intelligence report.\n\n"
        "TASKING ACKNOWLEDGMENT (your FIRST reply once a target is provided, before any tool runs):\n"
        "- Open with one short tasking line in a militarised security-analyst register, then an "
        "estimated completion time, then note that per-tool timings appear on each card. Scale BOTH "
        "the wording and the time to the ACTUAL scope of the target. Never claim a broad sweep "
        "'mapping every reachable data point' for a narrow single lookup, or it will read wrong.\n"
        "- Clean time units only: seconds under two minutes, minutes above. Calibrate by target type:\n"
        "    Username, full name, or email (broad multi-source sweep): \"Stand by. All collection "
        "assets tasked in parallel. Given the scale of the sweep and mapping every reachable data "
        "point on the target, intelligence report complete NLT five minutes. Per-asset timings report "
        "on each card as they clear.\"\n"
        "    Domain: \"Stand by. Tasking domain, DNS, and infrastructure assets. Estimated completion: "
        "two to three minutes. Per-asset timings report on each card.\"\n"
        "    Phone: \"Stand by. Tasking number intelligence and exposure checks. ECT approximately "
        "ninety seconds. Per-asset timings report on each card.\"\n"
        "    IP or a single quick lookup: \"Stand by. Tasking IP intelligence and geolocation. "
        "Estimated completion under sixty seconds. Per-asset timings report on each card.\"\n"
        "- Use this militarised register ONLY for this one opening line. Do not repeat the completion "
        "estimate in later updates, and write the report itself in the analytic register below.\n\n"
        "VOICE AND TRADECRAFT (follow exactly):\n"
        "- Register: professional intelligence analyst. Declarative, objective, concise, active "
        "voice. No marketing, no hype, no first person, no conversational filler.\n"
        "- Bottom line up front. The INTELLIGENCE SUMMARY is a key judgment: state the headline "
        "assessment first, then support it.\n"
        "- Express likelihood ONLY with these seven calibrated terms, never vague hedges such as "
        "'might', 'could', or 'maybe': almost no chance, very unlikely, unlikely, roughly even "
        "chance, likely, very likely, almost certainly. Do not invent percentages; cite a number "
        "only if a tool returned it.\n"
        "- State analytic confidence separately as high, moderate, or low, and give its basis (the "
        "quality and quantity of sourcing). Confidence is your certainty in the judgment, not the "
        "likelihood of the event. Keep the two distinct.\n"
        "- Distinguish observed data from assessment. Report what the tools returned as fact; label "
        "inferences with 'Assessment:'. Never present a judgment as if it were collected data.\n"
        "- Describe source reliability per finding: URL-verified is high, a name-only match is low, "
        "indexed data is moderate and not a live result.\n"
        "- Do not overclaim. A name match is a candidate, not a confirmed identity. Where evidence is "
        "thin, say so and offer a plausible alternative explanation.\n"
        "- Never use em dashes or en dashes. Use periods, commas, or colons. Use the hyphen only for "
        "list bullets and compound words.\n"
        "- Apply this register to short conversational answers too, not only full reports. When no "
        "tool is needed, reply in two or three terse analyst sentences under the same rules.\n\n"
        "FORMAT RULES (follow exactly):\n"
        "- Never use emojis, icons, or decorative symbols (no check marks, warning signs, "
        "magnifying glasses, stars, arrows). Plain text only.\n"
        "- No conversational preamble or sign-off. Do not write 'I'll investigate' or 'Let me know'. "
        "Output the report directly.\n"
        "- Report only what the tools returned; never invent data; mark gaps as 'Not available'.\n"
        "- Structure the report with these markdown headers (use '## '), in this order, omitting "
        "any section with no data:\n"
        "    ## INTELLIGENCE SUMMARY\n"
        "    ## SUBJECT\n"
        "    ## PLATFORM PRESENCE\n"
        "    ## KEY FINDINGS\n"
        "    ## SOURCES\n"
        "    ## RECOMMENDED NEXT STEPS\n"
        "- INTELLIGENCE SUMMARY: one to three sentences. Key judgment first, then the supporting "
        "assessment, then a confidence statement with its basis.\n"
        "- PLATFORM PRESENCE: one account per line as '- Platform: https://url (verified or "
        "candidate)'.\n"
        "- KEY FINDINGS: single-line '- ' bullets, one observation each, separating observed data "
        "from assessment.\n"
        "- SOURCES: one '- ' bullet per tool used, its outcome, and a reliability note, e.g. "
        "'- Sherlock: 8 accounts verified. Reliability: high.', "
        "'- Pastebin: unavailable (network error).'\n"
        "- Use '- ' for every bullet. Never leave a blank line between consecutive bullets.\n\n"
        + _DEPTH_ENRICH[depth]
        + _GRAPH_SUFFIX
    )

    while True:
        _tool_rounds += 1
        # When the budget is exhausted, do not error out (that used to abort with no graph at
        # all). Instead make this a final turn that forbids further tool calls, so the model
        # writes its report from the evidence gathered and the run still flows into the graph
        # pass below.
        force_final = _tool_rounds > _MAX_TOOL_ROUNDS
        full_content: list[dict] = []
        pending_tool_results: list[dict] = []
        current_block: dict | None = None
        current_tool_json = ""
        stop_reason = "end_turn"

        try:
            async with client.messages.stream(
                model=_CLAUDE_MODEL,
                max_tokens=4096,
                # Prompt caching: a breakpoint on the (single) system block caches the
                # system prompt + all tool definitions together (tools render before
                # system), so that large stable prefix is re-billed at ~0.1x on every
                # round instead of full price. Top-level cache_control auto-places a
                # second breakpoint on the last message block, so the growing tool-output
                # history is cached incrementally across rounds. Caching changes billing
                # only; the model sees identical content and produces identical output.
                system=[
                    {
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                tools=_CLAUDE_TOOLS,
                tool_choice={"type": "none"} if force_final else {"type": "auto"},
                messages=msgs,
                cache_control={"type": "ephemeral"},
            ) as stream:
                async for event in stream:
                    etype = event.type

                    if etype == "content_block_start":
                        cb = event.content_block
                        if cb.type == "text":
                            current_block = {"type": "text", "text": ""}
                            full_content.append(current_block)
                        elif cb.type == "tool_use":
                            current_block = {
                                "type": "tool_use",
                                "id": cb.id,
                                "name": cb.name,
                                "input": {},
                            }
                            current_tool_json = ""
                            full_content.append(current_block)

                    elif etype == "content_block_delta":
                        d = event.delta
                        if (
                            d.type == "text_delta"
                            and current_block
                            and current_block["type"] == "text"
                        ):
                            current_block["text"] += d.text
                            yield {"type": "text", "content": d.text}
                        elif d.type == "input_json_delta":
                            current_tool_json += d.partial_json

                    elif etype == "content_block_stop":
                        if current_block and current_block["type"] == "tool_use":
                            try:
                                input_data = (
                                    json.loads(current_tool_json) if current_tool_json else {}
                                )
                            except Exception:
                                input_data = {"input": current_tool_json}
                            current_block["input"] = input_data

                            tool_name = current_block["name"]
                            tool_input = input_data.get("input", "")
                            if not tool_input and input_data:
                                tool_input = next(
                                    (v for v in input_data.values() if isinstance(v, str)),
                                    str(input_data),
                                )

                            yield {
                                "type": "tool_start",
                                "tool": tool_name,
                                "input": str(tool_input),
                            }

                            t0 = time.monotonic()
                            result = await _run_tool(
                tool_name, str(tool_input), cache=tool_cache, ledger=corroboration_ledger
            )
                            elapsed = round(time.monotonic() - t0, 2)

                            yield {
                                "type": "tool_result",
                                "tool": tool_name,
                                "output": result,
                                "elapsed": elapsed,
                            }
                            pending_tool_results.append(
                                {
                                    "type": "tool_result",
                                    "tool_use_id": current_block["id"],
                                    "content": result,
                                }
                            )
                            tool_ran = True

                        current_block = None
                        current_tool_json = ""

                final_msg = await stream.get_final_message()
                stop_reason = final_msg.stop_reason or "end_turn"

        except Exception as exc:
            yield {"type": "error", "message": str(exc)}
            return

        if force_final or stop_reason != "tool_use" or not pending_tool_results:
            break

        msgs = msgs + [
            {"role": "assistant", "content": full_content},
            {"role": "user", "content": pending_tool_results},
        ]

    # Evidence graph: generated in a dedicated pass (its own token budget, full attention on
    # the evidence) so it is never truncated by the report and includes every entity found.
    # The frontend strips the ```graph block from the visible report and renders it as the graph.
    # max_tokens must be GENEROUS here: the prompt mandates every entity, and a large
    # investigation (40+ nodes) emitted ~3.7K tokens at the old 4096 cap, i.e. 90% of budget.
    # That tipped over into truncation on the biggest reports, leaving an unclosed/invalid JSON
    # block that the frontend correctly but silently drops, so no graph rendered at all. The cap
    # is the only thing being raised; you are billed only for tokens generated (~3-4K), so there
    # is no cost or latency change for normal runs, just headroom that prevents truncation.
    if tool_ran:
        try:
            graph_msgs = msgs + [
                {"role": "assistant", "content": full_content or "Report compiled above."},
                {
                    "role": "user",
                    "content": (
                        "Now output the evidence graph for this investigation: a single fenced "
                        "graph JSON block and nothing else, including EVERY distinct entity from "
                        "the tool outputs and the report above."
                    ),
                },
            ]
            graph_resp = await client.messages.create(
                model=_CLAUDE_MODEL,
                max_tokens=16000,
                system=_GRAPH_SYSTEM_PROMPT,
                messages=graph_msgs,
            )
            graph_text = "".join(
                b.text for b in graph_resp.content if getattr(b, "type", "") == "text"
            ).strip()
            # Only surface a complete block. A truncated graph (hit the cap) is invalid JSON the
            # frontend would drop anyway; suppressing it here keeps the intent explicit.
            if "```graph" in graph_text and graph_resp.stop_reason != "max_tokens":
                yield {"type": "text", "content": "\n\n" + graph_text}
        except Exception:
            pass  # graph is best-effort; never let it break the delivered report

    yield {"type": "done"}


async def _stream_ollama(
    messages: list[dict], ollama_host: str, ollama_model: str
) -> AsyncIterator[dict]:
    """Yield SSE event dicts using Ollama chat API with tool_use."""
    host = ollama_host.rstrip("/")
    msgs = list(messages)
    tool_cache = ToolCache()  # per-investigation memo (see _stream_claude)
    corroboration_ledger = CorroborationLedger()  # additive cross-tool notes

    ollama_tools = [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in _CLAUDE_TOOLS
    ]

    while True:
        try:
            payload = {
                "model": ollama_model,
                "messages": msgs,
                "tools": ollama_tools,
                "stream": False,
            }
            if _httpx is not None:
                async with _httpx.AsyncClient(timeout=120) as client:
                    r = await client.post(f"{host}/api/chat", json=payload)
                if r.status_code != 200:
                    yield {
                        "type": "error",
                        "message": f"Ollama returned HTTP {r.status_code}: {r.text[:200]}",
                    }
                    return
                data = r.json()
            else:
                # fallback: run blocking requests in a thread
                _payload = payload  # capture for lambda
                raw = await asyncio.to_thread(
                    lambda: _requests.post(f"{host}/api/chat", json=_payload, timeout=120)
                )
                if raw.status_code != 200:
                    yield {
                        "type": "error",
                        "message": f"Ollama returned HTTP {raw.status_code}: {raw.text[:200]}",
                    }
                    return
                data = raw.json()
        except Exception as exc:
            yield {"type": "error", "message": f"Ollama request failed: {exc}"}
            return

        msg = data.get("message", {})
        content = msg.get("content") or ""
        tool_calls = msg.get("tool_calls") or []

        if content:
            yield {"type": "text", "content": content}

        if not tool_calls:
            break

        tool_results_for_next = []
        for tc in tool_calls:
            fn = tc.get("function", {})
            tool_name = fn.get("name", "")
            raw_args = fn.get("arguments", {})
            if isinstance(raw_args, str):
                try:
                    raw_args = json.loads(raw_args)
                except Exception:
                    raw_args = {"input": raw_args}
            tool_input = raw_args.get("input", "")
            if not tool_input and raw_args:
                tool_input = next(
                    (v for v in raw_args.values() if isinstance(v, str)), str(raw_args)
                )

            yield {"type": "tool_start", "tool": tool_name, "input": str(tool_input)}

            t0 = time.monotonic()
            result = await _run_tool(
                tool_name, str(tool_input), cache=tool_cache, ledger=corroboration_ledger
            )
            elapsed = round(time.monotonic() - t0, 2)

            yield {"type": "tool_result", "tool": tool_name, "output": result, "elapsed": elapsed}
            tool_results_for_next.append({"role": "tool", "content": result})

        msgs = (
            msgs
            + [{"role": "assistant", "content": content, "tool_calls": tool_calls}]
            + tool_results_for_next
        )

    yield {"type": "done"}


async def _stream_openai(
    messages: list[dict],
    base_url: str,
    api_key: str,
    model: str,
) -> AsyncIterator[dict]:
    """Yield SSE event dicts using any OpenAI-compatible chat-completions API."""
    base = base_url.rstrip("/")
    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    msgs = list(messages)
    tool_cache = ToolCache()  # per-investigation memo (see _stream_claude)
    corroboration_ledger = CorroborationLedger()  # additive cross-tool notes

    openai_tools = [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in _CLAUDE_TOOLS
    ]

    while True:
        payload = {
            "model": model,
            "messages": msgs,
            "tools": openai_tools,
            "tool_choice": "auto",
            "stream": False,
        }
        try:
            if _httpx is not None:
                async with _httpx.AsyncClient(timeout=180) as client:
                    r = await client.post(url, json=payload, headers=headers)
                if r.status_code != 200:
                    # Do not echo the upstream response body: on a network-exposed
                    # bind this would turn a mistyped/attacker base_url into an
                    # internal-response oracle. The status code is enough to debug.
                    yield {
                        "type": "error",
                        "message": f"OpenAI endpoint returned HTTP {r.status_code}.",
                    }
                    return
                data = r.json()
            else:
                _payload = payload  # capture for lambda
                raw = await asyncio.to_thread(
                    lambda: _requests.post(url, json=_payload, headers=headers, timeout=180)
                )
                if raw.status_code != 200:
                    yield {
                        "type": "error",
                        "message": f"OpenAI endpoint returned HTTP {raw.status_code}.",
                    }
                    return
                data = raw.json()
        except Exception as exc:
            yield {"type": "error", "message": f"OpenAI request failed: {exc}"}
            return

        choices = data.get("choices") or []
        if not choices:
            yield {
                "type": "error",
                "message": f"OpenAI endpoint returned no choices: {str(data)[:300]}",
            }
            return
        msg = choices[0].get("message", {})
        content = msg.get("content") or ""
        tool_calls = msg.get("tool_calls") or []

        if content:
            yield {"type": "text", "content": content}

        if not tool_calls:
            break

        tool_results_for_next = []
        for tc in tool_calls:
            fn = tc.get("function", {})
            tool_name = fn.get("name", "")
            raw_args = fn.get("arguments", {})
            if isinstance(raw_args, str):
                try:
                    raw_args = json.loads(raw_args)
                except Exception:
                    raw_args = {"input": raw_args}
            tool_input = raw_args.get("input", "")
            if not tool_input and raw_args:
                tool_input = next(
                    (v for v in raw_args.values() if isinstance(v, str)), str(raw_args)
                )

            yield {"type": "tool_start", "tool": tool_name, "input": str(tool_input)}

            t0 = time.monotonic()
            result = await _run_tool(
                tool_name, str(tool_input), cache=tool_cache, ledger=corroboration_ledger
            )
            elapsed = round(time.monotonic() - t0, 2)

            yield {"type": "tool_result", "tool": tool_name, "output": result, "elapsed": elapsed}
            tool_results_for_next.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": result,
                }
            )

        msgs = (
            msgs
            + [{"role": "assistant", "content": content, "tool_calls": tool_calls}]
            + tool_results_for_next
        )

    yield {"type": "done"}


# ---------------------------------------------------------------------------
# Demo chat, pre-scripted SSE stream, no API key required
# ---------------------------------------------------------------------------


async def _demo_chat_stream(message: str) -> AsyncIterator[dict]:
    """Yield scripted SSE events that look like a real investigation."""

    async def stream_text(text: str) -> AsyncIterator[dict]:
        words = text.split(" ")
        for i, word in enumerate(words):
            chunk = word if i == len(words) - 1 else word + " "
            yield {"type": "text", "content": chunk}
            await asyncio.sleep(0.03)

    msg_lower = message.lower()

    # --- tools / availability query ---
    if any(kw in msg_lower for kw in ("tool", "available", "what can")):
        lines = [
            "I have **26 OSINT tools** available for investigations:\n\n",
            "**Identity:** `search_email`, `search_username`, `search_maigret`, `search_breach`, `search_gravatar`, `search_emailrep`\n\n",
            "**Network:** `search_ip`, `search_exposure`, `search_whois`, `search_domain`, `search_dns`, `search_harvester`, `search_ip2location`, `search_abuseipdb`\n\n",
            "**Recon:** `search_footprint`, `generate_dorks`, `search_dorks_live`, `scrape_url`, `search_paste`, `search_phone`, `search_shodan`, `search_virustotal`, `search_censys`, `search_github`, `search_exif`, `search_crypto`\n\n",
            "Just give me a target, email address, username, domain, or IP.",
        ]
        for line in lines:
            async for event in stream_text(line):
                yield event
        yield {"type": "done"}
        return

    # --- email investigation ---
    email_match = EMAIL_FIND_RE.search(message)
    if email_match or any(kw in msg_lower for kw in ("email", "investigate", "@")):
        email = email_match.group(0) if email_match else "demo@example.com"
        async for event in stream_text(f"Investigating **{email}**...\n\n"):
            yield event

        yield {"type": "tool_start", "tool": "search_email", "input": email}
        await asyncio.sleep(1.5)
        yield {
            "type": "tool_result",
            "tool": "search_email",
            "output": (
                "[+] Spotify       https://open.spotify.com/user/demo\n"
                "[+] GitHub        https://github.com/demo\n"
                "[+] Gravatar      https://gravatar.com/demo\n"
                "[+] WordPress     https://wordpress.com/demo\n"
                "[*] Holehe scan complete, 4 accounts found"
            ),
            "elapsed": 1.4,
        }

        yield {"type": "tool_start", "tool": "search_breach", "input": email}
        await asyncio.sleep(1.2)
        yield {
            "type": "tool_result",
            "tool": "search_breach",
            "output": (
                "[!] LinkedIn (2016-05-17), Passwords, Email addresses\n"
                "[!] Adobe (2013-10-04), Passwords, Email addresses, Usernames\n"
                "[*] 2 breach(es) found via HaveIBeenPwned"
            ),
            "elapsed": 1.1,
        }

        summary = (
            f"## Summary\n\nTarget **{email}** has accounts on **4 platforms** "
            "and appears in **2 known data breaches** (LinkedIn 2016, Adobe 2013). "
            "Credential rotation strongly advised."
        )
        async for event in stream_text(summary):
            yield event
        yield {"type": "done"}
        return

    # --- IP investigation ---
    ip_match = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", message)
    if ip_match or "ip" in msg_lower:
        ip = ip_match.group(0) if ip_match else "8.8.8.8"

        yield {"type": "tool_start", "tool": "search_ip", "input": ip}
        await asyncio.sleep(1.0)
        yield {
            "type": "tool_result",
            "tool": "search_ip",
            "output": (
                f"[+] IP: {ip}\n"
                "[+] Hostname: dns.google\n"
                "[+] Country: US, Mountain View, California\n"
                "[+] Org: AS15169 Google LLC\n"
                "[+] Timezone: America/Los_Angeles"
            ),
            "elapsed": 0.9,
        }

        yield {"type": "tool_start", "tool": "search_whois", "input": ip}
        await asyncio.sleep(0.8)
        yield {
            "type": "tool_result",
            "tool": "search_whois",
            "output": (
                "[+] IP Range: 8.8.8.0/24\n"
                "[+] Owner: Google LLC\n"
                "[+] Abuse: network-abuse@google.com\n"
                "[+] Country: US\n"
                "[+] Registered: 2014-03-14"
            ),
            "elapsed": 0.7,
        }

        summary = (
            f"**{ip}** is a Google public DNS server located in Mountain View, "
            "California. Owned by Google LLC (AS15169). No threat indicators found."
        )
        async for event in stream_text(summary):
            yield event
        yield {"type": "done"}
        return

    # --- default ---
    default_msg = (
        "I can help you investigate **emails**, **usernames**, **domains**, "
        "and **IP addresses** using 16 specialized OSINT tools. "
        "What would you like to look into?"
    )
    async for event in stream_text(default_msg):
        yield event
    yield {"type": "done"}


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(*, host_guard: bool = False) -> FastAPI:
    app = FastAPI(
        title="CLEARFRONT",
        version=_VERSION,
        docs_url=None,
        redoc_url=None,
    )

    # Host-header allowlist (anti DNS-rebinding). CORS alone cannot stop a
    # malicious page that rebinds its domain to 127.0.0.1: after the rebind the
    # request is same-origin and the localhost CORS regex passes. Pinning the
    # Host header closes that. Enabled by the entry points on the loopback bind;
    # left off for the TestClient (Host: testserver) and network binds.
    if host_guard:
        app.add_middleware(
            TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"]
        )

    app.add_middleware(
        CORSMiddleware,
        # Same-origin only: the UI is served by this server, so a wildcard would
        # only let malicious external sites call the API from your browser.
        allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # GET /api/health
    # ------------------------------------------------------------------

    @app.get("/api/health")
    async def health():
        ai_backend, ollama_host, ollama_reachable = _get_ai_backend()
        return {
            "status": "ok",
            "version": _VERSION,
            "setup_complete": _is_setup_complete(),
            "ai_backend": ai_backend,
            "ollama_host": ollama_host,
            "ollama_reachable": ollama_reachable,
            # Friendly label for the Claude backend, derived from the model id.
            "claude_model_label": _pretty_model(_CLAUDE_MODEL),
            # Maps Embed API key (referrer-restricted, free) for the location map.
            # Never expose it on a network-exposed bind: /api/health is
            # unauthenticated, so a public bind would hand the key to any caller.
            "google_maps_api_key": (
                "" if _PUBLIC_BIND else os.environ.get("GOOGLE_MAPS_API_KEY", "").strip()
            ),
        }

    # ------------------------------------------------------------------
    # GET /api/tools
    # ------------------------------------------------------------------

    @app.get("/api/tools")
    async def list_tools():
        result = []
        for meta in _TOOL_CATALOG:
            available, reason = _check_available(meta)
            result.append(
                {
                    "name": meta["name"],
                    "description": meta["description"],
                    "input_label": meta["input_label"],
                    "input_placeholder": meta["input_placeholder"],
                    "category": meta["category"],
                    "icon": meta.get("icon", ""),
                    "available": available,
                    "unavailable_reason": reason,
                }
            )
        return result

    # ------------------------------------------------------------------
    # GET /api/sponsors
    # ------------------------------------------------------------------

    @app.get("/api/sponsors")
    async def list_sponsors():
        from clearfront.sponsors import SponsorsValidationError, load_sponsors

        try:
            sponsors = load_sponsors()
        except SponsorsValidationError as exc:
            return JSONResponse({"status": "error", "message": str(exc)}, status_code=500)
        return {"status": "ok", "sponsors": sponsors}

    # ------------------------------------------------------------------
    # POST /api/run/{tool_name}
    # ------------------------------------------------------------------

    @app.post("/api/run/{tool_name}")
    async def run_tool(tool_name: str, req: RunRequest):
        if tool_name not in _RUNNERS:
            return JSONResponse(
                {
                    "status": "error",
                    "output": f"Unknown tool: {tool_name}",
                    "tool": tool_name,
                    "elapsed": 0,
                },
                status_code=404,
            )
        blocked = _blocked_local_tool(tool_name)
        if blocked:
            return JSONResponse(
                {"status": "error", "output": blocked, "tool": tool_name, "elapsed": 0},
                status_code=403,
            )
        start = time.monotonic()
        try:
            result = await _RUNNERS[tool_name](req.input, req.timeout)
            elapsed = round(time.monotonic() - start, 2)
            return {"status": "ok", "output": result, "tool": tool_name, "elapsed": elapsed}
        except Exception as exc:
            elapsed = round(time.monotonic() - start, 2)
            return JSONResponse(
                {"status": "error", "output": str(exc), "tool": tool_name, "elapsed": elapsed},
                status_code=500,
            )

    # ------------------------------------------------------------------
    # GET /api/stream/{tool_name} , Server-Sent Events
    # ------------------------------------------------------------------

    @app.get("/api/stream/{tool_name}")
    async def stream_tool(request: Request, tool_name: str, input: str, timeout: int = 120):
        if tool_name not in _RUNNERS:

            async def _err() -> AsyncIterator[dict]:
                yield {"data": json.dumps({"line": f"Unknown tool: {tool_name}", "done": False})}
                yield {"data": json.dumps({"line": "", "done": True, "elapsed": 0})}

            return EventSourceResponse(_err(), ping=15)

        blocked = _blocked_local_tool(tool_name)
        if blocked:

            async def _blocked_gen() -> AsyncIterator[dict]:
                yield {"data": json.dumps({"line": blocked, "done": False})}
                yield {"data": json.dumps({"line": "", "done": True, "elapsed": 0})}

            return EventSourceResponse(_blocked_gen(), ping=15)

        async def event_gen() -> AsyncIterator[dict]:
            yield {
                "data": json.dumps({"line": f"[*] Running {tool_name} on: {input}", "done": False})
            }
            yield {"data": json.dumps({"line": "", "done": False})}
            start = time.monotonic()
            try:
                result = await _RUNNERS[tool_name](input, timeout)
                elapsed = round(time.monotonic() - start, 2)
                for line in result.splitlines():
                    if await request.is_disconnected():
                        return
                    yield {"data": json.dumps({"line": line, "done": False})}
                    await asyncio.sleep(0.012)
                yield {"data": json.dumps({"line": "", "done": True, "elapsed": elapsed})}
            except Exception as exc:
                elapsed = round(time.monotonic() - start, 2)
                yield {"data": json.dumps({"line": f"Error: {exc}", "done": False})}
                yield {"data": json.dumps({"line": "", "done": True, "elapsed": elapsed})}

        return EventSourceResponse(event_gen(), ping=15)

    # ------------------------------------------------------------------
    # GET /api/chat/test, lightweight backend connectivity check
    # ------------------------------------------------------------------

    @app.get("/api/chat/test")
    async def chat_test():
        has_claude = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
        if has_claude:
            return {"status": "ok", "backend": "claude", "ollama_reachable": None}

        # OpenAI-compatible endpoint (LiteLLM, llama-swap, vLLM, …).
        openai_base = os.environ.get("OPENAI_BASE_URL", "").strip().rstrip("/")
        if openai_base:
            api_key = os.environ.get("OPENAI_API_KEY", "").strip()
            probe = await _probe_openai_endpoint(openai_base, api_key)
            # Reachable means the backend is configured & answering, even if the
            # key is rejected (401/403), the chat path will surface the auth
            # error clearly rather than being silently blocked as "none".
            return {
                "status": "ok",
                "backend": "openai" if probe["reachable"] else "none",
                "openai_reachable": probe["reachable"],
                "openai_auth_ok": probe["auth_ok"],
                "openai_status_code": probe["status_code"],
                "openai_base_url": openai_base,
            }

        ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        try:
            if _httpx is not None:
                async with _httpx.AsyncClient(timeout=1.5) as client:
                    r = await client.get(f"{ollama_host}/api/tags")
                    reachable = r.status_code == 200
            else:
                raw = await asyncio.to_thread(
                    lambda: _requests.get(f"{ollama_host}/api/tags", timeout=1.5)
                )
                reachable = raw.status_code == 200
        except Exception:
            reachable = False

        return {
            "status": "ok",
            "backend": "ollama" if reachable else "none",
            "ollama_reachable": reachable,
        }

    # ------------------------------------------------------------------
    # POST /api/openai/test, probe an OpenAI-compatible endpoint from the
    # server (the browser cannot: an http:// endpoint is blocked as
    # mixed-content from the https:// UI, and cross-origin requests fail CORS).
    # Accepts the values typed in Settings so the user can test before saving.
    # ------------------------------------------------------------------

    @app.post("/api/openai/test")
    async def openai_test(req: OpenAITestRequest):
        # Guard only the request-supplied URL; a blank field falls back to the
        # operator's own OPENAI_BASE_URL env, which is trusted.
        rejection = _reject_backend_url(req.openai_base_url)
        if rejection:
            return {
                "status": "ok",
                "reachable": False,
                "auth_ok": False,
                "status_code": None,
                "blocked": rejection,
            }
        base_url = (req.openai_base_url or os.environ.get("OPENAI_BASE_URL", "")).strip()
        api_key = (req.openai_api_key or os.environ.get("OPENAI_API_KEY", "")).strip()
        if not base_url:
            return {"status": "ok", "reachable": False, "auth_ok": False, "status_code": None}
        probe = await _probe_openai_endpoint(base_url, api_key)
        return {"status": "ok", **probe, "openai_base_url": base_url.rstrip("/")}

    # ------------------------------------------------------------------
    # POST /api/chat , AI chat with tool_use, SSE streaming
    # ------------------------------------------------------------------

    @app.post("/api/chat")
    async def chat(req: ChatRequest):
        messages: list[dict] = []
        for h in req.history:
            role = h.get("role", "user")
            content = h.get("content", "")
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": req.message})

        backend = _select_chat_backend(req)

        # Refuse a request-supplied backend URL that points at an internal
        # address (SSRF) or uses a non-http scheme, before any server-side fetch.
        backend_rejection = None
        if backend == "openai":
            backend_rejection = _reject_backend_url(req.openai_base_url)
        elif backend == "ollama":
            backend_rejection = _reject_backend_url(req.ollama_host)

        async def generate():
            if backend_rejection:
                yield f"data: {json.dumps({'type': 'error', 'message': backend_rejection})}\n\n"
                return
            if backend == "openai":
                base_url = (
                    req.openai_base_url
                    or os.environ.get("OPENAI_BASE_URL", "http://localhost:8080/v1")
                ).strip()
                api_key = (req.openai_api_key or os.environ.get("OPENAI_API_KEY", "")).strip()
                model = (req.openai_model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")).strip()
                gen = _stream_openai(messages, base_url, api_key, model)
            elif backend == "ollama":
                gen = _stream_ollama(messages, req.ollama_host, req.ollama_model)
            else:
                gen = _stream_claude(messages, depth=req.depth)

            async for event in gen:
                yield f"data: {json.dumps(event)}\n\n"

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # ------------------------------------------------------------------
    # POST /api/setup , save API keys to .env
    # ------------------------------------------------------------------

    @app.post("/api/report/export")
    async def export_report(req: ReportExportRequest):
        """Render a report's Markdown to a downloadable PDF.

        The Markdown is the user's own report, already rendered in the browser,
        so nothing new is collected or sent anywhere; this only reuses the
        existing pdf_report path (the same one the REPL/CLI use) to hand the
        analyst a file they can keep or pass to a removal/monitoring service.
        """
        from clearfront.pdf_report import generate_pdf_report

        markdown = (req.markdown or "").strip()
        if not markdown:
            return JSONResponse({"error": "No report content to export."}, status_code=400)
        # Bound the work a single unauthenticated request can trigger.
        if len(markdown) > _MAX_REPORT_MARKDOWN:
            return JSONResponse(
                {"error": "Report is too large to export."}, status_code=413
            )

        safe_title = re.sub(r"[^A-Za-z0-9._-]+", "-", req.title or "clearfront-report").strip("-.")
        safe_title = safe_title or "clearfront-report"

        with tempfile.TemporaryDirectory() as tmp:
            md_path = Path(tmp) / f"{safe_title}.md"
            md_path.write_text(markdown, encoding="utf-8")
            pdf_path = await generate_pdf_report(md_path)
            if pdf_path is None or not pdf_path.exists():
                return JSONResponse(
                    {"error": "PDF export unavailable. Install reportlab: pip install reportlab"},
                    status_code=501,
                )
            pdf_bytes = pdf_path.read_bytes()

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{safe_title}.pdf"'},
        )

    @app.post("/api/graph/export")
    async def export_graph(req: GraphExportRequest):
        """Export the evidence graph the browser already rendered as GraphML/JSON/Mermaid.

        This only reformats data the client already holds; nothing new is collected or
        sent anywhere. GraphML opens in Gephi/yEd/Maltego; Mermaid embeds in Markdown.
        """
        from clearfront.correlation import d3_to_graphml, d3_to_json, d3_to_mermaid

        graph = req.graph if isinstance(req.graph, dict) else {}
        if not graph.get("nodes"):
            return JSONResponse({"error": "No graph to export."}, status_code=400)

        builders = {
            "graphml": (d3_to_graphml, "application/graphml+xml", "graphml"),
            "json": (d3_to_json, "application/json", "json"),
            "mermaid": (d3_to_mermaid, "text/plain; charset=utf-8", "mmd"),
        }
        fmt = (req.format or "graphml").lower()
        if fmt not in builders:
            return JSONResponse({"error": f"Unknown format: {fmt}"}, status_code=400)

        builder, media_type, ext = builders[fmt]
        body = builder(graph)

        safe_title = re.sub(r"[^A-Za-z0-9._-]+", "-", req.title or "clearfront-graph").strip("-.")
        safe_title = safe_title or "clearfront-graph"

        return Response(
            content=body,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{safe_title}.{ext}"'},
        )

    @app.post("/api/setup")
    async def setup(request: Request):
        # On a network-exposed bind, an unauthenticated client must never be able
        # to rewrite the operator's .env (it could redirect the AI backend to
        # exfiltrate future investigations, or clobber keys). Configure such
        # deployments via a mounted .env instead.
        if _PUBLIC_BIND:
            return JSONResponse(
                {
                    "status": "error",
                    "error": "Setup is disabled on a network-exposed server. "
                    "Configure keys via the .env file.",
                },
                status_code=403,
            )
        body: dict = await request.json()
        env_path = _ROOT / ".env"
        existing: dict[str, str] = {}
        if env_path.exists():
            for raw in env_path.read_text().splitlines():
                line = raw.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    existing[k.strip()] = v.strip()
        accepted = []
        for k, v in body.items():
            key = str(k).strip()
            # Only persist known configuration keys, never arbitrary env vars.
            if key not in _SETTABLE_ENV_KEYS:
                continue
            v_str = str(v).strip()
            if v_str:
                existing[key] = v_str
                os.environ[key] = v_str
                accepted.append(key)
        env_path.write_text("\n".join(f"{k}={v}" for k, v in existing.items()) + "\n")
        return {"status": "ok", "accepted": accepted}

    # ------------------------------------------------------------------
    # POST /api/demo/chat , pre-scripted demo stream, no API key needed
    # ------------------------------------------------------------------

    @app.post("/api/demo/chat")
    async def demo_chat(req: ChatRequest):
        async def generate():
            async for event in _demo_chat_stream(req.message):
                yield f"data: {json.dumps(event)}\n\n"

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # ------------------------------------------------------------------
    # Static mounts, docs, then catch-all for frontend
    # ------------------------------------------------------------------

    docs_path = _ROOT / "docs"
    if docs_path.exists():
        app.mount("/docs", StaticFiles(directory=str(docs_path), html=True), name="docs")

    web_static = _WEB_DIR / "static"
    if web_static.exists():
        app.mount("/static", StaticFiles(directory=str(web_static)), name="static")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        index = _WEB_DIR / "index.html"
        if index.exists():
            return HTMLResponse(index.read_text())
        return HTMLResponse(
            "<h1>CLEARFRONT</h1>"
            "<p><strong>web/index.html not found.</strong></p>"
            "<p>If you installed via pip, this is a packaging issue, please report it at "
            "https://github.com/scottmartinanderson/clearfront/issues</p>"
            "<p>If running from source, make sure <code>clearfront/web/index.html</code> exists.</p>",
            status_code=404,
        )

    return app


# ---------------------------------------------------------------------------
# Entry points (called from cli.py)
# ---------------------------------------------------------------------------


async def serve_async(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run uvicorn within an already-running asyncio event loop."""
    from dotenv import load_dotenv

    load_dotenv()
    _set_public_bind(host)
    app = create_app(host_guard=not _PUBLIC_BIND)
    _print_banner(host, port)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning", loop="none")
    server = uvicorn.Server(config)
    await server.serve()


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Standalone blocking entry point."""
    from dotenv import load_dotenv

    load_dotenv()
    _set_public_bind(host)
    app = create_app(host_guard=not _PUBLIC_BIND)
    _print_banner(host, port)
    uvicorn.run(app, host=host, port=port, log_level="warning")


def _print_banner(host: str, port: int) -> None:
    display = "localhost" if host in ("0.0.0.0", "", "127.0.0.1", "localhost") else host
    print(f"[*] CLEARFRONT {_VERSION} web server")
    print(f"[*] App  → http://{display}:{port}/")
    print(f"[*] Docs → http://{display}:{port}/docs/")
    if host not in ("127.0.0.1", "localhost", ""):
        print("[!] WARNING: binding to a non-localhost address exposes this API "
              "(which has no authentication) to your network.")
        print("[!]          Anyone who can reach it can run tools and spend your API keys.")
        print("[!]          In this mode local-file tools (search_exif) and key setup "
              "are disabled, and internal backend URLs are refused, but you should still")
        print("[!]          use the default 127.0.0.1 unless you intend to expose it.")
    print("[*] Press Ctrl+C to stop.")
