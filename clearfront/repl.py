# clearfront/repl.py
"""
Clearfront Interactive REPL.

A Claude Code-style terminal interface for Clearfront.
Powered by prompt_toolkit for input handling and Rich for display.

Usage:
    clearfront                                  # Anthropic Claude (default)
    clearfront --provider ollama                # local Ollama model
    clearfront --provider ollama --ollama-model mistral
    clearfront --no-pdf                         # disable PDF export
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from clearfront import __version__
from clearfront.agent import OllamaAgent, OpenAICompatibleAgent, OISAgent
from clearfront import effort as _effort

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIN_REPORT_CHARS = 300

_TOOL_INFO_ROWS = [
    ("search_email", "holehe", "Social accounts linked to an email"),
    ("search_username", "sherlock", "Accounts across 300+ platforms"),
    ("search_breach", "HaveIBeenPwned", "Data breach exposure"),
    ("search_whois", "python-whois", "Domain registrant info"),
    ("search_ip", "ipinfo.io", "Geolocation, ASN, hostname"),
    ("search_domain", "sublist3r", "Subdomain enumeration"),
    ("generate_dorks", "built-in", "Google dork URLs"),
    ("search_paste", "psbdmp.ws", "Pastebin dump mentions"),
    ("search_phone", "phoneinfoga", "Carrier, country, line type"),
    ("search_shodan", "Shodan API", "Open ports, banners, CVEs"),
    ("search_virustotal", "VirusTotal API", "IP/domain/URL/hash threat analysis"),
    ("search_censys", "Censys API", "Internet infrastructure & certs"),
    ("search_ip2location", "IP2Location.io", "Enhanced IP geolocation & VPN/proxy detection"),
    ("search_abuseipdb", "AbuseIPDB API", "IP abuse confidence score"),
    ("search_github", "GitHub API", "Profile, repos, commit-email discovery"),
    ("search_dns", "dnspython", "DNS records & email security audit"),
]

# ---------------------------------------------------------------------------
# Rich console
# ---------------------------------------------------------------------------

console = Console()

# ---------------------------------------------------------------------------
# Prompt style
# ---------------------------------------------------------------------------

PROMPT_STYLE = Style.from_dict(
    {
        "prompt": "#00ff88 bold",
        "prompt-text": "#f1f5f9",
    }
)

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _featured_integrations_line() -> str:
    """Return a dim banner line listing featured sponsor names, or empty string."""
    try:
        from clearfront.sponsors import get_featured

        featured = get_featured()
        if not featured:
            return ""
        names = ", ".join(s["name"] for s in featured)
        return f"[dim]Featured integrations: {names}[/]"
    except Exception:
        return ""


def _print_banner(provider: str, model: str) -> None:
    if provider == "ollama":
        provider_info = f"[dim]Provider: Ollama ({model})[/]"
    elif provider == "openai":
        provider_info = f"[dim]Provider: OpenAI-compatible ({model})[/]"
    else:
        provider_info = f"[dim]Provider: Anthropic ({model})[/]"

    featured_line = _featured_integrations_line()
    panel_content = f"[bold #00ff88]Clearfront[/] [dim]v{__version__}[/]  [dim]·[/]  {provider_info}"
    if featured_line:
        panel_content += f"\n{featured_line}"

    console.print()
    console.print(
        Panel.fit(
            panel_content,
            border_style="#1e293b",
            padding=(0, 2),
        )
    )
    console.print(
        "  Type a target or question. [dim]'help'[/] for commands. [dim]'exit'[/] to quit."
    )
    console.print(
        "  [dim]Authorized use only: your own assets or targets you are authorized to assess. "
        "Public-source collection; targets and keys leave your machine to the providers you configure.[/]\n"
    )


def _print_help() -> None:
    console.print()
    console.print(
        Panel(
            "\n".join(
                [
                    "[bold]Commands:[/]",
                    "",
                    "  [#00ff88]<target>[/]          Investigate any target (email, username, domain, IP, name)",
                    "  [#00ff88]effort[/]             Set sweep effort (faster, balanced, deeper)",
                    "  [#00ff88]clear[/]             Clear conversation memory",
                    "  [#00ff88]save[/]              Save last report to reports/",
                    "  [#00ff88]tools[/]             List available OSINT tools",
                    "  [#00ff88]config[/]            Show current configuration",
                    "  [#00ff88]history[/]           Browse saved session history",
                    "  [#00ff88]help[/]              Show this message",
                    "  [#00ff88]exit[/] / Ctrl-D     Exit",
                    "",
                    "[bold]Examples:[/]",
                    "",
                    "  clearfront ❯ investigate target@example.com",
                    "  clearfront ❯ find all accounts for johndoe99",
                    "  clearfront ❯ what subdomains does example.com have?",
                    "  clearfront ❯ check if +14155552671 is a mobile number",
                    "  clearfront ❯ shodan search for apache servers in Berlin",
                ]
            ),
            title="[bold]Help[/]",
            border_style="#1e293b",
            padding=(0, 2),
        )
    )
    console.print()


def _print_tools() -> None:
    from rich.table import Table

    table = Table(
        box=box.SIMPLE_HEAD,
        border_style="#1e293b",
        header_style="bold #00ff88",
        show_header=True,
    )
    table.add_column("Tool", style="#f1f5f9")
    table.add_column("Method", style="dim")
    table.add_column("Finds", style="#94a3b8")

    for row in _TOOL_INFO_ROWS:
        table.add_row(*row)

    console.print()
    console.print(table)
    console.print()


def _print_tool_call(name: str, args: dict[str, Any]) -> None:
    arg_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
    console.print(f"  [dim]→[/] [#00ff88]{name}[/][dim]({arg_str})[/]")


def _print_result(content: str) -> None:
    console.print()
    console.print(
        Panel(
            Markdown(content),
            border_style="#00ff88",
            padding=(1, 2),
        )
    )
    console.print()


def _print_error(message: str) -> None:
    console.print()
    console.print(
        Panel(
            f"[bold red]Error:[/] {message}",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()


def _print_config(
    api_key: str | None,
    provider: str,
    model: str,
    ollama_host: str,
    is_pdf_disabled: bool,
    openai_base_url: str = "",
    effort: str = _effort.DEFAULT,
) -> None:
    masked = ("*" * 20 + api_key[-6:]) if api_key and len(api_key) > 6 else "not set"
    rows = [
        f"[bold]Provider:[/] {provider}",
        f"[bold]Model:[/]    {model}",
    ]
    if provider == "anthropic":
        rows.append(f"[bold]API Key:[/]  {masked}")
    elif provider == "openai":
        rows.append(f"[bold]Endpoint:[/] {openai_base_url}")
    else:
        rows.append(f"[bold]Ollama:[/]   {ollama_host}")
    rows += [
        f"[bold]Effort:[/]    {effort}",
        "[bold]Reports:[/]  ./reports/",
        f"[bold]PDF:[/]      {'disabled' if is_pdf_disabled else 'enabled'}",
    ]
    console.print()
    console.print(
        Panel(
            "\n".join(rows),
            title="[bold]Configuration[/]",
            border_style="#1e293b",
            padding=(0, 2),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Report saver
# ---------------------------------------------------------------------------


def _save_report(content: str) -> Path:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = reports_dir / f"{timestamp}_report.md"
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------


class OISRepl:
    """Interactive REPL session."""

    def __init__(
        self,
        api_key: str | None = None,
        provider: str = "anthropic",
        ollama_model: str = "llama3.2",
        ollama_host: str = "http://localhost:11434",
        openai_base_url: str = "http://localhost:8080/v1",
        openai_model: str = "gpt-4o-mini",
        openai_api_key: str | None = None,
        is_pdf_disabled: bool = False,
        effort: str = _effort.DEFAULT,
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._provider = provider
        self._ollama_model = ollama_model
        self._ollama_host = ollama_host
        self._openai_base_url = openai_base_url
        self._openai_model = openai_model
        self._openai_api_key = openai_api_key
        self._is_pdf_disabled = is_pdf_disabled
        self._effort = _effort.normalize(effort)

        self._agent: OISAgent | OllamaAgent | OpenAICompatibleAgent
        if provider == "ollama":
            self._agent = OllamaAgent(
                model=ollama_model,
                host=ollama_host,
                effort=self._effort,
            )
            self._display_model = ollama_model
        elif provider == "openai":
            self._agent = OpenAICompatibleAgent(
                model=openai_model,
                base_url=openai_base_url,
                api_key=openai_api_key,
                effort=self._effort,
            )
            self._display_model = openai_model
        else:
            self._agent = OISAgent(api_key=self._api_key, effort=self._effort)
            self._display_model = "claude-sonnet-4-20250514"

        self._last_response: str = ""
        self._session_start: datetime = datetime.now()
        self._session_prompts: list[str] = []
        self._session_tools: list[str] = []
        self._session_targets: list[str] = []
        self._session_report_path: str = ""
        self._session: PromptSession = PromptSession(
            history=FileHistory(str(Path.home() / ".clearfront_history")),
            style=PROMPT_STYLE,
        )

    def _get_prompt_tokens(self) -> HTML:
        return HTML("<prompt>clearfront</prompt> <prompt-text>❯</prompt-text> ")

    async def _handle_tool_call(self, name: str, args: dict[str, Any]) -> None:
        _print_tool_call(name, args)

    async def _run_investigation(self, user_input: str) -> None:
        self._session_prompts.append(user_input)

        console.print()
        console.print("  [dim]Thinking...[/]")

        response = await self._agent.run(
            prompt=user_input,
            on_tool_call=self._handle_tool_call,
        )

        if response.error:
            _print_error(response.error)
            return

        # Track tools and targets from this turn
        for tc in response.tool_calls:
            if tc.name not in self._session_tools:
                self._session_tools.append(tc.name)
            for v in tc.input.values():
                if isinstance(v, str) and v not in self._session_targets:
                    self._session_targets.append(v)

        if response.content:
            self._last_response = response.content
            _print_result(response.content)

        # Auto-save structured report
        if "##" in response.content and len(response.content) > _MIN_REPORT_CHARS:
            try:
                path = _save_report(response.content)
                self._session_report_path = str(path)
                console.print(f"  [dim]✓ Report saved → {path}[/]")
                if not self._is_pdf_disabled:
                    await self._generate_pdf(path)
                console.print()
            except Exception:
                logger.debug("Report save failed.", exc_info=True)

    async def _generate_pdf(self, md_path: Path) -> None:
        try:
            from clearfront.pdf_report import generate_pdf_report

            pdf_path = await generate_pdf_report(md_path)
            if pdf_path:
                console.print(f"  [dim]✓ PDF saved     → {pdf_path}[/]")
        except Exception:
            logger.debug("PDF generation failed.", exc_info=True)

    def _save_session(self) -> None:
        if not self._session_prompts:
            return
        from clearfront.session_history import SessionRecord, save_session

        duration = int((datetime.now() - self._session_start).total_seconds())
        record = SessionRecord(
            timestamp=self._session_start.strftime("%Y-%m-%dT%H:%M:%S"),
            duration_seconds=duration,
            prompts=self._session_prompts,
            tools_used=self._session_tools,
            targets=self._session_targets,
            report_path=self._session_report_path,
        )
        try:
            save_session(record)
        except Exception:
            logger.debug("Session save failed.", exc_info=True)

    @staticmethod
    def _persist_key_to_env(key: str, env_path: Path | None = None) -> Path | None:
        """Append ANTHROPIC_API_KEY to .env (cwd) if not already present.

        Returns the .env path on success (or if a key line already exists), or
        None if the file could not be written.
        """
        path = env_path or (Path.cwd() / ".env")
        try:
            existing = path.read_text(encoding="utf-8") if path.exists() else ""
            if "ANTHROPIC_API_KEY=" not in existing:
                sep = "" if existing == "" or existing.endswith("\n") else "\n"
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(f"{sep}ANTHROPIC_API_KEY={key}\n")
            return path
        except OSError:
            return None

    def _first_run_setup(self) -> bool:
        """Interactive first run when no Anthropic key is set.

        Prints a short authorized-use / self-check orientation, then offers to
        paste a key (saved to .env and used immediately) or skip to fully-local
        Ollama. Returns True to continue into the REPL, False to exit.
        """
        console.print()
        console.print(
            Panel(
                "\n".join(
                    [
                        "[bold]First run.[/] No Anthropic API key found. A few things first:",
                        "",
                        "  [#00ff88]•[/] Authorized use only: your own assets, or targets you are authorized to assess.",
                        "  [#00ff88]•[/] The safe way to start is a self-check of your own exposure (your own email, IP, or number).",
                        "  [#00ff88]•[/] When you investigate, the target and your API key leave your machine to the backends you configure.",
                    ]
                ),
                border_style="#1e293b",
                padding=(1, 2),
            )
        )
        console.print(
            "  Paste an Anthropic API key to save it to [bold].env[/] and start, "
            "or press Enter to skip.\n"
            "  [dim]Prefer fully local? Quit and run 'clearfront --provider ollama'.[/]"
        )
        try:
            key = input("  Anthropic API key: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return False
        if not key:
            console.print(
                "\n  No key set. Export one with "
                "[bold]export ANTHROPIC_API_KEY=sk-ant-...[/], or run "
                "[bold]clearfront --provider ollama[/] for a fully local model.\n"
            )
            return False
        os.environ["ANTHROPIC_API_KEY"] = key
        self._api_key = key
        self._agent = OISAgent(api_key=key, effort=self._effort)
        saved = self._persist_key_to_env(key)
        if saved:
            console.print(f"\n  [dim]Key saved to {saved} and active for this session.[/]\n")
        else:
            console.print("\n  [dim]Key active for this session (could not write .env).[/]\n")
        return True

    async def run(self) -> None:
        """Start the interactive REPL loop."""
        if self._provider == "anthropic" and not self._api_key:
            if not self._first_run_setup():
                return

        _print_banner(self._provider, self._display_model)

        from clearfront.session_history import count_sessions

        n = count_sessions()
        if n > 0:
            s = "s" if n != 1 else ""
            console.print(f"  [dim]💾 {n} session{s} saved, type 'history' to browse[/]\n")

        try:
            while True:
                try:
                    raw = await self._session.prompt_async(
                        self._get_prompt_tokens,
                        style=PROMPT_STYLE,
                    )
                except (EOFError, KeyboardInterrupt):
                    console.print("\n[dim]Goodbye.[/]\n")
                    break

                user_input = raw.strip()
                if not user_input:
                    continue

                if user_input.lower() in ("exit", "quit", "q"):
                    console.print("\n[dim]Goodbye.[/]\n")
                    break

                if user_input.lower() == "help":
                    _print_help()
                    continue

                if user_input.lower() == "tools":
                    _print_tools()
                    continue

                if user_input.lower() == "clear":
                    self._agent.clear_history()
                    console.print("  [dim]Conversation memory cleared.[/]\n")
                    continue

                if user_input.lower() == "config":
                    _print_config(
                        self._api_key,
                        self._provider,
                        self._display_model,
                        self._ollama_host,
                        self._is_pdf_disabled,
                        self._openai_base_url,
                        self._effort,
                    )
                    continue

                # 'effort' shows the current level; 'effort <level>' sets it. Only
                # treat 'effort <arg>' as a command when <arg> is a real level, so
                # a genuine query that happens to start with 'effort' still runs.
                effort_parts = user_input.split(maxsplit=1)
                if effort_parts[0].lower() == "effort" and (
                    len(effort_parts) == 1
                    or effort_parts[1].strip().lower() in {lvl["v"] for lvl in _effort.LEVELS}
                ):
                    if len(effort_parts) == 2:
                        chosen = effort_parts[1].strip().lower()
                        self._effort = chosen
                        self._agent.set_effort(chosen)
                        console.print(
                            f"  [dim]Sweep effort set to[/] [#00ff88]{chosen}[/][dim]. "
                            f"{_effort.describe(chosen)}[/]\n"
                        )
                    else:
                        console.print(f"\n  [bold]Sweep effort:[/] [#00ff88]{self._effort}[/]")
                        for lvl in _effort.LEVELS:
                            marker = "[#00ff88]›[/]" if lvl["v"] == self._effort else " "
                            console.print(
                                f"  {marker} [#00ff88]{lvl['v']:<9}[/][dim]{lvl['desc']}[/]"
                            )
                        console.print(
                            "  [dim]Set with: effort faster | balanced | deeper[/]\n"
                        )
                    continue

                if user_input.lower() == "save":
                    if self._last_response:
                        path = _save_report(self._last_response)
                        console.print(f"  [dim]✓ Saved → {path}[/]\n")
                    else:
                        console.print("  [dim]Nothing to save yet.[/]\n")
                    continue

                if user_input.lower() == "history":
                    from clearfront.session_history import display_history_table, load_sessions

                    display_history_table(load_sessions(limit=10), console)
                    continue

                await self._run_investigation(user_input)
        finally:
            self._save_session()
