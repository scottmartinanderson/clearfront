# clearfront/multi_target.py
"""
Multi-target investigation support.

Runs independent OSINT investigations for multiple targets in parallel
via asyncio.gather().  Each target gets its own timestamped report file.
A consolidated summary report is generated after all targets complete.

Maximum 10 targets per run.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from pathlib import Path

from clearfront.agent import AgentResponse, OISAgent, OllamaAgent, OpenAICompatibleAgent

logger = logging.getLogger(__name__)

MAX_TARGETS = 10


def _make_agent(
    provider: str,
    api_key: str | None,
    ollama_model: str,
    ollama_host: str,
    openai_base_url: str,
    openai_model: str,
    openai_api_key: str | None,
):
    """Build the agent matching the selected provider.

    The Anthropic branch references the module-level ``OISAgent`` name so tests
    that patch ``clearfront.multi_target.OISAgent`` keep working.
    """
    if provider == "ollama":
        return OllamaAgent(model=ollama_model, host=ollama_host)
    if provider == "openai":
        return OpenAICompatibleAgent(
            model=openai_model, base_url=openai_base_url, api_key=openai_api_key
        )
    return OISAgent(api_key=api_key)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_targets(source: str) -> list[str]:
    """
    Parse a target list from *source*.

    If *source* is the path of an existing file, read one target per line.
    Otherwise treat *source* as comma-separated inline targets.
    """
    p = Path(source)
    if p.exists() and p.is_file():
        lines = p.read_text(encoding="utf-8").splitlines()
        return [ln.strip() for ln in lines if ln.strip()]
    return [t.strip() for t in source.split(",") if t.strip()]


async def _investigate_one(
    target: str,
    make_agent,
    reports_dir: Path,
    date_prefix: str,
) -> tuple[str, AgentResponse]:
    """Run one investigation and persist its report."""
    agent = make_agent()
    logger.info("Multi-target: investigating %s", target)
    response = await agent.run(prompt=f"Investigate: {target}")

    if response.content and "##" in response.content and len(response.content) > 300:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)
        path = reports_dir / f"{date_prefix}_{safe}_report.md"
        path.write_text(response.content, encoding="utf-8")
        logger.info("Saved: %s", path)

    return target, response


def _extract_summary_section(content: str) -> str:
    """Return the first '## ' section of a report (the key-judgment summary).

    Works for the calibrated '## INTELLIGENCE SUMMARY' header and the legacy
    '## Summary' header. Falls back to a truncated excerpt when the report has
    no markdown sections.
    """
    first = content.find("## ")
    if first == -1:
        excerpt = content[:500].strip()
        return excerpt + ("…" if len(content) > 500 else "")
    nxt = content.find("\n## ", first + 3)
    end = nxt if nxt != -1 else len(content)
    return content[first:end].strip()


def _build_summary(results: list[tuple[str, AgentResponse]], date_prefix: str) -> str:
    lines = [
        "# Clearfront Multi-Target Investigation Summary",
        "",
        f"**Date:** {date_prefix}  ",
        f"**Targets investigated:** {len(results)}",
        "",
        "---",
        "",
    ]
    for target, response in results:
        lines.append(f"## {target}")
        lines.append("")
        if response.error:
            lines.append(f"**Error:** {response.error}")
        elif response.content:
            lines.append(_extract_summary_section(response.content))
        else:
            lines.append("No findings.")
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def run_multi_target(
    targets: list[str],
    api_key: str | None = None,
    is_pdf_disabled: bool = False,
    provider: str = "anthropic",
    ollama_model: str = "llama3.2",
    ollama_host: str = "http://localhost:11434",
    openai_base_url: str = "http://localhost:8080/v1",
    openai_model: str = "gpt-4o-mini",
    openai_api_key: str | None = None,
) -> str:
    """
    Investigate targets in parallel using asyncio.gather().

    Parameters
    ----------
    targets:
        List of OSINT targets (emails, usernames, domains, IPs, names).
        Maximum ``MAX_TARGETS`` entries.
    api_key:
        Anthropic API key.  Falls back to ``ANTHROPIC_API_KEY`` env var.
    is_pdf_disabled:
        When True, skip PDF generation for the summary report.

    Returns
    -------
    str
        Markdown summary report (also written to ``reports/``).

    Raises
    ------
    ValueError
        If more than ``MAX_TARGETS`` targets are supplied.
    """
    if len(targets) > MAX_TARGETS:
        raise ValueError(
            f"Multi-target investigation supports at most {MAX_TARGETS} targets; "
            f"got {len(targets)}. Split into smaller batches."
        )
    if not targets:
        return "No targets provided."

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    date_prefix = datetime.now().strftime("%Y-%m-%d")

    def make_agent():
        return _make_agent(
            provider,
            api_key,
            ollama_model,
            ollama_host,
            openai_base_url,
            openai_model,
            openai_api_key,
        )

    tasks = [_investigate_one(target, make_agent, reports_dir, date_prefix) for target in targets]
    results: list[tuple[str, AgentResponse]] = await asyncio.gather(*tasks)

    summary = _build_summary(results, date_prefix)

    summary_path = reports_dir / f"{date_prefix}_summary.md"
    summary_path.write_text(summary, encoding="utf-8")
    logger.info("Summary report: %s", summary_path)

    if not is_pdf_disabled:
        try:
            from clearfront.pdf_report import generate_pdf_report

            await generate_pdf_report(summary_path)
        except Exception:
            logger.debug("PDF skipped for summary.", exc_info=True)

    return summary
