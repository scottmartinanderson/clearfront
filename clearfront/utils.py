# clearfront/utils.py
"""
Shared utility functions for Clearfront tool modules.

run_subprocess() centralises the asyncio subprocess execution pattern
(binary check → create_subprocess_exec → wait_for → kill on timeout)
that all binary-based OSINT tool wrappers share.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shutil
import socket
import sys
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlparse

from clearfront.tools.exceptions import ToolNotFoundError, ToolTimeoutError

logger = logging.getLogger(__name__)


def is_internal_url(url: str) -> bool:
    """SSRF guard: True if *url* targets a localhost / private / link-local /
    reserved / cloud-metadata address. Resolves the hostname before deciding, so
    a name that points at a private IP is caught. Unresolvable hosts return False
    (there is nothing internal to reach; let the upstream fetch fail naturally).

    Shared by the scrape_url tool and the web console's AI-backend URL guard.
    """
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return True
    if host == "localhost" or host.endswith((".localhost", ".internal", ".local")):
        return True
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    for ip in addrs:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            return True
    return False


class SubprocessResult(NamedTuple):
    """Result of a completed external subprocess call."""

    stdout: str
    stderr: str
    return_code: int


async def run_subprocess(
    binary: str,
    args: list[str],
    timeout_seconds: int,
    install_hint: str = "",
    cwd: str | None = None,
) -> SubprocessResult:
    """
    Execute an external binary asynchronously and return its output.

    Parameters
    ----------
    binary:
        Executable name discoverable via PATH.
    args:
        Arguments forwarded to the binary.
    timeout_seconds:
        Hard wall-clock limit; process is killed on expiry.
    install_hint:
        Short installation message appended to ToolNotFoundError.
    cwd:
        Working directory for the child process. Use a throwaway directory for
        tools that write side-effect files into the cwd (e.g. sherlock saves
        ``<username>.txt``); stdout is captured either way.

    Raises
    ------
    ToolNotFoundError
        When the binary is absent from PATH.
    ToolTimeoutError
        When the process exceeds timeout_seconds.
    """
    # Prepend the venv/uv-tool bin dir so co-installed tools are found even
    # when the venv is not activated and its bin is absent from the user's PATH.
    venv_bin = str(Path(sys.executable).parent)
    search_path = os.pathsep.join([venv_bin, os.environ.get("PATH", "")])
    resolved = shutil.which(binary, path=search_path)
    if not resolved:
        detail = f" {install_hint}" if install_hint else ""
        raise ToolNotFoundError(f"'{binary}' is not installed or not in PATH.{detail}")
    binary = resolved

    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        raw_stdout, raw_stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout_seconds),
        )
        return SubprocessResult(
            stdout=raw_stdout.decode("utf-8", errors="replace").strip(),
            stderr=raw_stderr.decode("utf-8", errors="replace").strip(),
            return_code=process.returncode or 0,
        )
    except asyncio.TimeoutError:
        _kill_process(process)
        raise ToolTimeoutError(f"'{binary}' scan timed out after {timeout_seconds}s.")


def _kill_process(process: asyncio.subprocess.Process | None) -> None:
    """Terminate a subprocess, ignoring errors if it already exited."""
    if process is None:
        return
    try:
        process.kill()
    except ProcessLookupError:
        pass
