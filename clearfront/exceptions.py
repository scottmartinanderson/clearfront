# clearfront/tools/exceptions.py
"""
Shared exception hierarchy for all OSINT tool modules.
Centralising exceptions prevents duplication across tool files
and provides a single import point for callers.
"""


class OSINTError(Exception):
    """Base exception for all OSINT tool-related errors."""


class ToolNotFoundError(OSINTError):
    """Raised when a required external binary is absent from PATH."""


class ToolExecutionError(OSINTError):
    """Raised when an external tool exits with a non-zero status."""


class ToolTimeoutError(OSINTError):
    """Raised when a tool execution exceeds the configured time limit."""
