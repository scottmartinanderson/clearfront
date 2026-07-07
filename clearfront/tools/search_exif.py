# clearfront/tools/search_exif.py
"""
File metadata extraction module.

Wraps the 'exiftool' binary to read embedded metadata (EXIF / IPTC / XMP) from a
local file, camera make/model, software, timestamps, author, and GPS
coordinates. Embedded GPS is flagged, since it's the most common real-world
metadata leak. Returns a formatted string; never raises on failure.
"""

from __future__ import annotations

import json
import logging
import os

from clearfront.tools.exceptions import OSINTError
from clearfront.utils import run_subprocess

logger = logging.getLogger(__name__)

_BINARY = "exiftool"
_DEFAULT_TIMEOUT = 30
_INSTALL_HINT = (
    "Install it with: brew install exiftool (macOS) "
    "or apt install libimage-exiftool-perl (Linux)."
)

# Notable fields to surface, in display order (exiftool -j key → label).
_FIELDS = [
    ("FileType", "File type"),
    ("MIMEType", "MIME type"),
    ("Make", "Camera make"),
    ("Model", "Camera model"),
    ("LensModel", "Lens"),
    ("Software", "Software"),
    ("DateTimeOriginal", "Taken"),
    ("CreateDate", "Created"),
    ("ModifyDate", "Modified"),
    ("Artist", "Artist"),
    ("Creator", "Creator"),
    ("Author", "Author"),
    ("Copyright", "Copyright"),
]


async def _run_exiftool(file_path: str, timeout_seconds: int) -> str:
    """Execute exiftool against file_path and return raw JSON stdout."""
    result = await run_subprocess(
        binary=_BINARY,
        # -j: JSON output, -n: numeric values (decimal GPS), --: end option
        # parsing so a path beginning with '-' can never be read as a flag.
        args=["-j", "-n", "--", file_path],
        timeout_seconds=timeout_seconds,
        install_hint=_INSTALL_HINT,
    )
    return result.stdout


def _format_exif_results(raw: str, file_path: str) -> str:
    """Parse exiftool JSON and return a structured, GPS-flagging summary."""
    try:
        data = json.loads(raw) if raw.strip() else []
    except json.JSONDecodeError:
        return f"Scan error: could not parse exiftool output for '{file_path}'."

    meta = data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})
    if not meta:
        return f"No metadata found for '{file_path}'."

    lines = [f"Metadata for '{file_path}':", ""]
    for key, label in _FIELDS:
        value = meta.get(key)
        if value not in (None, ""):
            lines.append(f"[+] {label}: {value}")

    # GPS, the high-value exposure signal.
    lat, lon = meta.get("GPSLatitude"), meta.get("GPSLongitude")
    if lat is not None and lon is not None:
        lines.append(f"[+] GPS: {lat}, {lon}")
        lines.append(
            f"[!] FLAGGED: GPS location embedded, {lat}, {lon} "
            f"(https://maps.google.com/?q={lat},{lon})"
        )

    if len(lines) <= 2:  # only the header + blank line were added
        return (
            f"No notable metadata found for '{file_path}' "
            "(no EXIF / GPS / author tags present)."
        )
    return "\n".join(lines)


async def run_exif_osint(
    file_path: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Extract embedded metadata from a local file using exiftool.

    Returns a descriptive error string on failure rather than raising.

    Parameters
    ----------
    file_path:
        Path to a local image, PDF, or media file.
    timeout_seconds:
        Maximum execution time for the exiftool subprocess.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    file_path = (file_path or "").strip()
    if not file_path:
        return "Error: file path cannot be empty."
    if not os.path.isfile(file_path):
        return f"Error: file not found: '{file_path}'."

    logger.info("Starting metadata extraction for: %s", file_path)
    try:
        raw = await _run_exiftool(file_path, timeout_seconds)
        result = _format_exif_results(raw, file_path)
        logger.info("Metadata extraction complete for: %s", file_path)
        return result
    except OSINTError as exc:
        logger.warning("EXIF scan failed: %s", exc)
        return f"Scan error: {exc}"
    except Exception as exc:
        logger.exception("Unexpected error during EXIF scan.")
        return f"Internal error: {exc}"
