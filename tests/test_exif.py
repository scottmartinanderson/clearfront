# tests/test_exif.py
"""
Unit tests for the search_exif tool (clearfront/tools/search_exif.py).

All exiftool calls are mocked, no real binary is invoked, no network, no
real metadata read. Real temp files are used so the on-disk existence check
passes naturally.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from clearfront.tools.exceptions import ToolNotFoundError, ToolTimeoutError
from clearfront.utils import SubprocessResult


def _result(stdout: str) -> SubprocessResult:
    return SubprocessResult(stdout=stdout, stderr="", return_code=0)


class TestSearchExif:
    async def test_gps_is_flagged(self, tmp_path):
        f = tmp_path / "photo.jpg"
        f.write_bytes(b"x")
        payload = json.dumps(
            [{
                "FileType": "JPEG",
                "Make": "Apple",
                "Model": "iPhone 15",
                "GPSLatitude": 51.5074,
                "GPSLongitude": -0.1278,
            }]
        )
        with patch("clearfront.tools.search_exif.run_subprocess", new=AsyncMock(return_value=_result(payload))):
            from clearfront.tools.search_exif import run_exif_osint

            result = await run_exif_osint(str(f))
        assert "FLAGGED" in result
        assert "GPS" in result
        assert "51.5074" in result and "-0.1278" in result
        assert "iPhone 15" in result

    async def test_no_gps_no_flag(self, tmp_path):
        f = tmp_path / "edited.png"
        f.write_bytes(b"x")
        payload = json.dumps([{"FileType": "PNG", "Software": "Adobe Photoshop"}])
        with patch("clearfront.tools.search_exif.run_subprocess", new=AsyncMock(return_value=_result(payload))):
            from clearfront.tools.search_exif import run_exif_osint

            result = await run_exif_osint(str(f))
        assert "Adobe Photoshop" in result
        assert "FLAGGED" not in result

    async def test_no_metadata(self, tmp_path):
        f = tmp_path / "blank.jpg"
        f.write_bytes(b"x")
        with patch("clearfront.tools.search_exif.run_subprocess", new=AsyncMock(return_value=_result("[{}]"))):
            from clearfront.tools.search_exif import run_exif_osint

            result = await run_exif_osint(str(f))
        assert "no" in result.lower() and "metadata" in result.lower()

    async def test_missing_binary_returns_scan_error(self, tmp_path):
        f = tmp_path / "x.jpg"
        f.write_bytes(b"x")
        with patch(
            "clearfront.tools.search_exif.run_subprocess",
            new=AsyncMock(side_effect=ToolNotFoundError("'exiftool' is not installed")),
        ):
            from clearfront.tools.search_exif import run_exif_osint

            result = await run_exif_osint(str(f))
        assert "Scan error" in result
        assert "exiftool" in result.lower()

    async def test_timeout_returns_scan_error(self, tmp_path):
        f = tmp_path / "x.jpg"
        f.write_bytes(b"x")
        with patch(
            "clearfront.tools.search_exif.run_subprocess",
            new=AsyncMock(side_effect=ToolTimeoutError("'exiftool' scan timed out")),
        ):
            from clearfront.tools.search_exif import run_exif_osint

            result = await run_exif_osint(str(f))
        assert "Scan error" in result

    async def test_bad_json_does_not_raise(self, tmp_path):
        f = tmp_path / "x.jpg"
        f.write_bytes(b"x")
        with patch("clearfront.tools.search_exif.run_subprocess", new=AsyncMock(return_value=_result("not json"))):
            from clearfront.tools.search_exif import run_exif_osint

            result = await run_exif_osint(str(f))
        assert isinstance(result, str)
        assert "error" in result.lower()

    async def test_missing_file_returns_error(self):
        from clearfront.tools.search_exif import run_exif_osint

        result = await run_exif_osint("/nonexistent/path/nope.jpg")
        assert "not found" in result.lower()

    async def test_empty_path_returns_error(self):
        from clearfront.tools.search_exif import run_exif_osint

        result = await run_exif_osint("   ")
        assert "empty" in result.lower()
