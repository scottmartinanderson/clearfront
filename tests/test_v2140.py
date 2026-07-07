# tests/test_v2140.py
"""Tests for v2.14.0, AbuseIPDB integration."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from clearfront.tools.search_abuseipdb import run_abuseipdb_osint


def _mock_payload(score: int = 25) -> dict:
    return {
        "data": {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": score,
            "totalReports": 3,
            "countryCode": "US",
            "isp": "Example ISP",
            "domain": "example.com",
            "lastReportedAt": "2024-01-01T00:00:00+00:00",
        }
    }


async def test_missing_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    result = await run_abuseipdb_osint("8.8.8.8")
    assert "Scan error" in result
    assert "ABUSEIPDB_API_KEY" in result


async def test_invalid_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    result = await run_abuseipdb_osint("not-an-ip")
    assert result == "Invalid IP address format."


async def test_valid_ipv4_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    with patch(
        "clearfront.tools.search_abuseipdb._fetch_abuseipdb_data",
        new_callable=AsyncMock,
        return_value=_mock_payload(score=25),
    ):
        result = await run_abuseipdb_osint("1.2.3.4")
    assert "Abuse Confidence Score" in result
    assert "25%" in result


async def test_high_score_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    with patch(
        "clearfront.tools.search_abuseipdb._fetch_abuseipdb_data",
        new_callable=AsyncMock,
        return_value=_mock_payload(score=85),
    ):
        result = await run_abuseipdb_osint("1.2.3.4")
    assert "HIGH ABUSE CONFIDENCE" in result


async def test_low_score_no_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    with patch(
        "clearfront.tools.search_abuseipdb._fetch_abuseipdb_data",
        new_callable=AsyncMock,
        return_value=_mock_payload(score=0),
    ):
        result = await run_abuseipdb_osint("8.8.8.8")
    assert "HIGH ABUSE CONFIDENCE" not in result


async def test_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    with patch(
        "clearfront.tools.search_abuseipdb._fetch_abuseipdb_data",
        new_callable=AsyncMock,
        side_effect=aiohttp.ClientError("connection failed"),
    ):
        result = await run_abuseipdb_osint("1.2.3.4")
    assert "Scan error" in result
    assert "Network error" in result
