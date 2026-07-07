# tests/test_report_export.py
"""POST /api/report/export renders a report's Markdown to a downloadable PDF."""

from __future__ import annotations

import pytest

REPORT_MD = (
    "## INTELLIGENCE SUMMARY\n"
    "Subject maps to a single individual. Confidence: moderate, based on two "
    "URL-verified accounts.\n\n"
    "## SOURCES\n"
    "- Sherlock: 2 accounts verified. Reliability: high.\n"
)


def _client():
    try:
        from fastapi.testclient import TestClient
    except Exception:  # pragma: no cover - httpx/testclient missing
        pytest.skip("fastapi TestClient unavailable")
    from clearfront.web_server import create_app

    return TestClient(create_app())


def test_export_returns_pdf():
    try:
        import reportlab  # noqa: F401
    except ImportError:
        pytest.skip("reportlab not installed")

    resp = _client().post("/api/report/export", json={"markdown": REPORT_MD, "title": "unit-test"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert resp.content[:5] == b"%PDF-"


def test_export_rejects_empty_report():
    resp = _client().post("/api/report/export", json={"markdown": "   ", "title": "x"})
    assert resp.status_code == 400


def test_export_sanitizes_filename():
    try:
        import reportlab  # noqa: F401
    except ImportError:
        pytest.skip("reportlab not installed")

    resp = _client().post(
        "/api/report/export",
        json={"markdown": REPORT_MD, "title": "../../etc/pas swd"},
    )
    assert resp.status_code == 200
    disp = resp.headers.get("content-disposition", "")
    # Path separators and spaces must not survive into the download filename.
    assert "/" not in disp.split("filename=")[-1]
    assert " " not in disp.split("filename=")[-1].strip('"')
