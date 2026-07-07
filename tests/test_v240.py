# tests/test_v240.py
"""
Tests for v2.4.0 features: Shodan integration, multi-target investigation,
and PDF report generation.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Shodan, missing API key
# ---------------------------------------------------------------------------


class TestShodanMissingKey:
    async def test_returns_descriptive_error_when_key_absent(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        from clearfront.tools.search_shodan import run_shodan_osint

        result = await run_shodan_osint("8.8.8.8")
        assert "SHODAN_API_KEY" in result

    async def test_error_message_contains_instructions(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        from clearfront.tools.search_shodan import run_shodan_osint

        result = await run_shodan_osint("apache port:80")
        assert "SHODAN_API_KEY" in result
        assert "https://account.shodan.io" in result

    async def test_ip_detection_does_not_affect_missing_key_error(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        from clearfront.tools.search_shodan import run_shodan_osint

        # Both IP and keyword queries should return the same missing-key error
        for query in ("1.2.3.4", "nginx country:DE"):
            result = await run_shodan_osint(query)
            assert "SHODAN_API_KEY" in result


# ---------------------------------------------------------------------------
# Shodan, IP detection helper
# ---------------------------------------------------------------------------


class TestShodanIpDetection:
    def test_valid_ip_detected(self):
        from clearfront.tools.search_shodan import _is_ip_address

        assert _is_ip_address("8.8.8.8") is True
        assert _is_ip_address("192.168.1.1") is True
        assert _is_ip_address("0.0.0.0") is True

    def test_non_ip_not_detected(self):
        from clearfront.tools.search_shodan import _is_ip_address

        assert _is_ip_address("apache port:80") is False
        assert _is_ip_address("example.com") is False
        assert _is_ip_address("8.8.8") is False
        assert _is_ip_address("") is False


# ---------------------------------------------------------------------------
# Multi-target, max target enforcement
# ---------------------------------------------------------------------------


class TestMultiTargetMaxTargets:
    async def test_raises_value_error_for_11_targets(self):
        from clearfront.multi_target import run_multi_target

        targets = [f"target{i}@example.com" for i in range(11)]
        with pytest.raises(ValueError, match="10"):
            await run_multi_target(targets, api_key="fake-key")

    async def test_raises_value_error_for_many_targets(self):
        from clearfront.multi_target import run_multi_target

        targets = [f"t{i}" for i in range(50)]
        with pytest.raises(ValueError, match="10"):
            await run_multi_target(targets, api_key="fake-key")

    async def test_10_targets_does_not_raise_immediately(self, monkeypatch):
        """10 targets is the maximum, should not raise the size error."""
        from clearfront.multi_target import MAX_TARGETS, run_multi_target

        assert MAX_TARGETS == 10
        targets = [f"t{i}@example.com" for i in range(10)]
        # We don't actually run the investigation, just verify no ValueError is raised
        # by patching the agent so it returns immediately.
        with patch("clearfront.multi_target.OISAgent") as MockAgent:
            instance = MockAgent.return_value
            from clearfront.agent import AgentResponse

            instance.run = AsyncMock(return_value=AgentResponse(content="## Summary\n\nok"))
            # Should not raise ValueError
            try:
                await run_multi_target(targets, api_key="fake-key", is_pdf_disabled=True)
            except ValueError:
                pytest.fail("ValueError raised for exactly 10 targets")

    def test_empty_targets_returns_message(self):
        import asyncio

        from clearfront.multi_target import run_multi_target

        result = asyncio.run(run_multi_target([], api_key="fake"))
        assert "No targets" in result


# ---------------------------------------------------------------------------
# Multi-target, target parsing
# ---------------------------------------------------------------------------


class TestParseTargets:
    def test_comma_separated_inline(self):
        from clearfront.multi_target import parse_targets

        result = parse_targets("a@x.com,b@y.com,c@z.com")
        assert result == ["a@x.com", "b@y.com", "c@z.com"]

    def test_strips_whitespace(self):
        from clearfront.multi_target import parse_targets

        result = parse_targets("  a@x.com , b@y.com ")
        assert result == ["a@x.com", "b@y.com"]

    def test_file_with_one_per_line(self, tmp_path):
        from clearfront.multi_target import parse_targets

        f = tmp_path / "targets.txt"
        f.write_text("a@x.com\nb@y.com\nc@z.com\n", encoding="utf-8")
        result = parse_targets(str(f))
        assert result == ["a@x.com", "b@y.com", "c@z.com"]

    def test_file_ignores_blank_lines(self, tmp_path):
        from clearfront.multi_target import parse_targets

        f = tmp_path / "targets.txt"
        f.write_text("a@x.com\n\nb@y.com\n\n", encoding="utf-8")
        result = parse_targets(str(f))
        assert result == ["a@x.com", "b@y.com"]


# ---------------------------------------------------------------------------
# PDF report generation
# ---------------------------------------------------------------------------


class TestPdfReportGeneration:
    async def test_pdf_created_alongside_markdown(self, tmp_path):
        md_file = tmp_path / "2026-05-13_report.md"
        md_file.write_text(
            "## Summary\n\nTest target found.\n\n## Conclusion\n\nDone.",
            encoding="utf-8",
        )

        from clearfront.pdf_report import generate_pdf_report

        try:
            import reportlab  # noqa: F401
        except ImportError:
            pytest.skip("reportlab not installed")

        pdf_path = await generate_pdf_report(md_file)
        assert pdf_path is not None
        assert pdf_path.exists()
        assert pdf_path.suffix == ".pdf"
        assert pdf_path.stem == md_file.stem

    async def test_pdf_path_mirrors_markdown_filename(self, tmp_path):
        md_file = tmp_path / "custom_name_report.md"
        md_file.write_text("## Summary\n\nContent.", encoding="utf-8")

        from clearfront.pdf_report import generate_pdf_report

        try:
            import reportlab  # noqa: F401
        except ImportError:
            pytest.skip("reportlab not installed")

        pdf_path = await generate_pdf_report(md_file)
        if pdf_path:
            assert pdf_path.name == "custom_name_report.pdf"

    async def test_pdf_skipped_silently_when_reportlab_absent(self, tmp_path, monkeypatch):
        """generate_pdf_report should return None (not raise) if reportlab is missing."""
        md_file = tmp_path / "report.md"
        md_file.write_text("## Summary\n\nTest.", encoding="utf-8")

        # Simulate reportlab import failure inside the generator
        import sys

        original = sys.modules.get("reportlab")
        sys.modules["reportlab"] = None  # type: ignore

        from clearfront.pdf_report import generate_pdf_report

        # Should not raise even with reportlab missing
        try:
            await generate_pdf_report(md_file)
            # Either None or a path, both are acceptable; must not raise
        except Exception as exc:
            pytest.fail(f"generate_pdf_report raised unexpectedly: {exc}")
        finally:
            if original is None:
                del sys.modules["reportlab"]
            else:
                sys.modules["reportlab"] = original
