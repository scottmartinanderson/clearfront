# tests/test_security.py
"""
Regression tests for the security hardening:
  - argument-injection guards on the binary-wrapper tools (reject leading '-')
  - SSRF guard on scrape_url (block localhost / private / metadata targets)

All network-free: the guards reject before any subprocess or HTTP call.
"""

from __future__ import annotations


class TestArgInjectionGuards:
    async def test_email_rejects_leading_dash(self):
        from clearfront.tools.search_email import run_email_osint

        result = await run_email_osint("-oG/tmp/x@example.com")
        assert "invalid" in result.lower()

    async def test_username_rejects_leading_dash(self):
        from clearfront.tools.search_username import run_username_osint

        result = await run_username_osint("--output")
        assert "invalid" in result.lower()

    async def test_domain_rejects_leading_dash(self):
        from clearfront.tools.search_domain import run_domain_osint

        result = await run_domain_osint("-d")
        assert "invalid" in result.lower()

    async def test_phone_rejects_leading_dash(self):
        from clearfront.tools.search_phone import run_phone_osint

        result = await run_phone_osint("-n")
        assert "invalid" in result.lower()


class TestScrapeSSRFGuard:
    async def test_blocks_localhost(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")
        from clearfront.tools.scrape_url import run_scrape_url_osint

        result = await run_scrape_url_osint("http://localhost:8080/admin")
        assert "ssrf" in result.lower() or "internal" in result.lower()

    async def test_blocks_cloud_metadata_ip(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")
        from clearfront.tools.scrape_url import run_scrape_url_osint

        result = await run_scrape_url_osint("http://169.254.169.254/latest/meta-data/")
        assert "ssrf" in result.lower() or "internal" in result.lower()

    async def test_blocks_private_rfc1918(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")
        from clearfront.tools.scrape_url import run_scrape_url_osint

        result = await run_scrape_url_osint("http://192.168.1.1/")
        assert "ssrf" in result.lower() or "internal" in result.lower()


# ---------------------------------------------------------------------------
# Web-console network-exposure hardening
#
# The console has no auth by design and is safe on the default 127.0.0.1 bind.
# The shipped Docker image binds 0.0.0.0, so the following endpoints must refuse
# dangerous input when the server is network-exposed (_PUBLIC_BIND). See the
# 2026-07 security review.
# ---------------------------------------------------------------------------


def _testclient(host_guard: bool = False):
    import pytest

    try:
        from fastapi.testclient import TestClient
    except Exception:  # pragma: no cover - httpx/testclient missing
        pytest.skip("fastapi TestClient unavailable")
    from clearfront.web_server import create_app

    return TestClient(create_app(host_guard=host_guard))


class TestPublicBindDetection:
    def test_loopback_is_not_public(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", False)
        for host in ("127.0.0.1", "localhost", ""):
            ws._set_public_bind(host)
            assert ws._PUBLIC_BIND is False, host

    def test_non_loopback_is_public(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", False)
        for host in ("0.0.0.0", "192.168.1.10", "10.0.0.5"):
            ws._set_public_bind(host)
            assert ws._PUBLIC_BIND is True, host


class TestBackendUrlSSRFGuard:
    def test_local_bind_allows_internal_backend(self, monkeypatch):
        """A local operator may legitimately point at their own Ollama/LiteLLM."""
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", False)
        assert ws._reject_backend_url("http://localhost:11434") is None
        assert ws._reject_backend_url("http://127.0.0.1:4000/v1") is None

    def test_public_bind_blocks_internal_backend(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", True)
        for url in (
            "http://localhost:11434",
            "http://127.0.0.1:4000/v1",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1/",
        ):
            assert ws._reject_backend_url(url) is not None, url
        # A genuine external endpoint is still allowed.
        assert ws._reject_backend_url("https://api.openai.com/v1") is None

    def test_non_http_scheme_always_rejected(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", False)
        for url in ("file:///etc/passwd", "gopher://x/", "ftp://host/"):
            assert ws._reject_backend_url(url) is not None, url

    def test_openai_test_endpoint_blocks_internal_on_public_bind(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", True)
        resp = _testclient().post(
            "/api/openai/test", json={"openai_base_url": "http://169.254.169.254/"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("blocked")
        assert body["reachable"] is False


class TestSetupEndpointHardening:
    def test_setup_refused_on_public_bind(self, monkeypatch, tmp_path):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", True)
        monkeypatch.setattr(ws, "_ROOT", tmp_path)
        resp = _testclient().post("/api/setup", json={"ANTHROPIC_API_KEY": "x"})
        assert resp.status_code == 403
        assert not (tmp_path / ".env").exists()

    def test_setup_allowlists_keys_on_local_bind(self, monkeypatch, tmp_path):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", False)
        monkeypatch.setattr(ws, "_ROOT", tmp_path)
        resp = _testclient().post(
            "/api/setup",
            json={"HIBP_API_KEY": "good", "EVIL_INJECTED_KEY": "pwn", "PATH": "/x"},
        )
        assert resp.status_code == 200
        accepted = resp.json().get("accepted", [])
        assert "HIBP_API_KEY" in accepted
        assert "EVIL_INJECTED_KEY" not in accepted
        assert "PATH" not in accepted
        written = (tmp_path / ".env").read_text()
        assert "HIBP_API_KEY=good" in written
        assert "EVIL_INJECTED_KEY" not in written
        assert "PATH=/x" not in written


class TestLocalFileToolGating:
    def test_exif_blocked_over_network(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", True)
        resp = _testclient().post("/api/run/search_exif", json={"input": "/etc/hosts"})
        assert resp.status_code == 403
        assert "disabled" in resp.json()["output"].lower()

    def test_exif_allowed_on_local_bind(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", False)
        resp = _testclient().post("/api/run/search_exif", json={"input": "/no/such/file"})
        # Runs the tool (200); may report "file not found" or "not installed",
        # but must NOT be the network-exposed refusal.
        assert resp.status_code == 200
        assert "disabled on a network-exposed" not in resp.json()["output"].lower()

    async def test_agent_run_tool_blocks_exif_over_network(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setattr(ws, "_PUBLIC_BIND", True)
        out = await ws._run_tool("search_exif", "/etc/hosts")
        assert "disabled" in out.lower()


class TestHostHeaderAllowlist:
    def test_foreign_host_rejected_when_guarded(self):
        resp = _testclient(host_guard=True).get(
            "/api/health", headers={"Host": "evil.example.com"}
        )
        assert resp.status_code == 400

    def test_localhost_host_accepted_when_guarded(self):
        resp = _testclient(host_guard=True).get(
            "/api/health", headers={"Host": "127.0.0.1:8080"}
        )
        assert resp.status_code == 200


class TestHealthKeyLeak:
    def test_maps_key_withheld_on_public_bind(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setenv("GOOGLE_MAPS_API_KEY", "secret-maps-key")
        monkeypatch.setattr(ws, "_PUBLIC_BIND", True)
        resp = _testclient().get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["google_maps_api_key"] == ""

    def test_maps_key_present_on_local_bind(self, monkeypatch):
        from clearfront import web_server as ws

        monkeypatch.setenv("GOOGLE_MAPS_API_KEY", "secret-maps-key")
        monkeypatch.setattr(ws, "_PUBLIC_BIND", False)
        resp = _testclient().get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["google_maps_api_key"] == "secret-maps-key"


class TestPdfHeadingEscaping:
    def test_heading_img_tag_is_escaped(self):
        import pytest

        try:
            from reportlab.lib.styles import getSampleStyleSheet  # noqa: F401
        except ImportError:
            pytest.skip("reportlab not installed")
        from reportlab.lib.styles import getSampleStyleSheet

        from clearfront.pdf_report import _build_pdf_styles, _build_pdf_story

        styles = _build_pdf_styles(getSampleStyleSheet())
        payload = (
            '# <img src="http://169.254.169.254/latest/meta-data/"/>\n'
            '## <img src="http://10.0.0.1/x"/>\n'
        )
        story = _build_pdf_story(payload, styles, "2026-01-01")
        texts = [getattr(p, "text", "") for p in story]
        joined = "\n".join(texts)
        # The raw tag must never survive into a reportlab Paragraph (it would be
        # parsed as markup and trigger an outbound image fetch = SSRF).
        assert "<img" not in joined
        assert "&lt;img" in joined
