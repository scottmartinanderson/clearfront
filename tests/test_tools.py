# tests/test_tools.py
"""
Tests for individual tool modules: binary-missing, API-key-missing,
input detection helpers, generate_dorks output, and session history.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture(autouse=True)
def _stub_whatsmyname(monkeypatch):
    """search_username now also queries WhatsMyName over the network. Stub it by
    default so the suite never hits the network; tests that exercise the merge
    set their own replacement (which wins, applied after this fixture)."""
    async def _stub(username, **kwargs):
        return []

    monkeypatch.setattr(
        "clearfront.tools.search_username.run_whatsmyname_check", _stub, raising=False
    )


# ---------------------------------------------------------------------------
# generate_dorks, pure computation, no external deps
# ---------------------------------------------------------------------------


class TestGenerateDorks:
    async def test_returns_non_empty_string(self):
        from clearfront.tools.generate_dorks import run_dork_osint

        result = await run_dork_osint("test@example.com")
        assert isinstance(result, str)
        assert len(result) > 0

    async def test_contains_google_search_url(self):
        from clearfront.tools.generate_dorks import run_dork_osint

        result = await run_dork_osint("johndoe")
        assert "google.com/search" in result

    async def test_target_appears_in_output(self):
        from clearfront.tools.generate_dorks import run_dork_osint

        result = await run_dork_osint("uniquetarget99")
        assert "uniquetarget99" in result

    async def test_produces_multiple_dork_lines(self):
        from clearfront.tools.generate_dorks import run_dork_osint

        result = await run_dork_osint("example.com")
        assert result.count("[+]") >= 5


# ---------------------------------------------------------------------------
# search_email, binary missing
# ---------------------------------------------------------------------------


class TestSearchEmailMissingBinary:
    async def test_returns_string_when_holehe_absent(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_email import run_email_osint

        result = await run_email_osint("test@example.com")
        assert isinstance(result, str)

    async def test_error_mentions_holehe(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_email import run_email_osint

        result = await run_email_osint("test@example.com")
        assert "holehe" in result.lower() or "scan error" in result.lower()

    async def test_does_not_raise(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_email import run_email_osint

        try:
            await run_email_osint("test@example.com")
        except Exception as exc:
            pytest.fail(f"run_email_osint raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# search_username, binary missing
# ---------------------------------------------------------------------------


class TestSearchUsernameMissingBinary:
    async def test_returns_string_when_sherlock_absent(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_username import run_username_osint

        result = await run_username_osint("johndoe")
        assert isinstance(result, str)

    async def test_error_mentions_sherlock(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_username import run_username_osint

        result = await run_username_osint("johndoe")
        assert "sherlock" in result.lower() or "scan error" in result.lower()

    async def test_does_not_raise(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_username import run_username_osint

        try:
            await run_username_osint("johndoe")
        except Exception as exc:
            pytest.fail(f"run_username_osint raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# search_email, holehe output parsing (banner / ANSI / legend stripping)
# ---------------------------------------------------------------------------


class TestSearchEmailParsing:
    # Mirrors real holehe stdout: author banner, ANSI screen-clear, asterisk box,
    # hits, legend, summary, then the banner again.
    _RAW = (
        "Twitter : @palenath\n"
        "Github : https://github.com/megadose/holehe\n"
        "For BTC Donations : 1FHDM49QfZX6pJmhjLE5tB2K6CaTLMZpXZ\n"
        "\x1b[H\x1b[J\n"
        "**********************\n"
        "   target@example.com\n"
        "**********************\n"
        "[+] amazon.com\n"
        "[+] eventbrite.com\n"
        "[+] office365.com\n"
        "[+] spotify.com\n"
        "\n"
        "[+] Email used, [-] Email not used, [x] Rate limit\n"
        "121 websites checked in 10.19 seconds\n"
        "Twitter : @palenath\n"
        "Github : https://github.com/megadose/holehe\n"
        "For BTC Donations : 1FHDM49QfZX6pJmhjLE5tB2K6CaTLMZpXZ\n"
    )

    def test_extracts_only_real_hits(self):
        from clearfront.tools.search_email import _parse_holehe

        assert _parse_holehe(self._RAW) == [
            "amazon.com",
            "eventbrite.com",
            "office365.com",
            "spotify.com",
        ]

    def test_format_strips_banner_ansi_and_legend(self):
        from clearfront.tools.search_email import _format_email_results

        out = _format_email_results(self._RAW, "target@example.com")
        assert "amazon.com" in out and "spotify.com" in out
        assert "4 service(s)" in out
        # holehe promo / control noise must all be gone
        assert "palenath" not in out
        assert "BTC" not in out and "megadose" not in out
        assert "\x1b" not in out
        assert "Email used" not in out
        assert "*****" not in out

    def test_no_hits_returns_clean_message(self):
        from clearfront.tools.search_email import _format_email_results

        raw = "Twitter : @palenath\n[+] Email used, [-] Email not used, [x] Rate limit\n"
        out = _format_email_results(raw, "x@y.com")
        assert "No registered" in out
        assert "palenath" not in out


# ---------------------------------------------------------------------------
# search_username, sherlock output parsing (noise stripping + FP caveat)
# ---------------------------------------------------------------------------


class TestSearchUsernameParsing:
    _RAW = (
        "[*] Checking username testuser__ on:\n"
        "[+] Chess: https://www.chess.com/member/testuser__\n"
        "[+] TikTok: https://www.tiktok.com/@testuser__\n"
        "[+] YouTube: https://www.youtube.com/@testuser__\n"
    )

    def test_parses_site_url_pairs(self):
        from clearfront.tools.search_username import _parse_sherlock

        hits = _parse_sherlock(self._RAW)
        assert ("Chess", "https://www.chess.com/member/testuser__") in hits
        assert len(hits) == 3

    def test_classify_rejects_4xx(self):
        from clearfront.tools.search_username import REJECTED, _classify

        assert _classify("bob", 404, "https://x.com/bob", "anything") == REJECTED

    def test_classify_rejects_redirect_away(self):
        from clearfront.tools.search_username import REJECTED, _classify

        # 200 but bounced to the homepage - username no longer in the final URL
        assert _classify("bob", 200, "https://x.com/", "homepage html") == REJECTED

    def test_classify_confirms_username_in_body(self):
        from clearfront.tools.search_username import CONFIRMED, _classify

        # case-insensitive match in the page body
        assert _classify("Bob", 200, "https://x.com/Bob", "<title>BOB</title>") == CONFIRMED

    def test_classify_unconfirmed_when_no_echo(self):
        from clearfront.tools.search_username import UNCONFIRMED, _classify

        assert _classify("bob", 200, "https://x.com/bob", "loading application") == UNCONFIRMED

    def test_format_verified_tiers_and_hides_rejected(self):
        from clearfront.tools.search_username import _format_verified

        results = [
            ("Chess", "https://chess.com/member/bob", "confirmed"),
            ("TikTok", "https://tiktok.com/@bob", "unconfirmed"),
            ("Fake", "https://fake.com/", "rejected"),
        ]
        out = _format_verified("bob", results)
        assert "CONFIRMED" in out and "chess.com" in out
        assert "UNCONFIRMED" in out and "tiktok.com" in out
        assert "Ruled out: 1" in out
        assert "fake.com" not in out  # rejected candidates are not shown

    def test_format_verified_none_found(self):
        from clearfront.tools.search_username import _format_verified

        out = _format_verified("bob", [("Fake", "https://fake.com/", "rejected")])
        assert "No verified accounts" in out


# ---------------------------------------------------------------------------
# search_domain, binary missing
# ---------------------------------------------------------------------------


class TestSearchDomainMissingBinary:
    async def test_returns_string_when_sublist3r_absent(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_domain import run_domain_osint

        result = await run_domain_osint("example.com")
        assert isinstance(result, str)

    async def test_error_mentions_sublist3r(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_domain import run_domain_osint

        result = await run_domain_osint("example.com")
        assert "sublist3r" in result.lower() or "scan error" in result.lower()

    async def test_does_not_raise(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_domain import run_domain_osint

        try:
            await run_domain_osint("example.com")
        except Exception as exc:
            pytest.fail(f"run_domain_osint raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# search_phone, binary missing
# ---------------------------------------------------------------------------


class TestSearchPhoneMissingBinary:
    async def test_returns_string_when_phoneinfoga_absent(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_phone import run_phone_osint

        result = await run_phone_osint("+14155552671")
        assert isinstance(result, str)

    async def test_error_mentions_phoneinfoga(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_phone import run_phone_osint

        result = await run_phone_osint("+14155552671")
        assert "phoneinfoga" in result.lower() or "scan error" in result.lower()

    async def test_does_not_raise(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *_, **__: None)
        from clearfront.tools.search_phone import run_phone_osint

        try:
            await run_phone_osint("+14155552671")
        except Exception as exc:
            pytest.fail(f"run_phone_osint raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# search_breach, API key missing
# ---------------------------------------------------------------------------


class TestSearchBreachMissingApiKey:
    async def test_returns_string_when_hibp_key_absent(self, monkeypatch):
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
        from clearfront.tools.search_breach import run_breach_osint

        result = await run_breach_osint("test@example.com")
        assert isinstance(result, str)

    async def test_error_mentions_hibp_key(self, monkeypatch):
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
        from clearfront.tools.search_breach import run_breach_osint

        result = await run_breach_osint("test@example.com")
        assert "HIBP_API_KEY" in result

    async def test_does_not_raise_when_key_absent(self, monkeypatch):
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
        from clearfront.tools.search_breach import run_breach_osint

        try:
            await run_breach_osint("test@example.com")
        except Exception as exc:
            pytest.fail(f"run_breach_osint raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# search_virustotal, API key missing + input detection
# ---------------------------------------------------------------------------


class TestSearchVirusTotalMissingApiKey:
    async def test_returns_string_when_vt_key_absent(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        from clearfront.tools.search_virustotal import run_virustotal_osint

        result = await run_virustotal_osint("8.8.8.8")
        assert isinstance(result, str)

    async def test_error_mentions_virustotal_key(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        from clearfront.tools.search_virustotal import run_virustotal_osint

        result = await run_virustotal_osint("example.com")
        assert "VIRUSTOTAL_API_KEY" in result

    async def test_does_not_raise_when_key_absent(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        from clearfront.tools.search_virustotal import run_virustotal_osint

        try:
            await run_virustotal_osint("https://evil.example.com")
        except Exception as exc:
            pytest.fail(f"run_virustotal_osint raised unexpectedly: {exc}")


class TestVirusTotalInputDetection:
    def test_detects_ipv4(self):
        from clearfront.tools.search_virustotal import _detect_input_type

        assert _detect_input_type("8.8.8.8") == "ip"
        assert _detect_input_type("192.168.1.1") == "ip"
        assert _detect_input_type("0.0.0.0") == "ip"

    def test_detects_https_url(self):
        from clearfront.tools.search_virustotal import _detect_input_type

        assert _detect_input_type("https://example.com/path") == "url"

    def test_detects_http_url(self):
        from clearfront.tools.search_virustotal import _detect_input_type

        assert _detect_input_type("http://evil.com/malware.exe") == "url"

    def test_detects_md5_hash(self):
        from clearfront.tools.search_virustotal import _detect_input_type

        assert _detect_input_type("a" * 32) == "hash"

    def test_detects_sha1_hash(self):
        from clearfront.tools.search_virustotal import _detect_input_type

        assert _detect_input_type("a" * 40) == "hash"

    def test_detects_sha256_hash(self):
        from clearfront.tools.search_virustotal import _detect_input_type

        assert _detect_input_type("a" * 64) == "hash"

    def test_detects_domain(self):
        from clearfront.tools.search_virustotal import _detect_input_type

        assert _detect_input_type("example.com") == "domain"
        assert _detect_input_type("evil.site.ru") == "domain"

    def test_non_ip_non_hash_non_url_is_domain(self):
        from clearfront.tools.search_virustotal import _detect_input_type

        assert _detect_input_type("clearfront.github.io") == "domain"


# ---------------------------------------------------------------------------
# search_ip, output formatting
# ---------------------------------------------------------------------------


class TestSearchIpFormatting:
    def test_format_bogon(self):
        from clearfront.tools.search_ip import _format_ip_results

        result = _format_ip_results({"bogon": True}, "192.168.1.1")
        assert "bogon" in result.lower() or "private" in result.lower()

    def test_format_real_ip(self):
        from clearfront.tools.search_ip import _format_ip_results

        data = {
            "ip": "8.8.8.8",
            "org": "AS15169 Google LLC",
            "city": "Mountain View",
            "country": "US",
        }
        result = _format_ip_results(data, "8.8.8.8")
        assert "8.8.8.8" in result
        assert "Google" in result


class TestSearchIpAutoDetect:
    def test_self_aliases_recognised(self):
        from clearfront.tools.search_ip import _is_self_lookup

        assert _is_self_lookup("")
        assert _is_self_lookup("   ")
        assert _is_self_lookup("me")
        assert _is_self_lookup("SELF")
        assert _is_self_lookup("mine")
        assert not _is_self_lookup("8.8.8.8")
        assert not _is_self_lookup("example.com")

    def test_request_uses_self_endpoint_when_no_ip(self):
        import clearfront.tools.search_ip as mod

        url, _ = mod._ipinfo_request("")
        assert url == mod._IPINFO_SELF_URL

    def test_request_uses_targeted_endpoint_for_explicit_ip(self):
        import clearfront.tools.search_ip as mod

        url, _ = mod._ipinfo_request("8.8.8.8")
        assert url == "https://ipinfo.io/8.8.8.8/json"

    def test_request_includes_token_when_set(self):
        import clearfront.tools.search_ip as mod

        _, params = mod._ipinfo_request("8.8.8.8", api_key="tok123")
        assert params == {"token": "tok123"}

    async def test_run_autodetect_reports_detected_ip(self, monkeypatch):
        import clearfront.tools.search_ip as mod

        async def fake_fetch(ip, timeout_seconds, api_key=None):
            return {"ip": "203.0.113.7", "city": "Berlin", "org": "AS3320 Example ISP"}

        monkeypatch.setattr(mod, "_fetch_ip_data", fake_fetch)
        result = await mod.run_ip_osint("")
        assert "203.0.113.7" in result
        assert "your public IP" in result
        assert "VPN" in result  # self-lookup advisory note

    async def test_run_explicit_ip_has_no_self_note(self, monkeypatch):
        import clearfront.tools.search_ip as mod

        async def fake_fetch(ip, timeout_seconds, api_key=None):
            return {"ip": "8.8.8.8", "org": "AS15169 Google LLC"}

        monkeypatch.setattr(mod, "_fetch_ip_data", fake_fetch)
        result = await mod.run_ip_osint("8.8.8.8")
        assert "8.8.8.8" in result
        assert "your public IP" not in result


class TestSearchExposure:
    def test_format_report_ranks_risks_first(self):
        from clearfront.tools.search_exposure import _format_report

        report = _format_report(
            resolved_ip="203.0.113.7",
            ipinfo={"ip": "203.0.113.7", "city": "Berlin", "country": "DE", "org": "AS3320 ISP"},
            ptr="host.example.net",
            dnsbls=["Spamhaus ZEN", "SpamCop"],
            ip2l=None,
            is_self=True,
        )
        assert "203.0.113.7" in report
        assert "your public IP" in report
        assert "1 risk(s)" in report
        assert "Spamhaus ZEN" in report
        # severity order: RISK before WATCH before INFO
        assert report.index("[RISK]") < report.index("[WATCH]") < report.index("[INFO]")

    def test_format_report_clean_ip_has_no_risks(self):
        from clearfront.tools.search_exposure import _format_report

        report = _format_report(
            resolved_ip="8.8.8.8",
            ipinfo={"ip": "8.8.8.8", "city": "Mountain View", "org": "AS15169 Google LLC"},
            ptr=None,
            dnsbls=[],
            ip2l=None,
            is_self=False,
        )
        assert "0 risk(s)" in report
        assert "[RISK]" not in report
        assert "your public IP" not in report
        assert "Google LLC" in report

    def test_format_report_includes_ip2location_flags(self):
        from clearfront.tools.search_exposure import _format_report

        report = _format_report(
            resolved_ip="1.2.3.4",
            ipinfo={"ip": "1.2.3.4"},
            ptr=None,
            dnsbls=[],
            ip2l={
                "is_proxy": False, "is_vpn": True, "is_tor": False,
                "is_datacenter": True, "threat": "", "isp": "ExampleVPN",
            },
            is_self=False,
        )
        assert "VPN/proxy" in report
        assert "datacenter" in report.lower()

    def test_dnsbl_reverses_ipv4_and_skips_ipv6(self):
        from unittest.mock import patch

        import clearfront.tools.search_exposure as mod

        # IPv6 / malformed → no lookups, empty result
        assert mod._dnsbl_listings("2001:db8::1") == []

        captured = []

        def fake_resolve(self, name, rdtype):
            captured.append(name)
            if name.startswith("4.3.2.1.zen.spamhaus.org"):
                return [object()]
            raise Exception("not listed")

        with patch.object(mod.dns.resolver.Resolver, "resolve", fake_resolve):
            listed = mod._dnsbl_listings("1.2.3.4")
        assert listed == ["Spamhaus ZEN"]
        assert any(n.startswith("4.3.2.1.") for n in captured)

    async def test_run_exposure_autodetect_with_blocklist(self, monkeypatch):
        import clearfront.tools.search_exposure as mod

        async def _fake_fetch(ip, t):
            return {"ip": "203.0.113.9", "city": "Oslo", "org": "AS1 X"}

        monkeypatch.delenv("IP2LOCATION_API_KEY", raising=False)
        monkeypatch.setattr(mod, "_fetch_ip_data", _fake_fetch)
        monkeypatch.setattr(mod, "_reverse_ptr", lambda ip: "mail.acme.com")
        monkeypatch.setattr(mod, "_dnsbl_listings", lambda ip: ["Spamhaus ZEN"])

        result = await mod.run_exposure_osint("")
        assert "203.0.113.9" in result
        assert "your public IP" in result
        assert "[RISK]" in result and "Spamhaus ZEN" in result
        assert "mail.acme.com" in result

    async def test_run_exposure_bogon(self, monkeypatch):
        import clearfront.tools.search_exposure as mod

        async def _fake_fetch(ip, t):
            return {"bogon": True, "ip": "10.0.0.1"}

        monkeypatch.setattr(mod, "_fetch_ip_data", _fake_fetch)
        result = await mod.run_exposure_osint("10.0.0.1")
        assert "bogon" in result.lower() or "private" in result.lower()


# ---------------------------------------------------------------------------
# search_paste, output formatting
# ---------------------------------------------------------------------------


class TestSearchPasteFormatting:
    def test_format_no_results(self):
        from clearfront.tools.search_paste import _format_results

        result = _format_results("johndoe", [], "", [])
        assert "johndoe" in result
        assert "no pastes" in result.lower()

    def test_format_with_hibp_pastes(self):
        from clearfront.tools.search_paste import _format_results

        pastes = [{"Source": "Pastebin", "Id": "abc123", "Date": "2022-01-01", "EmailCount": 42}]
        result = _format_results("test@example.com", pastes, "", [])
        assert "pastebin.com/abc123" in result
        assert "HIBP" in result
        assert "42" in result

    def test_format_with_serp_results(self):
        from clearfront.tools.search_paste import _format_results

        serp = [{"url": "https://pastebin.com/xyz", "snippet": "leaked creds here"}]
        result = _format_results("acme", [], "Bright Data SERP", serp)
        assert "pastebin.com/xyz" in result
        assert "Bright Data SERP" in result

    def test_paste_dork_restricts_to_paste_sites(self):
        from clearfront.tools.search_paste import _paste_dork

        dork = _paste_dork("foo@bar.com")
        assert '"foo@bar.com"' in dork
        assert "site:pastebin.com" in dork
        assert "site:paste.ee" in dork

    def test_hibp_paste_link_pastebin(self):
        from clearfront.tools.search_paste import _hibp_paste_link

        assert _hibp_paste_link("Pastebin", "abc") == "https://pastebin.com/abc"
        assert "id: zzz" in _hibp_paste_link("AdHocUrl", "zzz")

    async def test_run_paste_combines_backends(self, monkeypatch):
        import clearfront.tools.search_paste as mod

        async def fake_to_thread(fn, *args, **kwargs):
            if fn is mod._fetch_hibp_pastes:
                return [{"Source": "Pastebin", "Id": "p1", "Date": "2021-01-01", "EmailCount": 5}]
            if fn is mod._serp_paste_search:
                return ("Bright Data SERP", [{"url": "https://paste.ee/p/abc", "snippet": "x"}])
            return None

        monkeypatch.setattr(mod.asyncio, "to_thread", fake_to_thread)
        result = await mod.run_paste_osint("victim@example.com")
        assert "pastebin.com/p1" in result
        assert "paste.ee/p/abc" in result

    async def test_run_paste_empty_query(self):
        from clearfront.tools.search_paste import run_paste_osint

        result = await run_paste_osint("")
        assert "must not be empty" in result


# ---------------------------------------------------------------------------
# search_whois, output formatting
# ---------------------------------------------------------------------------


class TestSearchWhoisFormatting:
    def test_format_no_data(self):
        from clearfront.tools.search_whois import _format_whois_results

        class FakeWhois:
            domain_name = None
            registrar = None
            creation_date = None
            expiration_date = None
            updated_date = None
            name_servers = None
            emails = None
            org = None
            country = None

        result = _format_whois_results(FakeWhois(), "example.com")
        assert "example.com" in result

    def test_format_with_registrar(self):
        from clearfront.tools.search_whois import _format_whois_results

        class FakeWhois:
            domain_name = "EXAMPLE.COM"
            registrar = "GoDaddy"
            creation_date = None
            expiration_date = None
            updated_date = None
            name_servers = None
            emails = None
            org = None
            country = None

        result = _format_whois_results(FakeWhois(), "example.com")
        assert "GoDaddy" in result


# ---------------------------------------------------------------------------
# search_shodan, output formatting helpers
# ---------------------------------------------------------------------------


class TestSearchShodanFormatters:
    def test_format_host_with_ports(self):
        from clearfront.tools.search_shodan import _format_host

        data = {
            "ip_str": "8.8.8.8",
            "org": "Google LLC",
            "country_name": "United States",
            "data": [{"port": 80}, {"port": 443}],
        }
        result = _format_host(data, "8.8.8.8")
        assert "8.8.8.8" in result
        assert "Google" in result
        assert "80" in result

    def test_format_search_no_matches(self):
        from clearfront.tools.search_shodan import _format_search

        result = _format_search({"total": 0, "matches": []}, "apache port:80")
        assert "No Shodan results" in result or "apache" in result

    def test_format_search_with_matches(self):
        from clearfront.tools.search_shodan import _format_search

        results = {
            "total": 1,
            "matches": [
                {"ip_str": "1.2.3.4", "port": 80, "org": "Acme", "location": {"country_name": "US"}}
            ],
        }
        result = _format_search(results, "apache")
        assert "1.2.3.4" in result


class TestSearchShodanNoData:
    async def test_json_parse_error_maps_to_clear_no_data_message(self, monkeypatch):
        """A 404 (no record for the host) is reported by the shodan lib as
        'Unable to parse JSON response'. We surface a clear no-data message
        (with a plan/credits hint) rather than the raw library error."""
        monkeypatch.setenv("SHODAN_API_KEY", "dummy")
        import shodan

        from clearfront.tools import search_shodan

        def boom(*args, **kwargs):
            raise shodan.APIError("Unable to parse JSON response")

        monkeypatch.setattr(shodan.Shodan, "host", boom, raising=False)
        result = await search_shodan.run_shodan_osint("8.8.8.8")
        assert "no shodan data" in result.lower()
        assert "query credits" in result.lower()
        assert "parse json" not in result.lower()


# ---------------------------------------------------------------------------
# search_censys, API key missing + input detection
# ---------------------------------------------------------------------------


class TestSearchCensysMissingPat:
    async def test_returns_string_when_pat_absent(self, monkeypatch):
        monkeypatch.delenv("CENSYS_PAT", raising=False)
        monkeypatch.delenv("CENSYS_SECRET", raising=False)
        from clearfront.tools.search_censys import run_censys_osint

        result = await run_censys_osint("8.8.8.8")
        assert isinstance(result, str)

    async def test_error_mentions_censys_pat(self, monkeypatch):
        monkeypatch.delenv("CENSYS_PAT", raising=False)
        monkeypatch.delenv("CENSYS_SECRET", raising=False)
        from clearfront.tools.search_censys import run_censys_osint

        result = await run_censys_osint("8.8.8.8")
        assert "CENSYS_PAT" in result

    async def test_does_not_raise_when_pat_absent(self, monkeypatch):
        monkeypatch.delenv("CENSYS_PAT", raising=False)
        monkeypatch.delenv("CENSYS_SECRET", raising=False)
        from clearfront.tools.search_censys import run_censys_osint

        try:
            await run_censys_osint("8.8.8.8")
        except Exception as exc:
            pytest.fail(f"run_censys_osint raised unexpectedly: {exc}")


class TestSearchCensysOrgIdOptional:
    async def test_org_id_not_required(self, monkeypatch):
        """A PAT with no org id is sufficient, the tool proceeds to the lookup
        (the token implies its org) rather than erroring on a missing org id."""
        monkeypatch.setenv("CENSYS_PAT", "censys_dummy")
        monkeypatch.delenv("CENSYS_ORG_ID", raising=False)
        import clearfront.tools.search_censys as mod

        async def fake_to_thread(fn, *args, **kwargs):
            return "[Censys] Type: ip"

        monkeypatch.setattr(mod.asyncio, "to_thread", fake_to_thread)
        result = await mod.run_censys_osint("8.8.8.8")
        assert "CENSYS_ORG_ID" not in result
        assert "[Censys]" in result

    async def test_org_id_passed_to_sdk_when_set(self, monkeypatch):
        monkeypatch.setenv("CENSYS_PAT", "censys_dummy")
        monkeypatch.setenv("CENSYS_ORG_ID", "org-123")
        from clearfront.tools.search_censys import _sdk_kwargs

        assert _sdk_kwargs("pat", "org-123") == {
            "personal_access_token": "pat",
            "organization_id": "org-123",
        }
        assert _sdk_kwargs("pat", "") == {"personal_access_token": "pat"}

    async def test_pat_falls_back_to_censys_secret(self, monkeypatch):
        """A PAT stored under the legacy CENSYS_SECRET slot still satisfies auth."""
        monkeypatch.delenv("CENSYS_PAT", raising=False)
        monkeypatch.setenv("CENSYS_SECRET", "censys_legacy_slot_pat")
        import clearfront.tools.search_censys as mod

        captured = {}

        async def fake_to_thread(fn, pat, org, target):
            captured["pat"] = pat
            return "[Censys] ok"

        monkeypatch.setattr(mod.asyncio, "to_thread", fake_to_thread)
        result = await mod.run_censys_osint("8.8.8.8")
        assert captured["pat"] == "censys_legacy_slot_pat"
        assert "[Censys]" in result

    async def test_free_plan_search_returns_clear_message(self, monkeypatch):
        """The paid-only search endpoint 403 surfaces a helpful message, not a
        misleading 'authentication failed'."""
        monkeypatch.setenv("CENSYS_PAT", "censys_dummy")
        import clearfront.tools.search_censys as mod

        async def fake_to_thread(fn, *args, **kwargs):
            raise RuntimeError(
                '{"status":403,"detail":"This endpoint requires an organization '
                'id for API access. Free users can only access this endpoint '
                'through the Platform UI."}'
            )

        monkeypatch.setattr(mod.asyncio, "to_thread", fake_to_thread)
        result = await mod.run_censys_osint("example.com")
        assert "paid Censys plan" in result
        assert "authentication failed" not in result.lower()


class TestSearchCensysFormatters:
    def test_format_ip_result_extracts_ports_services_asn(self):
        from clearfront.tools.search_censys import _format_ip_result

        host = {
            "ip": "8.8.8.8",
            "services": [
                {"port": 443, "protocol": "HTTPS"},
                {"port": 53, "protocol": "DNS"},
                {"port": 53, "protocol": "DNS"},
            ],
            "autonomous_system": {"asn": 15169, "name": "GOOGLE"},
            "location": {"country": "United States"},
        }
        out = _format_ip_result(host, "8.8.8.8")
        assert "8.8.8.8" in out
        assert "443" in out and "53" in out
        assert "HTTPS" in out and "DNS" in out
        assert "AS15169" in out and "GOOGLE" in out
        assert "United States" in out

    def test_format_ip_result_handles_empty_host(self):
        from clearfront.tools.search_censys import _format_ip_result

        out = _format_ip_result({}, "1.1.1.1")
        assert "1.1.1.1" in out
        assert isinstance(out, str)

    def test_format_domain_result_extracts_certs(self):
        from clearfront.tools.search_censys import _format_domain_result

        certs = [
            {
                "names": ["example.com", "www.example.com"],
                "parsed": {
                    "issuer": {"organization": ["DigiCert Inc"]},
                    "validity_period": {
                        "not_before": "2024-01-01T00:00:00Z",
                        "not_after": "2025-01-01T00:00:00Z",
                    },
                },
            }
        ]
        out = _format_domain_result(certs, "example.com")
        assert "Certificates Found: 1" in out
        assert "DigiCert Inc" in out
        assert "example.com" in out
        assert "2024-01-01" in out and "2025-01-01" in out

    def test_format_domain_result_handles_no_certs(self):
        from clearfront.tools.search_censys import _format_domain_result

        out = _format_domain_result([], "example.com")
        assert "Certificates Found: 0" in out


class TestSearchCensysInputDetection:
    def test_detects_ipv4(self):
        from clearfront.tools.search_censys import _is_ip_address

        assert _is_ip_address("8.8.8.8") is True
        assert _is_ip_address("192.168.1.1") is True
        assert _is_ip_address("0.0.0.0") is True

    def test_detects_domain(self):
        from clearfront.tools.search_censys import _is_ip_address

        assert _is_ip_address("example.com") is False
        assert _is_ip_address("sub.example.com") is False

    def test_non_ip_string_is_not_ip(self):
        from clearfront.tools.search_censys import _is_ip_address

        assert _is_ip_address("not-an-ip") is False
        assert _is_ip_address("google.com") is False


class TestSearchCensysHandlesInvalidIp:
    async def test_does_not_raise_on_invalid_input(self, monkeypatch):
        monkeypatch.delenv("CENSYS_PAT", raising=False)
        monkeypatch.delenv("CENSYS_SECRET", raising=False)
        from clearfront.tools.search_censys import run_censys_osint

        try:
            result = await run_censys_osint("999.999.999.999")
            assert isinstance(result, str)
        except Exception as exc:
            pytest.fail(f"run_censys_osint raised unexpectedly: {exc}")

    async def test_does_not_raise_on_domain(self, monkeypatch):
        monkeypatch.delenv("CENSYS_PAT", raising=False)
        monkeypatch.delenv("CENSYS_SECRET", raising=False)
        from clearfront.tools.search_censys import run_censys_osint

        try:
            result = await run_censys_osint("nonexistent.example.invalid")
            assert isinstance(result, str)
        except Exception as exc:
            pytest.fail(f"run_censys_osint raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# Session history, save, load, count, clear
# ---------------------------------------------------------------------------


class TestSessionHistory:
    def test_save_and_load_round_trip(self, tmp_path, monkeypatch):
        import clearfront.session_history as sh

        monkeypatch.setattr(sh, "HISTORY_DIR", tmp_path / "history")
        from clearfront.session_history import SessionRecord, load_sessions, save_session

        record = SessionRecord(
            timestamp="2026-05-17T12:00:00",
            duration_seconds=42,
            prompts=["investigate test@example.com"],
            tools_used=["search_email", "search_breach"],
            targets=["test@example.com"],
            report_path="reports/2026-05-17_report.md",
        )
        save_session(record)
        sessions = load_sessions()
        assert len(sessions) == 1
        s = sessions[0]
        assert s["timestamp"] == "2026-05-17T12:00:00"
        assert s["duration_seconds"] == 42
        assert s["prompts"] == ["investigate test@example.com"]
        assert s["tools_used"] == ["search_email", "search_breach"]
        assert s["targets"] == ["test@example.com"]

    def test_load_empty_when_dir_absent(self, tmp_path, monkeypatch):
        import clearfront.session_history as sh

        monkeypatch.setattr(sh, "HISTORY_DIR", tmp_path / "nonexistent")
        from clearfront.session_history import load_sessions

        assert load_sessions() == []

    def test_count_sessions_zero_when_empty(self, tmp_path, monkeypatch):
        import clearfront.session_history as sh

        monkeypatch.setattr(sh, "HISTORY_DIR", tmp_path / "history")
        from clearfront.session_history import count_sessions

        assert count_sessions() == 0

    def test_count_sessions_after_save(self, tmp_path, monkeypatch):
        import clearfront.session_history as sh

        monkeypatch.setattr(sh, "HISTORY_DIR", tmp_path / "history")
        from clearfront.session_history import SessionRecord, count_sessions, save_session

        save_session(SessionRecord(timestamp="2026-05-17T10:00:00", duration_seconds=5))
        save_session(SessionRecord(timestamp="2026-05-17T11:00:00", duration_seconds=10))
        assert count_sessions() == 2

    def test_load_limit_respected(self, tmp_path, monkeypatch):
        import clearfront.session_history as sh

        monkeypatch.setattr(sh, "HISTORY_DIR", tmp_path / "history")
        from clearfront.session_history import SessionRecord, load_sessions, save_session

        for i in range(5):
            save_session(
                SessionRecord(
                    timestamp=f"2026-05-17T1{i}:00:00",
                    duration_seconds=i,
                )
            )
        sessions = load_sessions(limit=3)
        assert len(sessions) == 3

    def test_clear_sessions_deletes_all(self, tmp_path, monkeypatch):
        import clearfront.session_history as sh

        monkeypatch.setattr(sh, "HISTORY_DIR", tmp_path / "history")
        from clearfront.session_history import (
            SessionRecord,
            clear_sessions,
            count_sessions,
            save_session,
        )

        save_session(SessionRecord(timestamp="2026-05-17T12:00:00", duration_seconds=1))
        save_session(SessionRecord(timestamp="2026-05-17T13:00:00", duration_seconds=2))
        deleted = clear_sessions()
        assert deleted == 2
        assert count_sessions() == 0

    def test_clear_sessions_when_no_history(self, tmp_path, monkeypatch):
        import clearfront.session_history as sh

        monkeypatch.setattr(sh, "HISTORY_DIR", tmp_path / "nonexistent")
        from clearfront.session_history import clear_sessions

        assert clear_sessions() == 0

    def test_load_newest_first(self, tmp_path, monkeypatch):
        import clearfront.session_history as sh

        monkeypatch.setattr(sh, "HISTORY_DIR", tmp_path / "history")
        from clearfront.session_history import SessionRecord, load_sessions, save_session

        save_session(SessionRecord(timestamp="2026-05-17T09:00:00", duration_seconds=1))
        save_session(SessionRecord(timestamp="2026-05-17T11:00:00", duration_seconds=2))
        sessions = load_sessions()
        assert sessions[0]["duration_seconds"] == 2


# ---------------------------------------------------------------------------
# run_subprocess, venv-bin path resolution (fix/venv-bin-tool-discovery)
# ---------------------------------------------------------------------------


class TestRunSubprocessPathResolution:
    async def test_search_path_includes_python_executable_dir(self):
        import sys
        from pathlib import Path

        from clearfront.tools.exceptions import ToolNotFoundError
        from clearfront.utils import run_subprocess

        captured: dict = {}

        def spy_which(name, path=None):
            captured["path"] = path
            return None

        with patch("shutil.which", side_effect=spy_which):
            with pytest.raises(ToolNotFoundError):
                await run_subprocess("fakebinary", [], 5)

        expected_prefix = str(Path(sys.executable).parent)
        assert captured.get("path", "").startswith(expected_prefix)

    async def test_resolved_full_path_passed_to_exec(self):
        from clearfront.utils import run_subprocess

        resolved_path = "/fake/venv/bin/mytool"
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"out", b"")
        mock_proc.returncode = 0

        with patch("shutil.which", return_value=resolved_path):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
                await run_subprocess("mytool", ["--arg"], 5)

        assert mock_exec.call_args[0][0] == resolved_path


# ---------------------------------------------------------------------------
# search_maigret, parsing, formatting, guards
# ---------------------------------------------------------------------------

_MAIGRET_SAMPLE = """[+] Using sites database: /path/to/data.json (3155 sites)
[-] Starting a search on top 69 sites...
[*] Checking username octocat on:
[+] GitHub: https://github.com/octocat
 ├─uid: 583231
 ├─location: San Francisco
 └─created_at: 2011-01-25T18:44:36Z
[+] Twitter: https://twitter.com/octocat
 ├─fullname: Octocat
 └─follower_count: 7
[+] SoundCloud: https://soundcloud.com/octocat
"""


class TestSearchMaigretParsing:
    def test_parse_extracts_hits_and_details(self):
        from clearfront.tools.search_maigret import _parse

        hits = _parse(_MAIGRET_SAMPLE)
        sites = [h[0] for h in hits]
        assert sites == ["GitHub", "Twitter", "SoundCloud"]
        # details captured for GitHub
        gh = dict(hits[0][2])
        assert gh["location"] == "San Francisco"
        assert gh["uid"] == "583231"

    def test_parse_excludes_database_banner(self):
        from clearfront.tools.search_maigret import _parse

        hits = _parse(_MAIGRET_SAMPLE)
        assert all("database" not in h[0].lower() for h in hits)

    def test_parse_urls_captured(self):
        from clearfront.tools.search_maigret import _parse

        urls = [h[1] for h in _parse(_MAIGRET_SAMPLE)]
        assert "https://github.com/octocat" in urls


class TestSearchMaigretFormatting:
    def test_format_no_hits(self):
        from clearfront.tools.search_maigret import _format

        out = _format([], "ghost")
        assert "No accounts found" in out
        assert "ghost" in out

    def test_format_with_hits_shows_sites_and_details(self):
        from clearfront.tools.search_maigret import _parse, _format

        out = _format(_parse(_MAIGRET_SAMPLE), "octocat")
        assert "GitHub: https://github.com/octocat" in out
        assert "3" in out  # count of accounts
        assert "location: San Francisco" in out


class TestSearchMaigretGuards:
    async def test_empty_username(self):
        from clearfront.tools.search_maigret import run_maigret_osint

        assert "must not be empty" in await run_maigret_osint("")

    async def test_leading_dash_rejected(self):
        from clearfront.tools.search_maigret import run_maigret_osint

        assert "must not start with" in await run_maigret_osint("-aXfV")

    async def test_run_uses_parsed_output(self, monkeypatch):
        import clearfront.tools.search_maigret as mod

        async def fake_run(username, top_sites, timeout_seconds):
            return _MAIGRET_SAMPLE

        monkeypatch.setattr(mod, "_run_maigret", fake_run)
        out = await mod.run_maigret_osint("octocat")
        assert "GitHub" in out and "Twitter" in out


# ---------------------------------------------------------------------------
# search_gravatar, hash + profile formatting (pure, no network)
# ---------------------------------------------------------------------------


class TestSearchGravatar:
    def test_email_hash_is_md5_of_lowercased_trimmed(self):
        from clearfront.tools.search_gravatar import _email_hash

        # md5("user@example.com"), case/whitespace must be normalised first.
        assert _email_hash("  User@EXAMPLE.com ") == "b58996c504c5638798eb6b511e6f49af"

    def test_format_profile_renders_name_and_linked_accounts(self):
        from clearfront.tools.search_gravatar import _format_profile

        entry = {
            "displayName": "Jane Doe",
            "currentLocation": "Berlin",
            "accounts": [
                {"shortname": "github", "url": "https://github.com/jane", "verified": True},
                {"shortname": "twitter", "url": "https://x.com/jane", "verified": "true"},
            ],
        }
        out = _format_profile(entry, "jane@example.com", "deadbeef")
        assert "Jane Doe" in out
        assert "Berlin" in out
        assert "github" in out and "https://github.com/jane" in out
        assert "(verified)" in out
        # tool output must not contain em/en dashes (analyst voice rule)
        assert "—" not in out and "–" not in out

    async def test_invalid_email_returns_error_without_network(self):
        from clearfront.tools.search_gravatar import run_gravatar_osint

        for bad in ("", "   ", "not-an-email", "-flag@x.com"):
            out = await run_gravatar_osint(bad)
            assert out.startswith("Error:")

    async def test_does_not_raise(self):
        from clearfront.tools.search_gravatar import run_gravatar_osint

        try:
            await run_gravatar_osint("notanemail")
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"run_gravatar_osint raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# search_emailrep, keyed tool; key-missing + formatting (pure, no network)
# ---------------------------------------------------------------------------


class TestSearchEmailRep:
    async def test_missing_key_returns_needs_key_message(self, monkeypatch):
        monkeypatch.delenv("EMAILREP_API_KEY", raising=False)
        from clearfront.tools.search_emailrep import run_emailrep_osint

        out = await run_emailrep_osint("test@example.com")
        assert out.startswith("Scan error: EMAILREP_API_KEY")

    def test_format_renders_reputation_profiles_and_flags(self):
        from clearfront.tools.search_emailrep import _format_emailrep

        sample = {
            "email": "jane@example.com",
            "reputation": "high",
            "suspicious": False,
            "references": 42,
            "details": {
                "profiles": ["twitter", "linkedin", "github"],
                "data_breach": True,
                "credentials_leaked": True,
                "first_seen": "01/01/2015",
                "deliverable": True,
            },
        }
        out = _format_emailrep(sample, "jane@example.com")
        assert "high" in out
        assert "twitter" in out and "github" in out
        assert "data breach" in out  # risk flag description
        assert "—" not in out and "–" not in out  # no em/en dashes

    async def test_invalid_email_returns_error(self):
        from clearfront.tools.search_emailrep import run_emailrep_osint

        out = await run_emailrep_osint("notanemail")
        assert out.startswith("Error:")

    async def test_does_not_raise(self, monkeypatch):
        monkeypatch.delenv("EMAILREP_API_KEY", raising=False)
        from clearfront.tools.search_emailrep import run_emailrep_osint

        try:
            await run_emailrep_osint("notanemail")
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"run_emailrep_osint raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# whatsmyname, bundled-data checker (pure rules + no-network guard)
# ---------------------------------------------------------------------------


class TestWhatsMyName:
    def test_account_exists_rules(self):
        from clearfront.tools.whatsmyname import _account_exists

        site = {"e_code": 200, "e_string": "avatar-container"}
        assert _account_exists(200, "<div class='avatar-container'>", site) is True
        assert _account_exists(404, "avatar-container", site) is False  # wrong status
        assert _account_exists(200, "no marker here", site) is False  # marker absent
        # an empty detection string must never confirm (avoids bare-200 false positives)
        assert _account_exists(200, "anything", {"e_code": 200, "e_string": ""}) is False

    def test_bundled_subset_loads(self):
        from clearfront.tools.whatsmyname import _load_sites

        sites = _load_sites()
        assert len(sites) > 100
        assert all("uri_check" in s for s in sites[:25])

    async def test_invalid_username_returns_empty_without_network(self):
        from clearfront.tools.whatsmyname import run_whatsmyname_check

        assert await run_whatsmyname_check("-bad") == []
        assert await run_whatsmyname_check("") == []


class TestUsernameMergesWhatsMyName:
    async def test_wmn_confirmations_merge_into_results(self, monkeypatch):
        import clearfront.tools.search_username as mod

        async def fake_sherlock(username, timeout_seconds):
            return ""  # no sherlock hits

        async def fake_wmn(username):
            return [("CoolSite", f"https://cool.example/u/{username}")]

        monkeypatch.setattr(mod, "_run_sherlock", fake_sherlock)
        monkeypatch.setattr(mod, "run_whatsmyname_check", fake_wmn)
        out = await mod.run_username_osint("octocat")
        assert "CoolSite" in out
        assert "CONFIRMED" in out
        assert "WhatsMyName" in out


# ---------------------------------------------------------------------------
# search_crypto, address detection + formatting (pure, no network)
# ---------------------------------------------------------------------------


class TestSearchCrypto:
    def test_detect_rules(self):
        from clearfront.tools.search_crypto import _detect

        assert _detect("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "btc"  # legacy
        assert _detect("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == "btc"  # bech32
        assert _detect("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045") == "eth"
        assert _detect("not-an-address") is None
        assert _detect("0xZZZ") is None

    def test_fmt_amount_trims_zeros(self):
        from clearfront.tools.search_crypto import _fmt_amount

        assert _fmt_amount(1.5, "BTC") == "1.5 BTC"
        assert _fmt_amount(0, "ETH") == "0 ETH"
        assert _fmt_amount(2.0, "BTC") == "2 BTC"

    async def test_invalid_address_returns_error_without_network(self):
        from clearfront.tools.search_crypto import run_crypto_osint

        out = await run_crypto_osint("definitely not an address")
        assert out.startswith("Error: not a recognized")

    async def test_does_not_raise(self):
        from clearfront.tools.search_crypto import run_crypto_osint

        try:
            await run_crypto_osint("garbage")
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"run_crypto_osint raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# search_harvester (theHarvester), domain validation + formatting (pure)
# ---------------------------------------------------------------------------


class TestSearchHarvester:
    def test_is_domain_rules(self):
        from clearfront.tools.search_harvester import _is_domain

        assert _is_domain("example.com") is True
        assert _is_domain("sub.example.co.uk") is True
        assert _is_domain("not a domain") is False
        assert _is_domain("-bad.com") is True  # leading hyphen in a label is allowed by the regex
        assert _is_domain("nodot") is False

    def test_clean_host_strips_ip(self):
        from clearfront.tools.search_harvester import _clean_host

        assert _clean_host("mail.example.com:1.2.3.4") == "mail.example.com"
        assert _clean_host("WWW.Example.com") == "www.example.com"

    def test_format_orders_emails_people_hosts(self):
        from clearfront.tools.search_harvester import _format_harvester

        data = {
            "emails": ["A@x.com", "a@x.com", "b@x.com"],
            "hosts": ["mail.x.com:1.2.3.4", "www.x.com", "mail.x.com"],
            "linkedin_people": ["Jane Doe"],
        }
        out = _format_harvester(data, "x.com")
        assert "Emails (2)" in out  # deduped + lowercased
        assert "a@x.com" in out and "b@x.com" in out
        assert "Jane Doe" in out and "People" in out
        assert "mail.x.com" in out and "www.x.com" in out
        assert "—" not in out and "–" not in out

    async def test_invalid_domain_returns_error_without_network(self):
        from clearfront.tools.search_harvester import run_harvester_osint

        out = await run_harvester_osint("definitely not a domain")
        assert out.startswith("Error: a valid domain")
