# tests/test_hudsonrock.py
"""Hudson Rock infostealer-exposure tool (ICE #22): defensive metadata, never plaintext."""

from __future__ import annotations

from clearfront.tools.search_hudsonrock import (
    _format_response,
    _looks_like_email,
    _malware_filename,
    run_hudsonrock_osint,
)

# A realistic Cavalier free-tier response. It carries credential fields (masked by
# Hudson Rock) and identifying machine strings; the tool must surface none of them.
EXPOSED = {
    "message": "This email address is associated with a compromised computer.",
    "total_user_services": 42,
    "total_corporate_services": 3,
    "stealers": [
        {
            "date_compromised": "2022-03-14",
            "operating_system": "Windows 10 Pro",
            "malware_path": "C:\\Users\\alice_secret\\Downloads\\invoice.exe",
            "antiviruses": ["Windows Defender"],
            "ip": "180.252.***.**",
            "top_passwords": ["@********m", "P@ssw0rd123"],
            "top_logins": ["alice.private@gmail.com", "r**********@gmail.com"],
            "computer_name": "DESKTOP-ALICE-SECRET",
        }
    ],
}


def test_looks_like_email():
    assert _looks_like_email("a@b.com") is True
    assert _looks_like_email("alice.smith@sub.example.co.uk") is True
    assert _looks_like_email("johndoe99") is False
    assert _looks_like_email("not an email") is False


def test_malware_filename_strips_identifying_directory():
    # The Windows username embedded in the path must be dropped; only the IOC remains.
    assert _malware_filename("C:\\Users\\alice_secret\\Downloads\\invoice.exe") == "invoice.exe"
    assert _malware_filename("/tmp/build/setup.bin") == "setup.bin"
    assert _malware_filename("") == ""


async def test_rejects_empty_input():
    out = await run_hudsonrock_osint("")
    assert out.startswith("Error:")


def test_clean_response():
    data = {"message": "not associated with a compromised computer", "stealers": []}
    out = _format_response("safe@example.com", data)
    assert "CLEAN" in out
    assert "not found in the free infostealer index" in out
    assert "[RISK]" not in out


def test_exposed_response_surfaces_defensive_metadata():
    out = _format_response("alice@example.com", EXPOSED)
    assert "[RISK]" in out and "EXPOSED" in out
    assert "1 infection" in out
    assert "2022-03-14" in out
    assert "Windows 10 Pro" in out
    assert "invoice.exe" in out  # malware basename IOC is surfaced
    assert "42 user" in out and "3 corporate" in out
    assert "rotate passwords" in out.lower()


def test_never_echoes_credentials_or_machine_identity():
    out = _format_response("alice@example.com", EXPOSED)
    forbidden = [
        "@********m",  # masked password
        "P@ssw0rd123",  # a plaintext-looking password: still never surfaced
        "alice.private@gmail.com",  # a compromised login
        "r**********@gmail.com",  # masked login
        "DESKTOP-ALICE-SECRET",  # identifying machine name
        "alice_secret",  # Windows username from the malware path
        "180.252",  # (masked) infected-machine IP
        "C:\\Users",  # full malware path / directory
    ]
    for secret in forbidden:
        assert secret not in out, f"tool leaked sensitive field: {secret!r}"


def test_caps_number_of_infections_shown():
    many = {"stealers": [{"date_compromised": f"2020-01-{d:02d}"} for d in range(1, 9)]}
    out = _format_response("alice@example.com", many)
    assert "8 infections" in out  # header reports the true total
    assert "and 3 more infection(s)" in out  # body caps at 5 and notes the rest


def test_handles_non_dict_payload():
    assert "No usable data" in _format_response("x@y.com", ["unexpected"])


def test_not_auto_pivoted():
    # Infostealer data is sensitive and authorized-use; it must stay analyst-invoked,
    # never wired into the auto-pivot routes.
    from clearfront import pivot

    routed = set()
    for tools in pivot._TOOL_ROUTES.values():
        routed.update(tools)
    assert "search_hudsonrock" not in routed
