# tests/test_authorized_use.py
"""Authorized-use posture is legible at the moment of action (REPL banner + web note)."""

from __future__ import annotations

from pathlib import Path

import clearfront


def test_repl_banner_states_authorized_use(capsys):
    from clearfront import repl

    repl._print_banner("anthropic", "claude-sonnet-4")
    out = capsys.readouterr().out
    assert "Authorized use only" in out


def test_web_console_has_no_auth_banner():
    # The authorized-use posture lives in the REPL banner and the legal docs, not
    # as a web-console banner (removed by product decision to keep the console clean).
    html = (Path(clearfront.__file__).parent / "web" / "index.html").read_text(encoding="utf-8")
    assert "triggerAuthNote" not in html
    assert "cf_auth_ack" not in html
