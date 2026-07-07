# tests/test_repl_first_run.py
"""REPL first-run: interactive key setup instead of a bare error, and .env persistence."""

from __future__ import annotations

import os


def test_persist_creates_env(tmp_path):
    from clearfront.repl import OISRepl

    env = tmp_path / ".env"
    p = OISRepl._persist_key_to_env("sk-ant-xyz", env)
    assert p == env
    assert "ANTHROPIC_API_KEY=sk-ant-xyz" in env.read_text(encoding="utf-8")


def test_persist_does_not_duplicate_existing_key(tmp_path):
    from clearfront.repl import OISRepl

    env = tmp_path / ".env"
    env.write_text("ANTHROPIC_API_KEY=existing\n", encoding="utf-8")
    OISRepl._persist_key_to_env("sk-ant-new", env)
    content = env.read_text(encoding="utf-8")
    assert content.count("ANTHROPIC_API_KEY=") == 1  # left as-is, not duplicated
    assert "existing" in content


def test_persist_appends_with_separating_newline(tmp_path):
    from clearfront.repl import OISRepl

    env = tmp_path / ".env"
    env.write_text("HIBP_API_KEY=abc", encoding="utf-8")  # no trailing newline
    OISRepl._persist_key_to_env("sk-ant-xyz", env)
    lines = env.read_text(encoding="utf-8").splitlines()
    assert "HIBP_API_KEY=abc" in lines
    assert "ANTHROPIC_API_KEY=sk-ant-xyz" in lines


def test_persist_returns_none_on_unwritable_path(tmp_path):
    from clearfront.repl import OISRepl

    # A path whose parent does not exist cannot be written.
    bad = tmp_path / "nope" / "deeper" / ".env"
    assert OISRepl._persist_key_to_env("sk-ant-xyz", bad) is None


def test_first_run_accepts_key(monkeypatch, tmp_path):
    from clearfront.repl import OISRepl

    monkeypatch.setattr(os, "environ", dict(os.environ))  # isolate env writes
    os.environ.pop("ANTHROPIC_API_KEY", None)
    r = OISRepl.__new__(OISRepl)  # avoid PromptSession/FileHistory side effects
    r._api_key = ""
    monkeypatch.setattr("builtins.input", lambda *a, **k: "sk-ant-test")
    monkeypatch.setattr(
        OISRepl, "_persist_key_to_env", staticmethod(lambda key, env_path=None: tmp_path / ".env")
    )
    assert r._first_run_setup() is True
    assert r._api_key == "sk-ant-test"
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-test"


def test_first_run_skip_returns_false(monkeypatch):
    from clearfront.repl import OISRepl

    monkeypatch.setattr(os, "environ", dict(os.environ))
    os.environ.pop("ANTHROPIC_API_KEY", None)
    r = OISRepl.__new__(OISRepl)
    r._api_key = ""
    monkeypatch.setattr("builtins.input", lambda *a, **k: "   ")  # whitespace = skip
    assert r._first_run_setup() is False
