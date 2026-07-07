# tests/test_cli_output.py
"""CLI -o/--output writes raw results to a file instead of stdout."""

from __future__ import annotations

import json

from clearfront import cli


def test_output_flag_parses_before_and_after_subcommand():
    p = cli._build_parser()
    assert p.parse_args(["-o", "out.json", "ip", "8.8.8.8"]).output == "out.json"
    assert p.parse_args(["ip", "8.8.8.8", "-o", "out.json"]).output == "out.json"
    assert getattr(p.parse_args(["ip", "8.8.8.8"]), "output", None) is None


def test_print_result_writes_raw_without_banner(tmp_path, monkeypatch):
    f = tmp_path / "out.txt"
    monkeypatch.setattr(cli, "_OUTPUT_FILE", str(f))
    cli._print_result("SCAN CONTENT HERE")
    content = f.read_text(encoding="utf-8")
    assert "SCAN CONTENT HERE" in content
    assert "SCAN RESULTS" not in content  # no banner written to the file


def test_labeled_results_append(tmp_path, monkeypatch):
    f = tmp_path / "out.txt"
    f.write_text("", encoding="utf-8")  # truncated at startup normally
    monkeypatch.setattr(cli, "_OUTPUT_FILE", str(f))
    cli._print_result_labeled("search_email", "AAA")
    cli._print_result_labeled("search_breach", "BBB")
    content = f.read_text(encoding="utf-8")
    assert "=== search_email ===" in content and "AAA" in content
    assert "=== search_breach ===" in content and "BBB" in content


def test_json_output_written_to_file(tmp_path, monkeypatch):
    f = tmp_path / "out.json"
    monkeypatch.setattr(cli, "_OUTPUT_FILE", str(f))
    cli._emit_json({"tool": "search_ip", "ok": True})
    assert json.loads(f.read_text(encoding="utf-8")) == {"tool": "search_ip", "ok": True}


def test_no_output_file_prints_to_stdout_with_banner(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_OUTPUT_FILE", None)
    cli._print_result("VISIBLE ON STDOUT")
    out = capsys.readouterr().out
    assert "VISIBLE ON STDOUT" in out
    assert "SCAN RESULTS" in out  # banner shown on stdout
