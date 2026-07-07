# tests/test_graph_export.py
"""Deterministic graph export (ICE #23): D3 exporters, web endpoint, CLI artifact."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

from clearfront.correlation import (
    EntityGraph,
    EntityType,
    Relationship,
    d3_to_graphml,
    d3_to_json,
    d3_to_mermaid,
    make_entity,
)

# An LLM-authored evidence graph (the web console's shape). "ghost" is referenced by a
# link but never declared as a node, so that link must be dropped as dangling.
WEB_GRAPH = {
    "nodes": [
        {"id": "e", "label": "a@b.com", "type": "EMAIL", "value": "a@b.com", "confidence": "verified"},
        {"id": "s", "label": "alice", "type": "SUBJECT", "value": "alice", "severity": ""},
        {"id": "b", "label": "AcmeBreach", "type": "BREACH", "value": "Acme 2021", "severity": "risk"},
    ],
    "links": [
        {"source": "s", "target": "e"},
        {"source": "e", "target": "b"},
        {"source": "s", "target": "ghost"},  # dangling -> dropped
    ],
}


# ---------------------------------------------------------------------------
# Generic D3 exporters
# ---------------------------------------------------------------------------


def test_d3_to_json_drops_dangling_and_whitelists_fields():
    data = json.loads(d3_to_json(WEB_GRAPH))
    assert len(data["nodes"]) == 3
    assert len(data["links"]) == 2  # the ghost link is gone
    # Empty fields (severity == "") are omitted; populated ones survive.
    subject = next(n for n in data["nodes"] if n["id"] == "s")
    assert "severity" not in subject
    email = next(n for n in data["nodes"] if n["id"] == "e")
    assert email["confidence"] == "verified"


def test_d3_to_json_is_deterministic_regardless_of_input_order():
    shuffled = {
        "nodes": list(reversed(WEB_GRAPH["nodes"])),
        "links": list(reversed(WEB_GRAPH["links"])),
    }
    assert d3_to_json(WEB_GRAPH) == d3_to_json(shuffled)


def test_d3_to_graphml_is_valid_xml_with_expected_counts():
    xml = d3_to_graphml(WEB_GRAPH)
    root = ET.fromstring(xml)
    ns = {"g": "http://graphml.graphdrawing.org/graphml"}
    nodes = root.findall(".//g:node", ns)
    edges = root.findall(".//g:edge", ns)
    assert len(nodes) == 3
    assert len(edges) == 2  # dangling edge dropped
    # A node's type is exported as a data value.
    assert "SUBJECT" in xml and "BREACH" in xml


def test_d3_to_graphml_is_deterministic():
    shuffled = {"nodes": list(reversed(WEB_GRAPH["nodes"])), "links": WEB_GRAPH["links"]}
    assert d3_to_graphml(WEB_GRAPH) == d3_to_graphml(shuffled)


def test_d3_to_mermaid_shape_and_sanitization():
    out = d3_to_mermaid(WEB_GRAPH)
    assert out.startswith("graph TD")
    # 3 node lines + 2 edge lines.
    assert out.count("-->") == 2
    # Unsafe characters are stripped from the label; only the ["..."] delimiters remain.
    tricky = {"nodes": [{"id": "x", "label": 'a"[b]<c>'}], "links": []}
    assert 'n0["abc"]' in d3_to_mermaid(tricky)


def test_d3_handles_link_endpoints_as_objects():
    # After the force-graph library renders, link endpoints become node objects.
    mutated = {
        "nodes": [{"id": "s", "label": "s"}, {"id": "e", "label": "e"}],
        "links": [{"source": {"id": "s"}, "target": {"id": "e"}}],
    }
    assert len(json.loads(d3_to_json(mutated))["links"]) == 1


def test_d3_exporters_handle_empty_graph():
    assert json.loads(d3_to_json({"nodes": [], "links": []})) == {"nodes": [], "links": []}
    assert d3_to_mermaid({}) == "graph TD"
    ET.fromstring(d3_to_graphml({}))  # still valid XML


# ---------------------------------------------------------------------------
# Web endpoint: POST /api/graph/export
# ---------------------------------------------------------------------------


def _client():
    try:
        from fastapi.testclient import TestClient
    except Exception:  # pragma: no cover - testclient missing
        pytest.skip("fastapi TestClient unavailable")
    from clearfront.web_server import create_app

    return TestClient(create_app())


@pytest.mark.parametrize(
    "fmt,ctype,ext",
    [
        ("graphml", "application/graphml+xml", "graphml"),
        ("json", "application/json", "json"),
        ("mermaid", "text/plain", "mmd"),
    ],
)
def test_graph_export_endpoint_formats(fmt, ctype, ext):
    resp = _client().post(
        "/api/graph/export", json={"graph": WEB_GRAPH, "format": fmt, "title": "unit"}
    )
    assert resp.status_code == 200
    assert ctype in resp.headers["content-type"]
    disp = resp.headers.get("content-disposition", "")
    assert "attachment" in disp
    assert disp.endswith(f'.{ext}"')


def test_graph_export_rejects_empty_graph():
    resp = _client().post("/api/graph/export", json={"graph": {"nodes": []}, "format": "json"})
    assert resp.status_code == 400


def test_graph_export_rejects_unknown_format():
    resp = _client().post(
        "/api/graph/export", json={"graph": WEB_GRAPH, "format": "gexf"}
    )
    assert resp.status_code == 400


def test_graph_export_sanitizes_filename():
    resp = _client().post(
        "/api/graph/export",
        json={"graph": WEB_GRAPH, "format": "json", "title": "../../etc/pas swd"},
    )
    assert resp.status_code == 200
    fname = resp.headers.get("content-disposition", "").split("filename=")[-1]
    assert "/" not in fname and " " not in fname.strip('"')


# ---------------------------------------------------------------------------
# CLI: clearfront graph
# ---------------------------------------------------------------------------


def _synthetic_graph() -> EntityGraph:
    g = EntityGraph()
    e1 = g.add_entity(make_entity(EntityType.EMAIL, "a@b.com", 1.0, "seed"))
    e2 = g.add_entity(make_entity(EntityType.DOMAIN, "b.com", 0.9, "search_whois"))
    g.add_relationship(
        Relationship(source=e1, target=e2, kind="registered", source_tool="search_whois")
    )
    return g


def _patch_investigate(monkeypatch):
    """Replace the BFS so no real tools run against a real target during tests."""
    graph = _synthetic_graph()

    async def fake_investigate(seed, **kwargs):
        return graph

    monkeypatch.setattr("clearfront.pivot.investigate_graph", fake_investigate)
    return graph


async def test_cli_graph_writes_all_formats(monkeypatch, tmp_path):
    from clearfront.cli import _handle_graph

    _patch_investigate(monkeypatch)
    base = tmp_path / "out"
    await _handle_graph(
        "a@b.com",
        output=str(base),
        fmt="all",
        max_depth=2,
        max_entities=40,
        max_tool_calls=60,
        timeout=30,
    )
    graphml = tmp_path / "out.graphml"
    js = tmp_path / "out.json"
    mmd = tmp_path / "out.mmd"
    assert graphml.exists() and js.exists() and mmd.exists()
    ET.fromstring(graphml.read_text())  # valid GraphML
    assert json.loads(js.read_text())["nodes"]  # valid JSON with nodes
    assert mmd.read_text().startswith("graph TD")


async def test_cli_graph_single_format_prints_to_stdout(monkeypatch, capsys):
    from clearfront.cli import _handle_graph

    _patch_investigate(monkeypatch)
    await _handle_graph(
        "a@b.com",
        output=None,
        fmt="mermaid",
        max_depth=2,
        max_entities=40,
        max_tool_calls=60,
        timeout=30,
    )
    out = capsys.readouterr().out
    assert "graph TD" in out


async def test_cli_graph_does_not_run_real_tools(monkeypatch, tmp_path):
    # If _handle_graph ever called the real BFS, this sentinel would be reached.
    called = {"real": False}
    graph = _synthetic_graph()

    async def fake_investigate(seed, **kwargs):
        called["real"] = True  # our stub, not the network BFS
        return graph

    monkeypatch.setattr("clearfront.pivot.investigate_graph", fake_investigate)
    from clearfront.cli import _handle_graph

    await _handle_graph(
        "a@b.com",
        output=str(tmp_path / "g"),
        fmt="json",
        max_depth=2,
        max_entities=40,
        max_tool_calls=60,
        timeout=30,
    )
    assert called["real"] is True  # went through the patched stub, never the real tools
