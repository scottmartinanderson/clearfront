# tests/test_mcp_authorized_use.py
"""Every MCP tool description carries the authorized-use / passivity clause."""

from __future__ import annotations

from clearfront import mcp_server


async def test_all_mcp_tools_carry_authorized_use_note():
    tools = await mcp_server.list_tools()
    # 30 collection tools + investigate_multi.
    assert len(tools) == 31
    for t in tools:
        assert t.description.endswith(mcp_server._AUTHORIZED_USE_NOTE), t.name
        assert "Authorized use only" in t.description


async def test_note_is_additive_not_replacing():
    tools = await mcp_server.list_tools()
    harvester = next(t for t in tools if t.name == "search_harvester")
    # Original description content is preserved, the note is appended.
    assert "theHarvester" in harvester.description
    assert "passive" in harvester.description.lower()
