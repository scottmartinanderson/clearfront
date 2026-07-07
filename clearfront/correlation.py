# clearfront/correlation.py
"""
Entity Correlation Graph, core data structures.

EntityType   : enum of recognized OSINT entity categories.
Entity       : immutable-by-identity node (dedup by type + normalized value).
Relationship : directed edge between two entities with a semantic label.
EntityGraph  : deduplicated graph with D3, GraphML, and Mermaid export.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Entity type
# ---------------------------------------------------------------------------


class EntityType(Enum):
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    IP = "ip"
    PHONE = "phone"
    HASH = "hash"
    URL = "url"
    PERSON = "person"
    ORG = "org"
    ASN = "asn"


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

_PROTO_RE = re.compile(r"^https?://", re.IGNORECASE)


def _normalize_value(entity_type: EntityType, value: str) -> str:
    """Return a canonical form used for deduplication."""
    stripped = value.strip()
    if entity_type == EntityType.EMAIL:
        return stripped.lower()
    if entity_type == EntityType.URL:
        return _PROTO_RE.sub("", stripped.lower()).rstrip("/")
    if entity_type in (EntityType.DOMAIN, EntityType.IP, EntityType.ASN):
        return stripped.lower()
    return stripped.lower()


# ---------------------------------------------------------------------------
# Entity
# ---------------------------------------------------------------------------


@dataclass
class Entity:
    """A single OSINT entity node.

    Equality and hashing are defined by (type, normalized) so that two
    Entity objects with the same semantic identity compare equal regardless
    of the original casing or whitespace.
    """

    type: EntityType
    value: str
    normalized: str
    confidence: float
    source_tools: set[str] = field(default_factory=set)

    def __hash__(self) -> int:
        return hash((self.type, self.normalized))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Entity):
            return False
        return self.type == other.type and self.normalized == other.normalized


def make_entity(
    entity_type: EntityType,
    value: str,
    confidence: float,
    source_tool: str = "",
) -> Entity:
    """Convenience constructor that fills normalized automatically."""
    normalized = _normalize_value(entity_type, value)
    tools: set[str] = {source_tool} if source_tool else set()
    return Entity(
        type=entity_type,
        value=value,
        normalized=normalized,
        confidence=confidence,
        source_tools=tools,
    )


# ---------------------------------------------------------------------------
# Relationship
# ---------------------------------------------------------------------------


@dataclass
class Relationship:
    """A directed edge between two entities with a semantic kind label."""

    source: Entity
    target: Entity
    kind: str
    source_tool: str
    confidence: float = 1.0


# ---------------------------------------------------------------------------
# Mermaid node shapes per entity type
# ---------------------------------------------------------------------------

_MERMAID_OPEN: dict[EntityType, str] = {
    EntityType.EMAIL: "[",
    EntityType.USERNAME: "([",
    EntityType.DOMAIN: "(",
    EntityType.IP: "[[",
    EntityType.PHONE: "[/",
    EntityType.HASH: "[",
    EntityType.URL: "(",
    EntityType.PERSON: "(((",
    EntityType.ORG: "{",
    EntityType.ASN: "[[",
}

_MERMAID_CLOSE: dict[EntityType, str] = {
    EntityType.EMAIL: "]",
    EntityType.USERNAME: "])",
    EntityType.DOMAIN: ")",
    EntityType.IP: "]]",
    EntityType.PHONE: "/]",
    EntityType.HASH: "]",
    EntityType.URL: ")",
    EntityType.PERSON: ")))",
    EntityType.ORG: "}",
    EntityType.ASN: "]]",
}

_MERMAID_UNSAFE_RE = re.compile(r'["\[\]{}\(\)/\\<>|]')


def _safe_mermaid_label(value: str, max_len: int = 40) -> str:
    """Strip Mermaid-unsafe characters and truncate."""
    return _MERMAID_UNSAFE_RE.sub("", value)[:max_len]


# ---------------------------------------------------------------------------
# EntityGraph
# ---------------------------------------------------------------------------


class EntityGraph:
    """Deduplicated directed graph of OSINT entities and their relationships."""

    def __init__(self) -> None:
        self._entities: dict[tuple[EntityType, str], Entity] = {}
        self._relationships: list[Relationship] = []
        self._rel_keys: set[tuple[Any, ...]] = set()

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_entity(self, entity: Entity) -> Entity:
        """Insert entity, merging duplicates. Returns the canonical instance."""
        key = (entity.type, entity.normalized)
        if key in self._entities:
            existing = self._entities[key]
            existing.source_tools.update(entity.source_tools)
            if entity.confidence > existing.confidence:
                existing.confidence = entity.confidence
            return existing
        canonical = Entity(
            type=entity.type,
            value=entity.value,
            normalized=entity.normalized,
            confidence=entity.confidence,
            source_tools=set(entity.source_tools),
        )
        self._entities[key] = canonical
        return canonical

    def add_relationship(self, rel: Relationship) -> None:
        """Insert relationship, silently discarding duplicates."""
        key = (
            rel.source.type,
            rel.source.normalized,
            rel.target.type,
            rel.target.normalized,
            rel.kind,
        )
        if key in self._rel_keys:
            return
        self._rel_keys.add(key)
        self._relationships.append(rel)

    def merge(self, other: EntityGraph) -> None:
        """Absorb all entities and relationships from *other* in place."""
        for entity in other._entities.values():
            self.add_entity(entity)
        for rel in other._relationships:
            self.add_relationship(rel)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def neighbors(self, entity: Entity) -> list[Entity]:
        """Return entities directly connected to *entity* (either direction)."""
        key = (entity.type, entity.normalized)
        seen: set[tuple[EntityType, str]] = set()
        result: list[Entity] = []
        for rel in self._relationships:
            src_key = (rel.source.type, rel.source.normalized)
            tgt_key = (rel.target.type, rel.target.normalized)
            if src_key == key and tgt_key not in seen:
                seen.add(tgt_key)
                result.append(rel.target)
            elif tgt_key == key and src_key not in seen:
                seen.add(src_key)
                result.append(rel.source)
        return result

    # ------------------------------------------------------------------
    # Sorted iterators (deterministic output)
    # ------------------------------------------------------------------

    def _sorted_entities(self) -> list[Entity]:
        return sorted(self._entities.values(), key=lambda e: (e.type.value, e.normalized))

    def _sorted_relationships(self) -> list[Relationship]:
        return sorted(
            self._relationships,
            key=lambda r: (
                r.source.type.value,
                r.source.normalized,
                r.target.type.value,
                r.target.normalized,
                r.kind,
            ),
        )

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """D3 node-link format: {nodes: [...], links: [...]}."""
        entities = self._sorted_entities()
        index: dict[tuple[EntityType, str], int] = {
            (e.type, e.normalized): i for i, e in enumerate(entities)
        }
        nodes = [
            {
                "id": i,
                "type": e.type.value,
                "value": e.value,
                "confidence": e.confidence,
                "tools": sorted(e.source_tools),
            }
            for i, e in enumerate(entities)
        ]
        links = []
        for rel in self._sorted_relationships():
            src = index.get((rel.source.type, rel.source.normalized))
            tgt = index.get((rel.target.type, rel.target.normalized))
            if src is not None and tgt is not None:
                links.append(
                    {
                        "source": src,
                        "target": tgt,
                        "kind": rel.kind,
                        "tool": rel.source_tool,
                    }
                )
        return {"nodes": nodes, "links": links}

    def to_json(self) -> str:
        """Serialise to JSON string (D3 node-link)."""
        return json.dumps(self.to_dict(), indent=2)

    def to_graphml(self) -> str:
        """Produce a valid GraphML document importable in Gephi, yEd, and Maltego."""
        ns = "http://graphml.graphdrawing.org/graphml"
        xsi = "http://www.w3.org/2001/XMLSchema-instance"
        schema_loc = (
            "http://graphml.graphdrawing.org/graphml "
            "http://graphml.graphdrawing.org/graphml/1.0rc/graphml.xsd"
        )

        root = ET.Element(
            "graphml",
            attrib={
                "xmlns": ns,
                "xmlns:xsi": xsi,
                "xsi:schemaLocation": schema_loc,
            },
        )

        def _key(key_id: str, for_: str, name: str, kind: str) -> None:
            ET.SubElement(
                root,
                "key",
                attrib={
                    "id": key_id,
                    "for": for_,
                    "attr.name": name,
                    "attr.type": kind,
                },
            )

        _key("d_type", "node", "type", "string")
        _key("d_value", "node", "value", "string")
        _key("d_confidence", "node", "confidence", "double")
        _key("d_tools", "node", "tools", "string")
        _key("d_kind", "edge", "kind", "string")
        _key("d_tool", "edge", "tool", "string")

        graph_el = ET.SubElement(root, "graph", attrib={"id": "G", "edgedefault": "directed"})

        entities = self._sorted_entities()
        index: dict[tuple[EntityType, str], int] = {
            (e.type, e.normalized): i for i, e in enumerate(entities)
        }

        def _data(parent: ET.Element, key_id: str, text: str) -> None:
            el = ET.SubElement(parent, "data", attrib={"key": key_id})
            el.text = text

        for i, e in enumerate(entities):
            node_el = ET.SubElement(graph_el, "node", attrib={"id": f"n{i}"})
            _data(node_el, "d_type", e.type.value)
            _data(node_el, "d_value", e.value)
            _data(node_el, "d_confidence", str(round(e.confidence, 4)))
            _data(node_el, "d_tools", ",".join(sorted(e.source_tools)))

        for edge_idx, rel in enumerate(self._sorted_relationships()):
            src = index.get((rel.source.type, rel.source.normalized))
            tgt = index.get((rel.target.type, rel.target.normalized))
            if src is None or tgt is None:
                continue
            edge_el = ET.SubElement(
                graph_el,
                "edge",
                attrib={"id": f"e{edge_idx}", "source": f"n{src}", "target": f"n{tgt}"},
            )
            _data(edge_el, "d_kind", rel.kind)
            _data(edge_el, "d_tool", rel.source_tool)

        ET.indent(root, space="  ")
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")

    def to_mermaid(self) -> str:
        """Produce a Mermaid graph TD diagram with sanitized node IDs."""
        entities = self._sorted_entities()
        node_id: dict[tuple[EntityType, str], str] = {
            (e.type, e.normalized): f"n{i}" for i, e in enumerate(entities)
        }

        lines = ["graph TD"]

        for i, e in enumerate(entities):
            nid = f"n{i}"
            open_br = _MERMAID_OPEN.get(e.type, "[")
            close_br = _MERMAID_CLOSE.get(e.type, "]")
            label = _safe_mermaid_label(e.value)
            lines.append(f'    {nid}{open_br}"{label}"{close_br}')

        for rel in self._sorted_relationships():
            src_id = node_id.get((rel.source.type, rel.source.normalized))
            tgt_id = node_id.get((rel.target.type, rel.target.normalized))
            if src_id is None or tgt_id is None:
                continue
            safe_kind = _MERMAID_UNSAFE_RE.sub("", rel.kind)
            lines.append(f'    {src_id} -->|"{safe_kind}"| {tgt_id}')

        return "\n".join(lines)

    def summary(self) -> str:
        """One-paragraph human-readable summary for CLI/REPL display."""
        by_type: dict[str, int] = {}
        for e in self._entities.values():
            by_type[e.type.value] = by_type.get(e.type.value, 0) + 1
        counts = ", ".join(f"{v} {k}" for k, v in sorted(by_type.items()) if v)
        total_e = len(self._entities)
        total_r = len(self._relationships)
        return f"Graph: {total_e} entities ({counts}), {total_r} relationships."


# ---------------------------------------------------------------------------
# Generic node-link (D3) exporters
#
# The web console renders an LLM-authored evidence graph in D3 node-link shape:
#   {"nodes": [{"id","label","type","value","source","confidence","severity"}],
#    "links": [{"source","target"}]}
# Its node types are richer than EntityType (SUBJECT, ACCOUNT, BREACH, PASTE,
# HOSTNAME, COMPANY, ...), so these functions export that arbitrary graph to the
# same portable formats as EntityGraph WITHOUT forcing it through the EntityType
# taxonomy (which would discard those types). Output is deterministic (nodes sorted
# by id, links sorted by endpoints) so the same graph always exports byte-identically.
# ---------------------------------------------------------------------------

# Semantic node fields carried through export, in a fixed emit order. Any other
# fields (e.g. the x/y/z layout coordinates the force-graph library adds in place)
# are dropped so the artifact stays clean and stable.
_D3_NODE_ATTRS = ("label", "type", "value", "source", "confidence", "severity")


def _d3_endpoint_id(value: Any) -> str:
    """A link endpoint may be a node id or, after rendering, the node object itself."""
    if isinstance(value, dict):
        return str(value.get("id"))
    return str(value)


def _d3_prepare(graph: Any) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """Return (sorted nodes, sorted (source, target) links) with dangling links dropped."""
    raw_nodes = graph.get("nodes") if isinstance(graph, dict) else None
    raw_links = graph.get("links") if isinstance(graph, dict) else None
    nodes = [
        n for n in (raw_nodes or []) if isinstance(n, dict) and n.get("id") is not None
    ]
    nodes = sorted(nodes, key=lambda n: str(n.get("id")))
    ids = {str(n.get("id")) for n in nodes}
    links: list[tuple[str, str]] = []
    for link in raw_links or []:
        if not isinstance(link, dict):
            continue
        src = _d3_endpoint_id(link.get("source"))
        tgt = _d3_endpoint_id(link.get("target"))
        if src in ids and tgt in ids:
            links.append((src, tgt))
    links = sorted(set(links))
    return nodes, links


def d3_to_json(graph: Any) -> str:
    """Canonical JSON for a D3 node-link graph: sorted, semantic fields only."""
    nodes, links = _d3_prepare(graph)
    out_nodes = [
        {"id": str(n.get("id")), **{k: n[k] for k in _D3_NODE_ATTRS if n.get(k) not in (None, "")}}
        for n in nodes
    ]
    out_links = [{"source": s, "target": t} for s, t in links]
    return json.dumps({"nodes": out_nodes, "links": out_links}, indent=2)


def d3_to_graphml(graph: Any) -> str:
    """GraphML for a D3 node-link graph, importable in Gephi, yEd, and Maltego."""
    ns = "http://graphml.graphdrawing.org/graphml"
    xsi = "http://www.w3.org/2001/XMLSchema-instance"
    schema_loc = (
        "http://graphml.graphdrawing.org/graphml "
        "http://graphml.graphdrawing.org/graphml/1.0rc/graphml.xsd"
    )
    root = ET.Element(
        "graphml",
        attrib={"xmlns": ns, "xmlns:xsi": xsi, "xsi:schemaLocation": schema_loc},
    )
    for attr in _D3_NODE_ATTRS:
        ET.SubElement(
            root,
            "key",
            attrib={"id": f"d_{attr}", "for": "node", "attr.name": attr, "attr.type": "string"},
        )

    graph_el = ET.SubElement(root, "graph", attrib={"id": "G", "edgedefault": "directed"})

    nodes, links = _d3_prepare(graph)
    index = {str(n.get("id")): i for i, n in enumerate(nodes)}

    for i, node in enumerate(nodes):
        node_el = ET.SubElement(graph_el, "node", attrib={"id": f"n{i}"})
        for attr in _D3_NODE_ATTRS:
            val = node.get(attr)
            if val in (None, ""):
                continue
            data_el = ET.SubElement(node_el, "data", attrib={"key": f"d_{attr}"})
            data_el.text = str(val)

    for edge_idx, (src, tgt) in enumerate(links):
        ET.SubElement(
            graph_el,
            "edge",
            attrib={
                "id": f"e{edge_idx}",
                "source": f"n{index[src]}",
                "target": f"n{index[tgt]}",
            },
        )

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def d3_to_mermaid(graph: Any) -> str:
    """Mermaid 'graph TD' for a D3 node-link graph, with sanitized ids and labels."""
    nodes, links = _d3_prepare(graph)
    index = {str(n.get("id")): i for i, n in enumerate(nodes)}

    lines = ["graph TD"]
    for i, node in enumerate(nodes):
        raw_label = node.get("label") or node.get("value") or node.get("id") or ""
        label = _safe_mermaid_label(str(raw_label))
        lines.append(f'    n{i}["{label}"]')
    for src, tgt in links:
        lines.append(f"    n{index[src]} --> n{index[tgt]}")
    return "\n".join(lines)
