# tests/test_crt.py
"""crt.sh certificate-transparency tool: domain cleaning, subdomain parsing, extractor."""

from __future__ import annotations

from clearfront.correlation import EntityType, make_entity
from clearfront.extractors import EXTRACTOR_REGISTRY, _extract_crt
from clearfront.tools.search_crt import _clean_domain, _extract_subdomains, run_crt_osint

CRT_OUT = """[crt.sh] 2 unique subdomain(s) in certificate transparency for 'example.com':
[crt.sh] Subdomain: api.example.com
[crt.sh] Subdomain: www.example.com
Source: crt.sh certificate transparency (public CA logs, passive).
"""


def test_clean_domain_strips_scheme_path_and_wildcard():
    assert _clean_domain("https://Example.com/path") == "example.com"
    assert _clean_domain("*.example.com") == "example.com"
    assert _clean_domain("  example.com.  ") == "example.com"


def test_extract_subdomains_filters_and_dedupes():
    records = [
        {"name_value": "www.example.com\n*.example.com", "common_name": "example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "notexample.org"},  # unrelated, excluded
        {"name_value": "evil-example.com"},  # not a subdomain, excluded
    ]
    subs = _extract_subdomains(records, "example.com")
    assert subs == ["api.example.com", "example.com", "www.example.com"]


def test_crt_extractor_emits_high_confidence_domain_nodes():
    seed = make_entity(EntityType.DOMAIN, "example.com", 1.0)
    ents, rels = _extract_crt(CRT_OUT, seed)
    assert {e.value for e in ents} == {"api.example.com", "www.example.com"}
    assert all(e.type == EntityType.DOMAIN for e in ents)
    assert all(e.confidence == 0.85 for e in ents)
    assert all(r.kind == "certificate_subdomain" for r in rels)


def test_crt_extractor_registered():
    assert EXTRACTOR_REGISTRY["search_crt"] is _extract_crt


async def test_run_crt_rejects_invalid_domain():
    out = await run_crt_osint("not a domain")
    assert out.startswith("Error:")
