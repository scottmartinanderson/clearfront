# tests/test_pivot_freetier.py
"""Free-tier auto-pivot: footprint ungated, maigret/gravatar routed and extracted."""

from __future__ import annotations

from clearfront import pivot
from clearfront.correlation import EntityType, make_entity
from clearfront.extractors import EXTRACTOR_REGISTRY, _extract_gravatar, _extract_maigret

GRAVATAR_OUT = """Public Gravatar profile found for 'jane@example.com':

[+] Display name: Jane Doe
[+] Name: Jane Doe
[+] Location: San Francisco

Linked accounts (2):
[+] github (verified): https://github.com/jane
[+] twitter: https://twitter.com/jane

Listed URLs (1):
[+] blog: https://janedoe.com

Profile: https://gravatar.com/abc123
"""

MAIGRET_OUT = """Maigret found 2 account(s) for 'janedoe' (3,000+ site database):

[+] GitHub: https://github.com/janedoe
      fullname: Jane Doe
      location: SF
[+] Reddit: https://reddit.com/user/janedoe

Source: maigret (account-existence across 3,000+ sites).
"""


def test_footprint_not_gated_behind_brightdata(monkeypatch):
    monkeypatch.delenv("BRIGHTDATA_API_KEY", raising=False)
    monkeypatch.delenv("BRIGHTDATA_SERP_ZONE", raising=False)
    assert pivot._is_key_available("search_footprint") is True
    assert pivot._is_key_available("search_gravatar") is True
    assert pivot._is_key_available("search_maigret") is True


def test_keyless_email_route_includes_gravatar_and_footprint(monkeypatch):
    for k in ("HIBP_API_KEY", "BRIGHTDATA_API_KEY", "BRIGHTDATA_SERP_ZONE"):
        monkeypatch.delenv(k, raising=False)
    email = make_entity(EntityType.EMAIL, "jane@example.com", 1.0)
    routable = pivot._get_routable_tools(email)
    assert "search_gravatar" in routable
    assert "search_footprint" in routable
    assert "search_breach" not in routable  # still needs HIBP_API_KEY


def test_keyless_username_route_includes_maigret(monkeypatch):
    for k in ("BRIGHTDATA_API_KEY", "BRIGHTDATA_SERP_ZONE"):
        monkeypatch.delenv(k, raising=False)
    user = make_entity(EntityType.USERNAME, "janedoe", 1.0)
    routable = pivot._get_routable_tools(user)
    assert "search_maigret" in routable
    assert "search_footprint" in routable


def test_arg_map_for_new_tools():
    email = make_entity(EntityType.EMAIL, "jane@example.com", 1.0)
    user = make_entity(EntityType.USERNAME, "janedoe", 1.0)
    assert pivot._build_arg_map("search_gravatar", email) == {"email": "jane@example.com"}
    assert pivot._build_arg_map("search_maigret", user) == {"username": "janedoe"}


def test_registry_has_new_extractors():
    assert EXTRACTOR_REGISTRY["search_gravatar"] is _extract_gravatar
    assert EXTRACTOR_REGISTRY["search_maigret"] is _extract_maigret


def test_gravatar_extractor_person_drives_pivot_loop():
    seed = make_entity(EntityType.EMAIL, "jane@example.com", 1.0)
    ents, rels = _extract_gravatar(GRAVATAR_OUT, seed)
    persons = [e for e in ents if e.type == EntityType.PERSON]
    urls = [e for e in ents if e.type == EntityType.URL]
    assert len(persons) == 1
    assert persons[0].value == "Jane Doe"
    # A reliable, self-published name must clear the pivot threshold so the
    # email -> real name -> footprint loop actually fires.
    assert persons[0].confidence >= pivot._PIVOT_MIN_CONFIDENCE
    assert {u.value for u in urls} == {
        "https://github.com/jane",
        "https://twitter.com/jane",
        "https://janedoe.com",
    }


def test_maigret_extractor_is_candidate_confidence():
    seed = make_entity(EntityType.USERNAME, "janedoe", 1.0)
    ents, rels = _extract_maigret(MAIGRET_OUT, seed)
    persons = [e for e in ents if e.type == EntityType.PERSON]
    urls = [e for e in ents if e.type == EntityType.URL]
    assert {u.value for u in urls} == {
        "https://github.com/janedoe",
        "https://reddit.com/user/janedoe",
    }
    assert len(persons) == 1 and persons[0].value == "Jane Doe"
    # Maigret is false-positive prone, so everything stays below the pivot
    # threshold, it enriches the graph but never seeds more tool calls.
    for e in ents:
        assert e.confidence < pivot._PIVOT_MIN_CONFIDENCE
