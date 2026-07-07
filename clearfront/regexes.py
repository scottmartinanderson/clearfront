# clearfront/regexes.py
"""Shared compiled regular expressions used across the package."""

import re

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

# Strict anchored match, validates that the entire string is an email address.
EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[a-z]{2,}$", re.IGNORECASE)

# Search-in-string variant, extracts email addresses embedded in larger text.
EMAIL_FIND_RE = re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}")

# ---------------------------------------------------------------------------
# Entity-type detection (anchored), used by search_footprint and pivot
# ---------------------------------------------------------------------------

URL_DETECT_RE = re.compile(r"^https?://", re.IGNORECASE)
IPV4_DETECT_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HASH_DETECT_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
PHONE_DETECT_RE = re.compile(r"^\+?\d{7,15}$")
DOMAIN_DETECT_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+$"
)


def detect_entity_kind(value: str) -> str:
    """Return a string label for the most likely entity type of *value*.

    Returns one of: ``"email"``, ``"url"``, ``"ip"``, ``"hash"``,
    ``"phone"``, ``"domain"``, ``"username"`` (single token without spaces),
    or ``"person"`` (multi-word, assumed full name).

    Detection order: email → url → ipv4 → hash → phone → domain → username/person.
    """
    v = value.strip()
    if EMAIL_RE.match(v):
        return "email"
    if URL_DETECT_RE.match(v):
        return "url"
    if IPV4_DETECT_RE.match(v):
        return "ip"
    if HASH_DETECT_RE.match(v):
        return "hash"
    if PHONE_DETECT_RE.match(v):
        return "phone"
    if DOMAIN_DETECT_RE.match(v):
        return "domain"
    if " " in v:
        return "person"
    return "username"
