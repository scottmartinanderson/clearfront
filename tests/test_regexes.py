# tests/test_regexes.py
"""
Tests for clearfront.regexes.

Documents the actual behaviour of EMAIL_RE and EMAIL_FIND_RE.

Shared pattern: [word.+-]+@[word-]+.[a-z]{2,}  (word = alphanumeric + _)

Known limitations (intentionally NOT changed by this refactor):
- Domain part [word-]+ does not allow dots, so subdomains (user@sub.host.com)
  and multi-label TLDs (user@host.co.uk) are not fully matched.
- EMAIL_FIND_RE has no re.IGNORECASE, so uppercase TLDs (UPPER@HOST.COM)
  are not matched.
- EMAIL_RE has re.IGNORECASE, so it matches uppercase input correctly.
"""

from __future__ import annotations

import pytest

from clearfront.regexes import EMAIL_FIND_RE, EMAIL_RE


# ---------------------------------------------------------------------------
# EMAIL_RE, whole-string validation (anchored, case-insensitive)
# ---------------------------------------------------------------------------


class TestEmailRE:
    @pytest.mark.parametrize(
        "address",
        [
            "user@example.com",
            "user+alias@example.com",
            "first.last@example.com",   # dot in local part is fine
            "User@EXAMPLE.COM",         # IGNORECASE: uppercase matches
            "u@x.io",
        ],
    )
    def test_matches_valid_email(self, address: str) -> None:
        assert EMAIL_RE.match(address) is not None, f"expected match for {address!r}"

    @pytest.mark.parametrize(
        "value",
        [
            "notanemail",
            "@nodomain.com",
            "missing-at-sign.com",
            "user@",
            "user@domain",              # no TLD
            "user@domain.",             # trailing dot, empty TLD
            "user@ domain.com",         # space in domain
            "user@domain.c",            # single-char TLD (< 2 chars)
            "user@domain.com trailing junk",   # extra text, $ anchor rejects
            "prefix user@domain.com",          # text before, ^ anchor rejects
        ],
    )
    def test_rejects_invalid_or_partial(self, value: str) -> None:
        assert EMAIL_RE.match(value) is None, f"expected no match for {value!r}"

    def test_anchoring_rejects_surrounding_text(self) -> None:
        assert EMAIL_RE.fullmatch("user@example.com") is not None
        assert EMAIL_RE.fullmatch("user@example.com extra") is None
        assert EMAIL_RE.fullmatch("prefix user@example.com") is None

    def test_subdomain_not_supported(self) -> None:
        # [\w-]+ stops at dots, subdomain emails do not match the full string.
        assert EMAIL_RE.match("user@sub.example.com") is None

    def test_multi_label_tld_not_supported(self) -> None:
        # [\w-]+\.[a-z]{2,} only handles a single TLD label.
        assert EMAIL_RE.match("user@example.co.uk") is None


# ---------------------------------------------------------------------------
# EMAIL_FIND_RE, extraction from larger text (no IGNORECASE)
# ---------------------------------------------------------------------------


class TestEmailFindRE:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("Contact us at support@example.com for help.", ["support@example.com"]),
            ("Two addresses: a@b.io and c+d@e.org here.", ["a@b.io", "c+d@e.org"]),
            ("No email in this sentence.", []),
            ("Dot in local: first.last@example.com today.", ["first.last@example.com"]),
            ("Plus alias: user+tag@example.org.", ["user+tag@example.org"]),
        ],
    )
    def test_finds_emails_in_text(self, text: str, expected: list[str]) -> None:
        found = EMAIL_FIND_RE.findall(text)
        assert found == expected, f"text={text!r}: got {found!r}, want {expected!r}"

    def test_extracts_embedded_with_punctuation(self) -> None:
        match = EMAIL_FIND_RE.search("(alice@example.com)")
        assert match is not None
        assert match.group(0) == "alice@example.com"

    def test_does_not_anchor(self) -> None:
        assert EMAIL_FIND_RE.search("hello world user@domain.org goodbye") is not None

    def test_no_match_on_empty_string(self) -> None:
        assert EMAIL_FIND_RE.search("") is None

    def test_uppercase_tld_not_matched(self) -> None:
        # EMAIL_FIND_RE has no re.IGNORECASE, [a-z]{2,} requires lowercase TLD.
        assert EMAIL_FIND_RE.search("UPPER@CASE.COM") is None

    def test_subdomain_partial_match(self) -> None:
        # [\w-]+ stops at the first dot in the domain, so only the first
        # label + TLD is captured; multi-label domains produce a shorter match.
        found = EMAIL_FIND_RE.findall("contact: user@sub.example.com end")
        assert found == ["user@sub.example"]  # stops before .com
