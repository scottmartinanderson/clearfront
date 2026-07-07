"""
Bright Data referral link.

Bright Data powers the optional search_dorks_live / search_footprint / scrape_url
tools (a free tier is available). This is the single place the sign-up URL is
defined, so every surface (CLI / MCP / web / docs) shows the same link in its
missing-key setup message. It is a referral link: signing up through it supports
Clearfront's development at no extra cost to you.
"""

from __future__ import annotations

_MAIN = "https://get.brightdata.com/8ygvxztgo5dr"

BRIGHTDATA_LINK_CLI = _MAIN
BRIGHTDATA_LINK_MCP = _MAIN
BRIGHTDATA_LINK_WEB = _MAIN
BRIGHTDATA_LINK_README = _MAIN
BRIGHTDATA_LINK_DOCS = _MAIN
BRIGHTDATA_LINK_CHANGELOG = _MAIN
