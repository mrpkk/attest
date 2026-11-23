"""SEO запроса «MCP server scan»: title, FAQ, JSON-LD, llms.txt, sitemap."""
from __future__ import annotations

import json
import re
from pathlib import Path

from attest.scan import scan_page
from attest.service import _sitemap

ROOT = Path(__file__).resolve().parents[1]
HTML = scan_page()


def test_title_and_h1_target_the_query():
    title = re.search(r"<title>(.*?)</title>", HTML, re.S).group(1)
    assert "MCP server scan" in title
    assert "mcp server scan" in HTML.lower()


def test_faq_block_and_schema():
    assert "How do I scan an MCP server?" in HTML
    blocks = re.findall(r'<script type="application/ld\+json">(.*?)</script>', HTML, re.S)
    types = [json.loads(b).get("@type") for b in blocks]
    assert "FAQPage" in types and "WebApplication" in types
    faq = next(json.loads(b) for b in blocks if json.loads(b).get("@type") == "FAQPage")
    assert len(faq["mainEntity"]) >= 3


def test_llms_sitemap_and_ref_marks():
    llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
    assert "MCP server scan" in llms and "https://attest.rta.lat/scan" in llms
    assert "<loc>https://attest.rta.lat/scan</loc>" in _sitemap()
    assert HTML.count("ref=scan-page") >= 3
