"""Статья под запрос «MCP server scan»: индексируемая, честная и связанная с инструментом."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.scan_article import scan_article_page  # noqa: E402
from attest.service import _sitemap  # noqa: E402


def test_article_is_substantive_and_targets_the_query():
    import re

    html = scan_article_page()
    words = len(re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style).*?</\1>", " ", html, flags=re.S)).split())
    assert words >= 700, f"{words} слов — статья тонкая для конкурентного запроса"
    assert "MCP server scan" in html
    assert 'rel="canonical"' in html and "/mcp-scan-guide" in html
    assert "TechArticle" in html


def test_article_links_back_with_ref_marks():
    html = scan_article_page()
    for link in ("/scan?ref=article-mcp-scan", "/docs/scan?ref=article-mcp-scan",
                 "/plans?ref=article-mcp-scan"):
        assert link in html, link


def test_article_does_not_overclaim():
    low = scan_article_page().lower()
    assert "cannot" in low and "does not replace" in low or "does not replace it" in low
    assert "no account, no card" in low


def test_article_is_in_sitemap_and_linked_from_an_indexed_page():
    assert "<loc>https://attest.rta.lat/mcp-scan-guide</loc>" in _sitemap()
    catalogs = (ROOT / "attest" / "catalogs.py").read_text(encoding="utf-8")
    assert "/mcp-scan-guide?ref=catalogs" in catalogs
    llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
    assert "/mcp-scan-guide" in llms
