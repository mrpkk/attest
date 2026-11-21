"""SEO страницы /scan под запрос «MCP server scan».

22.11.2026: страница была 2.7 КБ клиентского кода с одним абзацем — поисковику
нечего было индексировать, а человеку нечего прочитать до нажатия.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.scan import scan_page  # noqa: E402
from attest.service import _sitemap  # noqa: E402


def test_scan_is_in_the_sitemap():
    xml = _sitemap()
    assert "<loc>https://attest.rta.lat/scan</loc>" in xml


def test_llms_txt_describes_the_scan():
    text = (ROOT / "llms.txt").read_text(encoding="utf-8")
    assert "attest.rta.lat/scan" in text
    assert "tools/list" in text


def test_title_and_description_target_the_query():
    html = scan_page()
    title = re.search(r"<title>(.*?)</title>", html, re.S).group(1)
    desc = re.search(r'name="description" content="(.*?)"', html, re.S).group(1)
    assert "MCP server scan" in title
    assert "MCP server" in desc and "annotations" in desc
    assert len(title) <= 90 and 80 <= len(desc) <= 220


def test_page_has_readable_content_not_just_a_form():
    html = scan_page()
    assert "What a scan of an MCP server looks like" in html
    assert "Example result" in html
    assert "What the scan does not do" in html
    assert "<table>" in html
    assert len(html.encode("utf-8")) > 6000


def test_structured_data_is_valid_json():
    html = scan_page()
    start = html.index("application/ld+json") + len('application/ld+json">')
    data = json.loads(html[start:html.index("</script>", start)])
    assert data["@type"] == "WebApplication"
    assert data["offers"]["price"] == "0"


def test_internal_links_carry_ref():
    html = scan_page()
    for path in ("/docs/scan?ref=scan-page", "/store?ref=scan-page", "/plans?ref=scan-page"):
        assert path in html, path
