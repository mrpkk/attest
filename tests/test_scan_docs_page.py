"""Страница /docs/scan: четыре обязательных блока и лимит, совпадающий с кодом."""
from __future__ import annotations

from pathlib import Path

from attest.product_pages import scan_docs_page
from attest.service import FREE_DAILY_LIMIT

ROOT = Path(__file__).resolve().parents[1]


def test_docs_scan_has_all_four_blocks():
    html = scan_docs_page()
    for block in ("What is checked", "Limits, exactly", "Example of what a reply looks like",
                  "What the scan does not do"):
        assert block in html, block


def test_docs_scan_states_real_free_limit():
    html = scan_docs_page()
    assert f"Free limit: {FREE_DAILY_LIMIT} scans per day" in html
    assert "__FREE_LIMIT__" not in html


def test_docs_scan_page_in_sitemap_and_linked():
    from attest.service import _sitemap
    assert "<loc>https://attest.rta.lat/docs/scan</loc>" in _sitemap()
    assert 'href="/docs/scan' in (ROOT / "attest" / "scan.py").read_text(encoding="utf-8")
