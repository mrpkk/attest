"""Находимость страницы скана: sitemap, llms.txt, README и ref-метки.

21.11.2026: страница `/docs/scan` существовала, но её не было ни в карте сайта, ни
в llms.txt, ни в README — то есть о ней знал только тот, кто уже на неё попал.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import product_pages  # noqa: E402
from attest.metrics import channel_of  # noqa: E402
from attest.service import _sitemap  # noqa: E402


def test_sitemap_lists_the_scan_docs():
    assert "/docs/scan" in _sitemap()


def test_llms_txt_lists_the_scan_docs():
    text = (ROOT / "llms.txt").read_text(encoding="utf-8")
    assert "attest.rta.lat/docs/scan" in text
    assert "200 КБ" in text or "200 KB" in text


def test_readme_points_to_the_scan_docs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "attest.rta.lat/docs/scan" in readme
    assert "attest.rta.lat/free-scan" in readme


def test_links_carry_ref_markers_we_can_count():
    html = product_pages.scan_docs_page()
    assert 'href="/free-scan?ref=docs-scan"' in html
    scan_page = product_pages.free_scan_page()
    assert 'href="/docs/scan?ref=scan-page"' in scan_page


def test_ref_marker_becomes_a_channel():
    """Метка должна попадать в счётчик источника, а не быть украшением."""
    assert channel_of("/free-scan?ref=docs-scan", None) == "docs-scan"
    assert channel_of("/docs/scan?ref=scan-page", None) == "scan-page"
