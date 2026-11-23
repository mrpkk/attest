"""\/scan должен быть находим: sitemap, llms.txt, README и ref-метки."""
from __future__ import annotations

from pathlib import Path

from attest.service import _sitemap

BASE = Path(__file__).resolve().parents[1]


def test_sitemap_lists_scan_and_neighbours():
    xml = _sitemap()
    for page in ("/scan", "/free-scan", "/docs/scan"):
        assert f"{page}<" in xml, page


def test_llms_and_readme_mention_scan():
    assert "/scan" in (BASE / "llms.txt").read_text(encoding="utf-8")
    assert "/scan" in (BASE / "README.md").read_text(encoding="utf-8")


def test_scan_page_links_carry_ref_marks():
    src = (BASE / "attest" / "scan.py").read_text(encoding="utf-8")
    assert "?ref=scan-page" in src, "внутренние ссылки должны нести ref для воронки"
