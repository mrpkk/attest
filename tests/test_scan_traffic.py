"""Трафик на /scan: ссылки с ref-метками и карта сайта — под тестом, а не на память."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.service import _sitemap  # noqa: E402


def test_readme_points_to_scan_with_ref_mark():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "https://attest.rta.lat/scan?ref=readme" in readme
    assert "no account" in readme


def test_internal_pages_carry_ref_marks():
    """Клик из наших же страниц должен быть атрибутирован, иначе канал «прямой» врёт."""
    scan_pages = ["hub_page.py", "tools_page.py"]
    joined = "".join((ROOT / "attest" / n).read_text(encoding="utf-8") for n in scan_pages)
    assert "/scan?ref=hub" in joined, "ссылка из хаба должна нести метку"
    assert "ref=hub" in joined


def test_scan_is_in_sitemap_and_survives_the_check():
    sitemap = _sitemap()
    for page in ("/scan", "/free-scan", "/docs/scan", "/store"):
        assert f"<loc>https://attest.rta.lat{page}</loc>" in sitemap, page


def test_ref_values_fit_the_channel_limit():
    """`channel_of` режет ref до 32 символов и приводит к нижнему регистру — метки должны влезать."""
    from attest.metrics import channel_of

    for ref in ("readme", "tools", "hub"):
        assert channel_of(f"?ref={ref}", None) == ref
    assert channel_of("?ref=" + "x" * 60, None) == "x" * 32
