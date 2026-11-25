"""SEO /scan: карта сайта, внутренние ссылки, IndexNow — проверяемое, а не заявленное.

26.11.2026: поиск показал в индексе только `/` и `/article` — страница скана, главный
вход в продукт, не была проиндексирована. Здесь то, что можно проверить кодом.
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import indexnow  # noqa: E402
from attest.service import MANIFEST_FILES, _robots, _sitemap  # noqa: E402


def test_scan_is_in_sitemap_and_robots_allows_it():
    sitemap = _sitemap()
    assert "<loc>https://attest.rta.lat/scan</loc>" in sitemap
    assert "<loc>https://attest.rta.lat/docs/scan</loc>" in sitemap
    robots = _robots()
    assert "Allow: /" in robots and "Disallow: /mcp" in robots
    assert "sitemap.xml" in robots


def test_article_links_to_scan_with_ref_mark():
    """Единственная проиндексированная статья должна вести на страницу скана."""
    html = (ROOT / "attest" / "article.py").read_text(encoding="utf-8")
    assert 'href="/scan?ref=article"' in html


def test_indexnow_key_file_is_served_and_matches_its_name():
    key = indexnow.key()
    assert len(key) == 32
    path = ROOT / f"{key}.txt"
    assert path.is_file() and path.read_text(encoding="utf-8").strip() == key
    assert f"{key}.txt" in MANIFEST_FILES, "файл ключа должен отдаваться сервисом"


def test_indexnow_payload_names_key_location():
    p = indexnow.payload(["https://attest.rta.lat/scan"])
    assert p["host"] == "attest.rta.lat"
    assert p["keyLocation"] == f"https://attest.rta.lat/{p['key']}.txt"
    assert p["urlList"] == ["https://attest.rta.lat/scan"]
