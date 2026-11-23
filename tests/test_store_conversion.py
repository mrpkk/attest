"""Магазин: одна главная кнопка, доказательство цифрами, мобильность, вес."""
from __future__ import annotations

import re
from pathlib import Path

from attest.store_page import _tests_count, store_page

ROOT = Path(__file__).resolve().parents[1]
HTML = store_page()


def test_single_primary_cta():
    assert HTML.count('data-primary="1"') == 1
    hero = HTML.split('data-primary="1"')[0]
    assert 'href="/scan"' in hero.split("<a", 1)[-1] or "/scan" in HTML


def test_proof_has_real_number_not_adjective():
    n = _tests_count()
    assert n > 100, n
    assert f"<b>{n:,}</b> automated checks" in HTML
    for vague in ("world-class", "best-in-class", "trusted by thousands"):
        assert vague.lower() not in HTML.lower()


def test_mobile_viewport_and_no_fixed_width():
    assert 'name="viewport"' in HTML or "name=viewport" in HTML
    assert "width=device-width" in HTML
    # только свойство width:, не max-width (медиазапросы и max-width — норма для мобильных)
    assert not re.search(r"(?<![\w-])width:\s*(1[0-9]{3}|[2-9][0-9]{2})px", HTML), "фиксированная ширина ломает мобильные"


def test_page_is_light_and_has_no_external_assets():
    assert len(HTML.encode()) < 60_000, "страница не должна пухнуть"
    assert not re.search(r'<script[^>]+src=', HTML)
    links = [m for m in re.findall(r'<link[^>]+href="https?://[^"]+"[^>]*>', HTML)
             if 'rel="canonical"' not in m]
    assert not links, links
