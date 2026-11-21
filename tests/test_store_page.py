"""Магазин /store: доказательства рядом с ценой, мобильная вёрстка, бюджет веса.

22.11.2026: у страницы был хороший заголовок, но не было ни одного проверяемого
доказательства рядом с ценой, а вес и отзывчивость никто не проверял.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.store_page import store_page  # noqa: E402


def test_page_is_light():
    """Бюджет веса: страница должна оставаться лёгкой, иначе «скорость» — обещание."""
    html = store_page()
    assert len(html.encode("utf-8")) < 60_000, f"{len(html)} байт — слишком много"


def test_no_external_assets():
    """Никаких внешних шрифтов и картинок: они дают лишний запрос и утечку Referer."""
    html = store_page()
    assert not re.search(r'src="https?://', html)
    assert 'href="https://fonts' not in html
    assert "@import" not in html


def test_mobile_layout_is_real():
    html = store_page()
    assert 'name="viewport" content="width=device-width,initial-scale=1"' in html
    assert "@media (max-width:820px)" in html          # сетка складывается в колонку
    assert "clamp(" in html                            # заголовки не ломают узкий экран


def test_every_card_has_price_and_cta():
    html = store_page()
    cards = re.findall(r'<article class="card".*?</article>', html, re.S)
    assert len(cards) >= 6, f"карточек {len(cards)}"
    for card in cards:
        assert 'class="price"' in card, card[:80]
        assert 'class="btn small"' in card, card[:80]
        assert re.search(r'href="(/(?![/])|https://|mailto:)', card), card[:80]


def test_proof_is_next_to_the_prices():
    """Доказательство должно быть на странице, а не в письме после оплаты."""
    html = store_page()
    assert "Check it before you pay" in html
    assert "/api/funnel" in html            # живые цифры, которые можно открыть
    assert "/verify-receipt" in html        # подпись проверяется офлайн
    assert "/docs/scan" in html             # правило «ничего не нашли — без оплаты»
    assert "/plans" in html                 # путь к платному шагу


def test_hero_has_two_paths():
    """Первый экран: бесплатный скан и платное исправление — оба видны сразу."""
    html = store_page()
    hero = html.split('id="products"')[0]
    assert 'href="/scan"' in hero
    assert 'href="/plans"' in hero
