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


def test_hero_has_one_primary_action():
    """Одна главная кнопка: три равных кнопки — это выбор вместо действия (CRO)."""
    html = store_page()
    hero = html.split('<div class="wrap hero">')[1].split('id="products"')[0]
    assert hero.count('data-primary="1"') == 1
    assert len(re.findall(r'<a class="btn', hero)) == 2, "главная кнопка и один запасной путь"
    assert "No card, no account, 30 seconds" in hero
    assert "audit-sample.html" in hero, "пример результата не должен пропасть из первого экрана"


def test_store_page_is_cached_for_repeat_visits():
    """Повторный заход должен брать страницу из кэша браузера, а не ждать сервер."""
    src = (ROOT / "attest" / "service.py").read_text(encoding="utf-8")
    assert 'self._send_html(store_page(), cache_seconds=60)' in src


def test_price_is_unambiguous_in_the_hero():
    """$19 рядом с $199 без пояснения — это вопрос «сколько платить?» вместо покупки."""
    html = store_page()
    hero = html.split('<div class="wrap hero">')[1].split('id="products"')[0]
    assert "$19" in hero and "$199" in hero
    assert "first 10 teams" in hero, "условие founding-цены должно быть рядом с ценой"
    assert "<s>$199</s>" in hero, "старая цена показывается зачёркнутой, а не вместо новой"


def test_hero_links_to_what_the_scan_checks():
    """Доказательство до клика: что проверяет скан и чего не делает — со ссылкой и меткой."""
    hero = store_page().split('<div class="wrap hero">')[1].split('id="products"')[0]
    assert "/docs/scan?ref=store" in hero


def test_page_weight_budget_stays_honest():
    """После правок страница не должна расползтись: 22 КБ — потолок, выше него скорость станет обещанием."""
    size = len(store_page().encode("utf-8"))
    assert size < 22_000, f"{size} байт — страница выросла"


def test_buttons_are_big_enough_for_a_finger():
    """Кнопки в карточках были ~36 px: на телефоне в них трудно попасть (WCAG 2.5.8)."""
    html = store_page()
    import re

    small = re.search(r"\.btn\.small\{([^}]*)\}", html)
    assert small and "min-height:44px" in small.group(1), small.group(0) if small else "нет правила"
    main = re.search(r"\.btn\{([^}]*)\}", html)
    assert main and "padding:13px" in main.group(1), "главная кнопка не должна уменьшаться"


def test_no_fixed_width_that_can_overflow_a_phone():
    """Фиксированная ширина больше 360 px даёт горизонтальный скролл на телефоне."""
    import re

    html = store_page()
    bad = [w for w in re.findall(r"(?:^|[;{ ])width:(\d{3,})px", html) if int(w) > 360]
    assert not bad, f"фиксированные ширины: {bad}"
