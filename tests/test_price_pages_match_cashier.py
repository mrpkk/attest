"""Цена на странице attest = цена, которую выставит касса (01.11.2026, Агни).

Почему страж существует. Числа жили в трёх местах: в словаре `_handle_pack_order`,
в шаблоне страницы и в письме. Каждое «право» по-своему: страница могла просить
$1,600, касса выставлять $1,500, а письмо — третье. Человек платит не ту сумму,
которую прочитал, и это уже не опечатка, а потерянный покупатель.

Правило, которое держит тест: источник цены один — `PACK_TIERS` для пакетов,
`entitlement.PRICE_USD` для 30 дней, `AttestHandler.ppp_price_usd` для Индии,
`DENY_PRICE_USD` для журнала отказов. Страница имеет право называть только эти
числа, а страница продукта — ровно свои, ни одного лишнего и ни одного пропущенного.
"""

from __future__ import annotations

import re
import sys
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import entitlement  # noqa: E402
from attest.article import ARTICLE_HTML  # noqa: E402
from attest.eu_ai_act_page import EU_HTML  # noqa: E402
from attest.mcp_pages import SEO_PAGES, mcp_pass_page, seo_page  # noqa: E402
from attest.product_pages import (  # noqa: E402
    eu_ai_act_page, mcp_security_page, proof_of_place_page, trust_desk_page,
)
from attest.service import (  # noqa: E402
    DENY_PRICE_USD, LANDING, PACK_TIERS, PRICING, TRIAL_MIN_USD, AttestHandler, _PLANS_HTML,
)

PAY_TO = "0xefCD6886f73064ea9EcbaA4741Ef1309A0885C59"


def money(text: str) -> set[str]:
    """Суммы в обоих видах, как их пишет страница: `$1,500` и `99 USDC`."""
    dollars = {m.replace(",", "").rstrip(".") for m in re.findall(r"\$(\d[\d,\.]*)", text)}
    units = {m.replace(",", "").rstrip(".") for m in re.findall(r"(\d[\d,\.]*)\s*USDC", text)}
    return dollars | units


def tier_prices(product: str) -> set[str]:
    return {str(price) for price in PACK_TIERS[product].values()}


def catalogue() -> set[str]:
    """Все суммы, которые attest реально выставляет."""
    prices = {str(int(entitlement.PRICE_USD)), f"{AttestHandler.ppp_price_usd:g}",
              f"{DENY_PRICE_USD:g}", f"{TRIAL_MIN_USD:g}",
              str(PRICING["per_call"]["price"]), str(PRICING["free"]["price"])}
    for product in PACK_TIERS:
        prices |= tier_prices(product)
    return prices


def pay_page(path: str) -> str:
    """Страница /pay от настоящего метода: подменён только сокет, не цена."""
    stub = SimpleNamespace(path=path, x402_pay_to=PAY_TO,
                           ppp_price_usd=AttestHandler.ppp_price_usd)
    stub._plan_is_ppp = AttestHandler._plan_is_ppp
    stub._subscription_price_usd = lambda: AttestHandler._subscription_price_usd(stub)
    return AttestHandler._pay_page(stub)


SELLING_PAGES = {
    "/eu-ai-act": eu_ai_act_page(PAY_TO),
    "/mcp-security": mcp_security_page(PAY_TO),
    "/trust-desk": trust_desk_page(PAY_TO),
    "/proof-of-place": proof_of_place_page(PAY_TO),
    "/eu-ai-act-evidence": EU_HTML,
    "/mcp-security-pass": mcp_pass_page(PAY_TO),
    "/plans": _PLANS_HTML,
    "/": LANDING,
    "/article": ARTICLE_HTML,
    "/pay": pay_page("/pay"),
    "/pay?plan=ppp": pay_page("/pay?plan=ppp"),
}


@pytest.mark.parametrize("product,page", [
    ("eu_ai_act", eu_ai_act_page(PAY_TO)),
    ("mcp_security", mcp_security_page(PAY_TO)),
    ("trust_desk", trust_desk_page(PAY_TO)),
], ids=["eu_ai_act", "mcp_security", "trust_desk"])
def test_product_page_names_exactly_the_tiers_the_cashier_charges(product: str, page: str):
    """Страница продукта: ровно цены своих тарифов — ни лишней, ни пропавшей."""
    assert money(page) == tier_prices(product), (
        f"{product}: страница называет {sorted(money(page))}, касса берёт {sorted(tier_prices(product))}")


@pytest.mark.parametrize("page", ["/eu-ai-act-evidence", "/mcp-security-pass"])
def test_legacy_page_names_the_same_tiers_as_the_new_one(page: str):
    """Старый адрес того же продукта — те же числа, иначе две цены на один товар."""
    tiers = tier_prices("eu_ai_act" if page == "/eu-ai-act-evidence" else "mcp_security")
    assert money(SELLING_PAGES[page]) == tiers, (
        f"{page}: {sorted(money(SELLING_PAGES[page]))} против {sorted(tiers)}")


def test_proof_of_place_names_the_range_the_cashier_accepts():
    """Съёмка — диапазон $900–2,500: касса принимает сумму внутри него как pop_shoot.

    `money()` видит только `$900` (у 2,500 нет знака $), поэтому обычная сверка
    «страница = тарифы» здесь недостаточна: верхняя граница проверяется отдельно.
    """
    from attest.service import choose_tier

    page = SELLING_PAGES["/proof-of-place"]
    assert money(page) == {"300", "900", "99"}
    assert "$900–2,500" in page
    assert choose_tier(PACK_TIERS["proof_of_place"], 900) == "pop_shoot"
    assert choose_tier(PACK_TIERS["proof_of_place"], 2500) == "pop_shoot_travel"


@pytest.mark.parametrize("page", sorted(SELLING_PAGES))
def test_no_page_names_a_price_the_cashier_cannot_charge(page: str):
    """Сквозная проверка: каждая сумма на витрине существует в кассе."""
    extra = money(SELLING_PAGES[page]) - catalogue()
    assert not extra, f"{page} называет цену вне кассы: {sorted(extra)}"


@pytest.mark.parametrize("slug", sorted(SEO_PAGES))
def test_mcp_seo_page_names_no_invented_price(slug: str):
    extra = money(seo_page(slug)) - catalogue()
    assert not extra, f"/mcp/{slug} называет цену вне кассы: {sorted(extra)}"


def test_pay_page_shows_the_price_of_the_selected_plan():
    """Обычная и индийская страницы оплаты называют разные суммы — и обе настоящие."""
    assert str(int(entitlement.PRICE_USD)) in money(SELLING_PAGES["/pay"])
    assert f"{AttestHandler.ppp_price_usd:g}" in money(SELLING_PAGES["/pay?plan=ppp"])
    assert str(int(entitlement.PRICE_USD)) not in money(SELLING_PAGES["/pay?plan=ppp"]), (
        "индийская страница не должна называть западную цену")


def test_pricing_json_publishes_the_price_the_token_is_issued_for():
    """`/pricing` читают агенты: число там обязано совпадать с выдачей токена."""
    published = Decimal(PRICING["subscription"]["price"])
    assert published == Decimal(str(entitlement.PRICE_USD))
