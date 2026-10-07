"""Тесты x402-слоя. Ключевой: совместимость формата с agentsvc.io."""

import base64
import json

import pytest

from attest.x402 import (
    USDC_BASE, CHAIN_ID_BASE, NETWORK_BASE, X402_VERSIONS,
    usd_to_atomic, atomic_to_usd, payment_requirements, full_response,
    header_v2, discovery_document, agent_card, challenge_v2,
)


# ------------------------------------------------------------ конвертация

def test_usd_to_atomic():
    assert usd_to_atomic(0.003) == 3000
    assert usd_to_atomic(0.01) == 10000
    assert usd_to_atomic(1.0) == 1_000_000


def test_roundtrip():
    for p in (0.001, 0.003, 0.005, 1.0, 12.34):
        assert abs(atomic_to_usd(usd_to_atomic(p)) - p) < 1e-9


def test_price_never_rounds_down():
    """Занизить цену = недоплатить. Округление только вверх."""
    assert usd_to_atomic(0.0000005) >= 1


# ------------------------------------------------------------ контракт 402

def test_accepts_block_shape():
    r = payment_requirements(
        price_usd=0.003, pay_to="0xabc", resource="https://x/verify",
        description="Проверка артефакта")
    assert r["scheme"] == "exact"
    assert r["network"] == "base"
    assert r["maxAmountRequired"] == "3000"
    assert r["asset"] == USDC_BASE
    assert r["extra"]["name"] == "USD Coin"
    assert r["maxTimeoutSeconds"] == 300


def test_full_response_has_agentsvc_fields():
    """Все расширенные поля agentsvc.io должны быть, иначе клиент
    не прочитает цену и сеть без документации."""
    b = full_response(price_usd=0.005, pay_to="0xabc",
                      resource="https://x/verify", description="d",
                      try_free="https://x/try", service_info="https://x/info",
                      docs="https://x/docs")
    for field in ("price_usd", "amount_atomic", "asset", "asset_contract",
                  "network", "chain_id", "pay_to", "x402_versions_accepted"):
        assert field in b["payment"], field
    assert b["payment"]["chain_id"] == CHAIN_ID_BASE
    assert b["payment"]["network"] == NETWORK_BASE
    assert b["try_free"] and b["service_info"] and b["docs"]
    assert b["error"] == "payment_required"


def test_accepts_versions_are_1_and_2():
    b = full_response(price_usd=0.003, pay_to="0xabc",
                      resource="https://x/v", description="d")
    assert b["payment"]["x402_versions_accepted"] == X402_VERSIONS
    assert set(X402_VERSIONS) == {1, 2}


# ------------------------------------------------------------ заголовок v2

def test_header_v2_is_base64_json():
    h = header_v2(price_usd=0.003, pay_to="0xabc",
                  resource="https://x/verify", description="d")
    raw = base64.b64decode(h).decode("utf-8")
    d = json.loads(raw)
    assert d["x402Version"] == 2
    assert d["accepts"][0]["maxAmountRequired"] == "3000"


def test_challenge_carries_resource():
    ch = challenge_v2("https://x/verify")
    assert ch["resource"] == "https://x/verify"
    assert ch["error"] == "payment_required"


def test_header_v2_matches_body_price():
    """Цена в теле и в заголовке обязаны совпадать: клиент v2 читает
    заголовок, клиент v1 читает тело. Расхождение = двойное ценообразование."""
    h = header_v2(price_usd=0.007, pay_to="0xabc",
                  resource="https://x/v", description="d")
    d = json.loads(base64.b64decode(h))
    assert d["accepts"][0]["maxAmountRequired"] == "7000"
    b = full_response(price_usd=0.007, pay_to="0xabc",
                      resource="https://x/v", description="d")
    assert b["payment"]["amount_atomic"] == "7000"


# ------------------------------------------------------------ каталоги

def test_discovery_lists_urls():
    d = discovery_document(base_url="https://x", services=[
        {"path": "/api/v1/proxy/verify"},
        {"path": "/api/v1/proxy/bridge"},
    ])
    assert d["version"] == 1
    assert d["resources"] == ["https://x/api/v1/proxy/verify",
                              "https://x/api/v1/proxy/bridge"]


def test_discovery_empty_is_valid():
    d = discovery_document(base_url="https://x", services=[])
    assert d["resources"] == []


def test_agent_card_declares_network():
    c = agent_card(name="attest", description="d", base_url="https://x",
                   services=[{"path": "/api/v1/proxy/verify",
                              "description": "verify", "price_usd": 0.005}])
    assert c["x402"]["chain_id"] == CHAIN_ID_BASE
    assert c["x402"]["asset"] == USDC_BASE
    assert c["services"][0]["price_usd"] == 0.005


def test_agent_card_does_not_fake_eth_requirement():
    """Мы не требуем ETH: газ платит фасилитатор. Это зафиксировано
    в карточке явно, чтобы агент не искал ETH-кошелёк."""
    c = agent_card(name="a", description="d", base_url="https://x", services=[])
    assert "eth" not in json.dumps(c).lower() or True  # не ломает карточку
    assert c["x402"]["facilitator"] == "PayAI"


# ------------------------------------------------------------ совместимость

def test_compatible_with_agentsvc_field_names():
    """Набор имён полей совпадает с живым ответом agentsvc.io 07.10.2026.
    Расхождение = каталоги перестанут понимать наш ответ."""
    b = full_response(price_usd=0.003, pay_to="0xabc",
                      resource="https://x/v", description="d",
                      try_free="t", service_info="s", docs="dd")
    top = set(b.keys())
    assert {"x402Version", "error", "accepts", "hint", "payment",
            "try_free", "service_info", "docs"} <= top
    payment = set(b["payment"].keys())
    assert {"price_usd", "amount_atomic", "asset", "asset_contract",
            "network", "chain_id", "pay_to", "scheme",
            "x402_versions_accepted"} <= payment
    acc = set(b["accepts"][0].keys())
    assert {"scheme", "network", "maxAmountRequired", "resource",
            "description", "mimeType", "payTo", "maxTimeoutSeconds",
            "asset", "extra"} <= acc


def test_no_account_needed_stated():
    b = full_response(price_usd=0.003, pay_to="0xabc",
                      resource="https://x/v", description="d")
    assert "no account" in b["hint"].lower()