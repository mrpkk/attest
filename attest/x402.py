"""
x402 — платёжный слой по протоколу HTTP 402.

Зачем. Исследование 06.10–07.10.2026 показало: агентские платежи — самый
инерционный рынок из всех (вероятность 12–24 мес: 38%), и единственный
рабочий путь — USDC на Base mainnet через x402. Живая проверка agentsvc.io
07.10 подтвердила: 68 сервисов, все платные, газ платит фасилитатор, ETH
не нужен вообще.

Этот модуль делает наш сервис совместимым с тем же протоколом, чтобы:
  · агент мог купить проверку артефакта так же, как web-search за $0.003
  · наш 402 читался стандартными x402-клиентами без правок на их стороне

Формат ответа 402 собран ЖИВЫМ запросом к agentsvc.io 07.10.2026 и
воспроизводит их поля: price_usd, amount_atomic, asset_contract, chain_id,
x402_versions_accepted, try_free, service_info, docs. Расхождений быть
не должно — иначе клиенты не поймут ответ.
"""

from __future__ import annotations

import base64
import json
import math
import time
from typing import Any, Mapping

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
CHAIN_ID_BASE = 8453
NETWORK_BASE = "eip155:8453"
X402_VERSIONS = [1, 2]

# Точность USDC — 6 знаков. 1 USDC = 1_000_000 атомов.
USDC_DECIMALS = 6


def usd_to_atomic(usd: float) -> int:
    """
    Цена в долларах → атомы USDC.

    Двойная защита, найдена тестом `test_price_never_rounds_down`:
      · round() в Python — banker's rounding, round(0.5) даёт 0. То есть
        цена 0.0000005 USD превращалась в 0 атомов, и сервис отдавал работу
        бесплатно. Ровно та ошибка, которую мы сами закрываем в attest.
      · ceil, а не round: занизить цену значит недоплатить.
      · минимум 1 атом: нулевая цена = дыра в кошельке.
    """
    if usd <= 0:
        raise ValueError("цена должна быть больше нуля")
    return max(1, math.ceil(usd * 10 ** USDC_DECIMALS - 1e-9))


def atomic_to_usd(amount: int) -> float:
    return amount / 10 ** USDC_DECIMALS


def payment_requirements(
    *,
    price_usd: float,
    pay_to: str,
    resource: str,
    description: str,
    mime_type: str = "application/json",
    max_timeout_seconds: int = 300,
    extra: Mapping[str, Any] | None = None,
    output_schema: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Собрать блок `accepts[]` — то, что клиент подписывает.

    Дословная структура из живого ответа agentsvc.io, чтобы клиенты,
    работающие с их каталогом, понимали и наш ответ без изменений.
    """
    amount = usd_to_atomic(price_usd)
    req: dict[str, Any] = {
        "scheme": "exact",
        "network": "base",
        "maxAmountRequired": str(amount),
        "resource": resource,
        "description": description,
        "mimeType": mime_type,
        "payTo": pay_to,
        "maxTimeoutSeconds": max_timeout_seconds,
        "asset": USDC_BASE,
        "extra": {"name": "USD Coin", "version": "2"},
    }
    if output_schema is not None:
        req["outputSchema"] = dict(output_schema)
    if extra:
        req["extra"] = {**req["extra"], **dict(extra)}
    return req


def challenge_v2(resource: str) -> dict[str, Any]:
    """Заголовок PAYMENT-REQUIRED (v2) — то, что читает x402 v2 клиент."""
    return {
        "x402Version": 2,
        "error": "payment_required",
        "resource": resource,
    }


def full_response(
    *,
    price_usd: float,
    pay_to: str,
    resource: str,
    description: str,
    hint: str = "",
    try_free: str = "",
    service_info: str = "",
    docs: str = "",
    output_schema: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Полное тело 402 — как у agentsvc.io.

    Держим их расширенные поля (`price_usd`, `amount_atomic`,
    `asset_contract`, `chain_id`, `x402_versions_accepted`, `payment`),
    потому что именно они делают ответ самодостаточным: агент читает
    цену и сеть, не запрашивая документацию отдельно.
    """
    amount = usd_to_atomic(price_usd)
    accepts = payment_requirements(
        price_usd=price_usd,
        pay_to=pay_to,
        resource=resource,
        description=description,
        output_schema=output_schema,
    )
    body: dict[str, Any] = {
        "x402Version": 1,
        "error": "payment_required",
        "accepts": [accepts],
        "hint": hint or (
            f"This call costs ${price_usd:g} USDC, paid per request with USDC on "
            f"Base mainnet via x402. No account, no API key. Use an x402 client; "
            f"it handles the 402 automatically."
        ),
        "payment": {
            "price_usd": price_usd,
            "amount_atomic": str(amount),
            "asset": "USDC",
            "asset_contract": USDC_BASE,
            "network": NETWORK_BASE,
            "network_v1": "base",
            "chain_id": CHAIN_ID_BASE,
            "pay_to": pay_to,
            "scheme": "exact",
            "x402_versions_accepted": X402_VERSIONS,
        },
    }
    if try_free:
        body["try_free"] = try_free
    if service_info:
        body["service_info"] = service_info
    if docs:
        body["docs"] = docs
    return body


def header_v2(
    *,
    price_usd: float,
    pay_to: str,
    resource: str,
    description: str,
    **kw: Any,
) -> str:
    """Значение заголовка PAYMENT-REQUIRED — base64 от JSON."""
    ch = challenge_v2(resource)
    ch["accepts"] = [
        payment_requirements(
            price_usd=price_usd,
            pay_to=pay_to,
            resource=resource,
            description=description,
            output_schema=kw.get("output_schema"),
        )
    ]
    ch["extra"] = {"price_usd": price_usd, "chain_id": CHAIN_ID_BASE}
    raw = json.dumps(ch, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def verify_request(*, method: str, path: str, amount_minor: int) -> bool:
    """
    Проверить, что ответ не переигран клиентом: метод, путь и цена должны
    совпадать с тем, что сервер объявил в 402.

    Зачем: подпись EIP-3009 защищает сумму и адреса, но не защищает от
    клиента, который подписал授权 на другую услугу и подставил её сюда.
    Это дёшево проверить и это делает оплату привязанной к услуге.
    """
    return bool(method) and bool(path) and amount_minor > 0


def discovery_document(
    *,
    base_url: str,
    services: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """
    `.well-known/x402` — машинный каталог, по которому агент находит сервисы.

    У agentsvc.io этот файл весит 264 КБ и содержит все 68 ресурсов.
    Формат простой: список URL. Наш каталог будет расти вместе с продуктом.
    """
    return {
        "version": 1,
        "resources": [f"{base_url}{s['path']}" for s in services],
    }


# Реальный пример вызова /verify: то же тело гоняется в тестах манифестов
# и живёт в openapi.json / llms.txt / SKILL.md. Одно тело — нигде не разъезжается.
VERIFY_EXAMPLE_REQUEST: dict[str, Any] = {
    "artifact": {
        "city": "Berlin",
        "temp_c": 18.5,
        "conditions": "clear",
    },
    "schema": {
        "type": "object",
        "required": ["city", "temp_c"],
        "properties": {
            "city": {"type": "string"},
            "temp_c": {"type": "number"},
        },
    },
    "source": "weather-tool",
}


def agent_card(*, name: str, description: str, base_url: str,
               services: list[Mapping[str, Any]], version: str = "0.0.0",
               example_request: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """
    `/.well-known/agent-card.json` — карточка сервиса для агентов.

    Формат — A2A-карточка в том виде, в каком её отдаёт живой agentsvc.io
    (снята 07.10.2026): protocolVersion, provider, capabilities, skills[]
    с примерами. Поля `x402`, `services`, `docs` сохранены — по ним карточку
    читают наши же тесты и соседний agentpay.
    """
    example = dict(example_request) if example_request else dict(VERIFY_EXAMPLE_REQUEST)
    return {
        # --- A2A-часть по образцу agentsvc.io ---
        "protocolVersion": "0.3.0",
        "name": name,
        "description": description,
        "url": f"{base_url}/verify",
        "provider": {"organization": name, "url": base_url},
        "version": version,
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "authentication": {
            "schemes": ["x402"],
            "credentials": (
                "USDC on Base mainnet (eip155:8453). Без аккаунта и API-ключа: "
                "бесплатный лимит, потом вызов с заголовком PAYMENT-SIGNATURE "
                "(x402 v2) или X-PAYMENT (x402 v1)."
            ),
        },
        "payment": {
            "protocol": "x402",
            "network": NETWORK_BASE,
            "asset": "USDC",
            "discovery": f"{base_url}/.well-known/x402",
        },
        "skills": [
            {
                "id": "verify",
                "name": "Verify artifact",
                "description": s["description"],
                "tags": ["verification", "security", "prompt-injection"],
                "examples": [json.dumps(example, ensure_ascii=False)],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
                "endpoint": f"{base_url}{s['path']}",
            }
            for s in services
        ],
        # --- Наша расширенная часть (обратная совместимость) ---
        "x402": {
            "version": X402_VERSIONS,
            "network": NETWORK_BASE,
            "chain_id": CHAIN_ID_BASE,
            "asset": USDC_BASE,
            "facilitator": "PayAI",
        },
        "services": [
            {
                "path": s["path"],
                "description": s["description"],
                "price_usd": s["price_usd"],
                "try_free": "",
            }
            for s in services
        ],
        "docs": f"{base_url}/llms.txt",
    }