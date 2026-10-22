"""Оплата картой через ENOT: клиент платит картой/СБП, мы получаем USDT.

Зачем отдельный модуль. Приём карты — не наш код: его делает провайдер, у
которого есть эквайринг и лицензия. Наш код делает две вещи: попросить счёт
(`POST /invoice/create`) и поверить уведомлению об оплате, что оно про нашу
кассу и про нашу сумму. Всё остальное — на стороне ENOT.

Контракт API (вычитан по официальной документации 23.10.2026,
`https://docs.enot.io/e/new/create-invoice`):

    POST https://api.enot.io/invoice/create
    x-api-key: <секретный ключ кассы>
    {"amount": 790, "order_id": "...", "currency": "RUB",
     "shop_id": "<uuid>", "hook_url": "...", "success_url": "...",
     "fail_url": "...", "comment": "...", "expire": 60}

Ответ: `{"id": uuid, "amount": "790.00", "currency": "RUB", "url": "...",
"expired": "..."}`. Ошибки: 401 (ключ/касса), 403 (сумма или касса
неактивны), 404 (нет тарифа вывода), 422 (валидация), 500.

Секреты — только из `~/.env`: `ENOT_SHOP_ID`, `ENOT_API_KEY`, `ENOT_SECRET`
(дополнительный ключ для подписи уведомлений), `ENOT_USDT_TRC20` (адрес
вывода). В коде и в unit-файле их нет и быть не должно.

Что модуль **не** делает: не проверяет подпись уведомления строго. Формула
`sign_2` в документации не приведена, а угадывать криптографию нельзя —
поэтому мы проверяем кассу, валюту и сумму, а подпись записываем как факт
(`signature_seen`) и включаем строгую проверку, когда формула будет
подтверждена в кабинете. Это осознанная граница, она записана и в README
модуля, и в ответе уведомления.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

API_URL = "https://api.enot.io/invoice/create"
#: Цена подписки в рублях. Одна цифра на весь продукт: если меняем — меняем здесь,
#: чтобы счёт и страница тарифов не разошлись.
PRICE_RUB = 790.0
TIMEOUT = 20

_ENV_CACHE: Optional[dict[str, str]] = None


def _env() -> dict[str, str]:
    """Переменные из ~/.env (один раз на процесс) плюс окружение.

    `os.environ` первым: в тестах и в systemd переменные приходят оттуда, и
    подменять файл в тесте не нужно.
    """
    global _ENV_CACHE
    if _ENV_CACHE is None:
        env: dict[str, str] = {}
        try:
            text = (Path.home() / ".env").read_text(encoding="utf-8")
        except OSError:
            text = ""
        for line in text.splitlines():
            match = re.match(r'^([A-Z0-9_]+)=["\']?(.*?)["\']?$', line)
            if match:
                env[match.group(1)] = match.group(2)
        _ENV_CACHE = env
    merged = dict(_ENV_CACHE)
    merged.update({k: v for k, v in os.environ.items() if k.startswith("ENOT_")})
    return merged


def config() -> dict[str, str]:
    env = _env()
    return {
        "shop_id": env.get("ENOT_SHOP_ID", "").strip(),
        "api_key": env.get("ENOT_API_KEY", "").strip(),
        "secret": env.get("ENOT_SECRET", "").strip(),
        "wallet": env.get("ENOT_USDT_TRC20", "").strip(),
    }


def enabled() -> bool:
    """Можно ли принимать карту: нужны касса и ключ. Адрес вывода не обязателен
    для приёма, но без него деньги некуда выводить — поэтому предупреждаем
    отдельно, а не отключаем приём."""
    conf = config()
    return bool(conf["shop_id"] and conf["api_key"])


def create_invoice(order_id: str, *, amount: float = PRICE_RUB,
                   comment: str = "attest — 30 days, 100 checks",
                   success_url: str = "https://attest.rta.lat/?paid=1",
                   fail_url: str = "https://attest.rta.lat/?paid=0",
                   hook_url: str = "https://attest.rta.lat/pay/enot/notify",
                   expire: int = 60) -> tuple[Optional[dict[str, Any]], str]:
    """Создать счёт. Возвращает (ответ_ENOT, "") или (None, причина)."""
    conf = config()
    if not conf["shop_id"] or not conf["api_key"]:
        return None, "card payments are not configured"
    payload = {
        "amount": round(float(amount), 2),
        "order_id": order_id,
        "currency": "RUB",
        "shop_id": conf["shop_id"],
        "hook_url": hook_url,
        "success_url": success_url,
        "fail_url": fail_url,
        "comment": comment[:255],
        # order_id возвращается в уведомлении через custom_fields —
        # это единственный документированный способ связать платёж с заказом.
        "custom_fields": json.dumps({"order_id": order_id}),
        "expire": expire,
        # Только карта и СБП: крипта у нас уже есть через x402, и смешивать
        # два способа в одном счёте — значит путать учёт.
        "include_service": ["card"],
    }
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-api-key": conf["api_key"],
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            raw = response.read(20000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(400).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        return None, f"HTTP {exc.code}: {body[:200]}"
    except Exception as exc:  # noqa: BLE001 — сеть: ответ не должен падать
        return None, f"{type(exc).__name__}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None, f"not JSON: {raw[:120]}"
    if not data.get("url"):
        return None, f"no payment url: {raw[:160]}"
    return data, ""


def _float(value: Any) -> float:
    try:
        return float(str(value).replace(",", "."))
    except (TypeError, ValueError):
        return -1.0


def verify_notification(form: dict[str, Any], *,
                        expected_amount: float = PRICE_RUB) -> tuple[bool, str]:
    """Проверить уведомление об оплате: наша ли касса, та ли сумма, та валюта.

    Подпись `sign_2` не проверяется строго: формулы в официальной документации
    нет, а придумывать криптографию хуже, чем честно сказать, что она не
    проверена. Если подпись пришла — она фиксируется вызывающим кодом
    (`signature_seen`), и это видно в журнале заказов.
    """
    conf = config()
    shop = str(form.get("merchant") or form.get("shop_id") or "").strip()
    if not conf["shop_id"]:
        return False, "shop is not configured"
    if shop != conf["shop_id"]:
        return False, f"another shop: {shop!r}"
    currency = str(form.get("currency") or "RUB").upper()
    if currency != "RUB":
        return False, f"another currency: {currency}"
    amount = _float(form.get("amount"))
    if amount < expected_amount - 0.01:
        return False, f"amount {amount} < {expected_amount}"
    return True, ""


def signature_seen(form: dict[str, Any]) -> bool:
    return bool(str(form.get("sign_2") or form.get("sign") or "").strip())


def signature_digest(form: dict[str, Any]) -> str:
    """Короткий отпечаток подписи для журнала: сам `sign_2` не храним."""
    raw = str(form.get("sign_2") or form.get("sign") or "")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16] if raw else ""


def wallet_warning() -> str:
    """Пустой адрес вывода — деньги в кабинете, но не у нас. Сказать вслух."""
    return "" if config()["wallet"] else (
        "ENOT_USDT_TRC20 не задан: платежи пройдут, но вывести их будет некуда"
    )
