#!/usr/bin/env python3
"""Предоплаченный доступ: 30 дней за один платёж.

Почему не «подписка». x402 платит за вызов и ничего больше: в протоколе
нет ни периодичности, ни автосписания, ни хранения способа оплаты.
Попытка продавать по нему подписку означала бы обещать то, чего
протокол не умеет.

Поэтому подписка здесь — честная предоплата. Клиент один раз платит 9
USDC за 30 дней и получает подписанный токен. Дальше предъявляет его в
заголовке `X-ATTEST-ENTITLEMENT`. Списаний не происходит: когда срок
кончается, доступ кончается, и продление — снова явный платёж.

Это же делает токен проверяемым: он подписан тем же ключом Ed25519, что и
заверяния артефактов, и проверяется без обращения к сервису.

Что это даёт покупателю, чего нет у бесплатного тарифа: лимит не кончается
за сутки. Что даёт нам: подписку не нужно отзывать, хранить карту и
защищать от возвратов — деньги получены вперёд.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from .signing import sign, verify

HEADER = "X-ATTEST-ENTITLEMENT"
PLAN = "unlimited-30d"
PRICE_USD = 9.0
DEFAULT_DAYS = 30


@dataclass(frozen=True)
class Entitlement:
    subject: str
    plan: str
    issued_at: int
    valid_until: int

    def payload(self) -> dict[str, Any]:
        return {"subject": self.subject, "plan": self.plan,
                "issued_at": self.issued_at, "valid_until": self.valid_until}

    @property
    def expired(self) -> bool:
        return time.time() >= self.valid_until

    def days_left(self) -> int:
        return max(0, int((self.valid_until - time.time()) / 86400) + 1)


def issue(subject: str, days: int = DEFAULT_DAYS) -> dict[str, Any]:
    """Выдать токен. Вызывается только после подтверждённой оплаты."""
    now = int(time.time())
    ent = Entitlement(subject=subject, plan=PLAN, issued_at=now,
                      valid_until=now + days * 86400)
    body = json.dumps(ent.payload(), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    signed = sign(body)
    return {
        "token": json.dumps(
            {"payload": ent.payload(), "signature": signed.signature,
             "public_key": signed.public_key, "algorithm": signed.algorithm},
            separators=(",", ":"), ensure_ascii=False),
        "plan": ent.plan,
        "days": days,
        "valid_until": ent.valid_until,
        "header": HEADER,
        "auto_renews": False,
    }


def redeem(token: str | None, now: float | None = None,
           trusted_key: str | None = None) -> tuple[bool, str]:
    """Проверить предъявленный токен.

    Возвращает (действителен, причина). Причина важна: «недействителен» и
    «нет токена» — разные вещи, и клиенту нужна конкретная из них, чтобы
    понять, покупать ему продление или разбираться с ошибкой.

    Пустой токен — это не ошибка. Отсутствие подписки не должно
    выглядеть как поломка: без неё просто действует бесплатный тариф.

    `trusted_key` — публичный ключ сервиса. Он обязателен: без него
    проверка подписи не значит ничего. Токен несёт свой ключ, а ключ из
    токена нельзя принимать — иначе доступ выпускает кто угодно и любым
    ключом, стоит только прочитать исходник. Код открыт, поэтому такая
    подделка находится за минуту.

    Для проверки без обращения к сервису ключ берётся не из токена, а из
    `fingerprint()` на сайте: сверка отпечатка и есть то, что делает
    проверку независимой.
    """
    if not token or not token.strip():
        return False, "no entitlement supplied — the free tier applies"

    now = time.time() if now is None else now
    try:
        data = json.loads(token)
    except (json.JSONDecodeError, ValueError):
        return False, "entitlement is not valid JSON"
    # JSON массив или строка разбирается без ошибки, но `.get` на нём
    # падает. Присланное значение — это ввод клиента, а не наш объект:
    # разбирать его, а не верить, что это словарь.
    if not isinstance(data, dict):
        return False, ("entitlement is not a JSON object "
                       f"(got {type(data).__name__})")

    payload = data.get("payload")
    sig = data.get("signature")
    pub = data.get("public_key")
    if not payload or not sig or not pub:
        return False, "entitlement is incomplete"

    if data.get("algorithm") != "ed25519":
        return False, f"unsupported algorithm {data.get('algorithm')!r}"

    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    key = trusted_key or pub
    if trusted_key is None:
        return False, ("no trusted key supplied — refusing to trust the key "
                       "carried inside the token")
    if not verify(body, sig, key):
        return False, "entitlement signature does not match — it was altered"
    if key != pub:
        return False, "entitlement was signed by a different key"

    valid_until = payload.get("valid_until")
    if not isinstance(valid_until, (int, float)):
        return False, "entitlement has no expiry"
    if now >= valid_until:
        return False, f"entitlement expired {(now - valid_until) / 86400:.1f} days ago"

    return True, (f"valid for another "
                  f"{int((valid_until - now) / 86400) + 1} days")


def fingerprint() -> str:
    """Отпечаток ключа, которым подписан доступ.

    Публикуется на сайте. Покупатель сверяет его со своим токеном и
    получает проверку, которой нельзя подделать ни сервер, ни сеть.
    """
    from .signing import key_fingerprint
    return key_fingerprint()


def describe() -> dict[str, Any]:
    """Как это устроено — для /pricing, чтобы покупатель знал заранее."""
    return {
        "plan": PLAN,
        "price": str(PRICE_USD),
        "currency": "USDC",
        "period_days": DEFAULT_DAYS,
        "billing": "one-time prepayment",
        "auto_renews": False,
        "how": (
            "Pay once for 30 days, receive a signed entitlement token, "
            "send it in the X-ATTEST-ENTITLEMENT header. The token is "
            "Ed25519-signed and can be verified without this service. "
            "No recurring charges: when the 30 days run out, access stops "
            "and renewal is an explicit new payment."
        ),
        "limit": "no daily cap while the token is valid",
        "signed_with": fingerprint(),
        "verify_yourself": (
            "The token carries an Ed25519 signature. Check the fingerprint "
            "above against the token's public_key to confirm it was issued "
            "here — this service never trusts a key supplied by the token."
        ),
    }
