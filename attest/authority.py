#!/usr/bin/env python3
"""Было ли это действие разрешено.

`attest` отвечает на вопрос «подписано ли это тем ключом». Он не отвечает
на вопрос «имело ли право это делать». Подписанный действие не становится
разрешённым: право выдаётся отдельно и действует ограниченное время.

Здесь проверяется именно разрешение — по тем же правилам, что и в `drift`
(модуль `drift.py`, функция `check`). Правила продублированы намеренно:
зависимость от чужого репозитория в проверке безопасности означала бы, что
её нельзя выполнить, не имея доступа к сети и к чужому коду. Логика — это
шесть сравнений, их дешевле продублировать, чем сделать проверку
невыполнимой.

Но дублирование без защиты разъезжается. Поэтому ниже — тот же порядок
правил и тест, который закрепляет его. Если правила в `drift` изменятся,
здешний модуль разойдётся с ним, и это станет видно по тестам, а не по
жалобе клиента.

Что здесь принципиально: **мандат входит в подпись.** Если проверять
разрешение, но не заверять его, к любому действию можно приложить чужой
мандат — и подпись это не заметит.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Порядок правил значим и совпадает с drift.check: самая частая причина
# отказа идёт первой, чтобы ответ был полезным, а не просто верным.
RULES = ("amount", "payee", "audience", "currency", "window", "intent")

MANDATE_FIELDS = ("payee_id", "audience", "max_amount_minor", "currency",
                  "valid_from", "valid_until")


@dataclass(frozen=True)
class AuthorityVerdict:
    allowed: bool
    rule: str            # какое правило сработало либо "-"
    mandate: dict[str, Any]
    action: dict[str, Any]
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "rule": self.rule,
                "mandate": self.mandate, "action": self.action,
                "note": self.note}


def _as_int(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"поле {field!r}: ожидалось целое, получено {value!r}") from exc


def check_authority(mandate: dict[str, Any], action: dict[str, Any]
                    ) -> AuthorityVerdict:
    """Проверить, разрешает ли мандат это действие.

    Отсутствие мандата — не «разрешено». Проверяющий, не предъявивший
    полномочия, не доказал разрешения; возвращать при этом ALLOW значило
    бы превращать отсутствие данных в согласие.
    """
    missing = [f for f in MANDATE_FIELDS if f not in mandate]
    if missing:
        return AuthorityVerdict(
            False, "no_mandate", dict(mandate), dict(action),
            note=f"в мандате нет полей: {', '.join(missing)}")

    amt = _as_int(action.get("amount_minor", 0), "action.amount_minor")
    at = _as_int(action.get("at", 0), "action.at")

    if amt > _as_int(mandate["max_amount_minor"], "mandate.max_amount_minor"):
        return AuthorityVerdict(False, "amount", dict(mandate), dict(action),
                                note=f"сумма {amt} превышает лимит "
                                     f"{mandate['max_amount_minor']}")
    if action.get("payee_id") != mandate["payee_id"]:
        return AuthorityVerdict(False, "payee", dict(mandate), dict(action),
                                note="получатель не тот, что указан в мандате")
    if action.get("audience") != mandate["audience"]:
        return AuthorityVerdict(False, "audience", dict(mandate), dict(action),
                                note="аудитория не та")
    if action.get("currency") != mandate["currency"]:
        return AuthorityVerdict(False, "currency", dict(mandate), dict(action),
                                note="валюта не та")

    valid_from = _as_int(mandate["valid_from"], "mandate.valid_from")
    valid_until = _as_int(mandate["valid_until"], "mandate.valid_until")
    if not (valid_from <= at <= valid_until):
        return AuthorityVerdict(False, "window", dict(mandate), dict(action),
                                note=f"момент {at} вне окна "
                                     f"[{valid_from}, {valid_until}]")

    allowed_intents = mandate.get("allowed_intents") or ()
    if allowed_intents and action.get("intent") not in allowed_intents:
        return AuthorityVerdict(False, "intent", dict(mandate), dict(action),
                                note=f"намерение {action.get('intent')!r} не "
                                     f"перечислено в мандате")

    return AuthorityVerdict(True, "-", dict(mandate), dict(action),
                            note="действие укладывается в мандат")


def authority_hash(mandate: dict[str, Any], action: dict[str, Any]) -> str:
    """Хэш пары «мандат + действие» — то, что идёт в подпись.

    Хэшируется и действие тоже. Иначе подпись подтверждает, что мандат
    существовал, но не подтверждает, что проверялось именно это действие:
    к одному подписанному мандату можно было бы приложить любое.
    """
    import hashlib
    import json
    payload = json.dumps({"mandate": mandate, "action": action},
                         sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return "authority:" + hashlib.sha256(payload).hexdigest()
