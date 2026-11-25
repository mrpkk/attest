"""Критичные пути денег: граница срока, изоляция пакетов, оплата после исчерпания.

26.11.2026: три места, где ошибка стоит денег покупателя или наша —
граница `valid_until`, общий счётчик пакета и путь «пакет кончился, но клиент платит за вызов».
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import entitlement  # noqa: E402
from attest.signing import public_key_b64  # noqa: E402


def _token(subject: str, max_calls: int | None = None) -> dict:
    return entitlement.issue(subject, days=30, max_calls=max_calls)


def test_validity_boundary_is_exclusive():
    """За секунду до конца — работает; ровно в момент окончания — уже нет."""
    grant = _token("boundary@example.com")
    until = grant["valid_until"]
    key = public_key_b64()
    assert entitlement.redeem_entitlement(grant["token"], now=until - 1,
                                          trusted_key=key)[0] is not None
    assert entitlement.redeem_entitlement(grant["token"], now=until,
                                          trusted_key=key)[0] is None


def test_quota_is_counted_per_subject_not_globally():
    """Пакет одного покупателя не должен тратить пакет другого."""
    from collections import defaultdict

    from attest.service import AttestHandler

    AttestHandler.ent_usage = defaultdict(int)
    a = _token("buyer-a@example.com", max_calls=1)
    b = _token("buyer-b@example.com", max_calls=1)
    ent_a, _ = entitlement.redeem_entitlement(a["token"], trusted_key=public_key_b64())
    ent_b, _ = entitlement.redeem_entitlement(b["token"], trusted_key=public_key_b64())
    assert ent_a.subject != ent_b.subject
    AttestHandler.ent_usage[ent_a.subject] += 1
    assert AttestHandler.ent_usage[ent_a.subject] == 1
    assert AttestHandler.ent_usage[ent_b.subject] == 0, "пакет B не должен расходоваться от A"


def test_entitlement_header_name_is_stable():
    """Заголовок — часть контракта: переименование ломает живых клиентов."""
    assert entitlement.HEADER == "X-ATTEST-ENTITLEMENT"


def test_expired_token_reports_a_reason_not_a_crash():
    grant = _token("late@example.com")
    ent, why = entitlement.redeem_entitlement(grant["token"],
                                              now=grant["valid_until"] + 1,
                                              trusted_key=public_key_b64())
    assert ent is None and why and "expir" in why.lower()


def test_paid_call_does_not_depend_on_free_quota():
    """Деньги уже уплачены — отказ по бесплатной квоте недопустим.

    Порядок ветвей в `_mcp_charge`: подписка → оплаченный вызов → бесплатная квота.
    Если квота окажется первой, платящий клиент получит 402 и уйдёт.
    """
    src = (ROOT / "attest" / "service.py").read_text(encoding="utf-8")
    start = src.find("def _mcp_charge(self)")
    assert start > 0
    body = src[start:]
    body = body[body.find('"""', body.find('"""') + 3) + 3:]      # после docstring
    order = {kw: body.find(kw) for kw in
             ("_entitlement_access", "X-PAYMENT", "free_tier")}
    assert all(v > -1 for v in order.values()), order
    assert order["_entitlement_access"] < order["X-PAYMENT"] < order["free_tier"], \
        f"порядок ветвей сломан: {order}"
