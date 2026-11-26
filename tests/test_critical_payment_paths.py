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


def test_paid_but_delivery_failure_returns_paid_proof(monkeypatch):
    """Деньги приняли, выдача упала: клиент должен получить доказательство оплаты, а не обрыв."""
    import json
    import urllib.error
    import urllib.request
    from types import SimpleNamespace

    from attest.service import AttestHandler

    AttestHandler.free_tier.reset("ip:127.0.0.1")
    monkeypatch.setattr(AttestHandler.free_tier, "daily_limit", 0)   # monkeypatch, чтобы вернуть после теста
    monkeypatch.setattr(AttestHandler, "x402_pay_to", "0x" + "aa" * 20)

    def paid(self, header, amount_atoms=None):
        return SimpleNamespace(amount_atoms=5000, payer="0xpayer", pay_to=self.x402_pay_to,
                               nonce="0xnonce")

    def boom(self, payload, source, paid):
        raise RuntimeError("delivery exploded")

    monkeypatch.setattr(AttestHandler, "_verify_payment", paid)
    monkeypatch.setattr(AttestHandler, "_verify_result", boom)
    try:
        # тот же приём, что в tests/test_service.py: поднимаем сервер на свободном порту
        import threading
        from http.server import ThreadingHTTPServer

        srv = ThreadingHTTPServer(("127.0.0.1", 0), AttestHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}/verify"
        req = urllib.request.Request(url, data=json.dumps({"artifact": {"a": 1}}).encode(),
                                     headers={"Content-Type": "application/json",
                                              "X-PAYMENT": "ok"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            raise AssertionError("должен был вернуться 500")
        except urllib.error.HTTPError as exc:
            body = json.loads(exc.read().decode())
            assert exc.code == 500, body
            assert body["paid"] is True
            assert body["code"] == "DELIVERY_FAILED" and body["retryable"] is True
            assert body["payment"]["nonce"] == "0xnonce"
        finally:
            srv.shutdown()
            srv.server_close()
    finally:
        AttestHandler.free_tier.reset("ip:127.0.0.1")


def test_paid_check_is_counted_as_paid_not_only_as_payment(monkeypatch):
    """На проде было successful_paid_actions=1 при checks_paid=0 — счётчик проверок отставал."""
    from attest.metrics import METRICS

    if not METRICS.enabled:                       # тестовый прогон может выключить метрики
        import pytest
        pytest.skip("METRICS выключены в этом окружении")
    METRICS.check("unit-test", paid=True, client="c1", agent="test")
    snap = METRICS.snapshot()
    assert snap["checks_paid"] >= 1
    assert snap["checks_total"] >= snap["checks_free"] + snap["checks_paid"]
    src = (ROOT / "attest" / "service.py").read_text(encoding="utf-8")
    assert "METRICS.check(_channel, paid=True" in src, "оплаченный путь обязан считать проверку"
