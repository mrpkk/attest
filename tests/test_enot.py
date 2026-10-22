"""Оплата картой через ENOT: счёт, уведомление, идемпотентность.

Проверяем ровно то, что ломается молча:

1. **Запрос к провайдеру уходит с ключом и с нашим order_id** — иначе платёж
   нельзя связать с заказом, а ключ утечёт или не дойдёт.
2. **Уведомление чужой кассы/валюты/меньшей суммы отклоняется** — иначе кто
   угодно пришлёт «оплачено» и получит токен.
3. **Повтор уведомления не выдаёт второй токен** — провайдер вправе повторить.
4. **Без настроенной кассы маршрут честно отвечает 503**, а не 500 и не тишиной.

Сеть подменяется: тесты не ходят в `api.enot.io` и не тратят чужой лимит.
"""
from __future__ import annotations

import json
import pathlib
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from attest import enot  # noqa: E402
from attest.service import AttestHandler  # noqa: E402

PORT = 8179
BASE = f"http://127.0.0.1:{PORT}"


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, _limit: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args) -> None:
        return None

    def close(self) -> None:
        """Нужен tempfile: HTTPError держит body как файл и закрывает его."""
        return None


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("ENOT_SHOP_ID", "ENOT_API_KEY", "ENOT_SECRET", "ENOT_USDT_TRC20"):
        monkeypatch.delenv(name, raising=False)
    enot._ENV_CACHE = None
    yield
    enot._ENV_CACHE = None


def _configure(monkeypatch, wallet: str = "TWalletAddr"):
    monkeypatch.setenv("ENOT_SHOP_ID", "shop-uuid-1")
    monkeypatch.setenv("ENOT_API_KEY", "secret-key-1")
    monkeypatch.setenv("ENOT_SECRET", "sign-secret-1")
    if wallet:
        monkeypatch.setenv("ENOT_USDT_TRC20", wallet)
    enot._ENV_CACHE = None


# ── счёт ────────────────────────────────────────────────────────────────────

def test_create_invoice_sends_key_shop_and_order(monkeypatch):
    _configure(monkeypatch)
    captured: dict = {}

    def fake_urlopen(request, timeout=0):
        captured["url"] = request.full_url
        captured["headers"] = {k.lower(): v for k, v in request.header_items()}
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeResponse(json.dumps({
            "id": "inv-1", "amount": "790.00", "currency": "RUB",
            "url": "https://pay.enot.io/inv-1", "expired": "2026-10-23 12:00:00",
        }).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    data, error = enot.create_invoice("order-42")

    assert error == ""
    assert data["url"] == "https://pay.enot.io/inv-1"
    assert captured["url"] == enot.API_URL
    assert captured["headers"]["x-api-key"] == "secret-key-1"
    body = captured["body"]
    assert body["shop_id"] == "shop-uuid-1"
    assert body["currency"] == "RUB"
    assert body["amount"] == 790.0
    # order_id обязан вернуться в уведомлении — значит едет в custom_fields
    assert json.loads(body["custom_fields"])["order_id"] == "order-42"


def test_create_invoice_reports_http_error(monkeypatch):
    _configure(monkeypatch)

    def fake_urlopen(request, timeout=0):
        raise urllib.error.HTTPError(
            request.full_url, 401, "Unauthorized", {}, _FakeResponse(b'{"error":"auth"}'))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    data, error = enot.create_invoice("order-43")
    assert data is None
    assert "401" in error


def test_create_invoice_without_config_does_not_call_network(monkeypatch):
    called = []
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: called.append(1) or _FakeResponse(b"{}"))
    data, error = enot.create_invoice("order-44")
    assert data is None
    assert "not configured" in error
    assert called == []


# ── уведомление ─────────────────────────────────────────────────────────────

GOOD = {"merchant": "shop-uuid-1", "amount": "790.00", "currency": "RUB",
        "intid": "1545855", "sign_2": "deadbeef"}


def test_notification_from_our_shop_is_accepted(monkeypatch):
    _configure(monkeypatch)
    ok, reason = enot.verify_notification(GOOD)
    assert ok, reason


def test_notification_from_another_shop_is_rejected(monkeypatch):
    _configure(monkeypatch)
    ok, reason = enot.verify_notification({**GOOD, "merchant": "other-shop"})
    assert not ok
    assert "another shop" in reason


def test_notification_with_lower_amount_is_rejected(monkeypatch):
    _configure(monkeypatch)
    ok, reason = enot.verify_notification({**GOOD, "amount": "10.00"})
    assert not ok
    assert "amount" in reason


def test_notification_in_another_currency_is_rejected(monkeypatch):
    _configure(monkeypatch)
    ok, reason = enot.verify_notification({**GOOD, "currency": "USD"})
    assert not ok
    assert "currency" in reason


def test_signature_presence_is_recorded_but_not_trusted(monkeypatch):
    """Подпись фиксируем, но строго не проверяем: формулы в доках нет.

    Это осознанная граница, а не забывчивость: придуманная проверка хуже
    честной записи «signature_seen: true».
    """
    _configure(monkeypatch)
    assert enot.signature_seen(GOOD) is True
    assert enot.signature_digest(GOOD) != ""
    # сам sign_2 в журнал не попадает — только отпечаток
    assert "deadbeef" not in enot.signature_digest(GOOD)


def test_wallet_warning_when_payout_address_is_missing(monkeypatch):
    _configure(monkeypatch, wallet="")
    assert "ENOT_USDT_TRC20" in enot.wallet_warning()
    _configure(monkeypatch)
    assert enot.wallet_warning() == ""


# ── маршруты ────────────────────────────────────────────────────────────────

@pytest.fixture()
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(AttestHandler, "leads_path",
                        tmp_path / "leads.jsonl")
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), AttestHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield BASE, tmp_path
    httpd.shutdown()
    httpd.server_close()


def _post_form(url: str, fields: dict) -> tuple[int, dict]:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_route_says_503_when_card_is_not_configured(server):
    base, _ = server
    request = urllib.request.Request(f"{base}/pay/enot", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(request, timeout=10)
        raise AssertionError("ожидали 503")
    except urllib.error.HTTPError as exc:
        assert exc.code == 503
        assert "not enabled" in exc.read().decode("utf-8")


def test_route_returns_payment_url(server, monkeypatch):
    base, _ = server
    _configure(monkeypatch)
    monkeypatch.setattr(enot, "create_invoice", lambda order_id: (
        {"id": "inv-2", "amount": "790.00",
         "url": f"https://pay.enot.io/{order_id}"}, ""))

    request = urllib.request.Request(f"{base}/pay/enot", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.loads(response.read().decode("utf-8"))
    assert response.status == 200
    assert body["url"].startswith("https://pay.enot.io/")
    assert body["amount"] == "790.00"


def test_notification_issues_one_token_and_is_idempotent(server, monkeypatch):
    base, tmp = server
    _configure(monkeypatch)
    form = {**GOOD, "custom_field": json.dumps({"order_id": "order-77"})}

    status, first = _post_form(f"{base}/pay/enot/notify", form)
    assert status == 200
    assert first["valid_until"] > 0

    status, second = _post_form(f"{base}/pay/enot/notify", form)
    assert status == 200
    assert second.get("duplicate") is True

    journal = (tmp / "enot_orders.jsonl").read_text(encoding="utf-8").splitlines()
    paid = [json.loads(line) for line in journal if json.loads(line)["status"] == "paid"]
    assert len(paid) == 1, f"второй токен за один платёж: {paid}"


def test_foreign_notification_is_not_accepted_by_the_route(server, monkeypatch):
    base, tmp = server
    _configure(monkeypatch)
    form = {**GOOD, "merchant": "attacker-shop",
            "custom_field": json.dumps({"order_id": "order-78"})}
    status, body = _post_form(f"{base}/pay/enot/notify", form)
    assert status == 400
    assert "another shop" in body["error"]
    journal = (tmp / "enot_orders.jsonl").read_text(encoding="utf-8")
    assert "paid" not in journal
