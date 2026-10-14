#!/usr/bin/env python3
"""Доступ по предоплате: выдача, проверка, отказ подделке.

Тест на подделку здесь не формальность. Ключ для проверки когда-то брался
из самого токена, а токен — это то, что присылает недоверенный клиент.
Написание занимает минуту, исходник открыт: любой желающий выпускал себе
безлимит бесплатно. Тест фиксирует, что проверяющий ключ задаёт сервис.
"""

from __future__ import annotations

import base64
import json
import time
import unittest

from attest.entitlement import (DEFAULT_DAYS, HEADER, PRICE_USD, describe,
                                fingerprint, issue, redeem)
from attest.signing import public_key_b64


def _forged(subject: str = "attacker", days: int = 9999) -> str:
    """Токен, подписанный ключом, которого у сервиса нет."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    payload = {"subject": subject, "plan": "unlimited-30d",
               "issued_at": int(time.time()),
               "valid_until": int(time.time()) + days * 86400}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return json.dumps(
        {"payload": payload,
         "signature": base64.b64encode(sk.sign(body)).decode("ascii"),
         "public_key": base64.b64encode(pub).decode("ascii"),
         "algorithm": "ed25519"}, separators=(",", ":"))


class EntitlementTests(unittest.TestCase):
    def test_issued_token_passes_with_trusted_key(self):
        ok, why = redeem(issue("buyer", 30)["token"],
                         trusted_key=public_key_b64())
        self.assertTrue(ok, why)

    def test_without_trusted_key_it_refuses(self):
        # Ключ из токена не принимается: иначе доступ выпускает кто угодно.
        ok, why = redeem(issue("buyer", 30)["token"])
        self.assertFalse(ok)
        self.assertIn("trusted key", why)

    def test_foreign_key_is_rejected(self):
        ok, _ = redeem(_forged(), trusted_key=public_key_b64())
        self.assertFalse(ok, "подпись чужим ключом не должна проходить")

    def test_tampered_payload_is_rejected(self):
        token = issue("buyer", 30)["token"]
        data = json.loads(token)
        data["payload"]["valid_until"] = 99_999_999_999
        data["payload"]["subject"] = "someone-else"
        ok, _ = redeem(json.dumps(data), trusted_key=public_key_b64())
        self.assertFalse(ok, "изменённая полезная нагрузка не должна проходить")

    def test_expired_token_is_rejected(self):
        token = issue("buyer", 1)["token"]
        ok, why = redeem(token, now=time.time() + 3 * 86400,
                         trusted_key=public_key_b64())
        self.assertFalse(ok)
        self.assertIn("expired", why)

    def test_no_token_is_not_an_error(self):
        # Нет подписки — действует бесплатный тариф, а не поломка.
        for value in (None, "", "   "):
            ok, _ = redeem(value, trusted_key=public_key_b64())
            self.assertFalse(ok)

    def test_garbage_token_is_rejected(self):
        for value in ("мусор", "{", "[]", '{"payload":{}}'):
            ok, _ = redeem(value, trusted_key=public_key_b64())
            self.assertFalse(ok)

    def test_pricing_does_not_promise_recurring_charges(self):
        d = describe()
        self.assertFalse(d["auto_renews"])
        self.assertEqual(d["period_days"], DEFAULT_DAYS)
        self.assertEqual(d["price"], str(PRICE_USD))

    def test_describe_publishes_the_signing_fingerprint(self):
        # Без опубликованного отпечатка проверка «без сервиса» невозможна:
        # ключ пришлось бы взять из самого токена, то есть от подделывателя.
        self.assertTrue(describe()["signed_with"])
        self.assertEqual(describe()["signed_with"], fingerprint())

    def test_header_name_is_the_documented_one(self):
        self.assertEqual(HEADER, "X-ATTEST-ENTITLEMENT")

    def test_issued_token_carries_the_header_name(self):
        self.assertEqual(issue("buyer")["header"], HEADER)

    def test_plan_does_not_auto_renew(self):
        self.assertFalse(issue("buyer")["auto_renews"])


if __name__ == "__main__":
    unittest.main()


class MetricsTests(unittest.TestCase):
    """Метрики: единственный способ узнать, сработал ли канал.

    Без них подача в каталог — трата времени: 130 посетителей витрины дали
    ноль клиентов, и мы не смогли сказать, почему.
    """

    def test_source_comes_from_ref(self):
        from attest.metrics import channel_of
        self.assertEqual(channel_of("?ref=apify", None), "apify")

    def test_source_falls_back_to_referer(self):
        from attest.metrics import channel_of
        self.assertEqual(
            channel_of("", "https://glama.ai/mcp/servers"), "glama")

    def test_no_source_is_direct_not_empty(self):
        # «Пришёл сам» — тоже данные. Пустая строка потеряла бы этот факт.
        from attest.metrics import channel_of
        self.assertEqual(channel_of("", None), "direct")

    def test_ref_wins_over_referer(self):
        # Мы управляем ref в листинге; Referer может подменить посредник.
        from attest.metrics import channel_of
        self.assertEqual(
            channel_of("?ref=dify", "https://example.com"), "dify")

    def test_unknown_host_is_recorded_not_dropped(self):
        from attest.metrics import channel_of
        self.assertEqual(channel_of("", "https://example.com/x"), "example.com")

    def test_revenue_is_counted_in_atoms(self):
        from attest.metrics import Metrics
        m = Metrics()
        m.payment("apify", 5000)
        m.payment("apify", 5000)
        s = m.snapshot()
        self.assertEqual(s["revenue_atoms"], 10000)
        self.assertEqual(s["successful_paid_actions"], 2)

    def test_free_and_paid_checks_are_distinguishable(self):
        from attest.metrics import Metrics
        m = Metrics()
        m.check("dify", paid=False)
        m.check("dify", paid=True)
        s = m.snapshot()
        self.assertEqual(s["checks_free"], 1)
        self.assertEqual(s["checks_paid"], 1)

    def test_survives_restart(self):
        # Сервис перезапускается при каждой правке. Счётчики в памяти
        # обнулились бы ровно тогда, когда нужны.
        import tempfile
        from unittest import mock
        from attest import metrics as mod
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(mod, "STATE_PATH",
                                   __import__("pathlib").Path(d) / "m.json"):
                m = mod.Metrics()
                m.payment("windmill", 5000)
                m.save()
                again = mod.Metrics()
                again.load()
                self.assertEqual(again.snapshot()["revenue_atoms"], 5000)

    def test_no_negative_revenue_from_garbage(self):
        from attest.metrics import Metrics
        m = Metrics()
        m.payment("x", -1)
        self.assertEqual(m.snapshot()["revenue_atoms"], 0)
