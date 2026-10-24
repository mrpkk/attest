"""Живая проверка приёма денег: настоящая транзакция в Base Sepolia.

По умолчанию пропущена — идёт в сеть. Запуск:

    ATTEST_LIVE_ONCHAIN=1 python3 -m pytest tests/test_onchain_live.py -q

Доказывает то, чего не докажут подменённые ответы ноды: чек приходит,
логи Transfer разбираются по-настоящему, сумма и получатель совпадают,
а токен выдаётся один раз на транзакцию.

Транзакции — реальные платежи проекта по 0.005 USDC (см. docs/PROGRESS.md,
срез S6.2). Деньги тестовые, но запись в блокчейне настоящая.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attest import entitlement, onchain  # noqa: E402
from attest.service import AttestHandler  # noqa: E402
from attest.signing import public_key_b64  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("ATTEST_LIVE_ONCHAIN") != "1",
    reason="живая сеть: запускать с ATTEST_LIVE_ONCHAIN=1")

SEPOLIA_RPC = "https://sepolia.base.org"
SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
WALLET = "0xefCD6886f73064ea9EcbaA4741Ef1309A0885C59"
# Настоящий платёж 0.005 USDC на кошелёк проекта (S6.2, 16.10.2026).
TX = "0x38b6e9ea83970d97ee1ef5217abe8718ec0425d0607c07f3dbd0665f1142b9df"
PAID_ATOMS = 5_000


def test_real_transfer_is_recognised():
    transfer = onchain.confirm_transfer(TX, pay_to=WALLET, min_atoms=PAID_ATOMS,
                                        asset=SEPOLIA_USDC, rpc_url=SEPOLIA_RPC)
    assert transfer.amount_atoms == PAID_ATOMS
    assert transfer.payer.startswith("0x")
    assert transfer.confirmations >= 1


def test_real_transfer_to_another_wallet_is_rejected():
    with pytest.raises(onchain.TransferRejected, match="no USDC transfer"):
        onchain.confirm_transfer(TX, pay_to="0x" + "22" * 20, min_atoms=1,
                                 asset=SEPOLIA_USDC, rpc_url=SEPOLIA_RPC)


def test_real_transfer_cannot_pay_a_bigger_price():
    with pytest.raises(onchain.TransferRejected, match="required 1.000000"):
        onchain.confirm_transfer(TX, pay_to=WALLET, min_atoms=1_000_000,
                                 asset=SEPOLIA_USDC, rpc_url=SEPOLIA_RPC)


def test_claim_issues_a_token_exactly_once(tmp_path, monkeypatch):
    monkeypatch.setattr(AttestHandler, "x402_pay_to", WALLET)
    monkeypatch.setattr(AttestHandler, "x402_asset", SEPOLIA_USDC)
    monkeypatch.setattr(AttestHandler, "x402_network", "eip155:84532")
    monkeypatch.setattr(AttestHandler, "leads_path", tmp_path / "leads.jsonl")
    monkeypatch.setattr(entitlement, "PRICE_USD", PAID_ATOMS / 1_000_000)
    monkeypatch.setenv("ATTEST_RPC_URL", SEPOLIA_RPC)

    httpd = ThreadingHTTPServer(("127.0.0.1", 8177), AttestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        def claim() -> tuple[int, dict]:
            request = urllib.request.Request(
                "http://127.0.0.1:8177/pay/claim",
                data=json.dumps({"tx": TX}).encode(), method="POST",
                headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=40) as response:
                    return response.status, json.loads(response.read().decode())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode())

        status, body = claim()
        assert status == 200, body
        assert body["paid"] is True
        assert body["amount_usdc"] == pytest.approx(0.005)
        granted, reason = entitlement.redeem_entitlement(
            body["token"], trusted_key=public_key_b64())
        assert granted is not None, reason
        assert granted.valid_until > 0

        again, body_again = claim()
        assert again == 409
        assert "already used" in body_again["error"]
    finally:
        httpd.shutdown()
        httpd.server_close()
