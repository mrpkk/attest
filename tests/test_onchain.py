"""Прямая оплата USDC: проверка перевода по блокчейну.

Доверять хешу из запроса нельзя — все решения принимаются по ответу ноды.
Тесты подменяют RPC и проверяют ровно те случаи, из-за которых можно выдать
доступ бесплатно: чужой получатель, мало денег, упавшая транзакция,
недостаточно подтверждений, повторное использование хеша.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attest import onchain  # noqa: E402

PAY_TO = "0xefCD6886f73064ea9EcbaA4741Ef1309A0885C59"
PAYER = "0x1111111111111111111111111111111111111111"
TX = "0x" + "ab" * 32
USDC = onchain.USDC_BASE
TOPIC = onchain.TRANSFER_TOPIC


def _receipt(*, to: str = PAY_TO, amount: int = 9_000_000, status: int = 1,
             block: int = 100) -> dict:
    padded_to = "0x" + "0" * 24 + to[2:].lower()
    padded_from = "0x" + "0" * 24 + PAYER[2:]
    return {
        "status": hex(status),
        "blockNumber": hex(block),
        "logs": [{
            "address": USDC,
            "topics": [TOPIC, padded_from, padded_to],
            "data": hex(amount),
        }],
    }


@pytest.fixture
def rpc(monkeypatch):
    state = {"receipt": _receipt(), "head": 105}

    def fake(url, method, params, timeout=20.0):
        if method == "eth_blockNumber":
            return hex(state["head"])
        if method == "eth_getTransactionReceipt":
            return state["receipt"]
        raise AssertionError(f"неожиданный метод {method}")

    monkeypatch.setattr(onchain, "_rpc", fake)
    return state


def test_valid_transfer_is_accepted(rpc):
    t = onchain.confirm_transfer(TX, pay_to=PAY_TO, min_atoms=9_000_000)
    assert t.amount_atoms == 9_000_000
    assert t.payer == PAYER
    assert t.confirmations == 6


def test_wrong_recipient_is_rejected(rpc):
    rpc["receipt"] = _receipt(to="0x" + "22" * 20)
    with pytest.raises(onchain.TransferRejected, match="no USDC transfer"):
        onchain.confirm_transfer(TX, pay_to=PAY_TO, min_atoms=9_000_000)


def test_underpayment_is_rejected(rpc):
    rpc["receipt"] = _receipt(amount=1_000_000)
    with pytest.raises(onchain.TransferRejected, match="paid 1.000000 USDC, required 9.000000"):
        onchain.confirm_transfer(TX, pay_to=PAY_TO, min_atoms=9_000_000)


def test_failed_transaction_is_rejected(rpc):
    rpc["receipt"] = _receipt(status=0)
    with pytest.raises(onchain.TransferRejected, match="failed on-chain"):
        onchain.confirm_transfer(TX, pay_to=PAY_TO, min_atoms=1)


def test_unconfirmed_transaction_is_rejected(rpc):
    rpc["head"] = 100
    with pytest.raises(onchain.TransferRejected, match="waiting for confirmations: 1/2"):
        onchain.confirm_transfer(TX, pay_to=PAY_TO, min_atoms=1, confirmations=2)


def test_malformed_hash_is_rejected_before_any_rpc(rpc):
    with pytest.raises(onchain.TransferRejected, match="tx hash"):
        onchain.confirm_transfer("0x123", pay_to=PAY_TO, min_atoms=1)


def test_used_hash_is_remembered(tmp_path):
    path = tmp_path / "orders.jsonl"
    transfer = onchain.ConfirmedTransfer(tx_hash=TX, payer=PAYER, amount_atoms=9_000_000,
                                         block=100, confirmations=3)
    assert TX not in onchain.load_used(path)
    onchain.record(path, transfer, plan="unlimited-30d", subject=PAYER)
    assert TX in onchain.load_used(path)
