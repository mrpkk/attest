"""Прямой приём USDC на Base: проверка перевода по публичному RPC.

Зачем: у машины есть x402, а у человека — нет. Карточный путь требует
мерчант-аккаунта и KYC; пока его нет, покупатель вообще не может заплатить.
Здесь человек отправляет USDC на адрес проекта обычным кошельком и присылает
хеш транзакции — сервер сам проверяет перевод в блокчейне.

Границы доверия: мы не доверяем ни хешу, ни сумме из запроса. Всё берём из
`eth_getTransactionReceipt` публичной ноды: статус, получатель, токен, сумма.
Одна транзакция оплачивает ровно один заказ — хеши хранятся в файле заказов.
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass

# ERC-20 Transfer(address,address,uint256)
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
DEFAULT_RPC = "https://mainnet.base.org"
DEFAULT_CONFIRMATIONS = 2


class TransferRejected(Exception):
    """Перевод не подтверждает оплату. Причина всегда называется."""


@dataclass(frozen=True)
class ConfirmedTransfer:
    tx_hash: str
    payer: str
    amount_atoms: int
    block: int
    confirmations: int


def _rpc(url: str, method: str, params: list, timeout: float = 20.0) -> object:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode()
    req = urllib.request.Request(url, data=payload,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "attest/onchain"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.loads(r.read().decode())
    if body.get("error"):
        raise TransferRejected(f"RPC error: {body['error'].get('message', 'unknown')}")
    return body.get("result")


def _topic_to_address(topic: str) -> str:
    return "0x" + topic[-40:].lower()


def confirm_transfer(tx_hash: str, *, pay_to: str, min_atoms: int,
                     asset: str = USDC_BASE, rpc_url: str = DEFAULT_RPC,
                     confirmations: int = DEFAULT_CONFIRMATIONS,
                     timeout: float = 20.0) -> ConfirmedTransfer:
    """Проверить, что транзакция — успешный перевод USDC на pay_to не меньше min_atoms.

    Любое расхождение — TransferRejected с причиной: «не тот получатель»,
    «мало», «транзакция упала», «ещё не подтверждена». Молчаливого согласия нет.
    """
    tx_hash = (tx_hash or "").strip()
    if not (tx_hash.startswith("0x") and len(tx_hash) == 66):
        raise TransferRejected("tx hash must look like 0x followed by 64 hex characters")

    receipt = _rpc(rpc_url, "eth_getTransactionReceipt", [tx_hash], timeout)
    if not receipt:
        raise TransferRejected("transaction not found on Base yet")
    if int(receipt.get("status") or "0x0", 16) != 1:
        raise TransferRejected("transaction failed on-chain (status 0)")

    block = int(receipt.get("blockNumber") or "0x0", 16)
    head = int(_rpc(rpc_url, "eth_blockNumber", [], timeout) or "0x0", 16)
    done = head - block + 1
    if done < confirmations:
        raise TransferRejected(f"waiting for confirmations: {done}/{confirmations}")

    want_to = pay_to.lower()
    want_asset = asset.lower()
    total = 0
    payer = ""
    for log in receipt.get("logs") or []:
        if (log.get("address") or "").lower() != want_asset:
            continue
        topics = log.get("topics") or []
        if len(topics) != 3 or (topics[0] or "").lower() != TRANSFER_TOPIC:
            continue
        if _topic_to_address(topics[2]) != want_to:
            continue
        total += int(log.get("data") or "0x0", 16)
        if not payer:
            payer = _topic_to_address(topics[1])

    if total == 0:
        raise TransferRejected("no USDC transfer to the project wallet in this transaction")
    if total < min_atoms:
        raise TransferRejected(
            f"paid {total / 1_000_000:.6f} USDC, required {min_atoms / 1_000_000:.6f} USDC")

    return ConfirmedTransfer(tx_hash=tx_hash.lower(), payer=payer,
                             amount_atoms=total, block=block, confirmations=done)


def load_used(path) -> set[str]:
    """Хеши, которыми уже оплатили: второй раз тот же перевод не считается."""
    used: set[str] = set()
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    used.add(str(json.loads(line).get("tx", "")).lower())
                except ValueError:
                    continue
    except OSError:
        pass
    return used


def record(path, transfer: ConfirmedTransfer, *, plan: str, subject: str) -> None:
    """Записать заказ до выдачи токена: повторный запрос увидит хеш занятым."""
    entry = {"tx": transfer.tx_hash, "payer": transfer.payer,
             "amount_atoms": transfer.amount_atoms, "block": transfer.block,
             "plan": plan, "subject": subject, "ts": int(time.time())}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
