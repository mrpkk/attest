"""Квитанция платежа в сети (`receipt/1`): что переведено, кому и когда.

Зачем отдельный продукт: спор «перевод был или нет» в крипто-сделке стоит
от $5 до $50 тыс. Сторонам нужен документ, который проверяется без нас,
без сети и без доверия к серверу — только Ed25519 и байты.

Что здесь решено и почему именно так:

* **Сумма и адреса берутся из цепи, а не из запроса.** Иначе квитанция
  подтверждала бы то, что написал заявитель, а не то, что произошло.
* **Подписано каноническое тело без `signature` и `public_key`.** Ключ едет
  рядом: если бы он входил в подписанные байты, подмена ключа выглядела бы
  порчей тела, и вердикт `wrong_key` был бы недостижим.
* **Проверка офлайн.** `verify()` не делает сетевых вызовов: он отвечает на
  вопрос «эти байты подписаны этим ключом», а не «перевод существует».
  Второй вопрос решается по `tx_hash` в любом explorer — и это сказано в
  результате, а не выдано за проверенное.

`subject` — заявление заявителя, подписанное как заявление: сервис
удостоверяет перевод, а не то, что перевод был именно за это. Иначе квитанцию
«оплата виллы» мог бы получить любой по чужому хешу.

Квитанция не подтверждает поставку товара и не заменяет арбитраж. Она
фиксирует платёж.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field
from typing import Any

from . import onchain, signing
from .receipt import jcs

SPEC = "receipt/1"
PRICE_USD = 0.50
MAX_SUBJECT = 500

# Сеть → чем платят и куда идти за фактом. Пока одна: `onchain` умеет
# только Base/USDC, и обещать другие сети без проверки нельзя.
CHAINS: dict[str, dict[str, Any]] = {
    "base": {
        "chain_id": 8453,
        "asset": "USDC",
        "token": onchain.USDC_BASE,
        "rpc": onchain.DEFAULT_RPC,
    },
}

FIELDS = ("spec", "tx_hash", "chain", "amount", "asset", "from", "to",
          "block", "timestamp", "subject", "issuer", "public_key", "signature")


class ReceiptRejected(Exception):
    """Квитанция не выпускается. Причина называется всегда."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Verdict:
    status: str  # ok | tampered | wrong_key | unsigned | malformed
    detail: str
    key_fingerprint: str | None = None
    canonical: str | None = None   # каноническая форма всего объекта
    signed: str | None = None      # байты, которые подписаны (без ключа и подписи)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"verdict": self.status, "detail": self.detail,
                "key_fingerprint": self.key_fingerprint,
                "canonical": self.canonical, "signed": self.signed,
                "notes": self.notes}


def canonical_body(receipt: dict) -> bytes:
    """Байты, которые подписаны: JCS всего объекта без подписи и ключа."""
    body = {k: v for k, v in receipt.items() if k not in ("signature", "public_key")}
    return jcs.dumps(body).encode()


def key_fingerprint(public_key_b64: str) -> str:
    """Отпечаток ключа: то, что человек может сверить глазами."""
    return hashlib.sha256(base64.b64decode(public_key_b64)).hexdigest()[:16]


def _address(value: Any) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 42 or not text.startswith("0x"):
        raise ReceiptRejected(422, f"address must look like 0x followed by 40 hex characters: {value!r}")
    try:
        int(text, 0)
    except ValueError as exc:
        raise ReceiptRejected(422, f"address is not hexadecimal: {value!r}") from exc
    return text


def _amount(atoms: int) -> str:
    """Атомы → десятичная строка. Целые, без float: 1 атом = 0.000001."""
    return f"{atoms // 1_000_000}.{atoms % 1_000_000:06d}"


def issue(*, tx_hash: str, chain: str, subject: str, issuer: str,
          to: str | None = None, payer: str | None = None,
          rpc_url: str | None = None, confirmations: int = 2,
          key_path=None) -> dict:
    """Проверить перевод в цепи и подписать квитанцию.

    `to` и `payer` необязательны: цепь — источник истины. Если они переданы,
    они обязаны совпасть с цепью, иначе отказ: квитанция с чужим адресом
    бесполезна в споре и вредна как прецедент.
    """
    network = str(chain or "base").strip().lower()
    spec = CHAINS.get(network)
    if spec is None:
        raise ReceiptRejected(422, f"chain {network!r} is not supported: {sorted(CHAINS)}")

    text = str(subject or "").strip()
    if not text:
        raise ReceiptRejected(422, "subject is required: what was paid for")
    if len(text) > MAX_SUBJECT:
        raise ReceiptRejected(422, f"subject is longer than {MAX_SUBJECT} characters")

    issuer = str(issuer or "").strip()[:200]
    if not issuer:
        raise ReceiptRejected(422, "issuer is required: who signs the receipt")

    wanted_to = _address(to) if to else None
    wanted_from = _address(payer) if payer else None
    rpc = rpc_url or spec["rpc"]

    if wanted_to:
        transfer = onchain.confirm_transfer(
            tx_hash, pay_to=wanted_to, min_atoms=1, asset=spec["token"],
            rpc_url=rpc, confirmations=confirmations)
        payee, sender, atoms, block = wanted_to, transfer.payer, transfer.amount_atoms, transfer.block
    else:
        found = [t for t in onchain.transfers(tx_hash, asset=spec["token"], rpc_url=rpc,
                                             confirmations=confirmations)
                 if t.amount_atoms > 0]
        if not found:
            raise ReceiptRejected(422, "no transfer of the asset in this transaction")
        if len(found) > 1:
            raise ReceiptRejected(
                422, f"{len(found)} transfers in this transaction: pass `to` to choose one")
        payee, sender = found[0].payee, found[0].payer
        atoms, block = found[0].amount_atoms, found[0].block

    if wanted_from and wanted_from != sender:
        raise ReceiptRejected(
            422, f"sender does not match the chain: chain says {sender}")

    receipt = {
        "spec": SPEC,
        "tx_hash": tx_hash.strip().lower(),
        "chain": network,
        "amount": _amount(atoms),
        "asset": spec["asset"],
        "from": sender,
        "to": payee,
        "block": block,
        "timestamp": onchain.block_time(block, rpc_url=rpc),
        "subject": text,
        "issuer": issuer,
    }
    signature = signing.sign(canonical_body(receipt), key_path)
    receipt["public_key"] = signature.public_key
    receipt["signature"] = signature.signature
    return receipt


def _shape(receipt: Any) -> list[str]:
    """Структура до криптографии. Незнакомое поле — отказ, а не «игнорируем»."""
    if not isinstance(receipt, dict):
        return ["receipt must be a JSON object"]
    problems = [f"unknown field {key!r}" for key in receipt if key not in FIELDS]
    if receipt.get("spec") != SPEC:
        problems.append(f"spec must be {SPEC!r}")
    for name in ("tx_hash", "chain", "amount", "asset", "from", "to",
                 "timestamp", "subject", "issuer"):
        if not isinstance(receipt.get(name), str) or not receipt.get(name):
            problems.append(f"{name} must be a non-empty string")
    if not isinstance(receipt.get("block"), int) or isinstance(receipt.get("block"), bool):
        problems.append("block must be an integer")
    if receipt.get("chain") not in CHAINS:
        problems.append(f"chain must be one of {sorted(CHAINS)}")
    return problems


def _decoded(value: Any, size: int, name: str) -> tuple[bytes | None, str]:
    if not isinstance(value, str) or not value:
        return None, f"{name} is missing"
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None, f"{name} is not base64"
    if len(raw) != size:
        return None, f"{name} decodes to {len(raw)} bytes, expected {size}"
    return raw, ""


def verify(raw: bytes | str | dict, *, expected_key: str | None = None) -> Verdict:
    """Проверить квитанцию без сети. Секретов не нужно, доверия к нам — тоже.

    `expected_key` — ключ или отпечаток того, кому вы доверяете. Без него
    проверяется целостность и подпись, но не личность подписанта: это
    сказано в `notes`, а не выдано за «подлинность».
    """
    notes: list[str] = []
    if isinstance(raw, (bytes, str)):
        text = raw.decode() if isinstance(raw, bytes) else raw
        try:
            receipt = jcs.loads(text)
        except ValueError as exc:  # JSONDecodeError и CanonicalError — оба ValueError
            return Verdict("malformed", f"not JSON: {exc}")
        if not isinstance(receipt, dict):
            return Verdict("malformed", "receipt must be a JSON object")
        try:
            canonical = jcs.dumps(receipt)
        except jcs.CanonicalError as exc:
            return Verdict("malformed", f"receipt cannot be canonicalised: {exc}")
        if canonical != text:
            notes.append("input was not in canonical form; the canonical form was verified")
    elif isinstance(raw, dict):
        receipt = raw
        try:
            canonical = jcs.dumps(receipt)
        except jcs.CanonicalError as exc:
            return Verdict("malformed", f"receipt cannot be canonicalised: {exc}")
        notes.append("parsed object supplied: canonical form of the original bytes not checked")
    else:
        return Verdict("malformed", "receipt must be bytes, str or dict")

    problems = _shape(receipt)
    if problems:
        return Verdict("malformed", "; ".join(problems), canonical=canonical)

    if not receipt.get("signature") or not receipt.get("public_key"):
        return Verdict("unsigned", "receipt has no signature: nothing was signed",
                       canonical=canonical)

    public_raw, why_public = _decoded(receipt["public_key"], 32, "public_key")
    if public_raw is None:
        return Verdict("malformed", why_public, canonical=canonical)
    signature_raw, why_sig = _decoded(receipt["signature"], 64, "signature")
    if signature_raw is None:
        return Verdict("malformed", why_sig, canonical=canonical)

    payload = canonical_body(receipt)
    signed = payload.decode()
    if not signing.verify(payload, receipt["signature"], receipt["public_key"]):
        return Verdict("tampered",
                       "signature does not verify: the signed fields were changed",
                       canonical=canonical, signed=signed)

    fingerprint = key_fingerprint(receipt["public_key"])
    if expected_key:
        wanted = str(expected_key).strip()
        same = (fingerprint == wanted.lower() if len(wanted) == 16
                else _decoded(wanted, 32, "expected_key")[0] == public_raw)
        if not same:
            return Verdict("wrong_key",
                           f"signed by key {fingerprint}, not by the key you trust",
                           key_fingerprint=fingerprint, canonical=canonical, signed=signed)
        notes.append(f"key matches the expected one ({fingerprint})")
    else:
        notes.append(f"signed by key {fingerprint}: compare it with the issuer's published key")

    notes.append("the transfer itself was checked at issuance; re-check tx_hash in an explorer")
    return Verdict("ok", "signature verifies and the signed fields are unchanged",
                   key_fingerprint=fingerprint, canonical=canonical, signed=signed,
                   notes=notes)


def _main(argv: list[str] | None = None) -> int:
    """`python3 -m attest.payment_receipt verify receipt.json --key <b64>`.

    Проверка без сервера — то, ради чего квитанция и существует.
    """
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(prog="python3 -m attest.payment_receipt")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("verify", help="check a receipt offline")
    check.add_argument("file", help="path to the receipt JSON")
    check.add_argument("--key", help="issuer public key (base64) or its 16-char fingerprint")
    args = parser.parse_args(argv)

    verdict = verify(Path(args.file).read_bytes(), expected_key=args.key)
    print(json.dumps(verdict.as_dict(), ensure_ascii=False, indent=2))
    return 0 if verdict.status == "ok" else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
