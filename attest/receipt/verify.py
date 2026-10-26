"""Проверка одной квитанции: каноничность, хеш цепи, подпись, ключ.

Профиль: draft-noa-scitt-ai-agent-receipt, §4.2.

Три вещи, которые здесь решаются и которые эталонная реализация решает неверно
или не решает вовсе:

1. **Каноничность проверяется по полученным байтам** (JCS(parse(bytes)) == bytes,
   дефект G5). Пересборка «как нам удобно» проверяет наш парсер, а не подписанта.
2. **`chain.hash` пересчитывается.** Подпись его не покрывает: в хеш-вход
   входят все поля, кроме `chain.hash` и `sig.value`. Без пересчёта квитанция
   с произвольным хешем проходит все остальные проверки.
3. **Ключ проверяется как точка кривой.** Восемь канонических кодировок малого
   порядка и `y ≥ 2^255-19` отвергаются до проверки подписи: на этих классах
   распространённые библиотеки расходятся, и один и тот же набор байтов
   принимается одной реализацией и отвергается другой.

Порядок проверок намеренный: сначала дешёвые структурные (схема, литерал
алгоритма, base64), потом криптография. Ничего не считается «валидным», пока
не проверено всё.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs, schema

DOMAIN = b"NOA-Receipt-v0.1-sig:"
P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P


@dataclass
class Verdict:
    ok: bool
    status: str  # valid | malformed | tampered | untrusted | envelope-absent
    rejections: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def why(self) -> str:
        return "; ".join(self.rejections)


# --- ключ ------------------------------------------------------------------


def _decompress(raw: bytes) -> tuple[int, int] | None:
    """Восстановить точку из 32 байт или вернуть None, если это не точка."""
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    sign = raw[31] >> 7
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x2 = u * pow(v, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    if (x * x - x2) % P != 0:
        return None
    if x % 2 != sign:
        x = P - x
    return x, y


def _add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = a
    x2, y2 = b
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P
    return x3, y3


def has_small_order(raw: bytes) -> bool:
    """Точка малого порядка: [8]P — единица. Такие ключи дают подписи, которые
    «проверяются» у кого угодно, и поэтому запрещены профилем."""
    point = _decompress(raw)
    if point is None:
        return False
    acc = point
    for _ in range(3):
        acc = _add(acc, acc)
    return acc == (0, 1)


def check_key(raw: bytes) -> tuple[bool, str]:
    if len(raw) != 32:
        return False, f"key length {len(raw)} != 32"
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    if y >= P:
        return False, "y-coordinate is not a canonical field element (y >= 2^255-19)"
    if _decompress(raw) is None:
        return False, "not a point on curve25519"
    if has_small_order(raw):
        return False, "small-order point: not a valid signing key"
    return True, ""


# --- канонизация и подпись -------------------------------------------------


def _canonical_b64(value: str) -> tuple[bool, str]:
    """Канонический base64: ровно одна форма с padding, без пробелов,
    неиспользуемые биты последнего кванта — нули. Проверяется перекодированием."""
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False, "sig.value is not valid base64"
    if base64.b64encode(decoded).decode() != value:
        return False, "sig.value is not canonical base64"
    if len(decoded) != 64:
        return False, f"sig.value decodes to {len(decoded)} octets, expected 64"
    return True, ""


def hash_input(receipt: dict) -> str:
    body = {k: v for k, v in receipt.items() if k not in ("chain", "sig")}
    chain = {k: v for k, v in (receipt.get("chain") or {}).items() if k != "hash"}
    sig = {k: v for k, v in (receipt.get("sig") or {}).items() if k != "value"}
    if chain:
        body["chain"] = chain
    if sig:
        body["sig"] = sig
    return jcs.dumps(body)


def chain_hash(receipt: dict) -> str:
    return "sha256:" + hashlib.sha256(hash_input(receipt).encode()).hexdigest()


def message(receipt: dict) -> bytes:
    return DOMAIN + hashlib.sha256(hash_input(receipt).encode()).digest()


def sign(receipt: dict, private_key) -> dict:
    """Подписать квитанцию: заполнить sig.alg, sig.value и chain.hash."""
    out = dict(receipt)
    sig = dict(out.get("sig") or {})
    sig["alg"] = "ed25519"
    sig.pop("value", None)
    out["sig"] = sig
    sig["value"] = base64.b64encode(private_key.sign(message(out))).decode()
    chain = dict(out.get("chain") or {})
    chain["hash"] = chain_hash(out)
    out["chain"] = chain
    return out


# --- главный вход ----------------------------------------------------------


def verify_receipt(
    raw: bytes | str | dict,
    public_key: bytes,
    *,
    envelope: Any = None,
) -> Verdict:
    """Проверить одну квитанцию без сети и без доверия к отправителю.

    `raw` — байты в том виде, в каком пришли (тогда проверяется каноничность),
    либо уже разобранный объект (тогда каноничность проверить нельзя, и это
    сказано в результате, а не выдано за проверенное).
    """
    rejections: list[str] = []
    detail: dict[str, Any] = {}

    if isinstance(raw, (bytes, str)):
        text = raw.decode() if isinstance(raw, bytes) else raw
        try:
            receipt = jcs.loads(text)
        except jcs.CanonicalError as exc:
            return Verdict(False, "malformed", [f"parse: {exc}"])
        parsed_again = jcs.dumps(receipt) if isinstance(receipt, dict) else ""
        if parsed_again != text:
            # G5: пересборка не совпала с полученными байтами. Проверять
            # значения, которые подписант не подписывал, — нельзя.
            rejections.append("payload is not canonical: JCS(parse(bytes)) != bytes")
        detail["canonical_checked"] = True
    elif isinstance(raw, dict):
        receipt = raw
        detail["canonical_checked"] = False
        detail["canonical_note"] = "parsed object supplied: canonical form not verified"
    else:
        return Verdict(False, "malformed", ["receipt must be bytes, str or dict"])

    check = schema.check(receipt)
    if not check.ok:
        return Verdict(False, "malformed", check.rejections and [check.why()] or ["schema"], detail)

    alg = (receipt.get("sig") or {}).get("alg")
    if alg != "ed25519":
        # До любой криптографии: иначе реализация ответит на другой вопрос.
        return Verdict(False, "malformed", [f"sig.alg is {alg!r}, expected 'ed25519'"], detail)

    ok_b64, why_b64 = _canonical_b64(str((receipt.get("sig") or {}).get("value", "")))
    if not ok_b64:
        return Verdict(False, "malformed", [why_b64], detail)

    key_ok, why_key = check_key(public_key)
    if not key_ok:
        return Verdict(False, "malformed", [f"public key: {why_key}"], detail)

    expected = chain_hash(receipt)
    declared = (receipt.get("chain") or {}).get("hash")
    if declared != expected:
        return Verdict(False, "tampered", ["chain.hash does not match the recomputed hash"], detail)

    signature = base64.b64decode((receipt.get("sig") or {}).get("value", ""))
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message(receipt))
    except InvalidSignature:
        return Verdict(False, "tampered", ["signature does not verify"], detail)

    detail["native_signature"] = "verified"
    if envelope is None:
        detail["envelope"] = "absent: only the native signature was checked"
    else:
        # Конверт COSE — S5. Здесь честно сказано, что он не проверен,
        # а не выдан за проверенный.
        detail["envelope"] = "present but not verified in this step"

    if rejections:
        return Verdict(False, "tampered", rejections, detail)
    return Verdict(True, "valid", [], detail)
