"""Конверт COSE_Sign1: квитанция становится регистрируемым Signed Statement.

Профиль: draft-noa-scitt-ai-agent-receipt §4.1–4.3; RFC 9943 (SCITT), RFC 9597
(CWT Claims), RFC 9052 (COSE).

Что здесь строго и почему:

* **Тег 18 обязателен.** Нетегированную структуру нельзя угадывать: тег — часть
  типа, а не украшение.
* **alg = -19, и только он.** `-8` (EdDSA) — полиморфный идентификатор,
  помеченный как deprecated; принять его значит позволить проверяющему выбрать
  алгоритм за подписанта.
* **`kid` в защищённой шапке.** Идентификатор, не покрытый подписью, можно
  заменить, не сломав её, и атрибуция уйдёт другому.
* **`CWT_Claims` (метка 15) с `iss` и `sub`** — это и есть разница между
  «подписанный объект» и «регистрируемое утверждение».
* **Детерминированный CBOR** на разборе: недетерминированное кодирование
  отвергается, а не чинится.

Конверт не отменяет нативную подпись: их две, и проверять нужно обе. Здесь
проверяется внешняя; нативная — в `verify.py`.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import cbor

COSE_SIGN1_TAG = 18
ALG_ED25519 = -19
CWT_CLAIMS_LABEL = 15


@dataclass
class Envelope:
    ok: bool
    payload: bytes = b""
    kid: str | None = None
    issuer: str | None = None
    subject: str | None = None
    reason: str = ""
    notes: list[str] = field(default_factory=list)


def _kid_from_bytes(raw: bytes) -> str:
    """kid — байтовая строка. В текстовый идентификатор переводим только без
    потерь: иначе два разных идентификатора схлопнутся в один."""
    text = raw.decode("utf-8", errors="replace")
    if text.encode() != raw:
        raise ValueError("kid is not valid UTF-8: a lossy decode would collapse identifiers")
    return text


def sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    return cbor.dumps(["Signature1", protected, external_aad, payload])


def wrap(
    payload: bytes,
    *,
    kid: str,
    issuer: str,
    subject: str,
    private_key,
    content_type: str = "application/noa-receipt+jcs",
) -> bytes:
    """Обернуть канонический JSON квитанции в COSE_Sign1 с claims для SCITT."""
    protected_map = {
        1: ALG_ED25519,
        3: content_type,
        4: kid.encode(),
        CWT_CLAIMS_LABEL: {1: issuer, 2: subject},
    }
    protected = cbor.dumps(protected_map)
    signature = private_key.sign(sig_structure(protected, payload))
    return cbor.dumps(cbor.Tag(COSE_SIGN1_TAG, [protected, {}, payload, signature]))


def verify(envelope: bytes, public_key: bytes) -> Envelope:
    try:
        parsed = cbor.loads(envelope)
    except cbor.CBORError as exc:
        return Envelope(False, reason=f"not deterministic CBOR: {exc}")

    if not isinstance(parsed, cbor.Tag) or parsed.number != COSE_SIGN1_TAG:
        return Envelope(False, reason="COSE_Sign1 must carry tag 18")

    items = parsed.value
    if not isinstance(items, list) or len(items) != 4:
        return Envelope(False, reason="COSE_Sign1 is an array of four items")
    protected, unprotected, payload, signature = items
    if not isinstance(protected, bytes) or not isinstance(unprotected, dict):
        return Envelope(False, reason="protected must be bstr, unprotected must be a map")
    if not isinstance(payload, bytes):
        return Envelope(False, reason="payload must be attached as bstr (detached is not defined)")
    if not isinstance(signature, bytes):
        return Envelope(False, reason="signature must be bstr")

    try:
        header = cbor.loads(protected)
    except cbor.CBORError as exc:
        return Envelope(False, reason=f"protected header is not deterministic CBOR: {exc}")
    if not isinstance(header, dict):
        return Envelope(False, reason="protected header must be a map")

    if header.get(1) != ALG_ED25519:
        return Envelope(False, reason=f"protected alg is {header.get(1)!r}, expected -19 (Ed25519)")

    if CWT_CLAIMS_LABEL in header and CWT_CLAIMS_LABEL in unprotected:
        return Envelope(False, reason="CWT_Claims must occur exactly once across the two buckets")
    claims = header.get(CWT_CLAIMS_LABEL, unprotected.get(CWT_CLAIMS_LABEL))
    if not isinstance(claims, dict) or 1 not in claims or 2 not in claims:
        return Envelope(False, reason="protected CWT_Claims with iss (1) and sub (2) are required")
    issuer, subject = claims.get(1), claims.get(2)
    if not isinstance(issuer, str) or not isinstance(subject, str):
        return Envelope(False, reason="iss and sub must be text strings")

    raw_kid = header.get(4, unprotected.get(4))
    if not isinstance(raw_kid, bytes):
        return Envelope(False, reason="a key identifier (kid) is required")
    notes = ["kid taken from the protected header" if 4 in header
             else "kid taken from the unprotected header: resolves a key, names nobody"]
    try:
        kid = _kid_from_bytes(raw_kid)
    except ValueError as exc:
        return Envelope(False, reason=str(exc))

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, sig_structure(protected, payload)
        )
    except InvalidSignature:
        return Envelope(False, reason="COSE signature does not verify", kid=kid)

    return Envelope(True, payload=payload, kid=kid, issuer=issuer, subject=subject, notes=notes)


def to_base64(envelope: bytes) -> str:
    return base64.b64encode(envelope).decode()


def from_base64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)
