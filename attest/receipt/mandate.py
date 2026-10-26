"""Чтение мандата AP2: SD-JWT с раскрытиями, подпись, срок, лимиты.

Профиль: AP2 передаёт разрешение как SD-JWT Verifiable Credential
(мандат = подписанное утверждение «этому агенту разрешено вот это»).

Что модуль делает и чего не делает — граница важнее кода:

* **Делает:** разбирает SD-JWT, проверяет подпись издателя (EdDSA и ES256),
  собирает раскрытые утверждения, отдаёт срок и то, что издатель назвал
  лимитами, если оно там есть.
* **Не делает:** не выводит из мандата разрешение на конкретное действие.
  Правило «можно ли списать вот эту сумму за вот это» — политика развёртывания,
  а не свойство формата. Подставить сюда догадку значило бы выдать догадку за
  разрешение, то есть ровно то, ради предотвращения чего продукт существует.

Если поле в мандате не названо — оно не выдумывается, а отсутствует.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers, SECP256R1
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

VERIFIED = "verified"
DECODED_UNVERIFIED = "decoded-unverified"
MALFORMED = "malformed"


@dataclass
class Mandate:
    ok: bool
    status: str
    issuer: str | None = None
    subject: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None
    disclosed: dict[str, Any] = field(default_factory=dict)
    limits: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def why(self) -> str:
        return "; ".join(self.notes)


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def split(sd_jwt: str) -> tuple[str, str, list[str]]:
    """SD-JWT: `<jwt>~<disclosure>~...~`. Последний пустой элемент — норма."""
    parts = sd_jwt.strip().split("~")
    if not parts or not parts[0]:
        raise ValueError("empty credential")
    jwt = parts[0]
    disclosures = [p for p in parts[1:] if p]
    if jwt.count(".") != 2:
        raise ValueError("not a compact JWS: expected header.payload.signature")
    return jwt, "", disclosures


def _disclosure(raw: str) -> tuple[str, Any]:
    decoded = json.loads(_b64url_decode(raw))
    if not isinstance(decoded, list) or len(decoded) != 3:
        raise ValueError("a disclosure is [salt, name, value]")
    _, name, value = decoded
    if not isinstance(name, str):
        raise ValueError("disclosure name must be a string")
    return name, value


def _verify_es256(public_jwk: dict, signing_input: bytes, signature: bytes) -> bool:
    x = int.from_bytes(_b64url_decode(public_jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(public_jwk["y"]), "big")
    key = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
    half = len(signature) // 2
    r = int.from_bytes(signature[:half], "big")
    s = int.from_bytes(signature[half:], "big")
    try:
        key.verify(encode_dss_signature(r, s), signing_input, ECDSA(SHA256()))
        return True
    except InvalidSignature:
        return False


def read(sd_jwt: str, issuer_jwk: dict | None = None) -> Mandate:
    """Прочитать мандат. Без ключа издателя подпись не проверяется — и это сказано."""
    try:
        jwt, _, disclosures = split(sd_jwt)
        header_b64, payload_b64, signature_b64 = jwt.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(signature_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        return Mandate(False, MALFORMED, notes=[f"cannot decode: {exc}"])

    if not isinstance(header, dict) or not isinstance(payload, dict):
        return Mandate(False, MALFORMED, notes=["header and payload must be JSON objects"])

    disclosed: dict[str, Any] = {}
    notes: list[str] = []
    for raw in disclosures:
        try:
            name, value = _disclosure(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            notes.append(f"a disclosure was skipped: {exc}")
            continue
        disclosed[name] = value

    status = DECODED_UNVERIFIED
    if issuer_jwk is None:
        notes.append("no issuer key supplied: the signature was not verified")
    else:
        alg = header.get("alg")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        try:
            if alg == "EdDSA":
                key = Ed25519PublicKey.from_public_bytes(_b64url_decode(issuer_jwk["x"]))
                key.verify(signature, signing_input)
                status = VERIFIED
            elif alg == "ES256":
                status = VERIFIED if _verify_es256(issuer_jwk, signing_input, signature) else DECODED_UNVERIFIED
                if status != VERIFIED:
                    notes.append("ES256 signature does not verify")
            else:
                notes.append(f"algorithm {alg!r} is not supported: signature not verified")
        except (InvalidSignature, KeyError, ValueError) as exc:
            status = DECODED_UNVERIFIED
            notes.append(f"signature check failed: {type(exc).__name__}")

    limits = payload.get("limits") if isinstance(payload.get("limits"), dict) else {}
    if not limits:
        notes.append("the credential names no limits: not invented here")

    expires = payload.get("exp")
    return Mandate(
        ok=status == VERIFIED,
        status=status,
        issuer=str(payload["iss"]) if isinstance(payload.get("iss"), str) else None,
        subject=str(payload["sub"]) if isinstance(payload.get("sub"), str) else None,
        issued_at=payload.get("iat") if isinstance(payload.get("iat"), int) else None,
        expires_at=expires if isinstance(expires, int) else None,
        disclosed=disclosed,
        limits=dict(limits),
        notes=notes,
    )


def expired(mandate: Mandate, now: int) -> bool | None:
    """Просрочен ли мандат. None — срока нет, и это не «бессрочно»."""
    if mandate.expires_at is None:
        return None
    return now > mandate.expires_at


def digest(mandate: Mandate, salt: str = "") -> str:
    """Отпечаток мандата — чтобы ссылаться на него, не храня содержимое."""
    body = json.dumps({"iss": mandate.issuer, "sub": mandate.subject,
                       "exp": mandate.expires_at, "limits": mandate.limits,
                       "salt": salt}, sort_keys=True, ensure_ascii=False)
    return "sha256:" + hashlib.sha256(body.encode()).hexdigest()
