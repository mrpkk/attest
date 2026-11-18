#!/usr/bin/env python3
"""Living Proof: артефакт `lp/1` и офлайн-проверка.

Спека: `/media/Sruti/iamthat/work/sales/research/pop-lp/LP-SPEC.md` §4–5.
Проект **не продаётся** до G6 у Proof of Place; здесь собран только артефакт
и `verify()`, чтобы разморозка заняла дни, а не недели.

Что проверяется офлайн:
  * схема и непустые limits;
  * окно challenge (issued_at < expires_at, <= 120 секунд, не истекло);
  * факторы A+B, а выше policy.limit_usd — ещё C;
  * action.sha256 и evidence-ref у факторов;
  * Ed25519 подпись pinned-ключом (ключ не из артефакта).

Что офлайн не проверяется и сказано в limits:
  * одноразовость nonce (нужен журнал сервера);
  * живость человека не проверяется вообще: сервер принимает evidence-ref
    факторов как есть;
  * целостность видео (кадры не входят в артефакт).
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from copy import deepcopy
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Self

from .receipt import jcs
from .signing import public_key as _public_key
from .signing import sign as _sign
from .signing import verify as _verify_signature

VERSION = "lp/1"
VERDICTS = {"accept", "reject", "insufficient"}
KINDS = {"A_key_share", "B_live_task", "C_witness"}
MAX_CHALLENGE_SECONDS = 120
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_PREFIX = "ed25519:"
SIG_PREFIX = "base64:"


class Verdict(str):
    reason: str

    def __new__(cls, status: str, reason: str = "") -> Self:
        obj = super().__new__(cls, status)
        obj.reason = reason
        return obj


def canonical(value: Any) -> bytes:
    return jcs.dumps(value).encode("utf-8")


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _amount(value: Any) -> Decimal | None:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return number if number.is_finite() and number >= 0 else None


def _key_bytes(text: str) -> bytes:
    t = text.strip()
    if t.startswith(KEY_PREFIX):
        t = t[len(KEY_PREFIX):].strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", t):
        raw = bytes.fromhex(t)
    else:
        try:
            raw = base64.b64decode(t, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("public key is neither 64 hex chars nor base64") from exc
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return raw


def _nonce_bytes(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 else None


def sign(artifact: dict, key_path=None) -> dict:
    a = deepcopy(artifact)
    a.setdefault("v", VERSION)
    a["public_key"] = KEY_PREFIX + _public_key(key_path).hex()
    payload = canonical({k: v for k, v in a.items() if k != "signature"})
    a["signature"] = SIG_PREFIX + _sign(payload, key_path).signature
    return a


def _schema_reason(a: dict) -> str | None:
    if a.get("v") != VERSION:
        return f"unsupported version: {a.get('v')!r}"
    if not _text(a.get("assertion_id")):
        return "assertion_id is missing"
    if _timestamp(a.get("issued_at")) is None:
        return "issued_at must be RFC 3339 with a zone"
    if not isinstance(a.get("issuer"), dict) or not _text(a["issuer"].get("key_id")):
        return "issuer.key_id is missing"
    if not isinstance(a.get("subject"), dict) or not _text(a["subject"].get("did")):
        return "subject.did is missing"
    action = a.get("action")
    if not isinstance(action, dict):
        return "action is missing"
    if not _text(action.get("type")) or not _text(action.get("ref")):
        return "action.type/action.ref are missing"
    if not _text(action.get("counterparty")):
        return "action.counterparty is missing"
    if not isinstance(action.get("sha256"), str) or not HASH_RE.fullmatch(action["sha256"]):
        return "action.sha256 is not a sha256 hex digest"
    if _amount(action.get("amount_usd")) is None:
        return "action.amount_usd is not a non-negative decimal string"
    challenge = a.get("challenge")
    if not isinstance(challenge, dict):
        return "challenge is missing"
    if _nonce_bytes(challenge.get("nonce")) is None:
        return "challenge.nonce is not 32 base64url bytes"
    if not _text(challenge.get("code")) or not re.fullmatch(r"[0-9]{6}", challenge["code"]):
        return "challenge.code is not six digits"
    if _timestamp(challenge.get("issued_at")) is None or _timestamp(challenge.get("expires_at")) is None:
        return "challenge timestamps must be RFC 3339 with a zone"
    if not _text(challenge.get("object_required")):
        return "challenge.object_required is missing"
    if a.get("verdict") not in VERDICTS:
        return f"unsupported verdict: {a.get('verdict')!r}"
    limits = a.get("limits")
    if not isinstance(limits, list) or not limits or not all(_text(x) for x in limits):
        return "limits must be a non-empty list of strings"
    policy = a.get("policy")
    if not isinstance(policy, dict) or not _text(policy.get("required")):
        return "policy.required is missing"
    if _amount(policy.get("limit_usd")) is None:
        return "policy.limit_usd is not a non-negative decimal string"
    return None


def _challenge_reason(a: dict, now: datetime) -> str | None:
    ch = a["challenge"]
    issued = _timestamp(ch["issued_at"]); expires = _timestamp(ch["expires_at"])
    assert issued is not None and expires is not None
    if expires <= issued:
        return "challenge expires_at is not after issued_at"
    if (expires - issued).total_seconds() > MAX_CHALLENGE_SECONDS:
        return "challenge window is longer than 120 seconds"
    declared = _timestamp(a["issued_at"])
    assert declared is not None
    if declared > expires:
        return "issued_at is after challenge.expires_at"
    if now > expires:
        return "challenge has expired"
    return None


def _policy_reason(a: dict) -> str | None:
    factors = a.get("factors")
    if not isinstance(factors, list):
        return "factors is not a list"
    kinds = {f.get("kind") for f in factors if isinstance(f, dict)}
    if "A_key_share" not in kinds or "B_live_task" not in kinds:
        return "policy requires A_key_share and B_live_task"
    amount = _amount(a["action"]["amount_usd"]); limit = _amount(a["policy"]["limit_usd"])
    assert amount is not None and limit is not None
    if amount > limit and "C_witness" not in kinds:
        return "amount is above limit_usd without C_witness"
    if a.get("verdict") == "accept":
        for factor in factors:
            if not isinstance(factor, dict) or not _text(factor.get("ref")):
                return "accepted proof has a factor without evidence ref"
    return None


def _signature_reason(a: dict, pinned: str) -> str | None:
    signature = a.get("signature")
    if not signature:
        return "unsigned"
    declared = a.get("public_key")
    if not declared:
        return "unsigned"
    try:
        declared_raw = _key_bytes(declared)
        pinned_raw = _key_bytes(pinned)
    except ValueError:
        return "wrong_key"
    if declared_raw != pinned_raw:
        return "wrong_key"
    try:
        payload = canonical({k: v for k, v in a.items() if k != "signature"})
    except jcs.CanonicalError:
        return "tampered"
    sig = signature.strip()
    if sig.startswith(SIG_PREFIX):
        sig = sig[len(SIG_PREFIX):].strip()
    if not _verify_signature(payload, sig, base64.b64encode(pinned_raw).decode("ascii")):
        return "tampered"
    return None


def verify(artifact: bytes | str | dict, pinned_key: str, *, now: datetime | None = None) -> Verdict:
    """Проверить `lp/1` против pinned-ключа. Сеть не нужна."""
    if isinstance(artifact, dict):
        data = artifact
    else:
        try:
            data = json.loads(artifact)
        except (TypeError, ValueError, json.JSONDecodeError):
            return Verdict("malformed", "artifact is not valid JSON")
    if not isinstance(data, dict):
        return Verdict("malformed", "artifact is not a JSON object")
    reason = _schema_reason(data)
    if reason:
        return Verdict("malformed", reason)
    now = now or datetime.now(UTC)
    reason = _challenge_reason(data, now)
    if reason:
        return Verdict("stale", reason)
    reason = _policy_reason(data)
    if reason:
        return Verdict("policy_failed", reason)
    reason = _signature_reason(data, pinned_key)
    if reason == "unsigned":
        return Verdict("unsigned", "signature is missing")
    if reason == "wrong_key":
        return Verdict("wrong_key", "the proof was signed with a key other than the pinned one")
    if reason == "tampered":
        return Verdict("tampered", "signature does not match: the proof changed after signing")
    return Verdict("ok", "")
