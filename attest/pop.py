#!/usr/bin/env python3
"""Proof of Place: артефакт `pop/1` и проверка без нашего сервиса.

Спека: `/media/Sruti/iamthat/work/sales/research/pop-lp/POP-SPEC.md` §4–5.

Что здесь есть и чего здесь нет:

* **Есть** схема отчёта, цепочка `prev_hash` → `hash` у каждого слоя
  (включая первый) и подпись Ed25519 поверх JCS (RFC 8785).
* **Есть** проверка, которая берёт ключ **снаружи** артефакта. Ключ внутри
  JSON — удобство для читателя, а не доверие: документ, подписанный своим же
  ключом, доказывает только, что он сам себя подписал.
* **Нет** пересчёта байтов файлов из ZIP: их в JSON нет. Цепочка закрывает
  хеши файлов, но не сами файлы — `limits` говорит это прямо.
* **Нет** доверия GPS: координаты проверяются на диапазон и форму, не на
  правду. Слой `position` остаётся `weak`.

Вердикты намеренно короткие: `ok`, `tampered`, `unsigned`, `wrong_key`,
`expired`. Всё, что не сходится структурно или по цепочке, — `tampered`:
артефакт не тот, который выпустили, и другая формулировка только запутает.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from .receipt import jcs
from .signing import public_key as _public_key
from .signing import sign as _sign
from .signing import verify as _verify_signature

VERSION = "pop/1"
KINDS = {"report", "mark"}
LAYERS = ("content", "position", "independent", "immutability")
VERDICTS = {"confirmed", "partial", "contradicted", "insufficient"}
RESULTS = {"pass", "weak", "match", "mismatch", "unknown", "fail",
           "not_available"}
#: `confirmed` не может стоять рядом с расхождением или непроверенным слоем.
BAD_FOR_CONFIRMED = {"unknown", "fail", "not_available", "mismatch"}

HASH_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_PREFIX = "ed25519:"
SIG_PREFIX = "base64:"


class Verdict(str):
    """Вердикт и причина в одном: `verify(...) == "ok"` и `.reason`.

    Строка, а не объект, — чтобы код вызывающего не учил новый тип ради
    сравнения с одним литералом.
    """

    reason: str

    def __new__(cls, status: str, reason: str = "") -> "Verdict":
        obj = super().__new__(cls, status)
        obj.reason = reason
        return obj


def canonical(value: Any) -> bytes:
    """Канонический JSON по RFC 8785. Дробные числа — отказ профиля."""
    return jcs.dumps(value).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _seed(artifact: dict) -> str:
    return _sha256(
        f"{VERSION}|{artifact['report_id']}|{artifact['issued_at']}".encode())


def _layer_hash(prev: str, layer: dict) -> str:
    """Хеш слоя: предыдущий хеш + JCS слоя без собственного `hash`."""
    body = {k: v for k, v in layer.items() if k != "hash"}
    return _sha256(prev.encode("ascii") + canonical(body))


def seal(artifact: dict) -> dict:
    """Проставить `n`, `prev_hash`, `hash` всем слоям, включая первый."""
    a = deepcopy(artifact)
    a.setdefault("v", VERSION)
    a.setdefault("kind", "report")
    prev = _seed(a)
    for i, layer in enumerate(a["layers"]):
        layer["n"] = i + 1
        layer["prev_hash"] = prev
        prev = _layer_hash(prev, layer)
        layer["hash"] = prev
    return a


def sign(artifact: dict, key_path=None) -> dict:
    """Запечатать и подписать. Приватный ключ — файл Ed25519."""
    a = seal(artifact)
    a["public_key"] = KEY_PREFIX + _public_key(key_path).hex()
    payload = canonical({k: v for k, v in a.items() if k != "signature"})
    a["signature"] = SIG_PREFIX + _sign(payload, key_path).signature
    return a


# --- ключи и подпись -------------------------------------------------------


def _key_bytes(text: str) -> bytes:
    """32 байта ключа из `ed25519:<hex|base64>` или голого hex/base64."""
    if not isinstance(text, str):
        raise ValueError("public key must be a string")
    t = text.strip()
    if t.startswith(KEY_PREFIX):
        t = t[len(KEY_PREFIX):].strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", t):
        raw = bytes.fromhex(t)
    else:
        try:
            raw = base64.b64decode(t, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(
                "public key is neither 64 hex chars nor base64") from exc
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return raw


def _sig_b64(text: str) -> str:
    t = text.strip()
    if t.startswith(SIG_PREFIX):
        t = t[len(SIG_PREFIX):].strip()
    return t


def _signature_reason(artifact: dict, pinned: str) -> tuple[str, str] | None:
    """None — подпись сходится с pinned-ключом; иначе вердикт и причина."""
    signature = artifact.get("signature")
    if not signature:
        return "unsigned", "signature is missing"
    declared = artifact.get("public_key")
    if not declared:
        return "unsigned", "public_key is missing: the signature cannot be attributed"
    try:
        declared_raw = _key_bytes(declared)
        pinned_raw = _key_bytes(pinned)
    except ValueError as exc:
        return "wrong_key", str(exc)
    if declared_raw != pinned_raw:
        return "wrong_key", "the report was signed with a key other than the pinned one"
    try:
        payload = canonical(
            {k: v for k, v in artifact.items() if k != "signature"})
    except jcs.CanonicalError as exc:
        return "tampered", f"artifact is not canonicalizable: {exc}"
    verified = _verify_signature(
        payload, _sig_b64(signature),
        base64.b64encode(pinned_raw).decode("ascii"))
    if not verified:
        return "tampered", "signature does not match: the report changed after signing"
    return None


# --- схема -----------------------------------------------------------------


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _coordinate(value: Any, low: int, high: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        number = Decimal(value)
    except InvalidOperation:
        return False
    return number.is_finite() and low <= number <= high


def _schema_reason(a: dict) -> str | None:
    if a.get("v") != VERSION:
        return f"unsupported version: {a.get('v')!r}"
    if a.get("kind") not in KINDS:
        return f"unsupported kind: {a.get('kind')!r}"
    if not _text(a.get("report_id")):
        return "report_id is missing"
    if _timestamp(a.get("issued_at")) is None:
        return "issued_at is not an RFC 3339 timestamp with a zone"
    issuer = a.get("issuer")
    if not isinstance(issuer, dict) or not _text(issuer.get("key_id")):
        return "issuer.key_id is missing"
    subject = a.get("subject")
    if not isinstance(subject, dict):
        return "subject is missing"
    for field in ("type", "ref", "claim"):
        if not _text(subject.get(field)):
            return f"subject.{field} is missing"
    if _timestamp(a.get("captured_at")) is None:
        return "captured_at is not an RFC 3339 timestamp with a zone"
    location = a.get("location")
    if not isinstance(location, dict):
        return "location is missing"
    if not _coordinate(location.get("lat"), -90, 90):
        return "location.lat must be a decimal string in [-90, 90]"
    if not _coordinate(location.get("lon"), -180, 180):
        return "location.lon must be a decimal string in [-180, 180]"
    accuracy = location.get("accuracy_m")
    if not _integer(accuracy) or accuracy < 0:
        return "location.accuracy_m must be a non-negative integer"

    for field in ("public_key", "signature"):
        if field in a and not isinstance(a[field], str):
            return f"{field} must be a string"

    layers = a.get("layers")
    if not isinstance(layers, list) or len(layers) != len(LAYERS):
        return f"exactly {len(LAYERS)} layers are required: {', '.join(LAYERS)}"
    if [layer.get("name") if isinstance(layer, dict) else None
            for layer in layers] != list(LAYERS):
        return f"layers must be {', '.join(LAYERS)}, in this order"
    for i, layer in enumerate(layers, 1):
        name = layer.get("name")
        if layer.get("n") != i or not _integer(layer.get("n")):
            return f"layer {i} ({name}): n must be {i}"
        for field in ("prev_hash", "hash"):
            value = layer.get(field)
            if not isinstance(value, str) or not HASH_RE.match(value):
                return f"layer {i} ({name}): {field} is not a sha256 hex digest"
        if name != "immutability" and layer.get("result") not in RESULTS:
            return f"layer {i} ({name}): result is not allowed"
        if name == "content":
            files = layer.get("files")
            if not isinstance(files, list):
                return "content layer: files must be a list"
            for item in files:
                if not isinstance(item, dict) or not _text(item.get("name")):
                    return "content layer: every file needs a name"
                if not _integer(item.get("bytes")) or item["bytes"] < 0:
                    return "content layer: file bytes must be a non-negative integer"
                if not isinstance(item.get("sha256"), str) \
                        or not HASH_RE.match(item["sha256"]):
                    return "content layer: file sha256 is not a sha256 hex digest"
        if name == "independent" and "captured_at" in layer \
                and _timestamp(layer["captured_at"]) is None:
            return "independent layer: captured_at is not RFC 3339"

    discrepancies = a.get("discrepancies")
    if not isinstance(discrepancies, list):
        return "discrepancies must be a list"
    for item in discrepancies:
        if not isinstance(item, dict) or not _text(item.get("field")):
            return "every discrepancy needs a field"

    for field in ("limits", "not_checked"):
        values = a.get(field)
        if not isinstance(values, list) or not values:
            return f"{field} is empty: a report without {field} is not signable"
        if any(not _text(value) for value in values):
            return f"{field} contains an empty entry"

    verdict = a.get("verdict")
    if verdict not in VERDICTS:
        return f"verdict is not one of {sorted(VERDICTS)}"
    results = [layer.get("result") for layer in layers
               if layer.get("result") is not None]
    if verdict == "confirmed":
        if discrepancies:
            return "confirmed verdict with discrepancies"
        if any(result in BAD_FOR_CONFIRMED for result in results):
            return "confirmed verdict with a layer that did not confirm"
    if verdict == "contradicted" and not discrepancies:
        return "contradicted verdict without discrepancies"
    if verdict == "insufficient" and not any(
            result in {"unknown", "not_available"} for result in results):
        return "insufficient verdict without an unknown or unavailable layer"

    pdf_sha256 = a.get("pdf_sha256")
    if pdf_sha256 is not None and (
            not isinstance(pdf_sha256, str) or not HASH_RE.match(pdf_sha256)):
        return "pdf_sha256 is not a sha256 hex digest"
    return None


# --- цепочка ---------------------------------------------------------------


def _chain_reason(a: dict) -> str | None:
    prev = _seed(a)
    for i, layer in enumerate(a["layers"], 1):
        if layer["prev_hash"] != prev:
            return f"layer {i} ({layer['name']}): prev_hash breaks the chain"
        try:
            prev = _layer_hash(prev, layer)
        except jcs.CanonicalError as exc:
            return f"layer {i} ({layer['name']}): {exc}"
        if layer["hash"] != prev:
            return f"layer {i} ({layer['name']}): hash does not match the layer"
    return None


# --- проверка --------------------------------------------------------------


def verify(artifact, public_key: str, *, pdf: bytes | None = None,
           now: datetime | None = None) -> Verdict:
    """Проверить артефакт pinned-ключом. Сеть не нужна.

    `artifact` — JSON-текст, байты или уже разобранный dict.
    `pdf` — байты report.pdf; если переданы, сверяются с `pdf_sha256`.
    `now` — момент проверки для отметок потока (по умолчанию текущий).
    """
    if isinstance(artifact, (bytes, bytearray)):
        try:
            artifact = bytes(artifact).decode("utf-8")
        except UnicodeDecodeError:
            return Verdict("tampered", "artifact is not UTF-8")
    if isinstance(artifact, str):
        try:
            a = jcs.loads(artifact)
        except (ValueError, TypeError) as exc:
            return Verdict("tampered", f"artifact is not valid JSON: {exc}")
    else:
        a = deepcopy(artifact)
    if not isinstance(a, dict):
        return Verdict("tampered", "artifact is not a JSON object")
    if isinstance(public_key, (bytes, bytearray)):
        public_key = bytes(public_key).decode("ascii", "replace")

    reason = _schema_reason(a)
    if reason:
        return Verdict("tampered", reason)
    reason = _chain_reason(a)
    if reason:
        return Verdict("tampered", reason)
    rejected = _signature_reason(a, public_key)
    if rejected:
        return Verdict(*rejected)

    if pdf is not None:
        if not a.get("pdf_sha256"):
            return Verdict("tampered",
                           "pdf_sha256 is missing: the PDF cannot be bound")
        if _sha256(pdf) != a["pdf_sha256"]:
            return Verdict("tampered", "PDF hash does not match pdf_sha256")

    if a["kind"] == "mark":
        valid_for = a.get("valid_for_s")
        if not _integer(valid_for) or valid_for < 0:
            return Verdict("tampered", "mark without a non-negative valid_for_s")
        moment = now or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        issued = _timestamp(a["issued_at"])
        if moment > issued + timedelta(seconds=valid_for):
            return Verdict("expired", f"mark older than valid_for_s={valid_for}")

    key_id = a["issuer"].get("key_id", "?")
    return Verdict(
        "ok",
        f"{a['kind']} · {a['verdict']} · {len(a['layers'])} layers · "
        f"issuer key_id={key_id}")
