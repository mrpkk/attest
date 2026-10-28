"""Deny / Refusal Evidence — доказуемый журнал отказов (29.10.2026).

Зачем: журнал, где «все allowed», не доказывает, что система умеет отказывать.
Покупатель и аудитор спрашивают обратное — покажите отказы: кто просил, что,
почему отказано, и подпись, которую можно проверить без нас.

Запись: канонический JSON (JCS), Ed25519-подпись, цепочка `prev` (sha256).
Проверка офлайн: пересчитать хеши и подписи публичным ключом из самой записи.
Граница честности: подпись доказывает, что запись не менялась после выпуска и
сделана нашим ключом. Она не доказывает, что мы не выпустили другую цепь.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from . import signing
from .receipt import jcs

VERSION = 1
STATE = Path(os.environ.get(
    "ATTEST_STATE",
    str(Path.home() / ".local" / "share" / "attest" / "metrics.json"),
))
LOG_PATH = STATE.with_name("deny.jsonl")

_PUBLIC_FIELDS = ("hash", "signature", "public_key", "algorithm")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _body(event: dict[str, Any], prev: str) -> dict[str, Any]:
    body = {"v": VERSION, "prev": prev, **event}
    return body


def _canonical(body: dict[str, Any]) -> bytes:
    return jcs.dumps(body).encode()


def _hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(body)).hexdigest()


def make_event(*, reason: str, policy_id: str, task_id: str = "",
               artifact_hash: str = "", actor: str = "",
               meta: Optional[dict[str, Any]] = None,
               ts: Optional[str] = None) -> dict[str, Any]:
    """Событие отказа без подписи: то, что кладёт вызывающая сторона."""
    if not reason or not policy_id:
        raise ValueError("reason and policy_id are required: a denial without a rule is not evidence")
    return {
        "ts": ts or _now(),
        "decision": "deny",
        "reason": reason[:500],
        "policy_id": policy_id[:200],
        "task_id": task_id[:200],
        "artifact_hash": artifact_hash[:128],
        "actor": actor[:200],
        "meta": meta or {},
    }


def sign_record(event: dict[str, Any], prev: str = "", key_path: Path | None = None) -> dict[str, Any]:
    body = _body(event, prev)
    payload = _canonical(body)
    sig = signing.sign(payload, key_path)
    record = dict(body)
    record["hash"] = hashlib.sha256(payload).hexdigest()
    record.update(sig.as_dict())
    return record


def verify_record(record: dict[str, Any], prev: str = "") -> tuple[bool, str]:
    body = {k: v for k, v in record.items() if k not in _PUBLIC_FIELDS}
    if body.get("prev", "") != prev:
        return False, "prev does not match"
    payload = _canonical(body)
    if hashlib.sha256(payload).hexdigest() != record.get("hash"):
        return False, "hash does not match content"
    if not signing.verify(payload, record.get("signature", ""), record.get("public_key", "")):
        return False, "signature is invalid"
    return True, "ok"


def verify_log(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    prev = ""
    count = 0
    for index, record in enumerate(records):
        ok, why = verify_record(record, prev)
        if not ok:
            return {"ok": False, "records": count, "broken_at": index, "reason": why}
        prev = record.get("hash", "")
        count += 1
    return {"ok": True, "records": count, "broken_at": None, "reason": "ok",
            "head": prev}


def append(event: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    target = Path(path or LOG_PATH)
    records = read(target)
    prev = records[-1].get("hash", "") if records else ""
    record = sign_record(event, prev)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def read(path: Path | None = None) -> list[dict[str, Any]]:
    target = Path(path or LOG_PATH)
    if not target.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def _since_ts(value: str) -> Optional[float]:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def query(since: str = "", limit: int = 100, path: Path | None = None) -> dict[str, Any]:
    records = read(path)
    cutoff = _since_ts(since)
    if cutoff is not None:
        kept = []
        for r in records:
            try:
                ts = datetime.fromisoformat(str(r.get("ts", "")).replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
            if ts >= cutoff:
                kept.append(r)
        records = kept
    records = records[-max(1, min(limit, 500)):]
    by_policy: dict[str, int] = {}
    by_reason: dict[str, int] = {}
    for r in records:
        by_policy[r.get("policy_id", "?")] = by_policy.get(r.get("policy_id", "?"), 0) + 1
        by_reason[r.get("reason", "?")] = by_reason.get(r.get("reason", "?"), 0) + 1
    return {"events": records, "count": len(records),
            "head": records[-1].get("hash", "") if records else "",
            "by_policy": by_policy, "by_reason": by_reason}
