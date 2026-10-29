"""API-ключи для платных endpoint'ов (29.10.2026).

Зачем: оплата без выдачи продукта — дыра. После подтверждённой транзакции
клиент должен получить ключ, которым сразу пользуется, а не ждать письма.

Формат: `dn_<48 hex>`. В файле лежит только sha256 ключа — украденный файл
не даёт действующих ключей. Срок и лимит записи — в записи.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Optional

STATE = Path(os.environ.get(
    "ATTEST_STATE",
    str(Path.home() / ".local" / "share" / "attest" / "metrics.json"),
))
KEYS_PATH = STATE.with_name("api_keys.jsonl")
PREFIX = "dn_"


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def issue(*, plan: str, subject: str, tx: str, days: int,
          calls_limit: Optional[int] = None) -> dict[str, Any]:
    key = PREFIX + secrets.token_hex(24)
    record = {
        "hash": _hash(key),
        "plan": plan,
        "subject": subject[:200],
        "tx": tx[:100],
        "created": int(time.time()),
        "expires": int(time.time()) + days * 86400,
        "calls_limit": calls_limit,
        "calls_used": 0,
    }
    KEYS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with KEYS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return {"key": key, "plan": plan,
            "expires_at": record["expires"], "calls_limit": calls_limit}


def _records() -> list[dict[str, Any]]:
    if not KEYS_PATH.exists():
        return []
    out = []
    for line in KEYS_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def verify(key: str) -> Optional[dict[str, Any]]:
    if not key or not key.startswith(PREFIX):
        return None
    digest = _hash(key)
    for record in _records():
        if record.get("hash") == digest:
            if int(record.get("expires", 0)) < time.time():
                return None
            limit = record.get("calls_limit")
            if limit is not None and int(record.get("calls_used", 0)) >= int(limit):
                return None
            return record
    return None


def consume(key: str) -> Optional[dict[str, Any]]:
    """Списать один вызов: переписываем файл с увеличенным счётчиком."""
    record = verify(key)
    if record is None:
        return None
    records = _records()
    digest = _hash(key)
    for item in records:
        if item.get("hash") == digest:
            item["calls_used"] = int(item.get("calls_used", 0)) + 1
            break
    KEYS_PATH.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
        encoding="utf-8",
    )
    return record
