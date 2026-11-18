#!/usr/bin/env python3
"""Living Proof: серверная доля — challenge, одноразовый nonce, сборка `lp/1`.

Офлайн-проверка (`attest/lp.py`) отвечает на вопрос «подпись верна и артефакт
не подменён». Она не может ответить на другой: «этот код выдан именно на это
действие и использован один раз». Для этого нужен журнал, и он здесь.

Что делает сервер:
  * `issue()` — выдаёт nonce (32 случайных байта, base64url), 6-значный код,
    окно ≤120 секунд и `action_sha256` по JCS. Действие фиксируется до
    подтверждения: подменить сумму после выдачи кода нельзя.
  * `consume()` — гасит nonce ровно один раз. Повтор → `replay`, истёкший →
    `stale`, другое действие → `policy_failed`.
  * `build_assertion()` — собирает `lp/1` и подписывает его `attest.lp.sign`.
  * `confirm()` — `consume` + `build_assertion` за один шаг сервера.
  * `verify_assertion()` — сначала `lp.verify`, затем журнал: тот же nonce с
    другим `assertion_id` → `replay`.

Хранение: SQLite из стандартной библиотеки (`ATTEST_LP_DB`, по умолчанию
`/tmp/opencode/lp.db`). Журнал нужен только на время окна challenge (120 с),
поэтому `/tmp` — не компромисс, а достаточное место: после перезагрузки
истёкшие nonce всё равно бесполезны.

Чего здесь нет и что сказано в `limits` каждого артефакта:
  * живость человека и подлинность видео офлайн не проверяются;
  * попытки ввода кода не ограничиваются по частоте (1e6 за 120 с возможны);
  * биометрия не хранится и не собирается.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import lp
from .receipt import jcs

#: Журнал. Вне репозитория: это состояние сервера, а не исходник.
DEFAULT_DB = Path(os.environ.get("ATTEST_LP_DB", "/tmp/opencode/lp.db"))
#: Окно challenge ограничено схемой `lp/1` (120 с) — больше выдать нельзя.
MAX_TTL_SECONDS = lp.MAX_CHALLENGE_SECONDS
#: Предмет, который человек показывает в живой задаче. Меняется вызывающим.
DEFAULT_OBJECT = "object_with_serial"

#: Что артефакт проверяет сам, а что — нет. Список едет в каждом `lp/1`,
#: чтобы покупатель не додумывал гарантии, которых мы не даём.
LIMITS = [
    "nonce is single-use: the server journal rejects a second confirmation",
    "action is bound to the challenge by sha256 over JCS before confirmation",
    "human liveness is not verified at all: the server takes factor refs as given",
    "video authenticity is not verified at all: frames are not cross-checked",
    "wrong challenge codes are not rate-limited",
    "no biometrics are collected or stored",
]

_STATUS = {
    "ok": ("ok", ""),
    "unknown": ("policy_failed", "challenge nonce was not issued by this server"),
    "policy_failed": ("policy_failed", "challenge was issued for a different action"),
    "replay": ("replay", "challenge nonce was already used"),
    "stale": ("stale", "challenge has expired"),
    "unconfirmed": ("policy_failed", "challenge was never confirmed by the server"),
}


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def action_sha256(action: dict) -> str:
    """Хеш действия по RFC 8785: те же байты у нас и у проверяющего."""
    return hashlib.sha256(jcs.dumps(action).encode("utf-8")).hexdigest()


class ChallengeStore:
    """Журнал выданных nonce. Один файл, один UPDATE на гашение."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or DEFAULT_DB)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS challenges ("
                " nonce TEXT PRIMARY KEY,"
                " action_sha256 TEXT NOT NULL,"
                " code TEXT NOT NULL,"
                " issued_at TEXT NOT NULL,"
                " expires_at TEXT NOT NULL,"
                " expires_ts REAL NOT NULL,"
                " subject TEXT NOT NULL,"
                " object_required TEXT NOT NULL,"
                " consumed_at TEXT,"
                " assertion_id TEXT)"
            )
        # The file holds one-time challenge codes; keep it owner-only.
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def issue(
        self,
        action: dict,
        subject: dict,
        ttl_seconds: int = 120,
        *,
        object_required: str = DEFAULT_OBJECT,
        now: datetime | None = None,
    ) -> dict:
        if not isinstance(action, dict) or not isinstance(subject, dict):
            raise TypeError("action and subject must be JSON objects")
        if not 0 < ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError(f"ttl_seconds must be 1..{MAX_TTL_SECONDS}")
        moment = now or datetime.now(UTC)
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        code = f"{secrets.randbelow(1_000_000):06d}"
        digest = action_sha256(action)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO challenges (nonce, action_sha256, code, issued_at,"
                " expires_at, expires_ts, subject, object_required)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (nonce, digest, code, _iso(moment),
                 _iso(moment + timedelta(seconds=ttl_seconds)),
                 moment.timestamp() + ttl_seconds,
                 json.dumps(subject, ensure_ascii=False), object_required),
            )
        return {
            "nonce": nonce,
            "code": code,
            "issued_at": _iso(moment),
            "expires_at": _iso(moment + timedelta(seconds=ttl_seconds)),
            "action_sha256": digest,
            "object_required": object_required,
        }

    def get(self, nonce: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM challenges WHERE nonce = ?", (nonce,)).fetchone()
        return dict(row) if row is not None else None

    def consume(
        self,
        nonce: str,
        digest: str,
        assertion_id: str | None = None,
        *,
        now: datetime | None = None,
    ) -> str:
        """Погасить nonce. Возвращает `ok` / `replay` / `stale` /
        `policy_failed` / `unknown`."""
        moment = now or datetime.now(UTC)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM challenges WHERE nonce = ?", (nonce,)).fetchone()
            if row is None:
                return "unknown"
            if row["action_sha256"] != digest:
                return "policy_failed"
            if row["consumed_at"] is not None:
                return "replay"
            if moment.timestamp() > row["expires_ts"]:
                return "stale"
            # Условие `consumed_at IS NULL` в самом UPDATE: два одновременных
            # запроса не могут оба увидеть nonce свободным.
            cursor = conn.execute(
                "UPDATE challenges SET consumed_at = ?, assertion_id = ?"
                " WHERE nonce = ? AND consumed_at IS NULL",
                (_iso(moment), assertion_id, nonce),
            )
            if cursor.rowcount != 1:
                return "replay"
        return "ok"

    def check(self, nonce: str, digest: str, assertion_id: str) -> str:
        """Сверка артефакта с журналом без гашения (для `verify_assertion`)."""
        row = self.get(nonce)
        if row is None:
            return "unknown"
        if row["action_sha256"] != digest:
            return "policy_failed"
        if row["consumed_at"] is None:
            return "unconfirmed"
        if row["assertion_id"] != assertion_id:
            return "replay"
        return "ok"


_DEFAULT_STORE: ChallengeStore | None = None


def default_store() -> ChallengeStore:
    global _DEFAULT_STORE
    if _DEFAULT_STORE is None or str(_DEFAULT_STORE.path) != str(DEFAULT_DB):
        _DEFAULT_STORE = ChallengeStore(DEFAULT_DB)
    return _DEFAULT_STORE


def _store(store: ChallengeStore | None) -> ChallengeStore:
    return store or default_store()


def issue(
    action: dict,
    subject: dict,
    ttl_seconds: int = 120,
    *,
    object_required: str = DEFAULT_OBJECT,
    store: ChallengeStore | None = None,
    now: datetime | None = None,
) -> dict:
    return _store(store).issue(
        action, subject, ttl_seconds, object_required=object_required, now=now)


def consume(
    nonce: str,
    digest: str,
    assertion_id: str | None = None,
    *,
    store: ChallengeStore | None = None,
    now: datetime | None = None,
) -> str:
    return _store(store).consume(nonce, digest, assertion_id, now=now)


def _check_factors(factors: list[dict], verdict: str) -> None:
    if not isinstance(factors, list) or not factors:
        raise ValueError("factors must be a non-empty list")
    kinds = set()
    for factor in factors:
        if not isinstance(factor, dict) or not isinstance(factor.get("kind"), str):
            raise TypeError("every factor needs a kind")
        kinds.add(factor["kind"])
        if verdict == "accept" and not (isinstance(factor.get("ref"), str)
                                        and factor["ref"].strip()):
            raise ValueError(f"factor {factor['kind']} has no evidence ref")
    missing = {"A_key_share", "B_live_task"} - kinds
    if missing:
        raise ValueError("policy requires A_key_share and B_live_task: "
                         f"missing {', '.join(sorted(missing))}")


def build_assertion(
    challenge: dict,
    action: dict,
    subject: dict,
    factors: list[dict],
    *,
    verdict: str = "accept",
    issuer: dict | None = None,
    policy: dict | None = None,
    limits: list[str] | None = None,
    assertion_id: str | None = None,
    issued_at: datetime | None = None,
    key_path=None,
) -> dict:
    """Собрать `lp/1` и подписать. `challenge` — то, что вернул `issue()`."""
    if verdict not in lp.VERDICTS:
        raise ValueError(f"verdict must be one of {sorted(lp.VERDICTS)}")
    if not isinstance(action, dict) or not isinstance(subject, dict):
        raise TypeError("action and subject must be JSON objects")
    _check_factors(factors, verdict)
    artifact = {
        "v": lp.VERSION,
        "assertion_id": assertion_id or f"lp_{secrets.token_hex(12)}",
        "issued_at": _iso(issued_at or datetime.now(UTC)),
        "issuer": issuer or {"name": "RTA", "key_id": "rta-lp"},
        "subject": subject,
        "action": {**action, "sha256": action_sha256(action)},
        "challenge": {
            key: challenge[key] for key in
            ("nonce", "code", "issued_at", "expires_at", "object_required")
        },
        "factors": factors,
        "policy": policy or {
            "required": "A+B",
            "limit_usd": str(action.get("amount_usd", "0")),
            "above_limit": "A+B+C",
        },
        "verdict": verdict,
        "limits": list(limits or LIMITS),
    }
    return lp.sign(artifact, key_path)


def confirm(
    nonce: str,
    *,
    code: str,
    action: dict,
    subject: dict,
    factors: list[dict],
    verdict: str = "accept",
    issuer: dict | None = None,
    policy: dict | None = None,
    limits: list[str] | None = None,
    store: ChallengeStore | None = None,
    key_path=None,
    now: datetime | None = None,
) -> dict:
    """Подтверждение на сервере: код → гашение nonce → подписанный `lp/1`.

    Возвращает `{"ok": bool, "verdict": lp.Verdict, "artifact": dict | None}`.
    На отказе nonce не гасится, кроме случая `replay` (он уже погашен).
    """
    journal = _store(store)
    row = journal.get(nonce)
    if row is None:
        return {"ok": False, "verdict": lp.Verdict("policy_failed", "unknown nonce"),
                "artifact": None}
    if not isinstance(code, str) or code != row["code"]:
        return {"ok": False,
                "verdict": lp.Verdict("policy_failed", "challenge code does not match"),
                "artifact": None}
    assertion_id = f"lp_{secrets.token_hex(12)}"
    challenge = {key: row[key] for key in
                 ("nonce", "code", "issued_at", "expires_at", "object_required")}
    try:
        artifact = build_assertion(
            challenge, action, subject, factors, verdict=verdict, issuer=issuer,
            policy=policy, limits=limits, assertion_id=assertion_id,
            issued_at=now, key_path=key_path,
        )
    except ValueError as exc:
        return {"ok": False, "verdict": lp.Verdict("policy_failed", str(exc)),
                "artifact": None}
    status = journal.consume(nonce, action_sha256(action), assertion_id, now=now)
    if status != "ok":
        return {"ok": False, "verdict": lp.Verdict(status, _STATUS.get(status, ("", ""))[1]),
                "artifact": None}
    return {"ok": True, "verdict": lp.Verdict("ok", ""), "artifact": artifact}


def verify_assertion(
    artifact: bytes | str | dict,
    pinned_key: str,
    *,
    store: ChallengeStore | None = None,
    now: datetime | None = None,
) -> lp.Verdict:
    """`lp.verify` + журнал: артефакт должен быть тем, что сервер погасил."""
    result = lp.verify(artifact, pinned_key, now=now)
    if result != "ok":
        return result
    data = artifact if isinstance(artifact, dict) else json.loads(artifact)
    status = _store(store).check(
        data["challenge"]["nonce"], data["action"]["sha256"], data["assertion_id"])
    verdict, reason = _STATUS[status]
    return lp.Verdict(verdict, reason)
