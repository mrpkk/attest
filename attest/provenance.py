"""Provenance: криптографическое заверяние проверенного артефакта.

Без внешних зависимостей: HMAC-SHA256 (секрет агента) либо Ed25519
(если доступна cryptography). Цель — доказательство «этот артефакт
проверен в момент T источником S и с тех пор не менялся».
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


@dataclass
class ProvenanceRecord:
    attestation_id: str
    source: str
    verified_at: float
    content_hash: str
    verdict: str
    trust_score: float
    violations: list[dict[str, str]] = field(default_factory=list)
    signals: list[dict[str, str]] = field(default_factory=list)
    # Привязка к условиям генерации. None означает «условия не переданы»,
    # и это обязано быть видно, а не молча выглядеть как «привязка есть».
    chain_hash: str | None = None
    # Проверка разрешения. Заверяется вместе с артефактом: подпись должна
    # говорить не «это подписано», а «это подписано И это было разрешено».
    # Проверять мандат, но не заверять его — значит оставить дыру, где к
    # артефакту прикладывается чужое полномочие.
    authority_hash: str | None = None
    authority: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Attestation:
    record: ProvenanceRecord
    signature: str
    algorithm: str
    public_key: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"record": self.record.as_dict(), "signature": self.signature,
                "algorithm": self.algorithm, "public_key": self.public_key}

    def compact(self) -> str:
        """Однострочный формат для вставки в контекст агента."""
        r = self.record
        return (
            f"[attest:{self.algorithm}] id={r.attestation_id} source={r.source} "
            f"verdict={r.verdict} trust={r.trust_score:.2f} sha256={r.content_hash[7:19]} "
            f"violations={len(r.violations)} signals={len(r.signals)} at={r.verified_at:.0f}"
        )


def _key_from_env() -> bytes | None:
    """Секрет HMAC. Отсутствие — не повод подписывать запасным ключом.

    Раньше здесь возвращалась константа `attest-dev-key-do-not-use-in-production`.
    Она лежала в исходнике, то есть была опубликована вместе с ним, и любой
    мог подписать артефакт так, будто его заверял сервис. Подпись выглядела
    настоящей и не была ею — хуже, чем отсутствие подписи.
    """
    for name in ("ATTEST_SECRET", "ATTEST_HMAC_KEY"):
        value = os.environ.get(name)
        if value:
            return value.encode("utf-8")
    return None


def sign(record: ProvenanceRecord, key: bytes | None = None) -> Attestation:
    """Подпись заверяния.

    Предпочтительна Ed25519: публичный ключ едет в ответе, и проверяющий
    сверяет подпись сам, не обращаясь к нам. HMAC оставлен как запасной
    путь для старых записей, но без секрета он больше не подписывает —
    раньше подписывал константой из исходника.
    """
    payload = canonical(record.as_dict())
    try:
        from .signing import sign as ed_sign
        s = ed_sign(payload)
        return Attestation(record=record, signature=s.signature,
                           algorithm=s.algorithm, public_key=s.public_key)
    except (FileNotFoundError, RuntimeError) as exc:
        key = key or _key_from_env()
        if key is None:
            raise RuntimeError(
                "Подписать нечем: нет приватного ключа Ed25519 "
                f"({exc}) и не задан ATTEST_SECRET. Создать ключ: "
                "python3 -m attest keygen") from exc
        signature = "hmac-sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()
        return Attestation(record=record, signature=signature,
                           algorithm="hmac-sha256")


def verify(attestation: Attestation, key: bytes | None = None) -> bool:
    """Проверить заверяние.

    Ed25519 проверяется публичным ключом из самого заверяния — секрет не
    нужен. HMAC — секретом, и без него проверка возвращает False, а не
    «наверное, нормально».
    """
    if attestation.algorithm == "ed25519":
        from .signing import verify as ed_verify
        payload = canonical(attestation.record.as_dict())
        if not attestation.public_key:
            return False
        return ed_verify(payload, attestation.signature, attestation.public_key)
    key = key or _key_from_env()
    if key is None:
        return False
    expected = sign(attestation.record, key)
    return hmac.compare_digest(expected.signature, attestation.signature)


def new_record(
    source: str,
    artifact: Any,
    verdict: str,
    trust_score: float,
    violations: list[dict[str, str]] | None = None,
    signals: list[dict[str, str]] | None = None,
    chain_hash: str | None = None,
    authority_hash: str | None = None,
    authority: dict[str, Any] | None = None,
) -> ProvenanceRecord:
    return ProvenanceRecord(
        attestation_id=str(uuid.uuid4()),
        source=source,
        verified_at=time.time(),
        content_hash=digest(artifact),
        verdict=verdict,
        trust_score=round(trust_score, 3),
        violations=violations or [],
        signals=signals or [],
        chain_hash=chain_hash,
        authority_hash=authority_hash,
        authority=authority,
    )
