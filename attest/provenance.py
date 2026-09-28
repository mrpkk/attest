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

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Attestation:
    record: ProvenanceRecord
    signature: str
    algorithm: str

    def as_dict(self) -> dict[str, Any]:
        return {"record": self.record.as_dict(), "signature": self.signature, "algorithm": self.algorithm}

    def compact(self) -> str:
        """Однострочный формат для вставки в контекст агента."""
        r = self.record
        return (
            f"[attest:{self.algorithm}] id={r.attestation_id} source={r.source} "
            f"verdict={r.verdict} trust={r.trust_score:.2f} sha256={r.content_hash[7:19]} "
            f"violations={len(r.violations)} signals={len(r.signals)} at={r.verified_at:.0f}"
        )


def _key_from_env() -> bytes:
    for name in ("ATTEST_SECRET", "ATTEST_HMAC_KEY"):
        value = os.environ.get(name)
        if value:
            return value.encode("utf-8")
    return b"attest-dev-key-do-not-use-in-production"


def sign(record: ProvenanceRecord, key: bytes | None = None) -> Attestation:
    key = key or _key_from_env()
    payload = canonical(record.as_dict())
    signature = "hmac-sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()
    return Attestation(record=record, signature=signature, algorithm="hmac-sha256")


def verify(attestation: Attestation, key: bytes | None = None) -> bool:
    key = key or _key_from_env()
    expected = sign(attestation.record, key)
    return hmac.compare_digest(expected.signature, attestation.signature)


def new_record(
    source: str,
    artifact: Any,
    verdict: str,
    trust_score: float,
    violations: list[dict[str, str]] | None = None,
    signals: list[dict[str, str]] | None = None,
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
    )
