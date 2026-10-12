#!/usr/bin/env python3
"""Проверка заверяния без доверия к сервису.

Скрипт самодостаточен: он не импортирует `attest`, не читает `.env`,
не обращается к сети. Единственное, чему он доверяет, — Ed25519.

Так и должно выглядеть настоящее заверяние. Если проверка требует
доверия к проверяющему, это не заверяние, а его заявление.

Запуск:
    python3 attest/verify_standalone.py attestation.json
    python3 attest/verify_standalone.py -          # читает stdin
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _canon(value) -> bytes:
    """Канонический вид: те же правила, что при подписи.

    Порядок ключей обязан совпадать, иначе пересчитанная подпись не
    сойдётся с исходной. Поэтому здесь sort_keys=True — как и при подписи.
    """
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def verify(attestation: dict) -> dict:
    algo = attestation.get("algorithm")
    if algo != "ed25519":
        return {"valid": False,
                "reason": f"алгоритм {algo!r} не принимается: этот верификатор "
                          f"понимает только ed25519 и не доверяет HMAC — "
                          f"с HMAC проверяющему нужен наш секрет"}
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return {"valid": False,
                "reason": "нужен пакет cryptography: pip install cryptography"}

    rec = attestation.get("record")
    sig = attestation.get("signature")
    pub = attestation.get("public_key")
    if not rec or not sig or not pub:
        return {"valid": False,
                "reason": "неполное заверяние: нужны record, signature, public_key"}

    payload = _canon(rec)
    try:
        Ed25519PublicKey.from_public_bytes(_b64d(pub)).verify(_b64d(sig), payload)
    except (InvalidSignature, ValueError, TypeError):
        return {"valid": False,
                "reason": "подпись не сходится: запись меняли после подписания "
                          "либо подпись подделана"}
    return {"valid": True,
            "attestation_id": rec.get("attestation_id"),
            "source": rec.get("source"),
            "verdict": rec.get("verdict"),
            "trust_score": rec.get("trust_score"),
            "content_hash": rec.get("content_hash"),
            "chain_hash": rec.get("chain_hash"),
            "verified_at": rec.get("verified_at"),
            "key_fingerprint": hashlib.sha256(_b64d(pub)).hexdigest()[:16]}


def main(argv: list[str]) -> int:
    if not argv:
        print("как: python3 verify_standalone.py attestation.json", file=sys.stderr)
        return 2
    src = argv[0]
    raw = sys.stdin.read() if src == "-" else open(src, encoding="utf-8").read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"не разобрано как JSON: {exc}", file=sys.stderr)
        return 2
    att = data.get("attestation", data)
    res = verify(att)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))