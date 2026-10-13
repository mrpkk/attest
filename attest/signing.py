#!/usr/bin/env python3
"""Подпись, проверяемая без доверия к нам.

HMAC требует секрета, а секрет есть только у нас. Значит проверить подпись
может только сервис, и любой, кто не поверил сервису, обязан ему поверить
сначала. Для продукта про доверие это противоречие в самой основе.

Здесь Ed25519: приватный ключ подписывает, публичный едет в ответе.
Проверяющий сверяет подпись публичным ключом из самого заверяния —
секрет не нужен, сеть не нужна, наше участие не нужно.

Ключевая пара генерируется один раз и хранится локально. Если приватного
ключа нет, подпись не выполняется вовсе: лучше явный отказ, чем подпись
зашитым в исходник ключом, который знает кто угодно.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALGORITHM = "ed25519"

# Приватный ключ живёт рядом с базой, не в репозитории и не в .env:
# .env переносится между машинами, а ключ — нет.
KEY_PATH = Path(os.environ.get(
    "ATTEST_SIGNING_KEY",
    Path.home() / ".local" / "share" / "attest" / "signing.key",
))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        return Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Ed25519 недоступен: нужен пакет cryptography. "
            "Установка: pip install cryptography") from exc


def generate_keypair(path: Path | None = None) -> dict[str, str]:
    """Создать пару ключей. Приватный — файл с правами 600."""
    from cryptography.hazmat.primitives import serialization
    p = Path(path or KEY_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    priv = _ed25519().generate()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p.write_bytes(raw_priv)
    p.chmod(0o600)
    # public_key() отдаёт сырые байта; в наружу — base64, как и подпись.
    return {"public_key": _b64(public_key()), "key_path": str(p)}


def load_private_key(path: Path | None = None) -> bytes:
    """Приватный ключ. Отказ, если его нет, — а не запасной вариант.

    Запасной ключ, зашитый в исходник, хуже отсутствия подписи: он даёт
    видимость защиты, которой нет. Читатель кода увидит подпись, подписанную
    ключом, который опубликован рядом с ним.
    """
    p = Path(path or KEY_PATH)
    if not p.exists():
        raise FileNotFoundError(
            f"Приватного ключа нет: {p}. Создать: python3 -m attest keygen")
    return p.read_bytes()


def public_key(path: Path | None = None) -> bytes:
    """Публичный ключ в base64 — едет в каждом заверянии."""
    from cryptography.hazmat.primitives import serialization
    p = Path(path or KEY_PATH)
    if not p.exists():
        raise FileNotFoundError(
            f"Приватного ключа нет: {p}. Создать: python3 -m attest keygen")
    priv = _ed25519().from_private_bytes(p.read_bytes())
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@dataclass(frozen=True)
class SignatureResult:
    signature: str          # base64
    public_key: str         # base64
    algorithm: str

    def as_dict(self) -> dict[str, str]:
        return {"signature": self.signature, "public_key": self.public_key,
                "algorithm": self.algorithm}


def sign(payload: bytes, path: Path | None = None) -> SignatureResult:
    """Подписать. Публичный ключ прикладывается к подписи.

    Это и делает проверку независимой: ключ для сверки лежит рядом с
    подписью, а не выдаётся по запросу и не держится в секрете.
    """
    priv = _ed25519().from_private_bytes(load_private_key(path))
    sig = priv.sign(payload)
    return SignatureResult(
        signature=_b64(sig),
        public_key=_b64(public_key(path)),
        algorithm=ALGORITHM,
    )


def verify(payload: bytes, signature: str, public: str) -> bool:
    """Проверить подпись публичным ключом. Секретов не требует.

    Единственное, чему эта функция доверяет, — криптографии Ed25519.
    Ни сервису, ни сети, ни файлу с секретом.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(public)).verify(
            _unb64(signature), payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_key_b64(path: Path | None = None) -> str:
    """Публичный ключ в том же виде, в каком его кладёт `sign()`.

    `public_key()` отдаёт сырые байты, а `verify()` ждёт base64. Две формы
    одного ключа — источник ошибок вида «подпись не сходится» при полностью
    исправном ключе, поэтому для проверки пользоваться только этой.
    """
    import base64
    return base64.b64encode(public_key(path)).decode("ascii")


def key_fingerprint() -> str:
    """Короткий отпечаток ключа — чтобы показывать, каким ключом подписано."""
    import hashlib
    return hashlib.sha256(public_key()).hexdigest()[:16]


def self_test() -> dict[str, Any]:
    """Проверка, что ключ на месте и подпись проходит.

    Без этого нельзя честно утверждать, что заверяние вообще работает:
    сервис может годами отдавать HTTP 200 с подписью, которую никто не
    способен проверить.
    """
    from .provenance import canonical, new_record
    rec = new_record(source="selftest", artifact={"a": 1}, verdict="accept",
                     trust_score=1.0)
    payload = canonical(rec.as_dict())
    s = sign(payload)
    ok = verify(payload, s.signature, s.public_key)
    tampered = verify(payload + b" ", s.signature, s.public_key)
    return {"signs": True, "verifies": ok, "rejects_tampered": not tampered,
            "fingerprint": key_fingerprint(), "algorithm": ALGORITHM}
