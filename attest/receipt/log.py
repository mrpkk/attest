"""Служба прозрачности: дерево Меркла, доказательства, подписанная голова.

Профиль: RFC 9943 §5.1.3 (журнал неизменяем: записи нельзя изменить, удалить
или переупорядочить) + RFC 6962 (структура дерева и доказательств).

Зачем это вообще: самоподписанная цепь доказывает, что запись не менялась
**после** того, как её показали. Она не доказывает, что подписант не показал
другую цепь другому. Это называется эквивокацией, и единственный способ её
увидеть — третья сторона, которая публикует корень дерева.

Что здесь честно ограничено: доказательство включения подтверждает членство
в **той версии дерева, которую показали**. Отсутствие эквивокации требует
согласованных доказательств между состояниями и того, кто их мониторит; журнал
даёт первое, но не заменяет второго.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_hash(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_power_of_two_below(len(leaves))
    return node_hash(root_hash(leaves[:k]), root_hash(leaves[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    if not 0 <= index < len(leaves):
        raise ValueError("index outside the tree")
    if len(leaves) == 1:
        return []
    k = _largest_power_of_two_below(len(leaves))
    if index < k:
        return inclusion_proof(leaves[:k], index) + [root_hash(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [root_hash(leaves[:k])]


def consistency_proof(leaves: list[bytes], old_size: int) -> list[bytes]:
    if not 0 < old_size <= len(leaves):
        raise ValueError("old_size must be within the tree")
    if old_size == len(leaves):
        return []
    return _subproof(old_size, leaves, True)


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [root_hash(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [root_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root_hash(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 6962 §2.1.1: поднимаемся от листа к корню, склеивая с соседом."""
    if index < 0 or index >= size or size <= 0:
        return False
    fn, sn = index, size - 1
    node = leaf
    for sibling in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            node = node_hash(sibling, node)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            node = node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and node == root


def verify_consistency(old_size: int, new_size: int, proof: list[bytes],
                       old_root: bytes, new_root: bytes) -> bool:
    """RFC 6962 §2.1.2: старое дерево является префиксом нового."""
    if old_size > new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return True
    if not proof:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        fr = old_root
        rest = proof
    else:
        fr = proof[0]
        rest = proof[1:]
    sr = fr
    for sibling in rest:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(sibling, fr)
            sr = node_hash(sibling, sr)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, sibling)
        fn >>= 1
        sn >>= 1
    return fn == 0 and fr == old_root and sr == new_root


@dataclass
class TreeHead:
    size: int
    root: str          # hex
    timestamp: int
    signature: str = ""

    def body(self) -> bytes:
        return jcs.dumps({"size": self.size, "root": self.root, "ts": self.timestamp}).encode()

    def sign(self, private_key) -> "TreeHead":
        import base64
        self.signature = base64.b64encode(private_key.sign(b"NOA-STH-v0.1:" + self.body())).decode()
        return self

    def verify(self, public_key: bytes) -> bool:
        import base64
        if not self.signature:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                base64.b64decode(self.signature), b"NOA-STH-v0.1:" + self.body()
            )
            return True
        except (InvalidSignature, ValueError):
            return False


@dataclass
class TransparencyLog:
    """Журнал на диске: одна строка — один лист (hex). Без базы и без сервера."""

    path: Path
    leaves: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.path.exists():
            self.leaves = [bytes.fromhex(line) for line in
                           self.path.read_text().splitlines() if line.strip()]

    def append(self, statement: bytes) -> int:
        digest = leaf_hash(statement)
        self.leaves.append(digest)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(digest.hex() + "\n")
        return len(self.leaves) - 1

    def head(self, private_key=None) -> TreeHead:
        head = TreeHead(len(self.leaves), root_hash(self.leaves).hex(), int(time.time()))
        if private_key is not None:
            head.sign(private_key)
        return head

    def inclusion(self, index: int) -> dict[str, Any]:
        return {
            "index": index,
            "leaf": self.leaves[index].hex(),
            "proof": [h.hex() for h in inclusion_proof(self.leaves, index)],
            "head": self.head().__dict__,
        }

    def consistency(self, old_size: int) -> dict[str, Any]:
        old_root = root_hash(self.leaves[:old_size]).hex()
        return {
            "old_size": old_size,
            "old_root": old_root,
            "proof": [h.hex() for h in consistency_proof(self.leaves, old_size)],
            "head": self.head().__dict__,
        }
