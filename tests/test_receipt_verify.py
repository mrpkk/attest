"""S2: проверка одной квитанции.

Гейт: каноничность (G5), пересчёт `chain.hash`, канонический base64, отказ
ключам малого порядка и `y ≥ 2^255-19`, литерал `alg` до криптографии.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attest.receipt import jcs, verify


@pytest.fixture()
def keypair():
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes_raw()
    return priv, raw


def make(priv, **over) -> dict:
    receipt = {
        "spec": "noa.receipt/0.1",
        "id": "r-1",
        "ts": "2026-10-26T12:00:00Z",
        "scope": {"chain": "chain-1"},
        "agent": {"id": "agent-1", "principal": "SERVICE"},
        "action": {
            "id": "wire.transfer",
            "canonical": "wire.transfer",
            "riskClass": "HIGH",
            "paramsHash": "sha256:" + "a" * 64,
            "reversible": True,
        },
        "governance": {"mode": "on", "verdict": "EXECUTED", "sandboxed": False},
        "chain": {"seq": 0, "prevHash": None},
        "sig": {"alg": "ed25519", "kid": "k1"},
    }
    receipt.update(over)
    return verify.sign(receipt, priv)


def test_valid_receipt_verifies(unique_keypair=None):
    priv = Ed25519PrivateKey.generate()
    receipt = make(priv)
    raw = jcs.dumps(receipt).encode()
    result = verify.verify_receipt(raw, priv.public_key().public_bytes_raw())
    assert result.ok, result.why()
    assert result.detail["native_signature"] == "verified"
    assert result.detail["envelope"].startswith("absent")


def test_tampered_field_is_detected():
    priv = Ed25519PrivateKey.generate()
    receipt = make(priv)
    receipt["action"]["riskClass"] = "LOW"
    raw = jcs.dumps(receipt).encode()
    result = verify.verify_receipt(raw, priv.public_key().public_bytes_raw())
    assert not result.ok
    assert result.status in ("tampered", "malformed")


def test_chain_hash_substitution_is_detected():
    """Подпись не покрывает chain.hash — без пересчёта подмена проходит."""
    priv = Ed25519PrivateKey.generate()
    receipt = make(priv)
    receipt["chain"]["hash"] = "sha256:" + "b" * 64
    raw = jcs.dumps(receipt).encode()
    result = verify.verify_receipt(raw, priv.public_key().public_bytes_raw())
    assert not result.ok
    assert result.status == "tampered"


def test_non_canonical_bytes_are_rejected():
    """G5: пробелы и другой порядок ключей — другие байты, чем подписаны."""
    priv = Ed25519PrivateKey.generate()
    receipt = make(priv)
    raw = jcs.dumps(receipt)
    spaced = raw.replace(",", ", ")
    result = verify.verify_receipt(spaced.encode(), priv.public_key().public_bytes_raw())
    assert not result.ok
    assert "not canonical" in result.why()


def test_alg_is_checked_before_crypto():
    priv = Ed25519PrivateKey.generate()
    receipt = make(priv)
    receipt["sig"]["alg"] = "EdDSA"
    result = verify.verify_receipt(jcs.dumps(receipt).encode(), priv.public_key().public_bytes_raw())
    assert not result.ok
    assert "sig.alg" in result.why()


def test_non_canonical_base64_is_rejected():
    priv = Ed25519PrivateKey.generate()
    receipt = make(priv)
    receipt["sig"]["value"] = receipt["sig"]["value"].rstrip("=")
    result = verify.verify_receipt(jcs.dumps(receipt).encode(), priv.public_key().public_bytes_raw())
    assert not result.ok
    assert "base64" in result.why()


def test_identity_point_is_rejected_as_key():
    """Кодировка единицы — точка малого порядка: подпись ею «проверяется» везде."""
    ok, why = verify.check_key(b"\x01" + b"\x00" * 31)
    assert not ok
    assert "small-order" in why


@pytest.mark.parametrize("name,raw", [
    ("y=0", b"\x00" * 32),
    ("identity y=1", b"\x01" + b"\x00" * 31),
    ("y=p-1 (order 2)", (verify.P - 1).to_bytes(32, "little")),
])
def test_all_small_order_encodings_are_rejected(name, raw):
    """Проверка считается, а не берётся из таблицы: [8]P == identity.
    Эти три кодировки покрывают порядки 4, 1 и 2; порядок 8 ловится тем же
    вычислением, потому что условие «порядок делит 8» и есть проверяемое."""
    assert verify._decompress(raw) is not None, f"{name}: должна быть точкой"
    assert verify.has_small_order(raw), f"{name}: точка малого порядка"
    ok, why = verify.check_key(raw)
    assert not ok and "small-order" in why


def test_y_not_canonical_is_rejected():
    bad = (2**255 - 19).to_bytes(32, "little")
    ok, why = verify.check_key(bad)
    assert not ok
    assert "canonical field element" in why


def test_real_key_is_accepted():
    priv = Ed25519PrivateKey.generate()
    ok, why = verify.check_key(priv.public_key().public_bytes_raw())
    assert ok, why


def test_wrong_key_fails():
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    receipt = make(priv)
    result = verify.verify_receipt(jcs.dumps(receipt).encode(), other.public_key().public_bytes_raw())
    assert not result.ok
    assert result.status == "tampered"


def test_parsed_object_reports_that_canonicality_was_not_checked():
    priv = Ed25519PrivateKey.generate()
    receipt = make(priv)
    result = verify.verify_receipt(receipt, priv.public_key().public_bytes_raw())
    assert result.ok
    assert result.detail["canonical_checked"] is False


def test_hash_input_excludes_chain_hash_and_signature_value():
    priv = Ed25519PrivateKey.generate()
    receipt = make(priv)
    first = verify.hash_input(receipt)
    receipt["chain"]["hash"] = "sha256:" + "c" * 64
    receipt["sig"]["value"] = base64.b64encode(b"\x00" * 64).decode()
    assert verify.hash_input(receipt) == first
