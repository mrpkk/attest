"""Тесты `lp/1`: артефакт и офлайн-проверка.

Проверяем ровно то, что обещает `LP-SPEC.md` §5: подпись, окно challenge,
факторы и пределы. Живость человека и одноразовость nonce сюда не входят —
это сервер, и это записано в `limits`.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from attest.lp import sign, verify
from attest.signing import generate_keypair


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture()
def key(tmp_path):
    keys = generate_keypair(tmp_path / "lp.key")
    return keys["key_path"], keys["public_key"]


def base_artifact(now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    return {
        "v": "lp/1",
        "assertion_id": "lp_test_01",
        "issued_at": iso(now - timedelta(seconds=5)),
        "issuer": {"name": "RTA", "key_id": "rta-lp-test"},
        "subject": {"did": "did:key:z6Mktest", "label": "account:test"},
        "action": {
            "type": "approve_payment", "ref": "inv_1",
            "sha256": "a" * 64, "amount_usd": "250.00",
            "counterparty": "0x0000000000000000000000000000000000000001",
        },
        "challenge": {
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "code": "481902",
            "issued_at": iso(now - timedelta(seconds=10)),
            "expires_at": iso(now + timedelta(seconds=50)),
            "object_required": "coin_with_serial",
        },
        "factors": [
            {"kind": "A_key_share", "ref": "passkey:1", "server_share_id": "shr_1"},
            {"kind": "B_live_task", "ref": "video:1", "task": "show_code_with_object"},
        ],
        "policy": {"required": "A+B", "limit_usd": "250.00",
                   "above_limit": "A+B+C"},
        "verdict": "accept",
        "limits": ["not KYC", "no biometrics stored"],
    }


def signed(key_path: str, now: datetime | None = None) -> dict:
    return sign(base_artifact(now), key_path)


def test_honest_artifact_is_ok(key):
    key_path, pinned = key
    assert verify(signed(key_path), pinned) == "ok"


def test_changed_field_is_tampered(key):
    key_path, pinned = key
    a = signed(key_path)
    a["action"]["ref"] = "inv_2"  # policy не меняется — подпись обязана не сойтись
    assert verify(a, pinned) == "tampered"


def test_other_key_is_wrong_key(key, tmp_path):
    key_path, _ = key
    other = generate_keypair(tmp_path / "other.key")["public_key"]
    assert verify(signed(key_path), other) == "wrong_key"


def test_expired_window_is_stale(key):
    key_path, pinned = key
    now = datetime.now(UTC)
    a = signed(key_path, now)
    assert verify(a, pinned, now=now + timedelta(minutes=5)) == "stale"


def test_window_over_120_seconds_is_stale(key):
    key_path, pinned = key
    now = datetime.now(UTC)
    a = base_artifact(now)
    a["challenge"]["expires_at"] = iso(now + timedelta(seconds=121))
    a["challenge"]["issued_at"] = iso(now)
    a = sign(a, key_path)
    assert verify(a, pinned, now=now) == "stale"


def test_amount_above_limit_without_witness_is_policy_failed(key):
    key_path, pinned = key
    now = datetime.now(UTC)
    a = base_artifact(now)
    a["action"]["amount_usd"] = "500.00"
    a = sign(a, key_path)
    assert verify(a, pinned, now=now) == "policy_failed"


def test_witness_above_limit_is_ok(key):
    key_path, pinned = key
    now = datetime.now(UTC)
    a = base_artifact(now)
    a["action"]["amount_usd"] = "500.00"
    a["factors"].append({"kind": "C_witness", "ref": "witness:1"})
    a = sign(a, key_path)
    assert verify(a, pinned, now=now) == "ok"


def test_unsigned_is_unsigned(key):
    key_path, pinned = key
    a = signed(key_path)
    a.pop("signature")
    assert verify(a, pinned) == "unsigned"


def test_missing_limits_is_malformed(key):
    key_path, pinned = key
    a = signed(key_path)
    a["limits"] = []
    assert verify(a, pinned) == "malformed"


def test_accepted_factor_without_ref_is_policy_failed(key):
    key_path, pinned = key
    now = datetime.now(UTC)
    a = base_artifact(now)
    a["factors"][0].pop("ref")
    a = sign(a, key_path)
    assert verify(a, pinned, now=now) == "policy_failed"


def test_json_string_and_dict_agree(key):
    key_path, pinned = key
    a = signed(key_path)
    assert verify(json.dumps(a), pinned) == "ok"
    assert verify(a, pinned) == "ok"


def test_bad_nonce_is_malformed(key):
    key_path, pinned = key
    a = signed(key_path)
    a["challenge"]["nonce"] = "short"
    a["signature"] = "base64:AAAA"
    assert verify(a, pinned) == "malformed"
