"""Root Verdict v1: honest, tampered, wrong key, expired, revoked."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

from attest import signing
from attest.vajra import sign_verdict, verify_verdict


def _verdict(expires: str | None = None) -> dict:
    future = expires or (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    return {
        "schema": "vajra/root-verdict/1",
        "id": "blake3:test-verdict",
        "subject": {"type": "repository", "uri": "github.com/org/repo", "commit": "abc"},
        "scope": {"profile": "repo", "checks": ["sast", "sca"], "excluded": ["runtime"]},
        "claims": [{"id": "C-1", "text": "lockfile pinned", "status": "SUPPORTED", "evidence": ["ev:1"]}],
        "findings": [],
        "verdict": "SUPPORTED",
        "limits": ["runtime not tested", "no penetration test"],
        "rules_version": "0.1.0",
        "hash_alg": "sha256",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": future,
        "revocation_url": "https://vajra.dev/revocations/test",
    }


def _signed(tmp_path):
    key = tmp_path / "signing.key"
    info = signing.generate_keypair(key)
    return sign_verdict(_verdict(), key), info["public_key"]


def test_honest_verdict_verifies(tmp_path):
    signed, public = _signed(tmp_path)
    result = verify_verdict(signed, public)
    assert result["ok"] is True, result
    assert result["reason"] == "ok"
    assert result["verdict"] == "SUPPORTED"


def test_unsupported_is_authentic_not_tampered(tmp_path):
    key = tmp_path / "signing.key"
    info = signing.generate_keypair(key)
    v = _verdict()
    v["verdict"] = "UNSUPPORTED"
    signed = sign_verdict(v, key)
    result = verify_verdict(signed, info["public_key"])
    assert result["ok"] is True, result
    assert result["verdict"] == "UNSUPPORTED"


def test_tampered_claim_is_rejected(tmp_path):
    signed, public = _signed(tmp_path)
    bad = copy.deepcopy(signed)
    bad["claims"][0]["text"] = "lockfile missing"
    result = verify_verdict(bad, public)
    assert result["ok"] is False
    assert result["reason"] == "tampered"


def test_wrong_key_is_rejected(tmp_path):
    signed, _ = _signed(tmp_path)
    other = tmp_path / "other.key"
    info = signing.generate_keypair(other)
    result = verify_verdict(signed, info["public_key"])
    assert result["ok"] is False
    assert result["reason"] == "wrong_key"


def test_expired_is_rejected(tmp_path):
    signed, public = _signed(tmp_path)
    bad = copy.deepcopy(signed)
    bad["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    # signing must be recomputed because expires_at is signed
    bad = sign_verdict(bad, tmp_path / "signing.key")
    result = verify_verdict(bad, public)
    assert result["ok"] is False
    assert result["reason"] == "expired"


def test_revoked_is_rejected(tmp_path):
    signed, public = _signed(tmp_path)
    bad = copy.deepcopy(signed)
    bad["revoked"] = True
    bad = sign_verdict(bad, tmp_path / "signing.key")
    result = verify_verdict(bad, public)
    assert result["ok"] is False
    assert result["reason"] == "revoked"


def test_external_key_is_required(tmp_path):
    signed, _ = _signed(tmp_path)
    result = verify_verdict(signed, None)
    assert result["ok"] is False
    assert "external_key_required" in result["errors"]
