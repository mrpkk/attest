"""S4: привязка личности.

Гейт: манифест сверяется с НАТИВНОЙ подписью (G21), релей разрешён,
подмена отклоняется, UNTRUSTED отдельно от TAMPERED (G13), отсутствие
манифеста озвучивается (G14), точка привязана к открывающему цепь (G16).
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attest.receipt import chain, identity, jcs, verify

HASH_A = "sha256:" + "a" * 64


def receipt(agent: str, kid: str, priv, seq: int = 0, prev: str | None = None) -> dict:
    body = {
        "spec": "noa.receipt/0.1",
        "id": f"r-{seq}",
        "ts": "2026-10-26T12:00:00Z",
        "scope": {"chain": "chain-1"},
        "agent": {"id": agent, "principal": "SERVICE"},
        "action": {"id": "a", "canonical": "a", "riskClass": "HIGH",
                   "paramsHash": HASH_A, "reversible": True},
        "governance": {"mode": "on", "verdict": "EXECUTED", "sandboxed": False},
        "chain": {"seq": seq, "prevHash": prev},
        "sig": {"alg": "ed25519", "kid": kid},
    }
    return verify.sign(body, priv)


@pytest.fixture()
def world():
    alice = Ed25519PrivateKey.generate()
    relay = Ed25519PrivateKey.generate()
    thief = Ed25519PrivateKey.generate()
    keyring = {
        "alice": alice.public_key().public_bytes_raw(),
        "relay": relay.public_key().public_bytes_raw(),
        "thief": thief.public_key().public_bytes_raw(),
    }
    manifest = {"alice": ["alice"]}
    return alice, relay, thief, keyring, manifest


def test_authorized_agent_passes(world):
    alice, _, _, keyring, manifest = world
    r = receipt("alice", "alice", alice)
    result = verify.verify_receipt(jcs.dumps(r).encode(), keyring["alice"], manifest=manifest)
    assert result.ok, result.why()
    assert result.detail["attribution"]["status"] == "authorized"


def test_no_manifest_says_attribution_is_key_level_only(world):
    """G14: без манифеста нельзя утверждать, ЧТО ЭТО ЗА АГЕНТ."""
    alice, _, _, keyring, _ = world
    r = receipt("alice", "alice", alice)
    result = verify.verify_receipt(jcs.dumps(r).encode(), keyring["alice"])
    assert result.ok
    assert result.detail["attribution"]["status"] == "key-level-only"
    assert "not an identity claim" in result.why() or any(
        "not an identity claim" in n for n in result.detail["attribution"]["notes"])


def test_unauthorized_key_is_untrusted_not_tampered(world):
    """G13: байты целы, подпись верна — не тот ключ. Это отдельный вердикт."""
    alice, _, thief, keyring, manifest = world
    r = receipt("alice", "thief", thief)
    result = verify.verify_receipt(jcs.dumps(r).encode(), keyring["thief"], manifest=manifest)
    assert not result.ok
    assert result.status == "untrusted"
    assert "not authorized" in result.why()


def test_relay_is_allowed(world):
    """Законная передача: внутри подпись alice, конверт — релея."""
    alice, _, _, keyring, manifest = world
    r = receipt("alice", "alice", alice)
    result = verify.verify_receipt(jcs.dumps(r).encode(), keyring["alice"],
                                   manifest=manifest, envelope_kid="relay")
    assert result.ok, "релей нельзя отвергать только из-за внешней подписи"
    assert result.detail["attribution"]["status"] == "authorized"
    assert "relayed" in " ".join(result.detail["attribution"]["notes"])


def test_laundering_is_rejected(world):
    """G21: конверт подписан авторизованным ключом, запись внутри — чужим."""
    alice, _, thief, keyring, manifest = world
    r = receipt("alice", "thief", thief)
    result = verify.verify_receipt(jcs.dumps(r).encode(), keyring["thief"],
                                   manifest=manifest, envelope_kid="alice")
    assert not result.ok
    assert result.status == "untrusted"


def test_agent_not_in_manifest_is_unauthorized(world):
    alice, _, _, keyring, manifest = world
    r = receipt("bob", "alice", alice)
    result = verify.verify_receipt(jcs.dumps(r).encode(), keyring["alice"], manifest=manifest)
    assert not result.ok
    assert result.status == "untrusted"


def test_manifest_loader_rejects_unknown_spec():
    with pytest.raises(ValueError):
        identity.load_manifest({"spec": "other/0.1", "agents": {}})
    with pytest.raises(ValueError):
        identity.load_manifest({"spec": "noa.identity-manifest/0.1", "agents": {"a": "k1"}})


def test_manifest_loader_accepts_valid_document():
    m = identity.load_manifest({"spec": "noa.identity-manifest/0.1",
                                "agents": {"alice": ["k1", "k2"]}})
    assert m == {"alice": ["k1", "k2"]}


def test_checkpoint_key_must_belong_to_the_opener(world):
    """G16: доверенный ключ ещё не право говорить за эту цепь."""
    alice, relay, _, keyring, manifest = world
    keyring["relay"] = keyring["relay"]
    r0 = receipt("alice", "alice", alice, 0, None)
    cp = chain.sign_checkpoint({
        "spec": "noa.checkpoint/0.1", "chain": "chain-1",
        "highestSeq": 0, "headHash": r0["chain"]["hash"],
        "ts": "2026-10-26T12:00:00Z", "sig": {"alg": "ed25519", "kid": "relay"},
    }, relay)
    result = chain.verify_chain([r0], keyring, checkpoint=cp, manifest=manifest)
    assert result.checkpoint["state"] == "unusable"
    assert "UNTRUSTED" in result.checkpoint["reason"]
