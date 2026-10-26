"""S3: шесть условий цепи и контрольная точка.

Гейт: все условия сообщаются сразу (G9); неаутентифицированная точка не
обвиняет цепь (G6); законное расширение не считается конфликтом (G7);
неоднозначный kid сообщается (G11).
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attest.receipt import chain, jcs, verify

HASH_A = "sha256:" + "a" * 64


def receipt(seq: int, prev: str | None, priv, *, kid="k1", agent="agent-1",
            chain_id="chain-1", tenant=None, marker="") -> dict:
    scope = {"chain": chain_id}
    if tenant:
        scope["tenant"] = tenant
    body = {
        "spec": "noa.receipt/0.1",
        "id": f"r-{seq}{marker}",
        "ts": "2026-10-26T12:00:00Z",
        "scope": scope,
        "agent": {"id": agent, "principal": "SERVICE"},
        "action": {"id": "a", "canonical": "a", "riskClass": "HIGH",
                   "paramsHash": HASH_A, "reversible": True},
        "governance": {"mode": "on", "verdict": "EXECUTED", "sandboxed": False},
        "chain": {"seq": seq, "prevHash": prev},
        "sig": {"alg": "ed25519", "kid": kid},
    }
    return verify.sign(body, priv)


def chain_of(priv, n=3, **kw):
    out, prev = [], None
    for i in range(n):
        r = receipt(i, prev, priv, **kw)
        out.append(r)
        prev = r["chain"]["hash"]
    return out


@pytest.fixture()
def keys():
    priv = Ed25519PrivateKey.generate()
    return priv, {"k1": priv.public_key().public_bytes_raw()}


def test_valid_chain_passes_with_no_conditions(keys):
    priv, keyring = keys
    result = chain.verify_chain(chain_of(priv), keyring)
    assert result.ok, result.why()
    assert result.conditions == []
    assert result.checkpoint["state"] == "unanswered"


def test_unanswered_tail_is_reported_as_unanswered_not_clean(keys):
    priv, keyring = keys
    result = chain.verify_chain(chain_of(priv), keyring)
    assert result.checkpoint["state"] == "unanswered"
    assert "not clean" in result.checkpoint["reason"]


def test_broken_link(keys):
    priv, keyring = keys
    items = chain_of(priv)
    items[1]["chain"]["prevHash"] = HASH_A
    result = chain.verify_chain(items, keyring)
    assert "chain-link-broken" in result.conditions


def test_genesis_must_not_carry_prev_hash(keys):
    priv, keyring = keys
    items = chain_of(priv)
    items[0]["chain"]["prevHash"] = HASH_A
    assert "chain-link-broken" in chain.verify_chain(items, keyring).conditions


def test_duplicate_sequence(keys):
    priv, keyring = keys
    items = chain_of(priv)
    items[2]["chain"]["seq"] = 1
    result = chain.verify_chain(items, keyring)
    assert "chain-sequence-duplicate" in result.conditions


def test_gap_and_missing_genesis(keys):
    priv, keyring = keys
    items = chain_of(priv)
    result = chain.verify_chain(items[1:], keyring)
    assert "chain-sequence-gap" in result.conditions


def test_scope_mismatch(keys):
    priv, keyring = keys
    items = chain_of(priv)
    items[1]["scope"]["chain"] = "another-chain"
    assert "chain-scope-mismatch" in chain.verify_chain(items, keyring).conditions


def test_tenant_split(keys):
    priv, keyring = keys
    items = chain_of(priv, tenant="t1")
    items[2]["scope"]["tenant"] = "t2"
    assert "chain-tenant-split" in chain.verify_chain(items, keyring).conditions


def test_absent_tenant_does_not_reset_the_comparison(keys):
    """A -> отсутствует -> B это та же склейка, что A -> B."""
    priv, keyring = keys
    items = chain_of(priv, tenant="t1")
    items[1]["scope"].pop("tenant")
    items[2]["scope"]["tenant"] = "t2"
    assert "chain-tenant-split" in chain.verify_chain(items, keyring).conditions


def test_key_discontinuity(keys):
    priv, keyring = keys
    other = Ed25519PrivateKey.generate()
    keyring["k2"] = other.public_key().public_bytes_raw()
    items = chain_of(priv, n=2)
    items.append(receipt(2, items[-1]["chain"]["hash"], other, kid="k2"))
    result = chain.verify_chain(items, keyring)
    assert "chain-key-discontinuity" in result.conditions


def test_all_conditions_reported_at_once(keys):
    """G9: эталон возвращает первое найденное условие. Здесь — все."""
    priv, keyring = keys
    items = chain_of(priv, n=3)
    items[1]["chain"]["prevHash"] = HASH_A
    items[2]["chain"]["seq"] = 0
    result = chain.verify_chain(items, keyring)
    assert len(result.conditions) >= 2
    assert "chain-link-broken" in result.conditions
    assert "chain-sequence-duplicate" in result.conditions


def test_attacker_checkpoint_does_not_accuse_the_chain(keys):
    """G6: чужая точка даёт checkpoint-unverified, цепь остаётся чистой."""
    priv, keyring = keys
    attacker = Ed25519PrivateKey.generate()
    items = chain_of(priv)
    cp = chain.sign_checkpoint({
        "spec": "noa.checkpoint/0.1", "chain": "chain-1",
        "highestSeq": 2, "headHash": items[-1]["chain"]["hash"],
        "ts": "2026-10-26T12:00:00Z", "sig": {"alg": "ed25519", "kid": "k1"},
    }, attacker)
    result = chain.verify_chain(items, keyring, checkpoint=cp)
    assert result.ok, "проверенная цепь не должна страдать от чужой точки"
    assert result.conditions == []
    assert result.checkpoint["state"] == "unusable"
    assert "checkpoint-unverified" in result.checkpoint["reason"]


def test_checkpoint_for_another_chain_is_a_finding_about_the_checkpoint(keys):
    priv, keyring = keys
    items = chain_of(priv)
    cp = chain.sign_checkpoint({
        "spec": "noa.checkpoint/0.1", "chain": "other-chain",
        "highestSeq": 2, "headHash": items[-1]["chain"]["hash"],
        "ts": "2026-10-26T12:00:00Z", "sig": {"alg": "ed25519", "kid": "k1"},
    }, priv)
    result = chain.verify_chain(items, keyring, checkpoint=cp)
    assert result.ok
    assert result.checkpoint["state"] == "unusable"
    assert "another chain" in result.checkpoint["reason"]


def test_checkpoint_consistent(keys):
    priv, keyring = keys
    items = chain_of(priv)
    cp = chain.sign_checkpoint({
        "spec": "noa.checkpoint/0.1", "chain": "chain-1",
        "highestSeq": 2, "headHash": items[-1]["chain"]["hash"],
        "ts": "2026-10-26T12:00:00Z", "sig": {"alg": "ed25519", "kid": "k1"},
    }, priv)
    result = chain.verify_chain(items, keyring, checkpoint=cp)
    assert result.checkpoint["state"] == "answered"
    assert result.checkpoint["result"] == "consistent"


def test_old_checkpoint_over_a_longer_chain_is_not_a_conflict(keys):
    """G7: цепь выросла после выдачи точки — это расширение, а не подделка."""
    priv, keyring = keys
    items = chain_of(priv, n=4)
    cp = chain.sign_checkpoint({
        "spec": "noa.checkpoint/0.1", "chain": "chain-1",
        "highestSeq": 1, "headHash": items[1]["chain"]["hash"],
        "ts": "2026-10-26T12:00:00Z", "sig": {"alg": "ed25519", "kid": "k1"},
    }, priv)
    result = chain.verify_chain(items, keyring, checkpoint=cp)
    assert result.checkpoint["state"] == "answered"
    assert result.checkpoint["result"] == "consistent"
    assert "extends" in result.checkpoint["reason"]


def test_conflicting_checkpoint_is_reported_without_naming_a_cause(keys):
    priv, keyring = keys
    items = chain_of(priv, n=3)
    cp = chain.sign_checkpoint({
        "spec": "noa.checkpoint/0.1", "chain": "chain-1",
        "highestSeq": 2, "headHash": HASH_A,
        "ts": "2026-10-26T12:00:00Z", "sig": {"alg": "ed25519", "kid": "k1"},
    }, priv)
    result = chain.verify_chain(items, keyring, checkpoint=cp)
    assert result.checkpoint["result"] == "checkpoint-head-conflict"
    assert "cause is not established" in result.checkpoint["reason"]


def test_ambiguous_kid_is_reported(keys):
    priv, keyring = keys
    twin = Ed25519PrivateKey.generate()
    keyring["k1"] = [priv.public_key().public_bytes_raw(), twin.public_key().public_bytes_raw()]
    result = chain.verify_chain(chain_of(priv), keyring)
    # Профиль: kid, за которым больше одного ключа, обязан быть назван
    # неоднозначным, даже если ровно один ключ проверяет подпись.
    assert result.detail["ambiguous_kids"], "неоднозначный kid должен быть назван"
    assert all(r.get("kid_ambiguous") for r in result.per_receipt)


def test_unknown_key_does_not_accuse_the_chain(keys):
    priv, keyring = keys
    items = chain_of(priv, n=2)
    items.append(receipt(2, items[-1]["chain"]["hash"], priv, kid="k-unknown"))
    result = chain.verify_chain(items, keyring)
    assert "untrusted" in {r["status"] for r in result.per_receipt}
