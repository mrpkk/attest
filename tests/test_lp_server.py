"""Тесты серверной доли Living Proof: nonce, одноразовость, сборка `lp/1`.

Проверяем ровно то, что заявлено в `LP-ROADMAP.md` G3 для серверной части:
код выдаётся на действие, гасится один раз, истёкший не принимается, а
подписанный артефакт сверяется с журналом. Passkey, камера и живость сюда
не входят — они в `limits` артефакта отмечены как непроверяемые.
"""
from __future__ import annotations

import json
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from attest import lp
from attest.lp_server import (
    ChallengeStore,
    action_sha256,
    build_assertion,
    confirm,
    consume,
    issue,
    verify_assertion,
)
from attest.signing import generate_keypair

ACTION = {
    "type": "approve_payment",
    "ref": "inv_1",
    "amount_usd": "250.00",
    "counterparty": "0x0000000000000000000000000000000000000001",
}
SUBJECT = {"did": "did:key:z6Mktest", "label": "account:test"}
FACTORS = [
    {"kind": "A_key_share", "ref": "passkey:1", "server_share_id": "shr_1"},
    {"kind": "B_live_task", "ref": "video:1", "task": "show_code_with_object"},
]


@pytest.fixture()
def key(tmp_path):
    keys = generate_keypair(tmp_path / "lp.key")
    return keys["key_path"], keys["public_key"]


@pytest.fixture()
def store(tmp_path):
    return ChallengeStore(tmp_path / "lp.db")


def test_issue_then_confirm_then_verify(store, key):
    key_path, pinned = key
    challenge = issue(ACTION, SUBJECT, store=store)
    assert len(challenge["nonce"]) == 43
    assert len(challenge["code"]) == 6 and challenge["code"].isdigit()
    assert challenge["action_sha256"] == action_sha256(ACTION)

    out = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                  subject=SUBJECT, factors=FACTORS, store=store, key_path=key_path)
    assert out["ok"] is True
    assert out["artifact"]["verdict"] == "accept"
    assert out["artifact"]["action"]["sha256"] == action_sha256(ACTION)
    assert lp.verify(out["artifact"], pinned) == "ok"
    assert verify_assertion(out["artifact"], pinned, store=store) == "ok"


def test_limits_say_what_is_not_checked(store, key):
    key_path, _ = key
    challenge = issue(ACTION, SUBJECT, store=store)
    out = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                  subject=SUBJECT, factors=FACTORS, store=store, key_path=key_path)
    limits = " ".join(out["artifact"]["limits"])
    assert "single-use" in limits
    assert "liveness is not verified at all" in limits
    assert "video authenticity is not verified at all" in limits


def test_second_consume_is_replay(store, key):
    key_path, _ = key
    challenge = issue(ACTION, SUBJECT, store=store)
    first = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                    subject=SUBJECT, factors=FACTORS, store=store, key_path=key_path)
    assert first["ok"] is True
    assert consume(challenge["nonce"], action_sha256(ACTION), store=store) == "replay"
    second = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                     subject=SUBJECT, factors=FACTORS, store=store, key_path=key_path)
    assert second["ok"] is False
    assert second["verdict"] == "replay"


def test_second_assertion_on_same_nonce_is_replay(store, key):
    key_path, pinned = key
    challenge = issue(ACTION, SUBJECT, store=store)
    out = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                  subject=SUBJECT, factors=FACTORS, store=store, key_path=key_path)
    replay = build_assertion(challenge, ACTION, SUBJECT, FACTORS,
                             assertion_id="lp_other_assertion", key_path=key_path)
    assert lp.verify(replay, pinned) == "ok"
    assert verify_assertion(replay, pinned, store=store) == "replay"
    assert verify_assertion(out["artifact"], pinned, store=store) == "ok"


def test_expired_nonce_is_stale(store, key):
    key_path, _ = key
    now = datetime.now(UTC)
    challenge = issue(ACTION, SUBJECT, ttl_seconds=1, store=store, now=now)
    assert consume(challenge["nonce"], action_sha256(ACTION), store=store,
                   now=now + timedelta(seconds=2)) == "stale"
    out = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                  subject=SUBJECT, factors=FACTORS, store=store,
                  key_path=key_path, now=now + timedelta(seconds=2))
    assert out["ok"] is False
    assert out["verdict"] == "stale"
    assert out["verdict"].reason == "challenge has expired"


def test_ttl_over_the_schema_window_is_refused(store):
    with pytest.raises(ValueError):
        issue(ACTION, SUBJECT, ttl_seconds=121, store=store)


def test_swapped_action_is_policy_failed(store, key):
    key_path, _ = key
    challenge = issue(ACTION, SUBJECT, store=store)
    other = {**ACTION, "amount_usd": "1.00"}
    assert consume(challenge["nonce"], action_sha256(other), store=store) == "policy_failed"
    out = confirm(challenge["nonce"], code=challenge["code"], action=other,
                  subject=SUBJECT, factors=FACTORS, store=store, key_path=key_path)
    assert out["ok"] is False
    assert out["verdict"] == "policy_failed"
    # неверное действие не тратит честный код: настоящий код ещё работает
    good = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                   subject=SUBJECT, factors=FACTORS, store=store, key_path=key_path)
    assert good["ok"] is True


def test_wrong_code_does_not_burn_the_nonce(store, key):
    key_path, _ = key
    challenge = issue(ACTION, SUBJECT, store=store)
    bad = confirm(challenge["nonce"], code="000000" if challenge["code"] != "000000"
                  else "111111", action=ACTION, subject=SUBJECT, factors=FACTORS,
                  store=store, key_path=key_path)
    assert bad["ok"] is False
    assert bad["verdict"] == "policy_failed"
    assert consume(challenge["nonce"], action_sha256(ACTION), store=store) == "ok"


def test_missing_factor_b_is_policy_failed(store, key):
    key_path, pinned = key
    challenge = issue(ACTION, SUBJECT, store=store)
    out = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                  subject=SUBJECT, factors=FACTORS[:1], store=store, key_path=key_path)
    assert out["ok"] is False
    assert out["verdict"] == "policy_failed"

    artifact = build_assertion(challenge, ACTION, SUBJECT, FACTORS, key_path=key_path)
    artifact["factors"] = FACTORS[:1]
    assert verify_assertion(lp.sign(artifact, key_path), pinned, store=store) == "policy_failed"


def test_factor_without_ref_is_policy_failed(store, key):
    key_path, pinned = key
    challenge = issue(ACTION, SUBJECT, store=store)
    no_ref = [dict(FACTORS[0]), {k: v for k, v in FACTORS[1].items() if k != "ref"}]
    out = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                  subject=SUBJECT, factors=no_ref, store=store, key_path=key_path)
    assert out["ok"] is False
    assert out["verdict"] == "policy_failed"

    artifact = build_assertion(challenge, ACTION, SUBJECT, FACTORS, key_path=key_path)
    artifact["factors"] = no_ref
    assert verify_assertion(lp.sign(artifact, key_path), pinned, store=store) == "policy_failed"


def test_foreign_key_is_wrong_key(store, key, tmp_path):
    key_path, _ = key
    other = generate_keypair(tmp_path / "other.key")["public_key"]
    challenge = issue(ACTION, SUBJECT, store=store)
    out = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                  subject=SUBJECT, factors=FACTORS, store=store, key_path=key_path)
    assert verify_assertion(out["artifact"], other, store=store) == "wrong_key"


def test_unknown_nonce_is_refused(store, key):
    key_path, _ = key
    assert consume("n" * 43, action_sha256(ACTION), store=store) == "unknown"
    out = confirm("n" * 43, code="123456", action=ACTION, subject=SUBJECT,
                  factors=FACTORS, store=store, key_path=key_path)
    assert out["ok"] is False
    assert out["verdict"] == "policy_failed"


def test_state_survives_new_store_instance(tmp_path, key):
    key_path, pinned = key
    path = tmp_path / "shared.db"
    issued = ChallengeStore(path).issue(ACTION, SUBJECT)
    other = ChallengeStore(path)
    out = confirm(issued["nonce"], code=issued["code"], action=ACTION,
                  subject=SUBJECT, factors=FACTORS, store=other, key_path=key_path)
    assert out["ok"] is True

    third = ChallengeStore(path)
    assert consume(issued["nonce"], action_sha256(ACTION), store=third) == "replay"
    assert verify_assertion(json.dumps(out["artifact"]), pinned, store=third) == "ok"


def test_verdicts_other_than_accept_are_kept(store, key):
    key_path, pinned = key
    challenge = issue(ACTION, SUBJECT, store=store)
    out = confirm(challenge["nonce"], code=challenge["code"], action=ACTION,
                  subject=SUBJECT, factors=FACTORS, verdict="insufficient",
                  store=store, key_path=key_path)
    assert out["ok"] is True
    assert out["artifact"]["verdict"] == "insufficient"
    assert verify_assertion(out["artifact"], pinned, store=store) == "ok"


def test_db_file_is_owner_only(store):
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_two_concurrent_consumers_do_not_both_win(store):
    challenge = issue(ACTION, SUBJECT, store=store)
    digest = action_sha256(ACTION)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(challenge["nonce"], digest, store=store), range(2)))
    assert sorted(results) == ["ok", "replay"]
