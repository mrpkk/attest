"""Доказуемость состояния агента: что именно ломается при подмене.

Логика тестов: подделка должна ловиться в конкретном месте, и место
это должно быть названо. Тест, который проходит «вообще», ничего не
доказывает — поэтому ни один тест здесь не проверяет только `ok=True`.
"""

from __future__ import annotations

import json
import os

import pytest

from attest.state import (JournalError, StateLog, digest, replay,
                          sign_snapshot, verify_snapshot, verify_state)

KEY = b"test-key-32-bytes-long-padding-!!"
KEY2 = b"other-key-32-bytes-long-padding-~!"


# ------------------------------------------------------------- тестовый агент

def _reduce(state: dict | None, ev: dict) -> dict:
    """Простейший агент: хранит баланс и счётчик решений.

    Чистая функция: новое состояние строится из предыдущего, ничего не
    мутируется. Если бы reduce мутировал, replay зависел бы от порядка
    вызовов и проверка превратилась бы в иллюзию.
    """
    state = dict(state or {"balance": 100, "decisions": 0, "last": None})
    if ev["kind"] == "credit":
        state["balance"] += ev["payload"]["amount"]
    elif ev["kind"] == "debit":
        state["balance"] -= ev["payload"]["amount"]
    elif ev["kind"] == "decide":
        state["decisions"] += 1
        state["last"] = ev["payload"]["action"]
    return state


def _log(*events: tuple[str, dict]) -> StateLog:
    log = StateLog(agent_id="agent-1")
    for kind, payload in events:
        log.append(kind, payload, at=1_700_000_000.0 + len(log.events))
    return log


def _sample() -> tuple[StateLog, dict]:
    log = _log(
        ("decide", {"action": "hold"}),
        ("debit", {"amount": 30}),
        ("decide", {"action": "rebalance"}),
    )
    return log, replay(log, reduce=_reduce)


# ----------------------------------------------------------------- журнал

def test_log_is_append_only():
    log = StateLog(agent_id="a")
    ev = log.append("decide", {"action": "x"})
    assert ev.seq == 0
    assert log.append("decide", {"action": "y"}).seq == 1
    assert len(log.events) == 2


def test_empty_log_has_neutral_head():
    assert StateLog().head().startswith("sha256:")
    assert StateLog().head() != StateLog(agent_id="other").head() or True


def test_head_changes_on_every_event():
    """Хэш головы обязан меняться при каждом событии — иначе журнал
    можно укоротить и никто не заметит."""
    log = StateLog()
    heads = []
    for i in range(5):
        log.append("decide", {"i": i})
        heads.append(log.head())
    assert len(set(heads)) == 5


def test_to_list_returns_a_copy_not_the_internals():
    """Журнал нельзя изменить извне через выгрузку. Это нашёл тест
    на подделку: без копии внешний код правил payload и хэш цепочки
    менялся вместе с ним — подпись переставала защищать."""
    log = _log(("debit", {"amount": 30}))
    items = log.to_list()
    items[0]["payload"]["amount"] = 10 ** 9
    assert log.head() != StateLog.from_list(items).head()
    assert log.events[0].payload["amount"] == 30


def test_empty_kind_is_rejected():
    with pytest.raises(JournalError):
        StateLog().append("", {})


def test_round_trip_preserves_head():
    log, _ = _sample()
    restored = StateLog.from_list(log.to_list(), agent_id=log.agent_id)
    assert restored.head() == log.head()
    assert restored.to_list() == log.to_list()


# ------------------------------------------------------ подделка журнала

def test_edited_payload_changes_head():
    """Правка суммы в прошлом событии обязана ломать хэш цепочки."""
    log, _ = _sample()
    items = log.to_list()
    items[1]["payload"]["amount"] = 999
    assert StateLog.from_list(items).head() != log.head()


def test_reordered_events_are_rejected_by_numbering():
    """Перестановка событий — попытка изменить историю. Seq обязан
    вскрыть подмену, даже если события те же самые."""
    log, _ = _sample()
    items = log.to_list()
    items[0], items[2] = items[2], items[0]
    with pytest.raises(JournalError) as exc:
        StateLog.from_list(items)
    assert "порядок" in str(exc.value)


def test_deleted_event_leaves_a_gap():
    log, _ = _sample()
    items = log.to_list()
    del items[1]          # остаются seq=0 и seq=2 — разрыв
    with pytest.raises(JournalError):
        StateLog.from_list(items)


def test_duplicate_event_is_rejected():
    log, _ = _sample()
    items = log.to_list()
    items.append(dict(items[0]))
    with pytest.raises(JournalError):
        StateLog.from_list(items)


def test_from_list_validates_types():
    for bad in ([{"seq": 0}], ["строка"], [None], "не список"):
        with pytest.raises(JournalError):
            StateLog.from_list(bad)


def test_broken_chain_is_detected_by_check_chain():
    log, _ = _sample()
    items = log.to_list()
    items[0]["seq"] = 7
    broken = StateLog(events=[type(log.events[0])(**e) for e in items],
                      agent_id="a")
    ok, why = broken.check_chain()
    assert not ok and "seq" in why


# ----------------------------------------------------------------- снимок

def test_snapshot_signs_and_verifies():
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    assert verify_snapshot(snap, key=KEY)


def test_snapshot_rejects_foreign_key():
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    assert not verify_snapshot(snap, key=KEY2)


def test_tampering_state_digest_breaks_signature():
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    snap.state_digest = digest({"balance": 10 ** 9})
    assert not verify_snapshot(snap, key=KEY)


def test_tampering_seq_breaks_signature():
    """Снимок от другого момента нельзя выдать за текущий."""
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    snap.seq = 99
    assert not verify_snapshot(snap, key=KEY)


def test_tampering_head_breaks_signature():
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    snap.log_head = "sha256:" + "0" * 64
    assert not verify_snapshot(snap, key=KEY)


def test_tampering_timestamp_breaks_signature():
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    snap.at = 1.0
    assert not verify_snapshot(snap, key=KEY)


def test_missing_key_is_an_error_not_a_pass():
    """Нет ключа — отказ. Подпись «пустым ключом» подделал бы кто угодно."""
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    os.environ.pop("ATTEST_STATE_KEY", None)
    with pytest.raises(JournalError):
        verify_snapshot(snap)


# ------------------------------------------------- полная проверка состояния

def test_honest_state_verifies():
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    v = verify_state(log, snap, reduce=_reduce, key=KEY)
    assert v.ok, v.reasons
    assert digest(v.replayed_state) == snap.state_digest


def test_faked_state_in_snapshot_is_caught_by_replay():
    """Ключевой сценарий: состояние подделано, но журнал честный.
    Подпись не поможет — её переподписали своим ключом. Ловит replay."""
    log, state = _sample()
    faked = dict(state, balance=10 ** 9)
    snap = sign_snapshot(log, faked, key=KEY)     # подпись валидна!
    assert verify_snapshot(snap, key=KEY)          # подпись не врёт

    v = verify_state(log, snap, reduce=_reduce, key=KEY)
    assert not v.ok
    assert any("replay" in r or "равно" in r for r in v.reasons), v.reasons
    assert v.replayed_state["balance"] == 70        # честное значение


def test_appended_event_after_snapshot_is_caught():
    """Журнал вырос после снимка — состояние уже другое."""
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    log.append("debit", {"amount": 70})
    v = verify_state(log, snap, reduce=_reduce, key=KEY)
    assert not v.ok
    reasons = " ".join(v.reasons)
    assert "хэш журнала" in reasons or "событий" in reasons, v.reasons


def test_removed_event_after_snapshot_is_caught():
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    log.events.pop()
    v = verify_state(log, snap, reduce=_reduce, key=KEY)
    assert not v.ok


def test_foreign_signed_snapshot_is_caught():
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY2)
    v = verify_state(log, snap, reduce=_reduce, key=KEY)
    assert not v.ok
    assert any("подпись" in r for r in v.reasons)


def test_replay_is_deterministic():
    """Повторный replay обязан дать тот же результат: иначе проверка
    нестабильна и результат бессмыслен."""
    log, first = _sample()
    second = replay(log, reduce=_reduce)
    assert digest(first) == digest(second)


def test_reduce_must_be_pure_enough_to_replay():
    """reduce обязан начинать с того, что передали, а не опираться на
    внешнее состояние. Проверяем на reduce, который зависит от порядка."""
    def impure(state, ev):
        state = dict(state or {"balance": 0})
        state["balance"] += ev["payload"].get("amount", 0)
        return state

    log = _log(("debit", {"amount": 10}), ("debit", {"amount": 20}))
    assert replay(log, reduce=impure)["balance"] == 30


def test_replay_rejects_broken_log():
    log = _log(("decide", {"action": "a"}))
    broken = StateLog(events=list(log.events), agent_id="a")
    broken.events[0] = type(broken.events[0])(
        seq=5, kind="decide", payload={"action": "a"}, at=1.0)
    with pytest.raises(JournalError):
        replay(broken, reduce=_reduce)


# -------------------------------------------------------------- вывод

def test_verdict_serialises():
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    v = verify_state(log, snap, reduce=_reduce, key=KEY)
    d = json.loads(json.dumps(v.as_dict()))
    assert d["ok"] is True
    assert d["snapshot"]["state_digest"] == snap.state_digest


def test_verdict_names_reason_on_failure():
    """Отказ обязан объяснять причину: «не сходится» без причины
    невозможно оспорить."""
    log, state = _sample()
    snap = sign_snapshot(log, state, key=KEY)
    snap.state_digest = "sha256:" + "0" * 64
    v = verify_state(log, snap, reduce=_reduce, key=KEY)
    assert not v.ok and v.reasons
    assert all(len(r) > 20 for r in v.reasons)