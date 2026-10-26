"""Канонизация: RFC 8785 + требования профиля квитанций.

Гейт S1: пять «невозможных» квитанций из I-D §12 отклоняются, канонизация
сортирует ключи по UTF-16, а не по кодовым точкам, и отвергает то, что ломает
проверку до всякой схемы.
"""

from __future__ import annotations

import pytest

from attest.receipt import jcs, schema

HASH = "sha256:" + "a" * 64


def receipt(**over) -> dict:
    base = {
        "spec": "noa.receipt/0.1",
        "id": "r-1",
        "ts": "2026-10-26T12:00:00Z",
        "scope": {"chain": "chain-1"},
        "agent": {"id": "agent-1", "principal": "SERVICE"},
        "action": {
            "id": "wire.transfer",
            "canonical": "wire.transfer",
            "riskClass": "HIGH",
            "paramsHash": HASH,
            "reversible": True,
        },
        "governance": {"mode": "on", "verdict": "EXECUTED", "sandboxed": False},
        "chain": {"seq": 0, "prevHash": None, "hash": HASH},
        "sig": {"alg": "ed25519", "kid": "k1", "value": "c2ln"},
    }
    base.update(over)
    return base


# --- канонизация -----------------------------------------------------------


def test_keys_sort_by_utf16_code_units_not_code_points():
    """Эмодзи (вне BMP) в UTF-16 идёт суррогатами и должен стоять ПЕРВЫМ.

    По кодовым точкам U+1F600 > U+FF61, по единицам UTF-16 — наоборот.
    Если сортировать как Python по умолчанию, два «канонических» документа
    дают разные байты, а значит разные хеши.
    """
    doc = {"\uff61": 1, "\U0001f600": 2}
    assert jcs.dumps(doc) == '{"\U0001f600":2,"\uff61":1}'


def test_integers_and_no_spaces():
    assert jcs.dumps({"b": 1, "a": [1, 2]}) == '{"a":[1,2],"b":1}'


def test_escaping_follows_rfc8785():
    assert jcs.dumps({"k": 'a"b\\c\n\t\u0001'}) == '{"k":"a\\"b\\\\c\\n\\t\\u0001"}'


def test_non_ascii_is_literal_utf8():
    assert jcs.dumps({"k": "привет"}) == '{"k":"привет"}'


@pytest.mark.parametrize("value", [1.5, 0.005, float("inf")])
def test_floats_are_rejected(value):
    with pytest.raises(jcs.CanonicalError):
        jcs.dumps({"n": value})


def test_integer_out_of_range_rejected():
    with pytest.raises(jcs.CanonicalError):
        jcs.dumps({"n": 2**53})


def test_duplicate_and_forbidden_members_rejected_at_parse():
    with pytest.raises(jcs.CanonicalError):
        jcs.loads('{"a":1,"a":2}')
    with pytest.raises(jcs.CanonicalError):
        jcs.loads('{"__proto__":{"x":1}}')


def test_nan_constant_rejected_at_parse():
    with pytest.raises(jcs.CanonicalError):
        jcs.loads('{"a":NaN}')


def test_unpaired_surrogate_rejected():
    with pytest.raises(jcs.CanonicalError):
        jcs.dumps({"k": "\ud800"})


# --- схема: базовая валидность ---------------------------------------------


def test_valid_receipt_passes():
    result = schema.check(receipt())
    assert result.ok, result.why()


def test_unknown_member_is_rejected_not_ignored():
    result = schema.check(receipt(extra=1))
    assert not result.ok
    assert "closed-object" in result.why()


# --- гейт: пять «невозможных» квитанций из I-D §12 --------------------------


def test_A_sandbox_principal_with_sandboxed_false_is_rejected():
    r = receipt(agent={"id": "a", "principal": "SANDBOX_SIM"},
                governance={"mode": "on", "verdict": "EXECUTED", "sandboxed": False})
    assert not schema.check(r).ok, "G1: симуляция и выполнение одновременно"


def test_B_simulated_verdict_with_sandboxed_false_is_rejected():
    r = receipt(governance={"mode": "on", "verdict": "SIMULATED", "sandboxed": False})
    assert not schema.check(r).ok, "G1: SIMULATED при sandboxed=false"


def test_C_rollback_ref_without_reversible_is_rejected():
    r = receipt(action={"id": "a", "canonical": "a", "riskClass": "HIGH",
                        "paramsHash": HASH, "reversible": False, "rollbackRef": "snap_1"})
    assert not schema.check(r).ok, "G2: ссылка на откат у необратимого действия"


def test_D_rolled_back_without_reversible_is_rejected():
    r = receipt(governance={"mode": "on", "verdict": "ROLLED_BACK", "sandboxed": False},
                action={"id": "a", "canonical": "a", "riskClass": "HIGH",
                        "paramsHash": HASH, "reversible": False})
    assert not schema.check(r).ok, "G2: ROLLED_BACK при reversible=false"


def test_E_impossible_timestamp_is_rejected():
    r = receipt(ts="2026-13-45T99:99:99Z")
    result = schema.check(r)
    assert not result.ok, "G3: дата вне календаря"
    assert "rfc3339" in result.why()


# --- то, что эталон пропускал: закрытые словари ----------------------------


@pytest.mark.parametrize("field,value", [
    ("verdict", "executed"),
    ("verdict", "DONE"),
    ("mode", "ON"),
])
def test_vocabulary_is_case_sensitive(field, value):
    gov = {"mode": "on", "verdict": "EXECUTED", "sandboxed": False}
    gov[field] = value
    assert not schema.check(receipt(governance=gov)).ok


def test_hash_uppercase_is_rejected():
    r = receipt(chain={"seq": 0, "prevHash": None, "hash": "sha256:" + "A" * 64})
    assert not schema.check(r).ok


def test_id_longer_than_128_code_points_rejected():
    assert not schema.check(receipt(id="é" * 129)).ok
    assert schema.check(receipt(id="é" * 128)).ok


def test_boolean_is_not_an_integer():
    r = receipt(chain={"seq": True, "prevHash": None, "hash": HASH})
    assert not schema.check(r).ok
