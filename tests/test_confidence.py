"""Confidence l1-l5 на находку (взято из практики Lakera, 2026).

Правило детерминированное: severity -> уровень. Тест фиксирует, что уровень
не зависит от текста находки и попадает в JSON.
"""
from attest.poison import PoisonSignal


def _sig(severity: str) -> PoisonSignal:
    return PoisonSignal(kind="ignore_previous", severity=severity, where="description", evidence="x")


def test_critical_is_l5():
    assert _sig("critical").confidence == "l5"


def test_high_is_l4():
    assert _sig("high").confidence == "l4"


def test_medium_is_l3():
    assert _sig("medium").confidence == "l3"


def test_low_is_l2_and_unknown_is_l1():
    assert _sig("low").confidence == "l2"
    assert _sig("info").confidence == "l1"


def test_as_dict_carries_confidence():
    d = _sig("critical").as_dict()
    assert d["confidence"] == "l5"
    assert set(d) == {"kind", "severity", "confidence", "where", "evidence"}
