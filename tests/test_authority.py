"""Тесты проверки разрешения.

Два особых предмета внимания.

Первый — соответствие `drift`. Правила продублированы намеренно, и
дублирование без защиты разъезжается молча. Тест на сверку с живым
`drift` падает сразу, если правила разошлись, а не когда клиент
предъявит претензию.

Второй — отсутствие мандата. Оно должно давать отказ, а не согласие:
проверяющий, не предъявивший полномочия, не доказал разрешения.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.authority import (  # noqa: E402
    RULES,
    authority_hash,
    check_authority,
)

MANDATE = {
    "payee_id": "0xAAA", "audience": "client-7", "max_amount_minor": 100000,
    "currency": "USDC", "valid_from": 1000, "valid_until": 2000,
    "allowed_intents": ["transfer", "swap"],
}
OK_ACTION = {"payee_id": "0xAAA", "audience": "client-7",
             "amount_minor": 50000, "currency": "USDC", "at": 1500,
             "intent": "transfer"}


class TestAllow:
    def test_action_inside_mandate_allowed(self):
        v = check_authority(MANDATE, OK_ACTION)
        assert v.allowed is True
        assert v.rule == "-"

    def test_exact_limit_allowed(self):
        a = {**OK_ACTION, "amount_minor": 100000}
        assert check_authority(MANDATE, a).allowed is True

    def test_boundary_of_window_allowed(self):
        for at in (1000, 2000):
            assert check_authority(MANDATE, {**OK_ACTION, "at": at}).allowed

    def test_empty_intents_means_any(self):
        m = {**MANDATE, "allowed_intents": []}
        assert check_authority(m, {**OK_ACTION, "intent": "любое"}).allowed


class TestDeny:
    @pytest.mark.parametrize("bad,rule", [
        ({"amount_minor": 100001}, "amount"),
        ({"payee_id": "0xBBB"}, "payee"),
        ({"audience": "other"}, "audience"),
        ({"currency": "ETH"}, "currency"),
        ({"at": 999}, "window"),
        ({"at": 2001}, "window"),
        ({"intent": "drain"}, "intent"),
    ])
    def test_each_rule_denies(self, bad, rule):
        v = check_authority(MANDATE, {**OK_ACTION, **bad})
        assert v.allowed is False
        assert v.rule == rule

    def test_rule_order_is_pinned(self):
        # Порядок правил значим: самая частая причина отказа должна
        # называться первой, иначе ответ бесполезен при множественном
        # нарушении.
        broken = {**OK_ACTION, "amount_minor": 10 ** 9, "payee_id": "0xZZZ"}
        assert check_authority(MANDATE, broken).rule == "amount"

    def test_every_rule_is_reachable(self):
        seen = set()
        probes = {
            "amount": {"amount_minor": 10 ** 9},
            "payee": {"payee_id": "0xBBB"},
            "audience": {"audience": "z"},
            "currency": {"currency": "ETH"},
            "window": {"at": 0},
            "intent": {"intent": "drain"},
        }
        for expected, patch in probes.items():
            assert check_authority(MANDATE, {**OK_ACTION, **patch}).rule == expected
            seen.add(expected)
        assert seen == set(RULES)


class TestAbsenceOfMandate:
    def test_empty_mandate_denies(self):
        v = check_authority({}, OK_ACTION)
        assert v.allowed is False
        assert v.rule == "no_mandate"

    def test_missing_fields_named(self):
        v = check_authority({"payee_id": "0xAAA"}, OK_ACTION)
        assert "audience" in v.note

    def test_absence_never_means_allowed(self):
        for m in ({}, {"payee_id": "0xAAA"}, {"audience": "c"}):
            assert check_authority(m, OK_ACTION).allowed is False


class TestMalformedInput:
    def test_non_integer_amount_rejected(self):
        with pytest.raises(ValueError):
            check_authority(MANDATE, {**OK_ACTION, "amount_minor": "много"})

    def test_string_numbers_accepted(self):
        # JSON не различает 100 и "100"; приём строки не ослабляет проверку.
        assert check_authority(MANDATE,
                               {**OK_ACTION, "amount_minor": "50000"}).allowed


class TestAuthorityHash:
    def test_covers_mandate_and_action(self):
        h1 = authority_hash(MANDATE, OK_ACTION)
        h2 = authority_hash(MANDATE, {**OK_ACTION, "amount_minor": 1})
        assert h1 != h2

    def test_mandate_change_changes_hash(self):
        h1 = authority_hash(MANDATE, OK_ACTION)
        h2 = authority_hash({**MANDATE, "max_amount_minor": 200000}, OK_ACTION)
        assert h1 != h2

    def test_stable_across_calls(self):
        assert authority_hash(MANDATE, OK_ACTION) == authority_hash(
            MANDATE, OK_ACTION)

    def test_action_is_part_of_hash(self):
        # К подписанному мандату нельзя приложить любое действие.
        # Если бы хэшировался только мандат, все действия давали бы одно
        # и то же значение, и подпись перестала бы что-то значить.
        m_only = {k: v for k, v in MANDATE.items()}
        a = authority_hash(m_only, OK_ACTION)
        b = authority_hash(m_only, {**OK_ACTION, "intent": "drain"})
        assert a != b


class TestMirrorsDrift:
    """Сверка с живым drift: правила обязаны совпадать."""

    DRIFT = Path("/media/Sruti/iamthat/work/drift")

    @pytest.mark.skipif(not (Path("/media/Sruti/iamthat/work/drift") /
                             "drift.py").exists(),
                        reason="репозиторий drift недоступен")
    def test_matches_drift_on_every_rule(self):
        sys.path.insert(0, str(self.DRIFT))
        try:
            from drift import Action, Mandate, check as drift_check
        except ImportError:                      # pragma: no cover
            pytest.skip("drift не импортируется")
        md = Mandate.from_dict(MANDATE)
        probes = [
            OK_ACTION,
            {**OK_ACTION, "amount_minor": 10 ** 9},
            {**OK_ACTION, "payee_id": "0xBBB"},
            {**OK_ACTION, "audience": "other"},
            {**OK_ACTION, "currency": "ETH"},
            {**OK_ACTION, "at": 0},
            {**OK_ACTION, "intent": "drain"},
        ]
        for ad in probes:
            act = Action(payee_id=ad["payee_id"], audience=ad["audience"],
                         amount_minor=ad["amount_minor"], currency=ad["currency"],
                         at=ad["at"], intent=ad.get("intent", ""))
            expected, rule = drift_check(md, act)
            got = check_authority(MANDATE, ad)
            assert got.allowed == (expected == "ALLOW"), ad
            assert got.rule == rule, ad


class TestHonesty:
    def test_module_docstring_explains_duplication(self):
        src = (ROOT / "attest" / "authority.py").read_text(encoding="utf-8")
        assert "продублированы" in src

    def test_docstring_warns_absence_is_not_consent(self):
        src = (ROOT / "attest" / "authority.py").read_text(encoding="utf-8")
        assert "согласие" in src