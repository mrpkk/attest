"""S6: намерения и отсутствие.

Гейт: ни один код результата не утверждает негативный факт о ненаблюдённом;
конфликт двух источников возвращается с обоими утверждениями.
"""

from __future__ import annotations

import pytest

from attest.receipt import intent


class Verdict:
    def __init__(self, ok: bool, status: str = "valid") -> None:
        self.ok = ok
        self.status = status


def test_base_intent_answers_from_the_receipt_alone():
    a = intent.answer(intent.BASE_ACTION_RECEIPT, receipt_verdict=Verdict(True))
    assert a.satisfied and a.result == intent.SATISFIED


def test_base_intent_without_a_receipt_is_not_provided():
    a = intent.answer(intent.BASE_ACTION_RECEIPT)
    assert a.result == intent.NOT_PROVIDED


def test_controller_outcome_without_artifact_is_not_provided_not_denied():
    a = intent.answer(intent.CONTROLLER_OUTCOME)
    assert a.result == intent.NOT_PROVIDED
    assert "not a finding" in a.why()


def test_physical_completion_never_claimed_as_bare_proof():
    a = intent.answer(intent.PHYSICAL_COMPLETION,
                      outcomes=[{"authenticated": True, "result": "delivered"}])
    assert a.result == intent.SATISFIED
    assert "proven to policy" in a.why()


def test_conflicting_claims_carry_both():
    a = intent.answer(intent.CONTROLLER_OUTCOME,
                      outcomes=[{"authenticated": True, "result": "success"},
                                {"authenticated": True, "result": "failed"}])
    assert a.result == intent.CONFLICT
    assert len(a.claims) == 2, "оба утверждения должны остаться в ответе"


def test_independent_outcome_requires_derived_independence():
    a = intent.answer(intent.INDEPENDENT_OUTCOME, independence="UNKNOWN",
                      outcomes=[{"authenticated": True, "result": "ok"}])
    assert a.result == intent.NOT_PROVIDED
    assert "does not establish" in a.why()


def test_unauthenticated_outcome_is_indeterminate():
    a = intent.answer(intent.CONTROLLER_OUTCOME, outcomes=[{"authenticated": False}])
    assert a.result == intent.INDETERMINATE


def test_absence_tokens_are_four_distinct_facts():
    assert intent.absence_token(claimed=False, presented=False, decisive=False) == intent.NOT_CLAIMED
    assert intent.absence_token(claimed=None, presented=False, decisive=False) == intent.NOT_PROVIDED
    assert intent.absence_token(claimed=None, presented=True, decisive=False) == intent.INDETERMINATE
    assert intent.absence_token(claimed=None, presented=True, decisive=True,
                                applicable=False) == intent.NOT_APPLICABLE
    assert len(set(intent.ABSENCE)) == 4


def test_no_result_code_asserts_a_negative_fact_about_the_world():
    """Гейт S6: перечень кодов не содержит утверждений о ненаблюдённом."""
    codes = intent.result_codes()
    for code in codes:
        for banned in intent.FORBIDDEN_WORDS:
            assert banned not in code, f"код {code!r} утверждает негатив о мире"
    # и наоборот: токены отсутствия говорят о нашем входе, а не о мире
    assert intent.NOT_PROVIDED in codes and intent.INDETERMINATE in codes


def test_unknown_intent_is_refused():
    with pytest.raises(ValueError):
        intent.answer("IS_IT_SAFE")
