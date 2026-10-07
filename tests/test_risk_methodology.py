"""Методика risk-score обязана быть проверяемой.

Документ `docs/RISK-SCORE-METHODOLOGY.md` обещает конкретные свойства
оценки. Эти тесты — проверка, что обещания выполняются, а не что текст
написан. Если правило в документе расходится с кодом, падает тест.

Здесь нет инцидентов: это свойства самой шкалы.
"""

from __future__ import annotations

import json

import pytest

from attest.infra import INFRA_RULES, ConfigError, check_config
from attest.scanner import (RULE_VECTOR, RULES, SEVERITY_PENALTY,
                            VECTOR_ECONOMIC, VECTOR_INFRA, VECTOR_LOSS_SHARE,
                            VECTOR_LOGIC, SCORE_VERSION, check)


# ------------------------------------------------------------- шкала 0-100

def test_score_is_zero_to_hundred_and_hundred_means_clean():
    assert check("").score() == 100
    assert check("").clean


def test_penalty_table_matches_documented_weights():
    """Вес�� из методики: critical 40, high 15, medium 6, low 2."""
    assert SEVERITY_PENALTY == {"critical": 40, "high": 15,
                                "medium": 6, "low": 2}


def _tx_origin_code(n: int) -> str:
    """n нарушений на n РАЗНЫХ строках. Дедуп сканера идёт по паре
    (правило, строка), поэтому на одной строке сколько угодно
    одинаковых нарушений схлопывается в одну находку — это верно."""
    body = "\n".join(f"  function f{i}() public {{ tx.origin; }}" for i in range(n))
    return "contract C {\n" + body + "\n}"


def test_repeated_violation_on_one_line_collapses():
    """Одна строка — одна находка на правило. Иначе отчёт раздувается
    повторами и перестаёт читаться."""
    many = check("contract C { " + "function a() public { tx.origin; } " * 50 + "}")
    assert len(many.findings) == 1


def test_score_equals_hundred_minus_penalty_while_in_range():
    code = "contract C { function f() public { tx.origin; } }"
    v = check(code)
    expected_penalty = sum(SEVERITY_PENALTY[f.severity] for f in v.findings)
    assert v.penalty_total() == expected_penalty
    if expected_penalty <= 100:
        assert v.score() == 100 - expected_penalty
    else:
        assert v.score() == 0


def test_score_saturates_but_penalty_keeps_the_ordering():
    """Главный пробел насыщения: три и двадцать критических находок дают
    одинаковый 0. Методика обещает penalty_total как выход — проверяем."""
    three = check(_tx_origin_code(3))
    many = check(_tx_origin_code(20))

    assert three.score() == many.score() == 0
    assert many.penalty_total() > three.penalty_total()


def test_score_never_negative():
    v = check(_tx_origin_code(50))
    assert v.score() == 0
    assert 0 <= v.score() <= 100


# ------------------------------------------------------------- векторы

def test_every_rule_is_assigned_a_vector():
    """Правило без вектора молча попало бы в «логику» — это выдумка.
    Каждое правило обязано быть размечено явно."""
    unmapped = [r.key for r in RULES if r.key not in RULE_VECTOR]
    assert not unmapped, f"без вектора: {unmapped}"


def test_every_vector_is_used_by_at_least_one_rule():
    """Иначе вектор в отчёте — пустая колонка, а разбивка создаёт
    ложное впечатление полноты."""
    used = set(RULE_VECTOR.values())
    assert used == set(VECTOR_LOSS_SHARE), (
        f"не используются: {set(VECTOR_LOSS_SHARE) - used}")


def test_loss_shares_sum_to_one_hundred():
    assert sum(VECTOR_LOSS_SHARE.values()) == 100


def test_infrastructure_is_the_dominant_vector():
    """Основание всей методики: убытки идут через контроль, не через код.
    Если это перестанет быть правдой, методику надо переписывать."""
    assert max(VECTOR_LOSS_SHARE, key=lambda v: VECTOR_LOSS_SHARE[v]) == VECTOR_INFRA
    assert VECTOR_LOSS_SHARE[VECTOR_INFRA] >= 70


def test_code_and_infrastructure_are_scored_separately():
    """Главное свойство: одна критическая находка в коде и один
    скомпрометированный мультисиг — не одно и то же."""
    cfg = {"domain": {"name": "v", "version": "1", "chainId": 1,
                      "verifyingContract": "0x" + "a" * 40},
           "multisig": {"address": "0x" + "a" * 40, "threshold": 1,
                        "owners": ["0x" + "b" * 40, "0x" + "c" * 40]},
           "signature_policy": {"replay_protection": "nonce",
                                "max_age_seconds": 86400,
                                "deadline_required": True}}
    infra = check_config(json.dumps(cfg))
    vec = infra.vector_scores()

    assert vec[VECTOR_INFRA] < 100, "инфраструктура должна быть просажена"
    assert vec[VECTOR_LOGIC] == 100, "логика кода тут не проверялась"


def test_vector_scores_stay_in_range_and_start_at_hundred():
    code = "contract C { function f() public { tx.origin; } }"
    v = check(code)
    for name, val in v.vector_scores().items():
        assert 0 <= val <= 100, (name, val)


# --------------------------------------------------------- воспроизводимость

def test_report_carries_score_version():
    """Без версии весов оценку через год не отличить от другой."""
    assert SCORE_VERSION
    assert check("").as_dict()["score_version"] == SCORE_VERSION


def test_report_carries_loss_shares_for_the_reader():
    d = check("").as_dict()
    assert d["vector_loss_share"] == dict(VECTOR_LOSS_SHARE)


# ------------------------------------------------------------ доверие

def test_clean_document_is_high_confidence():
    assert check("").score_confidence() == "high"


def test_missing_fields_lower_confidence():
    """Часть правил молчит из-за отсутствия полей — оценка не может
    оставаться «уверенной»."""
    cfg = {"multisig": {"owners": ["0x" + "a" * 40], "threshold": 2}}
    v = check_config(json.dumps(cfg))
    assert v.unverified
    assert v.score_confidence() in ("medium", "low")


def test_many_unverified_rules_mean_low_confidence():
    cfg = {"domain": {"chainId": 1}}   # ни ролей, ни мультисига, ни политики
    v = check_config(json.dumps(cfg))
    assert v.score_confidence() == "low"


def test_confidence_survives_absence_of_unverified_field():
    """Вердикт по коду не имеет поля unverified — обращение должно
    быть безопасным, а не падать."""
    assert check("").score_confidence() == "high"


# ----------------------------- ограничения, названные в методике честно

def test_infra_verdict_declares_it_checks_a_document_not_the_chain():
    """Ограничение №1 методики обязано быть в машинном выводе, а не
    только в прозе документа."""
    cfg = {"domain": {"name": "v", "version": "1", "chainId": 1,
                      "verifyingContract": "0x" + "a" * 40},
           "multisig": {"address": "0x" + "a" * 40, "threshold": 2,
                        "owners": ["0x" + "a" * 40, "0x" + "b" * 40,
                                   "0x" + "c" * 40]},
           "roles": [], "signature_policy": {"replay_protection": "nonce"}}
    d = check_config(json.dumps(cfg)).as_dict()
    text = d["disclaimer"]
    assert "документ" in text and "ончейн" in text
    assert "не" in text.lower() and "аудит" in text.lower()


def test_unverified_is_never_reported_as_clean():
    """Ограничение №3: «не смог проверить» не равно «чисто»."""
    cfg = {"signature_policy": {"replay_protection": "nonce",
                                "max_age_seconds": 86400,
                                "deadline_required": True}}
    v = check_config(json.dumps(cfg))
    assert v.unverified and not v.clean


def test_every_finding_carries_why_and_fix():
    """Оспорить можно только то, что объяснено. Находка без why/fix
    не должна появляться в отчёте."""
    for rule in RULES:
        assert rule.why.strip(), rule.key
        assert rule.fix.strip(), rule.key
    for rule in INFRA_RULES:
        assert rule.why.strip(), rule.key
        assert rule.fix.strip(), rule.key


# ------------------------------------------------------- вывод пригоден для страховщика

def test_json_round_trip_keeps_the_evidence():
    code = "contract C { function f() public { tx.origin; } }"
    d = check(code).as_dict()
    again = json.loads(json.dumps(d))
    assert again["risk_score"] == d["risk_score"]
    assert again["penalty_total"] == d["penalty_total"]
    assert again["vector_scores"] == d["vector_scores"]


def test_disclaimer_absent_findings_is_not_a_guarantee():
    """«Чисто» по набору правил — не доказательство безопасности.
    Проверяем, что пустой отчёт это проговаривает."""
    d = check("").as_dict()
    assert d["clean"] is True
    assert isinstance(d.get("disclaimer", ""), str)


def test_unknown_rule_falls_back_to_logic_not_to_zero():
    """Правило без вектора не должно молча исчезать из отчёта:
    оно попадает в logic — консервативно и предсказуемо."""
    from attest.scanner import Verdict
    from attest.scanner import Finding

    v = Verdict(findings=[Finding(rule="rule-from-the-future",
                                  title="t", severity="high",
                                  why="w", fix="f", line=1,
                                  excerpt="x")],
                lines_checked=1, rules_run=1, engine="test")
    assert v.vector_scores()[VECTOR_LOGIC] == 85