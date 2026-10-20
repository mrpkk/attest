"""Тесты детектора пустоты.

Каждый тест — конкретный способ, которым агент производит артефакт,
проходящий валидацию по схеме и при этом пустой по содержанию.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attest.emptiness import (  # noqa: E402
    emptiness_score,
    emptiness_verdict,
    scan_for_emptiness,
)


def kinds(signals) -> set[str]:
    return {s.kind for s in signals}


class TestNormalArtifact:
    """Живой артефакт не должен ловиться. Ложное срабатывание хуже пропуска."""

    def test_real_finding_is_clean(self):
        art = {
            "summary": "Найдена уязвимость reentrancy в withdraw",
            "findings": ["Reentrancy в withdraw",
                         "Нет проверки recipient",
                         "Overflow в balanceOf"],
        }
        assert scan_for_emptiness(art) == []

    def test_prose_containing_word_example_is_clean(self):
        # «example» встречается в осмысленном тексте — это не заглушка.
        art = {"summary": "В example из документации поле заполняется значением"}
        assert kinds(scan_for_emptiness(art)) != {"stub_value"} or \
            all(s.severity == "low" for s in scan_for_emptiness(art))

    def test_verdict_is_present_for_clean_artifact(self):
        art = {"summary": "Контракт проверен, уязвимостей не найдено"}
        s = scan_for_emptiness(art)
        assert emptiness_verdict(emptiness_score(s), s) == "CONTENT_PRESENT"


class TestUniformList:
    """Самый частый сбой: список из одинаковых пунктов."""

    def test_all_identical_items(self):
        art = {"findings": ["Проверить контракт"] * 4}
        s = scan_for_emptiness(art)
        assert "uniform_list" in kinds(s)
        assert s[0].severity == "high"

    def test_majority_identical(self):
        art = {"findings": ["одинаковое", "уникальное-раз", "одинаковое",
                            "одинаковое", "ещё-одно-уникальное"]}
        s = scan_for_emptiness(art)
        assert "uniform_list" in kinds(s)

    def test_all_unique_items_not_flagged(self):
        art = {"findings": ["первый вывод", "второй вывод", "третий вывод"]}
        assert "uniform_list" not in kinds(scan_for_emptiness(art))

    def test_short_list_not_flagged(self):
        # Два одинаковых элемента — слишком мало, чтобы судить.
        art = {"findings": ["да", "да"]}
        assert "uniform_list" not in kinds(scan_for_emptiness(art))


class TestStubs:
    def test_field_is_placeholder_entirely(self):
        art = {"summary": "TODO", "owner": "N/A"}
        s = scan_for_emptiness(art)
        assert "stub_value" in kinds(s)
        assert all(x.severity == "high" for x in s if x.kind == "stub_value")

    def test_russian_stub_recognised(self):
        assert "stub_value" in kinds(scan_for_emptiness({"note": "待填"}))


class TestTruncation:
    def test_cut_at_end(self):
        art = {"analysis": "Долгий разбор контракта с делегированием вызовов..."}
        assert "truncated" in kinds(scan_for_emptiness(art))

    def test_mid_sentence_is_not_truncation(self):
        art = {"summary": "Проверка показала: всё в порядке, но есть нюанс."}
        assert "truncated" not in kinds(scan_for_emptiness(art))


class TestBlankAndRepetition:
    def test_whitespace_string_and_empty_list(self):
        art = {"summary": "   ", "findings": []}
        k = kinds(scan_for_emptiness(art))
        assert "blank_string" in k and "empty_list" in k

    def test_low_variety_text(self):
        art = {"summary": "проверка " * 14}
        assert "repetitive_text" in kinds(scan_for_emptiness(art))

    def test_varied_text_not_flagged(self):
        art = {"summary": "Контракт использует модификатор onlyOwner для вывода средств"}
        assert "repetitive_text" not in kinds(scan_for_emptiness(art))


class TestSchemaAwareness:
    SCHEMA = {
        "type": "object",
        "required": ["summary", "source"],
        "properties": {
            "summary": {"type": "string"},
            "source": {"type": "string", "default": "model-output"},
        },
    }

    def test_required_field_left_at_default(self):
        art = {"summary": "Готово", "source": "model-output"}
        assert "schema_default" in kinds(scan_for_emptiness(art, self.SCHEMA))

    def test_required_field_filled(self):
        art = {"summary": "Готово", "source": "user-input"}
        assert "schema_default" not in kinds(scan_for_emptiness(art, self.SCHEMA))


class TestScoring:
    def test_clean_is_zero(self):
        assert emptiness_score([]) == 0.0

    def test_verdicts_are_ordered(self):
        assert emptiness_verdict(0.0, []) == "CONTENT_PRESENT"
        assert emptiness_verdict(0.4, []) == "THIN_CONTENT"
        assert emptiness_verdict(0.9, []) == "VALID_BUT_EMPTY"

    def test_signal_without_schema_still_works(self):
        s = scan_for_emptiness({"findings": ["x"] * 5})
        assert s and emptiness_score(s) > 0

    def test_as_dict_is_json_friendly(self):
        s = scan_for_emptiness({"summary": "TODO"})
        assert isinstance(s[0].as_dict(), dict)
        assert set(s[0].as_dict()) == {"kind", "severity", "where",
                                        "evidence", "detail"}

    def test_duplicate_objects_are_detected(self):
        """Три одинаковых объекта — тоже заполнитель (кейс api.market 20.10).

        Раньше список сравнивался только по тексту листьев: у объектов
        текста нет, и дубли проходили как «форма в порядке».
        """
        s = scan_for_emptiness({"findings": [{"id": "a", "title": "x"}] * 3})
        assert s, "дубли в списке объектов не замечены"
        assert any(x.kind == "uniform_list" for x in s)
        assert emptiness_score(s) >= 0.8

    def test_distinct_objects_are_not_flagged(self):
        s = scan_for_emptiness({"findings": [
            {"id": "a", "title": "первое"}, {"id": "b", "title": "второе"}]})
        assert not any(x.kind == "uniform_list" for x in s)


class TestHonesty:
    def test_module_docstring_warns_absence_is_not_proof(self):
        # Отсутствие сигналов не означает осмысленности. Это должно быть
        # написано в коде, а не только в отчёте.
        src = (Path(__file__).resolve().parents[1] / "attest" /
               "emptiness.py").read_text(encoding="utf-8")
        assert "не означает" in src