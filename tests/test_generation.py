"""Тесты привязки артефакта к условиям генерации.

Проверяется не «работает ли хэш», а различает ли он разные ситуации:
условия те же, условия другие, условий не было вовсе. Ошибка в этом
модуле выглядит как подтверждение подделки, поэтому проверки строятся
на парах, которые обязаны различаться.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attest.generation import (  # noqa: E402
    GenerationContext,
    chain_hash,
    verify_chain,
)

AH = "sha256:deadbeef"


def ctx(**kw) -> GenerationContext:
    base = dict(
        model="claude-sonnet-4",
        model_version="2026-05",
        prompt="Найди уязвимости в withdraw",
        parameters={"temperature": 0.2, "max_tokens": 2000},
        generated_at=1791828000.0,
        generator="agent-audit/1.4",
    )
    base.update(kw)
    return GenerationContext(**base)


class TestBinding:
    def test_full_context_binds(self):
        h = chain_hash(AH, ctx())
        assert h is not None and h.startswith("chain:")

    def test_same_conditions_same_hash(self):
        assert chain_hash(AH, ctx()) == chain_hash(AH, ctx())

    def test_parameter_order_does_not_matter(self):
        a = ctx(parameters={"temperature": 0.2, "max_tokens": 2000})
        b = ctx(parameters={"max_tokens": 2000, "temperature": 0.2})
        assert chain_hash(AH, a) == chain_hash(AH, b)

    def test_verified_against_own_conditions(self):
        h = chain_hash(AH, ctx())
        r = verify_chain({"content_hash": AH, "chain_hash": h}, ctx())
        assert r["status"] == "CHAIN_VERIFIED"
        assert r["bound"] is True


class TestTampering:
    def test_changed_prompt_breaks_binding(self):
        h = chain_hash(AH, ctx())
        r = verify_chain({"content_hash": AH, "chain_hash": h},
                         ctx(prompt="Найди уязвимости в transfer"))
        assert r["status"] == "CHAIN_MISMATCH"

    def test_changed_temperature_breaks_binding(self):
        h = chain_hash(AH, ctx())
        assert verify_chain({"content_hash": AH, "chain_hash": h},
                            ctx(parameters={"temperature": 0.9,
                                            "max_tokens": 2000})
                            )["status"] == "CHAIN_MISMATCH"

    def test_changed_model_breaks_binding(self):
        h = chain_hash(AH, ctx())
        assert verify_chain({"content_hash": AH, "chain_hash": h},
                            ctx(model="gpt-4"))["status"] == "CHAIN_MISMATCH"

    def test_changed_artifact_hash_breaks_binding(self):
        h = chain_hash(AH, ctx())
        assert verify_chain({"content_hash": "sha256:other", "chain_hash": h},
                            ctx())["status"] == "CHAIN_MISMATCH"

    def test_model_version_matters(self):
        h = chain_hash(AH, ctx())
        assert chain_hash(AH, ctx(model_version="2026-06")) != h


class TestAbsenceIsVisible:
    """Нет условий — это факт, который должен быть виден, а не молчать."""

    def test_empty_context_gives_no_chain(self):
        assert chain_hash(AH, GenerationContext()) is None

    def test_no_chain_reported_as_such(self):
        r = verify_chain({"content_hash": AH}, GenerationContext())
        assert r["status"] == "NO_CHAIN"
        assert r["bound"] is False

    def test_chain_claimed_without_conditions(self):
        # Привязка заявлена, а предъявить условия нечем. Это не то же
        # самое, что «привязки нет»: кто-то утверждает о цепочке, которую
        # проверить невозможно. Путать эти два состояния нельзя.
        h = chain_hash(AH, GenerationContext(model="m"))
        r = verify_chain({"content_hash": AH, "chain_hash": h},
                         GenerationContext())
        assert r["status"] == "CHAIN_MISSING_CONDITIONS"
        assert r["bound"] is False

    def test_conditions_supplied_after_signing(self):
        # Условия передали, а привязки в подписи нет — значит подпись
        # сделана до того, как условия вообще были известны.
        r = verify_chain({"content_hash": AH}, GenerationContext(model="m"))
        assert r["status"] == "CHAIN_ADDED_AFTER_SIGNING"
        assert r["bound"] is False

    def test_completeness_lists_missing_fields(self):
        c = GenerationContext(model="m")
        comp = c.completeness()
        assert comp["complete"] is False
        assert "prompt" in comp["missing"]
        assert comp["total_fields"] == 6


class TestNoiseIgnored:
    def test_streaming_flag_does_not_change_binding(self):
        a = ctx()
        b = ctx(parameters={"temperature": 0.2, "max_tokens": 2000, "stream": True})
        assert chain_hash(AH, a) == chain_hash(AH, b)

    def test_session_id_does_not_change_binding(self):
        a = chain_hash(AH, ctx())
        b = chain_hash(AH, ctx(parameters={"temperature": 0.2, "max_tokens": 2000,
                                           "session_id": "abc"}))
        assert a == b

    def test_prompt_text_not_leaked_in_dict(self):
        d = ctx(prompt="секретный промпт").as_dict()
        assert "prompt" not in d
        assert d["prompt_hash"].startswith("sha256:")


class TestPartialContext:
    def test_single_field_still_binds(self):
        h = chain_hash(AH, GenerationContext(model="gpt-4"))
        assert h is not None
        r = verify_chain({"content_hash": AH, "chain_hash": h},
                         GenerationContext(model="gpt-4"))
        assert r["status"] == "CHAIN_VERIFIED"

    def test_single_field_survives_mismatch(self):
        h = chain_hash(AH, GenerationContext(model="gpt-4"))
        r = verify_chain({"content_hash": AH, "chain_hash": h},
                         GenerationContext(model="claude"))
        assert r["status"] == "CHAIN_MISMATCH"

    def test_mismatch_reports_both_hashes(self):
        h = chain_hash(AH, ctx())
        r = verify_chain({"content_hash": AH, "chain_hash": h}, ctx(model="x"))
        assert "stated" in r and "recomputed" in r


class TestHonesty:
    def test_docstring_states_none_means_no_binding(self):
        src = (Path(__file__).resolve().parents[1] / "attest" /
               "generation.py").read_text(encoding="utf-8")
        assert "ложью" in src