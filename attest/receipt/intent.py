"""Намерение спрашивающего и честная форма отсутствия.

Профиль: draft-noa-scitt-ai-agent-receipt §8.2–8.3.

Две идеи, и обе про то, чего инструмент **не** имеет права сказать.

**1. Валидность ≠ достаточность.** Квитанция может быть криптографически
безупречной и при этом не отвечать на заданный вопрос. «Дай доказательство,
что груз дошёл» и «дай запись о том, что агент отправил команду» — разные
вопросы, и валидная квитанция отвечает только на второй. Свалить это в одно
«недействительно» значит уничтожить знание: человек узнал конкретное.

**2. Отсутствие — не отрицание.** «Проверяющий не получил доказательства» ≠
«доказательства не существует». Первое — про наш вход, второе — утверждение
о мире, которого мы не наблюдали. Инструмент проверки не имеет права
производить второе из первого: именно так невиновный становится обвинённым.

Отсюда закрытый набор токенов и запрет на коды вида «нет доказательств»,
«не существует», «не было».
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Что именно спросили.
BASE_ACTION_RECEIPT = "BASE_ACTION_RECEIPT"
CONTROLLER_OUTCOME = "CONTROLLER_OUTCOME"
PHYSICAL_COMPLETION = "PHYSICAL_COMPLETION"
INDEPENDENT_OUTCOME = "INDEPENDENT_OUTCOME"
INTENTS = (BASE_ACTION_RECEIPT, CONTROLLER_OUTCOME, PHYSICAL_COMPLETION, INDEPENDENT_OUTCOME)

# Чего не хватило. Четыре разных факта, которые нельзя сливать.
NOT_CLAIMED = "NOT_CLAIMED"          # изготовитель ничего не заявлял по этому пункту
NOT_PROVIDED = "NOT_PROVIDED"        # заявление может быть, но доказательства не дали
NOT_APPLICABLE = "NOT_APPLICABLE"    # вопрос не возникает для этого действия
INDETERMINATE = "INDETERMINATE"      # доказательство предъявлено, но вопрос не решает
ABSENCE = (NOT_CLAIMED, NOT_PROVIDED, NOT_APPLICABLE, INDETERMINATE)

# Результаты ответа.
SATISFIED = "SATISFIED"
CONFLICT = "CONFLICT"

# Слова, которых не должно быть в кодах результата: они утверждают
# негативный факт о мире, а не о нашем входе.
FORBIDDEN_WORDS = ("NO_EVIDENCE", "DOES_NOT_EXIST", "DID_NOT_HAPPEN", "ABSENT_FROM_WORLD",
                   "PROVEN_FALSE", "NOT_EXISTS")


@dataclass
class Answer:
    intent: str
    result: str
    claims: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def satisfied(self) -> bool:
        return self.result == SATISFIED

    def why(self) -> str:
        return "; ".join(self.notes) if self.notes else self.result


def answer(
    intent: str,
    *,
    receipt_verdict: Any = None,
    outcomes: list[dict[str, Any]] | None = None,
    independence: str = "UNKNOWN",
    trust_policy: str = "",
) -> Answer:
    """Ответить на вопрос, не выдавая непроверенное за проверенное."""
    if intent not in INTENTS:
        raise ValueError(f"unknown intent: {intent!r}")

    if intent == BASE_ACTION_RECEIPT:
        if receipt_verdict is None:
            return Answer(intent, NOT_PROVIDED, notes=["no receipt was supplied"])
        if getattr(receipt_verdict, "ok", False):
            return Answer(intent, SATISFIED, claims=[{"source": "receipt", "status": "valid"}])
        return Answer(intent, INDETERMINATE,
                      notes=[f"the receipt did not verify: {getattr(receipt_verdict, 'status', 'unknown')}"])

    if intent in (CONTROLLER_OUTCOME, PHYSICAL_COMPLETION):
        if not outcomes:
            return Answer(intent, NOT_PROVIDED,
                          notes=["the receipt carries no outcome artifact; this is not a finding "
                                 "that no outcome occurred"])
        if len(outcomes) > 1:
            verdicts = {str(o.get("result", "")).lower() for o in outcomes}
            if len(verdicts) > 1:
                # Два источника расходятся: показываем оба, не стирая ни один.
                return Answer(intent, CONFLICT, claims=outcomes,
                              notes=["two authenticated claims disagree; both are carried, "
                                     "neither is preferred"])
        claim = outcomes[0]
        if claim.get("authenticated") is not True:
            return Answer(intent, INDETERMINATE, claims=outcomes,
                          notes=["the outcome artifact is not authenticated"])
        note = f"held to the stated trust policy: {trust_policy}" if trust_policy else \
               "no trust policy named: the strongest result is 'proven to policy'"
        return Answer(intent, SATISFIED, claims=outcomes, notes=[note])

    # INDEPENDENT_OUTCOME
    if independence != "INDEPENDENT_ORGANIZATION":
        return Answer(intent, NOT_PROVIDED, claims=outcomes or [],
                      notes=[f"independence is {independence}: the configuration does not "
                             "establish separate administrative control"])
    if not outcomes:
        return Answer(intent, NOT_PROVIDED, notes=["independent, but there is no outcome artifact"])
    return Answer(intent, SATISFIED, claims=outcomes,
                  notes=["independence derived from the verifier's own configuration"])


def absence_token(*, claimed: bool | None, presented: bool, decisive: bool,
                  applicable: bool = True) -> str:
    """Единая точка выбора токена отсутствия — чтобы их не выбирали по вкусу."""
    if not applicable:
        return NOT_APPLICABLE
    if claimed is False:
        return NOT_CLAIMED
    if not presented:
        return NOT_PROVIDED
    if not decisive:
        return INDETERMINATE
    return SATISFIED


def result_codes() -> tuple[str, ...]:
    """Все коды, которые инструмент может вернуть. Используется тестом-стражем."""
    return INTENTS + ABSENCE + (SATISFIED, CONFLICT)
