#!/usr/bin/env python3
"""Привязка артефакта к условиям его получения.

Проверка формы и подписи доказывает: «вот этот файл подписан этим ключом
в момент T». Она не доказывает, откуда файл взялся. Между «агент сделал
вывод» и «проверяющий увидел результат» может стоять любой другой вывод,
и подпись этого не различит.

Здесь ровно эта связь. Условия генерации — модель, её версия, промпт,
параметры, момент — связываются с хэшем артефакта в один `chain_hash`.
Меняется любое звено, и привязка перестаёт сходиться.

Ключевое свойство: **отсутствие привязки видно явно**. Если условия не
переданы, `chain_hash` равен None, и потребитель ответа видит это, а не
полагается на то, что «значит, всё в порядке». Молча пропущенная
проверка хуже отсутствующей.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

# Поля, которые не имеет смысла привязывать: они не влияют на то,
# что именно сгенерировано.
IGNORED_PARAMS = {"stream", "n", "user", "session_id"}


@dataclass(frozen=True)
class GenerationContext:
    """Условия, при которых артефакт был получен.

    Все поля необязательные: у вызывающей стороны может не быть части
    сведений. Но пустота не выдаётся за полноту — см. `completeness`.
    """

    model: str = ""
    model_version: str = ""
    prompt: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    generated_at: float | None = None
    generator: str = ""          # кто вызвал модель: агент, пайплайн, человек
    generator_version: str = ""

    @property
    def prompt_hash(self) -> str:
        return _sha256(self.prompt) if self.prompt else ""

    def normalized_params(self) -> dict[str, Any]:
        """Параметры, из которых убран шум.

        Порядок ключей значения не имеет — иначе два одинаковых вызова,
        сериализованные по-разному, дали бы разные привязки.
        """
        out = {}
        for k in sorted(self.parameters):
            if k.lower() in IGNORED_PARAMS:
                continue
            v = self.parameters[k]
            if isinstance(v, (str, int, float, bool)) or v is None:
                out[k] = v
            else:
                out[k] = _sha256(json.dumps(v, sort_keys=True, ensure_ascii=False))
        return out

    def completeness(self) -> dict[str, Any]:
        """Что в привязке есть, а чего нет.

        Возвращается словарём, а не флагом: покупателю нужны конкретные
        отсутствующие поля, а не «привязка неполная».
        """
        missing = []
        if not self.model:
            missing.append("model")
        if not self.model_version:
            missing.append("model_version")
        if not self.prompt:
            missing.append("prompt")
        if not self.parameters:
            missing.append("parameters")
        if self.generated_at is None:
            missing.append("generated_at")
        if not self.generator:
            missing.append("generator")
        return {
            "complete": not missing,
            "missing": missing,
            "bound_fields": len(GENERATION_FIELDS) - len(missing),
            "total_fields": len(GENERATION_FIELDS),
        }

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("prompt", None)
        d["prompt_hash"] = self.prompt_hash
        d["parameters"] = self.normalized_params()
        d["completeness"] = self.completeness()
        return d


GENERATION_FIELDS = ("model", "model_version", "prompt", "parameters",
                     "generated_at", "generator")


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def chain_hash(artifact_hash: str, ctx: GenerationContext) -> str | None:
    """Хэш, связывающий артефакт с условиями генерации.

    Возвращает None, если из условий нечего связывать: пустой промпт при
    пустой модели не даёт привязки, и выдавать за неё хэш пустого объекта
    было бы ложью. None означает «привязки нет», и это видно в ответе.
    """
    payload = {
        "artifact_hash": artifact_hash,
        "model": ctx.model,
        "model_version": ctx.model_version,
        "prompt_hash": ctx.prompt_hash,
        "parameters": ctx.normalized_params(),
        "generated_at": ctx.generated_at,
        "generator": ctx.generator,
        "generator_version": ctx.generator_version,
    }
    if not any(payload[k] for k in
               ("model", "model_version", "prompt_hash", "parameters",
                "generated_at", "generator")):
        return None
    return "chain:" + hashlib.sha256(_canon(payload)).hexdigest()


def verify_chain(attestation_record: dict[str, Any],
                 ctx: GenerationContext) -> dict[str, Any]:
    """Проверяет, что заявленные условия действительно дают заявленный хэш.

    Возвращает не bool, а разбор: где именно не сошлось и каких полей
    не хватает. Сказать «подделка» без указания, что не совпало, —
    значит заставить проверяющего искать самому.
    """
    stated = attestation_record.get("chain_hash")
    recomputed = chain_hash(attestation_record.get("content_hash", ""), ctx)

    if stated is None and recomputed is None:
        return {"status": "NO_CHAIN",
                "bound": False,
                "detail": "generation conditions were not supplied — there is no binding"}
    if stated is None:
        return {"status": "CHAIN_ADDED_AFTER_SIGNING", "bound": False,
                "detail": "signed without a binding; conditions were supplied later"}
    if recomputed is None:
        return {"status": "CHAIN_MISSING_CONDITIONS", "bound": False,
                "detail": "conditions are claimed in the binding but none can be supplied"}
    if stated == recomputed:
        return {"status": "CHAIN_VERIFIED", "bound": True,
                "detail": "generation conditions match the signed ones"}
    return {"status": "CHAIN_MISMATCH", "bound": False,
            "detail": "conditions do not match the signed ones — "
                      "the artifact came from different conditions, or the signature is forged",
            "stated": stated, "recomputed": recomputed}