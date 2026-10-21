"""Ядро: единая точка проверки артефакта.

attest(artifact, schema, source) -> AttestResult с вердиктом:
  accept — можно вставлять в контекст агента
  review  — есть находки, но не критичные
  reject  — артефакт небезопасен или сломан, в контекст не пускать
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .poison import PoisonSignal, scan_for_poison
from .provenance import Attestation, new_record, sign, verify
from .generation import GenerationContext, chain_hash as make_chain_hash
from .authority import authority_hash as make_authority_hash, check_authority
from .provenance import digest as _content_hash

_GEN_FIELDS = ("model", "model_version", "prompt", "parameters",
              "generated_at", "generator", "generator_version")
from .schema import SchemaViolation, validate_against_schema
from .emptiness import scan_for_emptiness, emptiness_score

SEVERITY_WEIGHT = {"critical": 40.0, "high": 15.0, "medium": 5.0, "low": 1.0}
VIOLATION_WEIGHT = 8.0

# сигнатуры, которых нет ни в одном честном ответе инструмента
INJECTION_KINDS = {
    "ignore_previous", "disregard_context", "forget_instructions", "prompt_injection",
    "special_token_smuggle", "role_block_smuggle", "assistant_turn_smuggle",
    "conceal_from_user", "conceal_from_user_ru", "exfiltrate_secrets", "exfiltrate_network",
    "injection_in_data_field", "role_override",
}

# опасные команды, которых не бывает в честном ответе сервиса
DANGEROUS_COMMANDS = {
    "destructive_command", "remote_exec_pipe", "remote_exec_pipe_line", "obfuscated_exec",
    "live_credential_shape", "aws_key_shape", "private_key_material", "base64_exfiltration",
    "exfiltration_instruction", "metadata_endpoint", "mixed_script_word", "zero_width_smuggle",
    "hidden_html",
}

CRITICAL_KINDS = {
    "exfiltrate_secrets", "exfiltrate_network", "live_credential_shape", "aws_key_shape",
    "private_key_material", "obfuscated_exec", "remote_exec_pipe", "remote_exec_pipe_line",
    "injection_in_data_field", "mixed_script_word", "exfiltration_instruction",
}


@dataclass
class AttestResult:
    verdict: str
    trust_score: float
    attestation: Attestation
    violations: list[SchemaViolation] = field(default_factory=list)
    signals: list[PoisonSignal] = field(default_factory=list)
    reason: str = ""

    @property
    def safe(self) -> bool:
        return self.verdict != "reject"

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "trust_score": self.trust_score,
            "reason": self.reason,
            "violations": [v.as_dict() for v in self.violations],
            "signals": [s.as_dict() for s in self.signals],
            "attestation": self.attestation.as_dict(),
        }

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, indent=indent)


def _score(violations: list[SchemaViolation], signals: list[PoisonSignal]) -> float:
    penalty = sum(VIOLATION_WEIGHT for _ in violations)
    penalty += sum(SEVERITY_WEIGHT.get(s.severity, 5.0) for s in signals)
    return max(0.0, 100.0 - penalty)


def _verdict(violations: list[SchemaViolation], signals: list[PoisonSignal], score: float,
             empty_score: float = 0.0) -> tuple[str, str]:
    critical = [s for s in signals if s.kind in CRITICAL_KINDS or s.kind in DANGEROUS_COMMANDS or s.severity == "critical"]
    if critical:
        return "reject", f"critical signal: {critical[0].kind} @ {critical[0].where}"
    if not signals and not violations and empty_score < 0.8:
        return "accept", "schema is valid, no poisoning signals"
    if violations:
        hard = [v for v in violations if v.rule in ("type", "required", "null", "depth", "empty", "size",
                                                     "minimum", "maximum", "minLength", "maxLength",
                                                     "minItems", "maxItems", "invalid_json")]
        if hard:
            return "reject", f"contract violation: {hard[0].rule} @ {hard[0].path}"
    # Форма в порядке, содержания нет: пустые значения, дубли, заглушки.
    # Это отказ, а не «мелкая находка» — иначе клиент получает accept на
    # артефакт, в котором нечего принимать (баг, найденный api.market 20.10).
    if empty_score >= 0.8:
        return "reject", f"form is valid but the artifact is empty ({empty_score:.2f})"
    # сигнатурная инъекция = отказ, даже в доверенном поле: «ignore all previous
    # instructions» не бывает в честном ответе инструмента
    signature_attack = [s for s in signals if s.kind in INJECTION_KINDS]
    if signature_attack:
        return "reject", f"signature injection: {signature_attack[0].kind} @ {signature_attack[0].where}"

    # два независимых сигнала высокой тяжести = скоординированная атака,
    # а не единичная неточность формулировки
    strong = [s for s in signals if s.severity == "high"]
    if len(strong) >= 2:
        return "reject", f"multiple independent signals: {', '.join(s.kind for s in strong[:3])}"
    if score < 60:
        return "reject", f"trust score too low ({score:.0f}/100)"
    if empty_score >= 0.35:
        return "review", f"thin content: form is valid, substance is doubtful ({empty_score:.2f})"
    if score < 90:
        return "review", f"has findings, needs a human look ({score:.0f}/100)"
    return "accept", f"minor findings ({score:.0f}/100)"


def _coerce_json_field(value: Any, field_name: str) -> tuple[Any, str | None]:
    """Строка с JSON внутри — это тоже JSON.

    REST-клиенты присылают схему строкой, а артефакт — текстом ответа
    инструмента. Пока строка молча превращалась в None, проверка формы не
    выполнялась вовсе, и сервис отвечал `accept` на пустой артефакт: обещание
    из описания не выполнялось (баг найден ревьюером api.market 20.10.2026).

    Возвращает (значение, ошибка). Ошибка — текст для violations, а не
    исключение: клиент должен получить вердикт, а не 500.
    """
    if value is None or isinstance(value, (dict, list)):
        return value, None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None, None
        try:
            return json.loads(text), None
        except json.JSONDecodeError as exc:
            return None, f"{field_name}: не JSON ({exc.msg}, позиция {exc.pos})"
    return None, f"{field_name}: ожидался объект, массив или JSON-строка"


def attest(artifact: Any, schema: dict[str, Any] | None = None, source: str = "unknown", sign_it: bool = True,
    generation: "dict[str, Any] | None" = None,
    payload_mandate: "dict[str, Any] | None" = None,
    payload_action: "dict[str, Any] | None" = None,
    require_json: bool = False,
) -> AttestResult:
    """Проверить артефакт и выдать вердикт с подписью.

    `require_json` — контракт HTTP-эндпоинта: артефакт агента это JSON
    (объект или массив). Голую строку без схемы проверить нечем, а `accept`
    на ней означал бы «можно вставлять в контекст» то, что не проверено.
    """
    if require_json:
        artifact, artifact_error = _coerce_json_field(artifact, "artifact")
    else:
        artifact_error = None
    schema, schema_error = _coerce_json_field(schema, "schema")

    violations = validate_against_schema(artifact, schema)
    if schema_error:
        violations.append(SchemaViolation("$schema", "invalid_json", schema_error))
    if artifact_error:
        violations.append(SchemaViolation("$", "invalid_json", artifact_error))
    signals = scan_for_poison(artifact)
    hollow = scan_for_emptiness(artifact, schema if isinstance(schema, dict) else None)
    empty_score = emptiness_score(hollow)
    score = _score(violations, signals)
    # Пустота — тоже основание для недоверия: вердикт «reject» при score 100
    # выглядел бы противоречиво и сбивал бы с толку читателя записи.
    score = max(0.0, score - empty_score * 30.0)
    verdict, reason = _verdict(violations, signals, score, empty_score)

    # Привязка считается от хэша содержимого, который new_record посчитает
    # тем же способом. Считаем заранее, чтобы chain_hash вошёл в подпись,
    # а не существовал рядом с ней.
    # Разрешение считается независимо от формы артефакта. Отказ здесь не
    # делает артефакт недействительным — он делает его неразрешённым, и
    # это разные утверждения.
    auth_hash = None
    auth = None
    mandate = payload_mandate
    if isinstance(mandate, dict):
        act = payload_action if isinstance(payload_action, dict) else {}
        verdict_auth = check_authority(mandate, act)
        auth = verdict_auth.as_dict()
        auth_hash = make_authority_hash(mandate, act)

    chain = None
    if isinstance(generation, dict):
        chain = make_chain_hash(
            _content_hash(artifact),
            GenerationContext(**{k: v for k, v in generation.items()
                                 if k in _GEN_FIELDS}),
        )

    record = new_record(
        source=source,
        artifact=artifact,
        verdict=verdict,
        trust_score=score,
        chain_hash=chain,
        authority_hash=auth_hash,
        authority=auth,
        violations=[v.as_dict() for v in violations],
        signals=[s.as_dict() for s in signals] + [s.as_dict() for s in hollow],
    )
    attestation = sign(record) if sign_it else Attestation(record=record, signature="unsigned", algorithm="none")

    return AttestResult(
        verdict=verdict,
        trust_score=score,
        attestation=attestation,
        violations=violations,
        signals=signals,
        reason=reason,
    )
