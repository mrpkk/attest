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
from .schema import SchemaViolation, validate_against_schema

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


def _verdict(violations: list[SchemaViolation], signals: list[PoisonSignal], score: float) -> tuple[str, str]:
    critical = [s for s in signals if s.kind in CRITICAL_KINDS or s.kind in DANGEROUS_COMMANDS or s.severity == "critical"]
    if critical:
        return "reject", f"критичный сигнал: {critical[0].kind} @ {critical[0].where}"
    if not signals and not violations:
        return "accept", "схема в порядке, признаков отравления нет"
    if violations:
        hard = [v for v in violations if v.rule in ("type", "required", "null", "depth", "empty", "size", "minimum", "maximum")]
        if hard:
            return "reject", f"нарушение контракта: {hard[0].rule} @ {hard[0].path}"
    # сигнатурная инъекция = отказ, даже в доверенном поле: «ignore all previous
    # instructions» не бывает в честном ответе инструмента
    signature_attack = [s for s in signals if s.kind in INJECTION_KINDS]
    if signature_attack:
        return "reject", f"сигнатурная инъекция: {signature_attack[0].kind} @ {signature_attack[0].where}"

    # два независимых сигнала высокой тяжести = скоординированная атака,
    # а не единичная неточность формулировки
    strong = [s for s in signals if s.severity == "high"]
    if len(strong) >= 2:
        return "reject", f"несколько независимых сигналов: {', '.join(s.kind for s in strong[:3])}"
    if score < 60:
        return "reject", f"доверие слишком низкое ({score:.0f}/100)"
    if score < 90:
        return "review", f"есть замечания, требуется взгляд человека ({score:.0f}/100)"
    return "accept", f"незначительные замечания ({score:.0f}/100)"


def attest(artifact: Any, schema: dict[str, Any] | None = None, source: str = "unknown", sign_it: bool = True) -> AttestResult:
    """Проверить артефакт и вернуть вердикт с подписью."""
    violations = validate_against_schema(artifact, schema)
    signals = scan_for_poison(artifact)
    score = _score(violations, signals)
    verdict, reason = _verdict(violations, signals, score)

    record = new_record(
        source=source,
        artifact=artifact,
        verdict=verdict,
        trust_score=score,
        violations=[v.as_dict() for v in violations],
        signals=[s.as_dict() for s in signals],
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
