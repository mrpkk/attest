"""Attest — проверка артефактов, проходящих через AI-агента.

Слой доверия к результату: схема, отравление контекста, provenance.
Не governance (кто дал доступ) и не evals (тест своего агента) —
это верификация ЧУЖОГО артефакта в момент попадания в контекст.
"""

__version__ = "0.1.0"

from .schema import SchemaViolation, validate_against_schema
from .poison import PoisonSignal, scan_for_poison
from .provenance import Attestation, ProvenanceRecord, sign, verify
from .state import (JournalError, Snapshot, StateLog, StateVerdict,
                    replay, sign_snapshot, verify_snapshot, verify_state)

__all__ = [
    "SchemaViolation",
    "validate_against_schema",
    "PoisonSignal",
    "scan_for_poison",
    "Attestation",
    "ProvenanceRecord",
    "JournalError",
    "Snapshot",
    "StateLog",
    "StateVerdict",
    "replay",
    "sign_snapshot",
    "verify_snapshot",
    "verify_state",
    "sign",
    "verify",
    "attest",
]

from .core import attest, AttestResult
