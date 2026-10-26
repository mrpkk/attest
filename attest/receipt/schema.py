"""Схема квитанции `noa.receipt/0.1` и правила, которые отклоняют ложь.

Профиль: draft-noa-scitt-ai-agent-receipt (IETF, SCITT), §3.

Что здесь решается и почему именно так:

* **Объект закрыт.** Незнакомое поле — отказ, а не «игнорируем». Иначе две
  реализации по-разному считают хеш одного документа.
* **Тип проверяется до сравнения.** `true` — не `1`, `"1"` — не `1`.
* **Противоречие внутри записи — отказ.** Квитанция не может одновременно
  говорить «симуляция» и «выполнено»: читатель не должен выбирать, какому
  маркеру верить. Это дефекты G1/G2 эталонной реализации, измеренные на живых
  байтах (все пять верификаторов вернули VALID).
* **Дата проверяется по существу.** `2026-13-45T99:99:99Z` совпадает по форме
  и лежит вне календаря; это дефект G3, и он тоже проходил везде.

Модуль не проверяет подписи и цепь — это следующий шаг (S2/S3). Здесь только
то, что можно решить по одному объекту.
"""

from __future__ import annotations

import calendar
import re
from dataclasses import dataclass, field
from typing import Any

SPEC = "noa.receipt/0.1"
MAX_ID = 128

PRINCIPAL = {"HUMAN", "SERVICE", "POLICY", "SANDBOX_SIM"}
VERDICT = {"ALLOWED", "BLOCKED", "DEFERRED", "EXECUTED", "FAILED", "ROLLED_BACK", "SIMULATED"}
RISK = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "IRREVERSIBLE"}
MODE = {"off", "shadow", "approvals_on", "on"}
COMPLIANCE_VERDICT = {"ALLOW", "DENY"}

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HMAC_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
# RFC 3339: дата, время, дробная часть 1..9, Z или ±ЧЧ:ММ. Секунда 60 запрещена профилем.
TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$"
)


@dataclass
class Rejection:
    path: str
    rule: str
    detail: str


@dataclass
class Check:
    ok: bool
    rejections: list[Rejection] = field(default_factory=list)

    def why(self) -> str:
        return "; ".join(f"{r.path}: {r.rule} ({r.detail})" for r in self.rejections)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def valid_timestamp(text: Any) -> tuple[bool, str]:
    """Проверить RFC 3339 по существу, а не по форме."""
    if not isinstance(text, str):
        return False, "not a string"
    m = TS_RE.match(text)
    if not m:
        return False, "not RFC 3339"
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    if not 1 <= month <= 12:
        return False, f"month {month} outside 1..12"
    last = calendar.monthrange(year, month)[1]
    if not 1 <= day <= last:
        return False, f"day {day} outside 1..{last}"
    if hour > 23:
        return False, f"hour {hour} outside 0..23"
    if minute > 59:
        return False, f"minute {minute} outside 0..59"
    if second > 59:
        # Профиль прямо запрещает представление секунды 60: без таблицы
        # високосных секунд офлайн-проверяющий не может решить, валидна она или нет.
        return False, "second 60 is forbidden by the profile"
    offset = m.group(8)
    if offset and offset not in ("Z", "z"):
        oh, om = int(offset[1:3]), int(offset[4:6])
        if oh > 23 or om > 59:
            return False, f"offset {offset} out of range"
    return True, ""


def check(receipt: Any) -> Check:
    rej: list[Rejection] = []

    def bad(path: str, rule: str, detail: str = "") -> None:
        rej.append(Rejection(path, rule, detail))

    if not isinstance(receipt, dict):
        return Check(False, [Rejection("$", "type", "receipt must be an object")])

    allowed = {"spec", "id", "ts", "scope", "agent", "action", "governance", "chain", "sig"}
    for key in receipt:
        if key not in allowed:
            bad(f"$.{key}", "closed-object", "unknown member is rejected, not ignored")

    if receipt.get("spec") != SPEC:
        bad("$.spec", "literal", f"expected {SPEC!r}, no version negotiation")

    rid = receipt.get("id")
    if not isinstance(rid, str) or not rid:
        bad("$.id", "non-empty-string")
    elif len(rid) > MAX_ID:
        bad("$.id", "length", f"{len(rid)} code points > {MAX_ID}")

    ok_ts, why_ts = valid_timestamp(receipt.get("ts"))
    if not ok_ts:
        bad("$.ts", "rfc3339", why_ts)

    scope = receipt.get("scope")
    if not isinstance(scope, dict):
        bad("$.scope", "type", "object required")
        scope = {}
    for key in scope:
        if key not in {"tenant", "chain"}:
            bad(f"$.scope.{key}", "closed-object")
    if not isinstance(scope.get("chain"), str) or not scope.get("chain"):
        bad("$.scope.chain", "non-empty-string")
    if "tenant" in scope and not isinstance(scope["tenant"], str):
        bad("$.scope.tenant", "type", "string when present")

    agent = receipt.get("agent")
    if not isinstance(agent, dict):
        bad("$.agent", "type", "object required")
        agent = {}
    for key in agent:
        if key not in {"id", "model", "principal"}:
            bad(f"$.agent.{key}", "closed-object")
    if not isinstance(agent.get("id"), str) or not agent.get("id"):
        bad("$.agent.id", "non-empty-string")
    if "model" in agent and agent["model"] is not None and not isinstance(agent["model"], str):
        bad("$.agent.model", "type", "string or null")
    if agent.get("principal") not in PRINCIPAL:
        bad("$.agent.principal", "vocabulary", f"one of {sorted(PRINCIPAL)}")

    action = receipt.get("action")
    if not isinstance(action, dict):
        bad("$.action", "type", "object required")
        action = {}
    for key in action:
        if key not in {"id", "canonical", "riskClass", "paramsHash", "reversible", "rollbackRef"}:
            bad(f"$.action.{key}", "closed-object")
    for name in ("id", "canonical"):
        if not isinstance(action.get(name), str) or not action.get(name):
            bad(f"$.action.{name}", "non-empty-string")
    if action.get("riskClass") not in RISK:
        bad("$.action.riskClass", "vocabulary", f"one of {sorted(RISK)}")
    params = action.get("paramsHash")
    if not isinstance(params, str) or not (HASH_RE.match(params) or HMAC_RE.match(params)):
        bad("$.action.paramsHash", "digest", "sha256:<64 lowercase hex> or hmac-sha256:<64 lowercase hex>")
    if not isinstance(action.get("reversible"), bool):
        bad("$.action.reversible", "type", "boolean literal")
    if "rollbackRef" in action and action["rollbackRef"] is not None and not isinstance(action["rollbackRef"], str):
        bad("$.action.rollbackRef", "type", "string or null")

    gov = receipt.get("governance")
    if not isinstance(gov, dict):
        bad("$.governance", "type", "object required")
        gov = {}
    for key in gov:
        if key not in {"mode", "verdict", "sandboxed", "ruleId", "approval", "compliance"}:
            bad(f"$.governance.{key}", "closed-object")
    if gov.get("mode") not in MODE:
        bad("$.governance.mode", "vocabulary", f"one of {sorted(MODE)}")
    if gov.get("verdict") not in VERDICT:
        bad("$.governance.verdict", "vocabulary", f"one of {sorted(VERDICT)}")
    if not isinstance(gov.get("sandboxed"), bool):
        bad("$.governance.sandboxed", "type", "boolean literal")

    approval = gov.get("approval")
    if approval is not None:
        if not isinstance(approval, dict):
            bad("$.governance.approval", "type", "object or null")
        else:
            for key in approval:
                if key not in {"by", "at"}:
                    bad(f"$.governance.approval.{key}", "closed-object")
            if not isinstance(approval.get("by"), str):
                bad("$.governance.approval.by", "type", "string")
            ok_at, why_at = valid_timestamp(approval.get("at"))
            if not ok_at:
                bad("$.governance.approval.at", "rfc3339", why_at)

    comp = gov.get("compliance")
    if comp is not None:
        if not isinstance(comp, dict):
            bad("$.governance.compliance", "type", "object or null")
        else:
            for key in comp:
                if key not in {"policyHash", "readSetHash", "inputsHash", "verdict"}:
                    bad(f"$.governance.compliance.{key}", "closed-object")
            for name in ("policyHash", "readSetHash", "inputsHash"):
                value = comp.get(name)
                if not isinstance(value, str) or not HASH_RE.match(value):
                    bad(f"$.governance.compliance.{name}", "digest", "sha256:<64 lowercase hex>")
            if "verdict" in comp and comp["verdict"] not in COMPLIANCE_VERDICT:
                bad("$.governance.compliance.verdict", "vocabulary", "ALLOW or DENY")

    chain = receipt.get("chain")
    if not isinstance(chain, dict):
        bad("$.chain", "type", "object required")
        chain = {}
    for key in chain:
        if key not in {"seq", "prevHash", "hash"}:
            bad(f"$.chain.{key}", "closed-object")
    seq = chain.get("seq")
    if not _is_int(seq) or seq < 0:
        bad("$.chain.seq", "integer", "integer >= 0")
    for name in ("prevHash", "hash"):
        value = chain.get(name)
        if name == "prevHash" and value is None:
            continue
        if not isinstance(value, str) or not HASH_RE.match(value):
            bad(f"$.chain.{name}", "digest", "sha256:<64 lowercase hex>" + (" or null at genesis" if name == "prevHash" else ""))

    sig = receipt.get("sig")
    if not isinstance(sig, dict):
        bad("$.sig", "type", "object required")
        sig = {}
    for key in sig:
        if key not in {"alg", "kid", "value"}:
            bad(f"$.sig.{key}", "closed-object")
    if sig.get("alg") != "ed25519":
        bad("$.sig.alg", "literal", "exact lowercase 'ed25519'")
    for name in ("kid", "value"):
        if not isinstance(sig.get(name), str) or not sig.get(name):
            bad(f"$.sig.{name}", "non-empty-string")

    # --- правила совместимости (G1, G2) -------------------------------------
    simulated_by_principal = agent.get("principal") == "SANDBOX_SIM"
    simulated_by_verdict = gov.get("verdict") == "SIMULATED"
    if (simulated_by_principal or simulated_by_verdict) and gov.get("sandboxed") is False:
        bad("$.governance.sandboxed", "cross-field",
            "must be true when principal is SANDBOX_SIM or verdict is SIMULATED")

    if action.get("rollbackRef") not in (None, ) and action.get("reversible") is not True:
        bad("$.action.rollbackRef", "cross-field", "only allowed when reversible is true")
    if gov.get("verdict") == "ROLLED_BACK" and action.get("reversible") is not True:
        bad("$.governance.verdict", "cross-field", "ROLLED_BACK requires reversible: true")

    return Check(not rej, rej)
