"""Привязка личности: кто именно действовал — и чего эта привязка не доказывает.

Профиль: draft-noa-scitt-ai-agent-receipt, §6 и §6.1.

Тонкость, на которой эталонная реализация ошибается в обе стороны (G21):

* подпись внутри квитанции (`sig.kid`, «нативная») называет **агента**;
* подпись конверта (внешняя) называет **того, кто переслал** документ.

Эталон сверяет манифест с внешней подписью. Следствия, измеренные на живых
байтах: законный релей отвергается («агент не авторизован для ключа релея»),
а подмена проходит (нативная подпись чужим ключом внутри конверта, подписанного
авторизованным ключом, принимается).

Здесь наоборот: манифест сверяется с нативной подписью, релей разрешён,
подмена — отказ.

И честная граница: без манифеста привязка остаётся на уровне ключа — «подписал
какой-то ключ, которому доверяет проверяющий», и ничего про то, какой это агент.
Это не мелкая оговорка; читатель должен видеть, где кончается доказанное.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import jcs

MANIFEST_SPEC = "noa.identity-manifest/0.1"


@dataclass
class Attribution:
    status: str  # authorized | unauthorized | key-level-only | malformed
    agent_id: str = ""
    native_kid: str = ""
    envelope_kid: str | None = None
    notes: list[str] = field(default_factory=list)

    def why(self) -> str:
        return "; ".join(self.notes)


def load_manifest(raw: bytes | str | dict | None) -> dict[str, list[str]] | None:
    """Разобрать манифест. Формат вне профиля (§1.5), поэтому свой и простой:
    `{"spec": ..., "agents": {"<agent id>": ["<kid>", ...]}}`."""
    if raw is None:
        return None
    data = jcs.loads(raw) if isinstance(raw, (bytes, str)) else raw
    if not isinstance(data, dict):
        raise ValueError("manifest must be an object")
    if data.get("spec") != MANIFEST_SPEC:
        raise ValueError(f"manifest spec must be {MANIFEST_SPEC!r}")
    agents = data.get("agents")
    if not isinstance(agents, dict):
        raise ValueError("manifest.agents must be an object")
    out: dict[str, list[str]] = {}
    for agent, kids in agents.items():
        if not isinstance(agent, str) or not isinstance(kids, list):
            raise ValueError("manifest.agents maps an agent id to a list of kid strings")
        if not all(isinstance(k, str) and k for k in kids):
            raise ValueError("authorized key identifiers must be non-empty strings")
        out[agent] = list(kids)
    return out


def check_attribution(
    receipt: dict,
    manifest: dict[str, list[str]] | None,
    *,
    envelope_kid: str | None = None,
) -> Attribution:
    agent_id = str((receipt.get("agent") or {}).get("id", ""))
    native_kid = str((receipt.get("sig") or {}).get("kid", ""))
    notes: list[str] = []

    if envelope_kid and envelope_kid != native_kid:
        # Релей — законная передача: подпись внутри не его, он только переслал.
        notes.append("relayed: the envelope was emitted by another key; that is allowed")
    if envelope_kid and envelope_kid == native_kid:
        notes.append("the envelope and the receipt were signed by the same key")

    if manifest is None:
        return Attribution("key-level-only", agent_id, native_kid, envelope_kid,
                           notes + ["no manifest: attribution is key-level only, "
                                    "not an identity claim about the agent"])

    allowed = manifest.get(agent_id)
    if allowed is None:
        return Attribution("unauthorized", agent_id, native_kid, envelope_kid,
                           notes + [f"agent {agent_id!r} is not in the manifest"])
    if native_kid not in allowed:
        # Подмена: конверт мог быть подписан авторизованным ключом, но запись
        # внутри — нет. Решает нативная подпись.
        return Attribution("unauthorized", agent_id, native_kid, envelope_kid,
                           notes + [f"key {native_kid!r} is not authorized for agent {agent_id!r}"])
    return Attribution("authorized", agent_id, native_kid, envelope_kid, notes)
