"""Пакет квитанций: канонизация (JCS) и схема `noa.receipt/0.1`.

Профиль: draft-noa-scitt-ai-agent-receipt (IETF SCITT). Шаги S1–S4 канона
`docs/SPEC-VARUNA.md`. Никаких сетевых вызовов: проверка должна работать
без сети и без нас.
"""

from __future__ import annotations

from . import jcs, schema

__all__ = ["jcs", "schema"]
