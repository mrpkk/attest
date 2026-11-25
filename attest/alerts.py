"""Алерты attest: падение и всплеск ошибок → Slack-совместимый webhook.

Зачем. Сервис живёт без присмотра; «упало» и «сыпет 500-ми» до сих пор замечал
только тот, кто сам зашёл на /health. Здесь два сигнала:

* `watchdog.py` — внешний проход: /health и /verify отвечают не 200 → тревога;
* `alert_errors()` — внутренний счётчик 5xx: если за окно их больше порога,
  сообщение уходит один раз за окно, а не на каждый запрос.

Транспорт — Slack incoming webhook (`{"text": "..."}`), потому что он же
принимается Mattermost и большинством «slack-compatible» приёмников. Адрес
берётся из `ATTEST_SLACK_WEBHOOK` в `~/.env`; без него алерты пишутся в лог и
считаются недоставленными — молчания не изображаем.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("attest.alerts")

ENV_KEY = "ATTEST_SLACK_WEBHOOK"
ERROR_WINDOW_SECONDS = 300.0
ERROR_THRESHOLD = 5
_state = {"sent_at": 0.0, "errors": [], "down_sent_at": 0.0}


def _env_value(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if value:
        return value
    try:
        for line in (Path.home() / ".env").read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def webhook_configured() -> bool:
    return bool(_env_value(ENV_KEY))


def _transient(reason: str) -> bool:
    """Стоит ли повторять: сеть, таймаут, 429 и 5xx — да; 4xx (кроме 429) — нет, повтор бесполезен."""
    if reason.startswith("http_"):
        code = int(reason.split("_", 1)[1] or 0)
        return code == 429 or 500 <= code < 600
    return True


def post(text: str, url: str | None = None, timeout: int = 10,
         attempts: int = 2, retry_delay: float = 2.0) -> tuple[bool, str]:
    """Отправить сообщение. (доставлено, причина отказа) — без исключений наружу.

    Один повтор на транзиентную ошибку (сеть, 429, 5xx): webhook-приёмники падают и
    восстанавливаются, а потерянный алерт — это «тишина вместо тревоги» (26.11.2026).
    """
    target = url or _env_value(ENV_KEY)
    if not target:
        log.warning("alert без webhook: %s", text[:200])
        return False, "webhook_not_configured"
    payload = json.dumps({"text": text[:1900]}).encode("utf-8")
    req = urllib.request.Request(
        target, data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "attest-alerts/1"})
    reason = ""
    for attempt in range(max(1, attempts)):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if 200 <= resp.status < 300:
                    return True, ""
                reason = f"http_{resp.status}"
        except urllib.error.HTTPError as exc:
            reason = f"http_{exc.code}"
        except Exception as exc:  # noqa: BLE001 — сеть/таймаут: алерт не должен ронять сервис
            reason = f"{type(exc).__name__}"
        if attempt + 1 < max(1, attempts) and _transient(reason) and retry_delay > 0:
            time.sleep(retry_delay)
        elif not _transient(reason):
            break
    return False, reason


def alert_errors(count: int = 1, now: float | None = None,
                 threshold: int = ERROR_THRESHOLD, url: str | None = None) -> dict:
    """Учесть `count` ошибок 5xx; при превышении порога — одно сообщение за окно."""
    now = time.time() if now is None else now
    recent = [t for t in _state["errors"] if now - t <= ERROR_WINDOW_SECONDS]
    recent.extend([now] * max(1, int(count)))
    _state["errors"] = recent
    if len(recent) < threshold:
        return {"sent": False, "reason": "below_threshold", "errors": len(recent)}
    if now - _state["sent_at"] < ERROR_WINDOW_SECONDS:
        return {"sent": False, "reason": "already_sent", "errors": len(recent)}
    ok, why = post(
        f"⚠️ attest: {len(recent)} ошибок 5xx за {int(ERROR_WINDOW_SECONDS // 60)} мин. "
        f"Проверить: https://attest.rta.lat/stats и journalctl -u attest", url=url)
    if ok:
        _state["sent_at"] = now
    return {"sent": ok, "errors": len(recent), "reason": why or "sent"}


def alert_down(reason: str = "", now: float | None = None,
               cooldown: float = 900.0, url: str | None = None) -> dict:
    """Сервис недоступен/не отвечает: одно сообщение за 15 минут, а не каждую минуту.

    Отдельный счётчик от алертов 5xx: падение сервиса и всплеск ошибок — разные события,
    и глушить одно другим нельзя.
    """
    now = time.time() if now is None else now
    if now - _state["down_sent_at"] < cooldown:
        return {"sent": False, "reason": "already_sent"}
    ok, why = post(f"🔴 attest DOWN: {reason[:160] or 'health недоступен'} · "
                   f"проверить: systemctl --user status attest, journalctl -u attest", url=url)
    if ok:
        _state["down_sent_at"] = now
    return {"sent": ok, "reason": why or "sent"}


def status() -> dict:
    """Что видно снаружи: настроен ли канал и когда последний раз что-то уходило."""
    return {"webhook_configured": webhook_configured(),
            "last_error_alert_at": _state["sent_at"] or None,
            "last_down_alert_at": _state["down_sent_at"] or None}


def reset() -> None:
    """Сбросить состояние (для тестов и для нового окна)."""
    _state["sent_at"] = 0.0
    _state["down_sent_at"] = 0.0
    _state["errors"] = []
