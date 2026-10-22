#!/usr/bin/env python3
"""Хостельные вызовы MCP-инструментов: ловят падения до isError.

Наблюдение (Arhan Canli, комментарий к статье на dev.to 22.10.2026):
`isError` работает только если ничто не бросает исключение ДО того, как
обработчик соберёт результат. Его find_tool падал на запросе "constructor":
обращение к свойству объекта возвращало собственный конструктор Object,
клиент видел протокольную ошибку вместо читаемого результата.

Проверяем наши инструменты тем же способом: constructor, proto, toString,
пустая строка, строка в 10 000 символов, и несколько форм payload.
Успех = ответ пришёл как результат (isError или нет), а не как -32603.

Запуск: python3 tools/hostile_mcp_check.py [url ...]
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

URLS = sys.argv[1:] or ["https://attest.rta.lat/mcp", "https://rta.lat/mcp"]

HOSTILE_STRINGS = ["constructor", "proto", "toString", "", "x" * 10000]
TOOLS = ["verify_artifact", "verify_artifact_batch", "bridge_check"]

PAYLOADS = [
    ("строка-имя", lambda s: {"artifact": s}),
    ("объект-имя", lambda s: {"artifact": {"findings": s}}),
    ("в списке", lambda s: {"artifacts": [s]}),
]


def call(url: str, tool: str, arguments: dict) -> tuple[str, str]:
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }).encode()
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "User-Agent": "hostile-check/1.0"}
    # Без ключа бесплатный лимит (20/сутки) кончается на середине проверки и
    # дальше приходит 402 — его нельзя отличить от падения. Поэтому здесь
    # используется entitlement-токен (100 вызовов).
    token = os.environ.get("ATTEST_ENTITLEMENT", "").strip()
    if token:
        headers["X-ATTEST-ENTITLEMENT"] = token
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "ignore")[:120]
        if exc.code == 429:
            return "ЛИМИТ", f"429 {body}"
        if exc.code == 402:
            return "БАРЬЕР", "402 free limit reached (нужен ключ)"
        return "HTTP-ОШИБКА", f"{exc.code} {body}"
    except Exception as exc:  # noqa: BLE001
        return "ИСКЛЮЧЕНИЕ", f"{type(exc).__name__}: {exc}"
    for line in raw.splitlines():
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" in d:
            code = d["error"].get("code")
            msg = str(d["error"].get("message"))[:110]
            return ("ПРОТОКОЛЬНАЯ-ОШИБКА" if code in (-32603, -32602, -32601)
                    else "ОШИБКА"), f"{code} {msg}"
        result = d.get("result")
        if isinstance(result, dict) and "content" in result:
            return "РЕЗУЛЬТАТ", "isError=%s" % result.get("isError")
        return "РЕЗУЛЬТАТ", json.dumps(result, ensure_ascii=False)[:90]
    return "НЕ-РАСПОЗНАНО", raw[:110]


PAUSE = 3.2  # лимит частоты: 20 вызовов в минуту


def main() -> int:
    bad = 0
    limited = 0
    total = 0
    for url in URLS:
        print(f"\n=== {url}")
        for tool in TOOLS:
            for label, make in PAYLOADS:
                for value in HOSTILE_STRINGS:
                    total += 1
                    status, detail = call(url, tool, make(value))
                    if status == "ЛИМИТ":
                        limited += 1
                        time.sleep(PAUSE)
                        continue
                    if status == "БАРЬЕР":
                        limited += 1
                        time.sleep(PAUSE)
                        continue
                    if status != "РЕЗУЛЬТАТ":
                        bad += 1
                        shown = (value[:24] + "…") if len(value) > 24 else repr(value)
                        print(f"  ПРОВАЛ {tool:22} {label:12} {shown:28} → {status}: {detail}")
                    time.sleep(PAUSE)
    print(f"\nвызовов: {total}, провалов: {bad}, ограничений лимитом: {limited}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
