#!/usr/bin/env python3
"""Снимок воронки: метрики + дельта к прошлому снимку.

Зачем: «воронка не поехала» — это не число, а отсутствие изменений. Снимок
каждые сутки показывает, что именно сдвинулось: просмотры по каналам,
проверки, заявки на пакет, выручка, повторные использования.

Запуск: python3 tools/funnel-snapshot.py
Файлы: ~/.local/share/attest/funnel/<время>.json
"""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

BASE = "https://attest.rta.lat"
OUT = Path.home() / ".local/share/attest/funnel"
UA = "Mozilla/5.0 (X11; Linux x86_64) attest-funnel-snapshot"


def fetch() -> dict:
    req = urllib.request.Request(f"{BASE}/metrics", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        m = fetch()
    except Exception as exc:  # noqa: BLE001
        print(f"метрики не получились: {type(exc).__name__}: {exc}")
        return 1

    prev = None
    snaps = sorted(OUT.glob("*.json"))
    if snaps:
        try:
            prev = json.loads(snaps[-1].read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            prev = None

    now = {
        "ts": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "views_total": m.get("listing_views_total", 0),
        "views_by_channel": m.get("listing_views", {}),
        "checks_total": m.get("checks_total", 0),
        "checks_paid": m.get("checks_paid", 0),
        "revenue_usdc": m.get("revenue_usdc", "0"),
        "unique_payers": m.get("unique_payers", 0),
        "repeat_usage_7d": m.get("repeat_usage_7d", 0),
        "leads_total": m.get("leads_total", 0),
        "feedback": m.get("feedback", {}),
    }
    path = OUT / (time.strftime("%Y%m%d-%H%M") + ".json")
    path.write_text(json.dumps(now, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"снимок: {path.name}")
    if prev:
        def d(key: str) -> int:
            return int(now.get(key, 0)) - int(prev.get(key, 0))
        print(f"  просмотры: {now['views_total']} (+{d('views_total')})")
        print(f"  проверки:  {now['checks_total']} (+{d('checks_total')})")
        print(f"  оплачено:  {now['checks_paid']} (+{d('checks_paid')})")
        print(f"  заявки:    {now['leads_total']} (+{d('leads_total')})")
        print(f"  выручка:   {now['revenue_usdc']} USDC")
        print(f"  платящих:  {now['unique_payers']} | повторных: {now['repeat_usage_7d']}")
    else:
        print(json.dumps(now, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
