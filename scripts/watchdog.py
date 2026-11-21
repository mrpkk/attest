#!/usr/bin/env python3
"""Внешний сторож attest: /health и /verify → тревога в Slack при смене состояния.

Почему отдельным процессом: если сервис лежит, он сам о себе не сообщит. Сторож
ходит снаружи, помнит прошлое состояние и пишет **один раз** на падение и один раз
на возврат — иначе тревога превращается в спам.

    python3 scripts/watchdog.py              # проверить и, если надо, сообщить
    python3 scripts/watchdog.py --quiet      # только при проблеме (для cron)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import alerts  # noqa: E402

BASE = "https://attest.rta.lat"
# Проверяем не только «жив», но и путь продажи: страница бесплатного скана и
# счётчик воронки. Упавший /free-scan — это потерянный покупатель, а /health при
# этом может отвечать 200.
CHECKS = ("/health", "/free-scan", "/api/funnel")
STATE = ROOT / "data" / "watchdog.json"


def probe(url: str, timeout: int = 12) -> int:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "attest-watchdog/1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except Exception:  # noqa: BLE001 — сеть/таймаут
        return 0


def check(base: str = BASE, probes=None) -> dict:
    results = {path: (probes or probe)(f"{base}{path}") for path in CHECKS}
    bad = {path: code for path, code in results.items() if code != 200}
    return {"ok": not bad, "results": results, "bad": bad}


def run_once(state_path: Path = STATE, base: str = BASE, probes=None,
             send=None) -> dict:
    state = {}
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        pass
    res = check(base, probes)
    status = "ok" if res["ok"] else "down"
    previous = state.get("status")
    sent = None
    sender = send or (lambda text: alerts.post(text))

    if status == "down" and previous != "down":
        detail = ", ".join(f"{p} → {c}" for p, c in res["bad"].items())
        sent = sender(f"🔴 attest недоступен: {detail}. Проверить: "
                      f"systemctl status attest; journalctl -u attest -n 40")
    elif status == "ok" and previous == "down":
        sent = sender("🟢 attest снова отвечает 200.")

    state.update({"status": status, "checked_at": int(time.time()),
                  "results": res["results"]})
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, ensure_ascii=False))
    except OSError:
        pass
    return {"status": status, **res, "alert": sent}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = run_once()
    if a.json:
        print(json.dumps(res, ensure_ascii=False))
    elif not a.quiet or res["status"] != "ok":
        print(f"attest: {res['status']}")
        for path, code in res["results"].items():
            print(f"  {path} → {code}")
        if res["alert"] is not None:
            print(f"  тревога: {'доставлена' if res['alert'][0] else res['alert'][1]}")
    return 0 if res["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
