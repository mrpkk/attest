#!/usr/bin/env python3
"""Сторож продуктов: касса + то, что реально доставляет.

Зачем. У каждого товара два места, где он может сломаться: страница оплаты в кассе
и механизм доставки. Проверять только `/health` attest мало — он не знает, что
касса перестала отдавать `site-guard-year` или что Sheet Doctor больше не чистит файл.

    python3 scripts/products_watchdog.py            # проверить и сказать
    python3 scripts/products_watchdog.py --quiet    # только при проблеме (для cron)
    python3 scripts/products_watchdog.py --json

Тревога — в Slack-совместимый webhook из `ATTEST_SLACK_WEBHOOK` (см. attest/alerts.py).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import alerts  # noqa: E402

CASHIER = "https://nidhipati.ailegal.legal/pay/card?product="
STATE = ROOT / "data" / "products_watchdog.json"

#: slug в кассе → что ещё проверять кроме страницы оплаты.
PRODUCTS: dict[str, str] = {
    "site-guard-year": "site_guard",       # реальные проверки сайтов клиентов
    "sheet-doctor": "sheet_doctor",        # скрипт действительно чистит файл
    "doc-answer-box": "pay_only",          # доставка вручную, проверяем кассу
    "channel-vault-export": "not_built",   # продукт ещё не готов — так и помечаем
}


def http_code(url: str, timeout: int = 15) -> int:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "attest-products/1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except Exception:  # noqa: BLE001
        return 0


def site_guard_ok() -> tuple[bool, str]:
    """Живые проверки зарегистрированных сайтов (то, что продаём за $49/год)."""
    try:
        sys.path.insert(0, str(ROOT))
        from attest import site_guard

        sites = site_guard.load()
        if not sites:
            return False, "нет зарегистрированных сайтов"
        bad = []
        for site in sites:
            ok, code, detail = site_guard.check_http(site["url"])
            if not ok:
                bad.append(f"{site['url']} → {code or detail[:40]}")
        return (not bad), ("; ".join(bad) if bad else f"{len(sites)} сайтов отвечают")
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"[:120]


def sheet_doctor_ok() -> tuple[bool, str]:
    """Скрипт чистки должен переживать свой собственный пример."""
    script = Path("/media/Sruti/iamthat/work/sales/sheet-doctor/sheet_doctor.py")
    sample = script.parent / "messy.csv"
    if not script.exists() or not sample.exists():
        return False, "нет скрипта или примера"
    try:
        res = subprocess.run([sys.executable, str(script), str(sample), "--out", "/tmp/opencode/sd_check.csv"],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}"
    return (res.returncode == 0), (res.stderr or res.stdout or "")[:120].strip()


def check_products() -> dict:
    results: dict[str, dict] = {}
    for slug, kind in PRODUCTS.items():
        code = http_code(CASHIER + slug)
        entry = {"cashier": code, "ok": code == 200, "kind": kind, "detail": ""}
        if kind == "site_guard":
            ok, detail = site_guard_ok()
            entry.update(ok=entry["ok"] and ok, detail=detail)
        elif kind == "sheet_doctor":
            ok, detail = sheet_doctor_ok()
            entry.update(ok=entry["ok"] and ok, detail=detail)
        elif kind == "not_built":
            # Касса отдаёт страницу, но продукта нет: это честное состояние,
            # а не сбой. Следим только за тем, чтобы не начали продавать молча.
            entry["detail"] = "продукт не собран — продажа только через waitlist"
        results[slug] = entry
    broken = {slug: e for slug, e in results.items() if not e["ok"] and e["kind"] != "not_built"}
    return {"products": results, "broken": broken, "ok": not broken}


def run_once(state_path: Path = STATE, send=None) -> dict:
    state: dict = {}
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        pass
    res = check_products()
    previous = state.get("status")
    status = "ok" if res["ok"] else "down"
    alert = None
    sender = send or (lambda text: alerts.post(text))
    if status == "down" and previous != "down":
        detail = "; ".join(f"{slug}: {'касса ' + str(e['cashier']) if e['cashier'] != 200 else e['detail']}"
                           for slug, e in res["broken"].items())
        alert = sender(f"🔴 Продукты: сломано {len(res['broken'])} — {detail}")
    elif status == "ok" and previous == "down":
        alert = sender("🟢 Продукты снова в порядке: касса и доставка отвечают.")
    state.update({"status": status, "checked_at": int(time.time()), **res})
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, ensure_ascii=False))
    except OSError:
        pass
    return {"status": status, **res, "alert": alert}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = run_once()
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    elif not a.quiet or res["status"] != "ok":
        for slug, entry in res["products"].items():
            mark = "✓" if entry["ok"] else "✗"
            extra = f" · {entry['detail']}" if entry["detail"] else ""
            print(f"  {mark} {slug}: касса {entry['cashier']}{extra}")
        print("итог: " + ("все продукты живы" if res["ok"] else f"сломано: {len(res['broken'])}"))
        if res["alert"] is not None:
            print(f"  тревога: {'доставлена' if res['alert'][0] else res['alert'][1]}")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
