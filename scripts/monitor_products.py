#!/usr/bin/env python3
"""Мониторинг продуктов: один проход по живым адресам, алерт при падении.

    python3 scripts/monitor_products.py                  — проверить
    python3 scripts/monitor_products.py --json           — машинно
    python3 scripts/monitor_products.py --base https://attest.rta.lat --nip http://127.0.0.1:8291

Проверяются не «сервисы вообще», а точки, где покупатель встречает продукт: страница магазина,
бесплатный скан и платёжные страницы Site Guard / Sheet Doctor / Doc Box / Founding audit.
Алерт уходит тем же каналом, что и остальные (attest/alerts.py), с окном анти-спама.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

PRODUCTS = (
    ("attest /scan", "{attest}/scan"),
    ("attest /store", "{attest}/store"),
    ("Site Guard", "{nip}/pay/card?product=site-guard-year"),
    ("Sheet Doctor", "{nip}/pay/card?product=sheet-doctor"),
    ("Doc Answer Box", "{nip}/pay/card?product=doc-answer-box"),
    ("Founding audit", "{nip}/pay/card?product=agent-spend-audit-founding"),
)


def check_one(url: str, timeout: int = 8) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, ""
    except urllib.error.HTTPError as e:
        return e.code, f"http_{e.code}"
    except Exception as e:  # noqa: BLE001 — сеть/таймаут
        return 0, type(e).__name__


def run(attest: str, nip: str, fetch=check_one) -> dict:
    rows = []
    for name, tpl in PRODUCTS:
        url = tpl.format(attest=attest, nip=nip)
        code, err = fetch(url)
        rows.append({"name": name, "url": url, "code": code, "ok": code == 200, "error": err})
    bad = [r for r in rows if not r["ok"]]
    return {"checked": len(rows), "down": len(bad), "rows": rows, "ok": not bad}


def alert(failed: list[dict]) -> dict:
    """Одно сообщение на проход, а не по сообщению на каждую упавшую ссылку."""
    from attest import alerts

    detail = "; ".join(f"{r['name']} {r['code'] or r['error']}" for r in failed)
    return alerts.alert_down(f"продукты недоступны: {detail}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attest", default="http://127.0.0.1:8185")
    ap.add_argument("--nip", default="http://127.0.0.1:8291")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--alert", action="store_true", help="отправить алерт при падении")
    a = ap.parse_args()
    res = run(a.attest, a.nip)
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        for r in res["rows"]:
            print(("OK   " if r["ok"] else "FAIL ") + f"{r['code'] or r['error']:>12} · {r['name']}")
        print(f"итог: {res['checked'] - res['down']}/{res['checked']} живы")
    if not res["ok"] and a.alert:
        print("алерт:", alert([r for r in res["rows"] if not r["ok"]]))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
