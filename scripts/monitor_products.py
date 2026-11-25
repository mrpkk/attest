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
    # 26.11.2026: свой же сторож получал 403 на /scan и /store — фильтр режет `Python-urllib`.
    # Монитор ходит под своим именем, как watchdog, иначе он врёт про падение продукта.
    req = urllib.request.Request(url, headers={"User-Agent": "attest-products-monitor/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
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


STATE = __import__("pathlib").Path(__file__).resolve().parents[1] / "data" / "products_monitor.json"


def alert(failed: list[dict]) -> dict:
    """Одно сообщение на проход, а не по сообщению на каждую упавшую ссылку."""
    from attest import alerts

    detail = "; ".join(f"{r['name']} {r['code'] or r['error']}" for r in failed)
    ok, why = alerts.post(f"🔴 продукт недоступен: {detail} · открыть: "
                          f"{failed[0]['url'] if failed else '—'}")
    return {"sent": ok, "reason": why or "sent"}


def _load_state(path) -> dict:
    try:
        return json.loads(__import__("pathlib").Path(path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — нет файла/битый JSON: начинаем с чистого состояния
        return {}


def _save_state(path, state: dict) -> None:
    p = __import__("pathlib").Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


def notify(res: dict, state_path=None, now: float | None = None, repeat_after: float = 6 * 3600.0) -> dict:
    """Алерт на смену состояния, а не на каждый проход.

    Процесс таймера каждый раз новый, поэтому «одно сообщение за окно» из alerts.py здесь
    не работает: кулдаун живёт в памяти процесса. Состояние храним в файле (26.11.2026):
    упало — одно сообщение; лежит — напоминание раз в 6 часов; поднялось — одно «снова».
    """
    import time

    now = time.time() if now is None else now
    state = _load_state(state_path) if state_path else {}
    down = not res["ok"]
    was_down = bool(state.get("down"))
    last = float(state.get("last_alert_at") or 0)
    failed = [r for r in res["rows"] if not r["ok"]]
    out = {"sent": False, "reason": "state_changed"}

    if down and (not was_down or now - last >= repeat_after):
        out = alert(failed)
    elif down:
        out = {"sent": False, "reason": "already_reported"}
    elif was_down:
        from attest import alerts
        ok, why = alerts.post("🟢 продукты снова отвечают 200")
        out = {"sent": ok, "reason": why or "sent"}

    # 26.11.2026: состояние пишем и когда отправка не удалась. Иначе после падения без канала
    # флаг «down» остаётся навсегда и следующий проход начинает спамить при каждом запуске.
    if down != was_down or out.get("sent"):
        state = {"down": down, "last_alert_at": now if out.get("sent") else last,
                 "last_attempt_at": now,
                 "names": [r["name"] for r in failed] if down else []}
        if state_path:
            _save_state(state_path, state)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attest", default="http://127.0.0.1:8185")
    ap.add_argument("--nip", default="http://127.0.0.1:8291")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--alert", action="store_true", help="отправить алерт при падении")
    ap.add_argument("--state", default=str(STATE), help="файл состояния: алерт на смену, не на каждый проход")
    a = ap.parse_args()
    res = run(a.attest, a.nip)
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        for r in res["rows"]:
            print(("OK   " if r["ok"] else "FAIL ") + f"{r['code'] or r['error']:>12} · {r['name']}")
        print(f"итог: {res['checked'] - res['down']}/{res['checked']} живы")
    if a.alert:
        print("алерт:", notify(res, state_path=a.state))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
