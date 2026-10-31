#!/usr/bin/env python3
"""Выдать ключ пакета раннего доступа по заявке с /start.

Заявка приходит на страницу https://attest.rta.lat/start и складывается в
`~/.local/share/attest/leads.jsonl`. Этот скрипт берёт заявку, выпускает
подписанный токен на 100 проверок / 30 дней и печатает письмо, которое
осталось отправить (mail_send.py умеет отправлять).

Ключ выпускает агент, а не публичная форма: форма не может ни выдать
токен, ни положить его в письмо. Это осознанно — ключ выдаётся людям,
а не всем, кто умеет нажать кнопку.

Использование:
  python3 tools/issue-lead.py --list
  python3 tools/issue-lead.py team@example.com --note "scan results"
  python3 tools/issue-lead.py team@example.com --paid --days 30
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attest import entitlement  # noqa: E402

LEADS = Path.home() / ".local/share/attest/leads.jsonl"
EARLY_CALLS = 100
EARLY_DAYS = 30


def read_leads() -> list[dict]:
    if not LEADS.exists():
        return []
    out = []
    for line in LEADS.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def mail_text(email: str, token: str, calls: int, days: int) -> str:
    return f"""Hi,

Here is your early-access key for attest: {calls} artifact checks for {days} days.
No account, no card, no recurring charges.

Send it in the X-ATTEST-ENTITLEMENT header:

  curl -X POST https://attest.rta.lat/verify \\
    -H 'Content-Type: application/json' \\
    -H 'X-ATTEST-ENTITLEMENT: {token}' \\
    -d '{{"artifact": {{"findings": [{{"id": "f1", "title": "hello"}}]}}}}'

The same header works over MCP:

  {{"mcpServers": {{"attest": {{"url": "https://attest.rta.lat/mcp"}}}}}}

What you get per check: schema contract, emptiness, generation provenance and
mandate authority, with an Ed25519-signed verdict you can verify offline.

When the {days} days run out, the key stops working. $99/30 days keeps it running
($49 for India pricing) — or just keep using the free tier: 5 checks a day,
no signup.

If the checks do not help, tell us what you were trying to verify and we will
fix the tool rather than sell you more of it.

Maksim
attest — verification for AI agent artifacts
https://attest.rta.lat
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("email", nargs="?", help="почта заявителя")
    ap.add_argument("--list", action="store_true", help="показать заявки")
    ap.add_argument("--note", default="", help="что заявитель проверяет")
    ap.add_argument("--paid", action="store_true",
                    help="выдать обычную подписку (без лимита вызовов)")
    ap.add_argument("--calls", type=int, default=EARLY_CALLS)
    ap.add_argument("--days", type=int, default=EARLY_DAYS)
    args = ap.parse_args()

    if args.list or not args.email:
        leads = read_leads()
        if not leads:
            print("заявок нет:", LEADS)
            return 0
        print(f"заявок: {len(leads)}  ({LEADS})")
        for rec in leads:
            when = time.strftime("%Y-%m-%d %H:%M",
                                 time.localtime(rec.get("ts", 0)))
            print(f"  {rec.get('email','?'):<34} {when}  {rec.get('note','')[:60]}")
        return 0

    max_calls = None if args.paid else args.calls
    token = entitlement.issue(args.email, days=args.days, max_calls=max_calls)
    print("=== письмо ===")
    print(mail_text(args.email, token["token"],
                    args.calls if max_calls else 0, args.days))
    print("=== токен (для отправки) ===")
    print(token["token"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
