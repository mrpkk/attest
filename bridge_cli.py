#!/usr/bin/env python3
"""
CLI моста BRIDGE — мост между агентом, заказчиком и деньгами.

Заказчик:
  bridge job    "сделай отчёт" --budget 5000000 --client maksim
  bridge check  <job-id>
  bridge release <job-id>      принять работу, отдать бюджет
  bridge refund  <job-id>      отклонить, вернуть бюджет

Агент:
  bridge jobs                   посмотреть открытые
  bridge deliver <job-id> --agent my-agent --file result.json

Третья сторона:
  bridge verify receipt.json --secret KEY            проверить без доступа к базе
  bridge verify receipt.json --file artifact.json    + сверить артефакт
  bridge trust some-agent                            репутация
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attest.bridge import Bridge  # noqa: E402

DEFAULT_DB = os.environ.get(
    "BRIDGE_DB", str(Path.home() / ".attest" / "bridge.json")
)


def _fmt_minor(amount: int, currency: str = "USDC") -> str:
    return f"{amount / 1_000_000:,.6f} {currency}"


def _open_db(args) -> Bridge:
    return Bridge(args.db, secret=os.environ.get("BRIDGE_SECRET", "bridge-dev-secret"))


def cmd_job(args) -> int:
    b = _open_db(args)
    spec = {}
    if args.spec:
        spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    job = b.new_job(
        title=args.title,
        spec=spec,
        amount_minor=args.budget,
        client=args.client,
        pay_to=args.pay_to or "",
    )
    print(f"Задача создана: {job.id}")
    print(f"  что:   {job.title}")
    print(f"  бюджет: {_fmt_minor(job.budget.amount_minor)} в эскроу")
    print(f"  сеть:   {job.budget.network}")
    print(f"  агент сдаёт: bridge deliver {job.id} --agent <id> --file result.json")
    return 0


def cmd_jobs(args) -> int:
    b = _open_db(args)
    jobs = b.list_jobs()
    if not jobs:
        print("Задач нет.")
        return 0
    print(f"{'ID':<14}{'СТАТУС':<12}{'БЮДЖЕТ':>16}  ЧТО")
    for j in jobs:
        print(f"{j['id']:<14}{j['status']:<12}{_fmt_minor(j['budget']['amount_minor']):>16}  {j['title'][:44]}")
    return 0


def cmd_check(args) -> int:
    b = _open_db(args)
    for j in b.list_jobs():
        if j["id"] == args.job_id:
            print(json.dumps(j, ensure_ascii=False, indent=2))
            return 0
    print(f"Задача {args.job_id} не найдена.", file=sys.stderr)
    return 1


def cmd_deliver(args) -> int:
    b = _open_db(args)
    artifact = json.loads(Path(args.file).read_text(encoding="utf-8"))
    receipt, verdict = b.deliver(args.job_id, args.agent, artifact)

    if args.out:
        Path(args.out).write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    print(f"RECEIPT: {receipt['body']['receipt_id']}")
    print(f"  вердикт: {'ПРИНЯТО' if verdict.accepted else 'ОТКАЗАНО'}")
    print(f"    по спецификации: {'ок' if verdict.spec_ok else 'не соответствует'}")
    print(f"    яд в артефакте:  {'ок' if verdict.poison_ok else 'ОБНАРУЖЕН'}")
    if verdict.detail.get("poison"):
        for hit in verdict.detail["poison"][:5]:
            kind = getattr(hit, "kind", hit)
            where = getattr(hit, "where", "")
            print(f"      - {kind} в {where}")
    print(f"  отпечаток: {receipt['body']['fingerprint'][:24]}")
    if args.out:
        print(f"  receipt сохранён: {args.out}")
    print(f"  заказчик может принять: bridge release {args.job_id}")
    return 0 if verdict.accepted else 2


def cmd_release(args) -> int:
    b = _open_db(args)
    budget = b.release(args.job_id)
    print(f"Бюджет {_fmt_minor(budget.amount_minor)} передан агенту {budget.pay_to or '(адрес не указан)'}")
    return 0


def cmd_refund(args) -> int:
    b = _open_db(args)
    budget = b.refund(args.job_id)
    print(f"Бюджет {_fmt_minor(budget.amount_minor)} возвращён заказчику")
    return 0


def cmd_verify(args) -> int:
    """Проверка receipt без доступа к базе — то, ради чего всё затевалось."""
    receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    secret = args.secret or os.environ.get("BRIDGE_SECRET", "bridge-dev-secret")
    artifact = None
    if args.file:
        artifact = json.loads(Path(args.file).read_text(encoding="utf-8"))
    result = Bridge.verify_receipt(receipt, secret, artifact)

    body = receipt.get("body", {})
    print(f"Работа: {body.get('job_title', '?')}")
    print(f"Агент: {body.get('agent', '?')}")
    print(f"  подпись:   {'ВЕРНА' if result['signature_ok'] else 'НЕВЕРНА'}")
    if result["fingerprint_ok"] is not None:
        print(f"  артефакт:  {'СОВПАДАЕТ' if result['fingerprint_ok'] else 'ИЗМЕНЁН'}")
    if result["reason"]:
        print(f"  причина:   {result['reason']}")
    return 0 if result["signature_ok"] else 1


def cmd_trust(args) -> int:
    t = Bridge.trust(args.agent, args.db)
    print(f"Агент: {t['agent']}")
    print(f"  сдач:     {t['deliveries']}")
    print(f"  принято:  {t['accepted']}")
    print(f"  отказов:  {t['rejected']}")
    print(f"  объём:    {_fmt_minor(t['volume_minor'])}")
    print(f"  доверие:  {t['trust_score'] * 100:.1f}%")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="bridge", description="Мост: агент → работа → деньги")
    ap.add_argument("--db", default=DEFAULT_DB, help="путь к базе моста")
    sub = ap.add_subparsers(dest="cmd", required=True)

    j = sub.add_parser("job", help="создать задачу с бюджетом в эскроу")
    j.add_argument("title")
    j.add_argument("--budget", type=int, required=True, help="в минорных единицах (1 USDC = 1000000)")
    j.add_argument("--client", required=True)
    j.add_argument("--pay-to", default="", help="адрес агента-получателя")
    j.add_argument("--spec", default="", help="JSON-файл со спецификацией")
    j.set_defaults(fn=cmd_job)

    jb = sub.add_parser("jobs", help="список задач")
    jb.set_defaults(fn=cmd_jobs)

    c = sub.add_parser("check", help="состояние задачи")
    c.add_argument("job_id")
    c.set_defaults(fn=cmd_check)

    d = sub.add_parser("deliver", help="агент сдаёт артефакт")
    d.add_argument("job_id")
    d.add_argument("--agent", required=True)
    d.add_argument("--file", required=True, help="JSON с артефактом")
    d.add_argument("--out", default="", help="куда сохранить receipt")
    d.set_defaults(fn=cmd_deliver)

    r = sub.add_parser("release", help="принять работу и отдать бюджет")
    r.add_argument("job_id")
    r.set_defaults(fn=cmd_release)

    rf = sub.add_parser("refund", help="отклонить и вернуть бюджет")
    rf.add_argument("job_id")
    rf.set_defaults(fn=cmd_refund)

    v = sub.add_parser("verify", help="проверить receipt без доступа к базе")
    v.add_argument("receipt")
    v.add_argument("--file", default="", help="артефакт для сверки отпечатка")
    v.add_argument("--secret", default="")
    v.set_defaults(fn=cmd_verify)

    t = sub.add_parser("trust", help="репутация агента по фактам сделок")
    t.add_argument("agent")
    t.set_defaults(fn=cmd_trust)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())