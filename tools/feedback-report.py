#!/usr/bin/env python3
"""Отчёд по обратной связи с лендинга attest.

Читает append-only журнал отзывов и печатает сводку по страницам и
последние записи. Нужен, чтобы не ходить на сервер по SSH ради
двух строк комментария.

    python3 tools/feedback-report.py            # сводка + 20 последних
    python3 tools/feedback-report.py --limit 5  # только 5 последних
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

DEFAULT = Path(os.environ.get("ATTEST_STATE_DIR", Path.home() / ".local/share/attest")) / "feedback.jsonl"


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # битая строка не должна ронять весь отчёт
    return rows


def report(rows: list[dict], limit: int) -> str:
    if not rows:
        return "Отзывов пока нет."
    verdicts = Counter(r.get("verdict", "?") for r in rows)
    pages = Counter(r.get("page", "?") for r in rows)
    out = [
        f"Всего отзывов: {len(rows)}  (полезно {verdicts.get('up', 0)}, "
        f"бесполезно {verdicts.get('down', 0)})",
        "По страницам: " + ", ".join(f"{p} — {n}" for p, n in pages.most_common()),
        "",
    ]
    for r in rows[-limit:]:
        ts = r.get("ts")
        when = datetime.fromtimestamp(ts).strftime("%d.%m %H:%M") if isinstance(ts, (int, float)) else "?"
        mark = "👍" if r.get("verdict") == "up" else "👎"
        comment = (r.get("comment") or "").strip() or "—"
        out.append(f"{when}  {mark}  {r.get('page', '?'):12s}  {comment}")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=20, help="сколько последних записей показать")
    ap.add_argument("--path", type=Path, default=DEFAULT, help="путь к feedback.jsonl")
    args = ap.parse_args()
    print(report(load(args.path), args.limit))


if __name__ == "__main__":
    main()
