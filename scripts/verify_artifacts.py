#!/usr/bin/env python3
"""Проверка артефактов в CI: один вызов attest на файл, код возврата решает судьбу сборки.

Зачем: разовая проверка в браузере не возвращает клиента. Проверка в пайплайне —
возвращает: она стоит в сборке и работает каждый коммит.

Зависимостей нет (urllib), поэтому запускается на голом python в любом раннере.

Использование:
    python3 scripts/verify_artifacts.py 'reports/*.json'
    python3 scripts/verify_artifacts.py 'reports/*.json' --schema schema.json --fail-on any
    python3 scripts/verify_artifacts.py 'reports/*.json' --json > verdicts.json

Код возврата: 0 — все приняты, 1 — есть отказ, 2 — ошибка вызова.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_URL = os.getenv("ATTEST_URL", "https://attest.rta.lat/verify")


def verify_one(path: Path, schema: dict | None, url: str) -> dict:
    """Отправить один артефакт. Ошибка сети — это ошибка, а не «принято»."""
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"file": str(path), "verdict": "error", "trust_score": 0,
                "reason": f"not valid JSON: {type(exc).__name__}"}
    payload: dict = {"artifact": artifact, "source": path.name}
    if schema:
        payload["schema"] = schema
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 # Cloudflare отвечает 403 (1010) на пустой User-Agent.
                 "User-Agent": "attest-ci/1.0 (+https://attest.rta.lat)"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        # 402 = исчерпан бесплатный лимит; это не «артефакт плохой».
        return {"file": str(path), "verdict": "error", "trust_score": 0,
                "reason": f"HTTP {exc.code}: {exc.read()[:160].decode(errors='ignore')}"}
    except Exception as exc:
        return {"file": str(path), "verdict": "error", "trust_score": 0,
                "reason": f"{type(exc).__name__}: {exc}"}
    return {"file": str(path), "verdict": data.get("verdict"),
            "trust_score": data.get("trust_score"), "reason": data.get("reason", "")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("patterns", nargs="+", help="glob-шаблоны файлов артефактов")
    ap.add_argument("--schema", help="JSON Schema для проверки формы")
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--fail-on", choices=("reject", "any"), default="reject",
                    help="reject: падать только на отказе; any: и на нарушениях")
    ap.add_argument("--json", action="store_true", help="машинный вывод")
    args = ap.parse_args()

    schema = json.loads(Path(args.schema).read_text(encoding="utf-8")) if args.schema else None
    files: list[Path] = []
    for pattern in args.patterns:
        files.extend(Path(p) for p in sorted(glob.glob(pattern, recursive=True)))
    if not files:
        print(f"нет файлов по шаблону: {' '.join(args.patterns)}", file=sys.stderr)
        return 2

    results = [verify_one(p, schema, args.url) for p in files]
    failed = [r for r in results
              if r["verdict"] in ("reject", "error")
              or (args.fail_on == "any" and r["verdict"] != "accept")]

    if args.json:
        print(json.dumps({"results": results, "failed": len(failed),
                          "total": len(results)}, ensure_ascii=False, indent=2))
    else:
        width = max(len(r["file"]) for r in results)
        for r in results:
            print(f"  {r['file']:<{width}}  {r['verdict']:<7}  {r['trust_score']:>5}  {r['reason'][:70]}")
        print(f"\n  итог: {len(results) - len(failed)} принято, {len(failed)} с проблемой из {len(results)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
