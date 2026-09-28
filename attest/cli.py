"""CLI: проверка артефакта из stdin или файла, вывод вердикта + подписи.

  echo '{"a":1}' | python -m attest.cli --schema schema.json
  python -m attest.cli --file result.json --source moltbook
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import attest
from .provenance import verify

EXIT_OK = 0
EXIT_REVIEW = 10
EXIT_REJECT = 20


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="attest", description="Attest — проверка артефактов агента")
    p.add_argument("--file", help="путь к JSON-файлу с артефактом (по умолчанию stdin)")
    p.add_argument("--schema", help="путь к JSON-схеме")
    p.add_argument("--source", default="stdin", help="источник артефакта")
    p.add_argument("--json", action="store_true", help="полный JSON-вывод")
    p.add_argument("--verify", action="store_true", help="только проверить подпись входного attestation")
    p.add_argument("--key", help="HMAC-ключ")
    args = p.parse_args(argv)

    if args.file:
        path = Path(args.file)
        if not path.is_file():
            print(f"ошибка: файл не найден — {path}", file=sys.stderr)
            return EXIT_REJECT
        try:
            raw = path.read_text("utf-8")
        except OSError as e:
            print(f"ошибка: не удалось прочитать {path} — {e}", file=sys.stderr)
            return EXIT_REJECT
    else:
        raw = sys.stdin.read()

    if args.verify:
        from .provenance import ProvenanceRecord, Attestation

        data = json.loads(raw)
        # принимаем и полный результат (--json), и голую attestation
        payload = data.get("attestation", data)
        try:
            att = Attestation(
                record=ProvenanceRecord(**payload["record"]),
                signature=payload["signature"],
                algorithm=payload.get("algorithm", "none"),
            )
        except (KeyError, TypeError) as e:
            print(f"ошибка: в файле нет корректной attestation ({e})", file=sys.stderr)
            return EXIT_REJECT
        key = args.key.encode() if args.key else None
        ok = verify(att, key)
        if ok:
            r = att.record
            print(f"подпись валидна: {r.source} verdict={r.verdict} trust={r.trust_score} sha256={r.content_hash[7:19]}")
        else:
            print("подпись НЕ валидна — содержимое изменено после проверки")
        return EXIT_OK if ok else EXIT_REJECT

    try:
        artifact = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"ошибка: вход не JSON — {e}", file=sys.stderr)
        return EXIT_REJECT

    if args.schema:
        spath = Path(args.schema)
        if not spath.is_file():
            print(f"ошибка: схема не найдена — {spath}", file=sys.stderr)
            return EXIT_REJECT
        try:
            schema = json.loads(spath.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ошибка: схема не читается — {e}", file=sys.stderr)
            return EXIT_REJECT
    else:
        schema = None

    result = attest(artifact, schema, source=args.source)

    if args.json:
        print(result.to_json(indent=2))
    else:
        r = result.attestation.record
        print(f"вердикт: {result.verdict.upper()}  доверие: {result.trust_score:.0f}/100")
        print(f"причина:  {result.reason}")
        print(f"источник: {r.source}  sha256: {r.content_hash[7:19]}")
        for v in result.violations:
            print(f"  схема   {v.path}: {v.rule} — {v.detail}")
        for s in result.signals:
            print(f"  отрава  {s.kind} [{s.severity}] @ {s.where} — {s.evidence[:80]}")
        print(result.attestation.compact())

    return {"accept": EXIT_OK, "review": EXIT_REVIEW, "reject": EXIT_REJECT}[result.verdict]


if __name__ == "__main__":
    raise SystemExit(main())
