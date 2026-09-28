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

    raw = Path(args.file).read_text("utf-8") if args.file else sys.stdin.read()

    if args.verify:
        data = json.loads(raw)
        rec = data["record"]
        from .provenance import ProvenanceRecord, Attestation

        att = Attestation(
            record=ProvenanceRecord(**rec),
            signature=data["signature"],
            algorithm=data.get("algorithm", "none"),
        )
        key = args.key.encode() if args.key else None
        ok = verify(att, key)
        print("подпись валидна" if ok else "подпись НЕ валидна")
        return EXIT_OK if ok else EXIT_REJECT

    try:
        artifact = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"ошибка: вход не JSON — {e}", file=sys.stderr)
        return EXIT_REJECT

    schema = json.loads(Path(args.schema).read_text("utf-8")) if args.schema else None
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
