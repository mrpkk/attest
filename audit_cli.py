#!/usr/bin/env python3
"""
CLI аудита смарт-контрактов.

    python3 audit_cli.py путь/к/контракту.sol
    python3 audit_cli.py контракт.sol --json
    python3 audit_cli.py контракт.sol --format sarif
    cat контракт.sol | python3 audit_cli.py -

Зачем. Рынок аудита ~$1.8 млрд, ручной аудит стоит $5 000–$250 000.
Протоколы с бюджетом меньше $15 000 не аудируются вообще. Этот сканер —
дешёвый фильтр перед дорогим аудитом и средство непрерывной проверки при
каждом мерже, а не замена аудиту.

Честная граница: он находит известные классы уязвимостей по исходному коду.
Чистый результат означает «чисто по этим правилам», а не «контракт безопасен».
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attest.ast_analyzer import analyze as ast_analyze  # noqa: E402
from attest.scanner import check, rules_manifest  # noqa: E402

COLOR = {
    "critical": "\033[41;97m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[90m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


def read_source(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")


def color(sev: str, text: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLOR.get(sev, '')}{text}{COLOR['reset']}"


def render_text(v, src: str, use_color: bool) -> str:
    out = [f"{COLOR['bold'] if use_color else ''}attest · аудит смарт-контракта{COLOR['reset'] if use_color else ''}",
           "",
           f"  {v.summary()}",
           ""]
    if not v.findings:
        out.append(f"  {COLOR['dim'] if use_color else ''}"
                   "Чисто по проверяемым классам. Это НЕ гарантия безопасности:"
                   " формальная верификация и ручной аудит не заменены."
                   f"{COLOR['reset'] if use_color else ''}")
        return "\n".join(out)

    for f in v.findings:
        out.append(f"  {color(f.severity, f.severity.upper(), use_color)}  "
                   f"{f.title}")
        out.append(f"    строка {f.line}: {f.excerpt}")
        out.append(f"    {COLOR['dim'] if use_color else ''}почему:{COLOR['reset'] if use_color else ''} "
                   f"{f.why.strip()}")
        out.append(f"    {COLOR['dim'] if use_color else ''}лечить:{COLOR['reset'] if use_color else ''} "
                   f"{f.fix.strip()}")
        out.append("")
    out.append(f"  {COLOR['dim'] if use_color else ''}"
               + v.as_dict()["disclaimer"]
               + f"{COLOR['reset'] if use_color else ''}")
    return "\n".join(out)


def _sarif_level(sev: str) -> str:
    return ("error" if sev == "critical" else
            "warning" if sev in ("high", "medium") else "note")


def render_sarif(v, source: str = "contract.sol") -> str:
    """SARIF — формат, который читают GitHub Code Scanning и IDE."""
    # Правила обязаны лежать в driver.rules: без них GitHub показывает
    # «ruleId not found» и прячет пояснение, зачем находка считается находкой.
    rules = [{
        "id": m["key"],
        "name": m["key"],
        "shortDescription": {"text": m["title"]},
        "fullDescription": {"text": m["why"].strip()},
        "help": {"text": m["fix"].strip()},
        "defaultConfiguration": {"level": _sarif_level(m["severity"])},
    } for m in rules_manifest()]
    uri = Path(source).name if source != "-" else "contract.sol"
    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "attest-scanner",
                "informationUri": "https://github.com/mrpkk/attest",
                # Кто реально смотрел код: AST (solc) или регулярки.
                # GitHub прячет properties из вида, но они остаются в файле.
                "properties": {"engine": getattr(v, "engine", "regex")},
                "rules": rules,
            }},
            "results": [{
                "ruleId": f.rule,
                "level": _sarif_level(f.severity),
                "message": {"text": f"{f.title}. {f.why.strip()}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": f.line},
                    }
                }],
            } for f in v.findings],
        }],
    }, ensure_ascii=False, indent=2)


def main() -> int:
    ap = argparse.ArgumentParser(prog="audit", description="Аудит смарт-контракта")
    ap.add_argument("source", help="путь к .sol или - для stdin")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--format", choices=["text", "sarif"], default="text")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--rules", action="store_true", help="показать правила")
    ap.add_argument("--quiet", action="store_true", help="только код возврата")
    ap.add_argument("--engine", choices=["auto", "ast", "regex"], default=None,
                    help="кто смотрит код: solc AST (auto) или регулярки; "
                         "по умолчанию ATTEST_SCANNER_ENGINE или auto")
    args = ap.parse_args()

    if args.rules:
        print(json.dumps(rules_manifest(), ensure_ascii=False, indent=2))
        return 0

    try:
        src = read_source(args.source)
    except OSError as exc:
        print(f"не читается: {exc}", file=sys.stderr)
        return 2

    v = check(src, engine=args.engine)

    if args.quiet:
        pass
    elif args.as_json:
        print(json.dumps(v.as_dict(), ensure_ascii=False, indent=2))
    elif args.format == "sarif":
        print(render_sarif(v, args.source))
    else:
        print(render_text(v, src, use_color=not args.no_color and sys.stdout.isatty()))

    # Код возврата пригоден для CI: 0 — чисто, 1 — есть находки, 2 — ошибка
    return 1 if v.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())