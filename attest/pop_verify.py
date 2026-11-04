#!/usr/bin/env python3
"""Офлайн-проверка отчёта Proof of Place.

    python -m attest.pop_verify report.json --key public_key.txt

Печатает вердикт и причину. Код возврата: 0 — `ok`, 1 — любой другой
вердикт, 2 — файл не прочитан. Сеть, аккаунт и наш сервер не нужны:
единственное, чему верит проверка, — подпись Ed25519 pinned-ключом.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pop import verify


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m attest.pop_verify",
        description="Verify a pop/1 report against a pinned Ed25519 key.")
    parser.add_argument("artifact", help="report.json")
    parser.add_argument("--key", required=True,
                        help="pinned public key file (64 hex chars or base64)")
    parser.add_argument("--pdf", help="report.pdf, checked against pdf_sha256")
    args = parser.parse_args(argv)
    try:
        artifact = Path(args.artifact).read_bytes()
        key = Path(args.key).read_text(encoding="utf-8")
        pdf = Path(args.pdf).read_bytes() if args.pdf else None
    except OSError as exc:
        print(f"verdict: error\nreason:  {exc}", file=sys.stderr)
        return 2
    result = verify(artifact, key, pdf=pdf)
    print(f"verdict: {result}")
    print(f"reason:  {result.reason}")
    return 0 if result == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
