#!/usr/bin/env python3
"""`lp_verify` — офлайн-проверка `lp/1` без сети и без нашего сервиса.

    python3 -m attest.lp_verify proof.json --key public_key.txt

Ключ pinned: передаётся файлом/строкой, НЕ берётся из proof.json.
Выход: `ok` и код 0; иначе вердикт и код 1.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .lp import verify


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lp_verify")
    parser.add_argument("proof", type=Path)
    parser.add_argument("--key", required=True,
                        help="pinned public key: file, base64 or ed25519:<hex>")
    args = parser.parse_args(argv)

    key = args.key
    candidate = Path(key)
    if candidate.is_file():
        key = candidate.read_text(encoding="utf-8").strip()

    verdict = verify(args.proof.read_bytes(), key)
    print(verdict)
    if verdict != "ok":
        print(verdict.reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
