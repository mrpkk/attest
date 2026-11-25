#!/usr/bin/env python3
"""Отправить адреса в IndexNow (Bing, Yandex, Seznam). Google — нет, у него Search Console.

    python3 scripts/indexnow.py                      # ключевые страницы
    python3 scripts/indexnow.py https://attest.rta.lat/scan
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import indexnow  # noqa: E402

DEFAULT = ["https://attest.rta.lat/scan", "https://attest.rta.lat/docs/scan",
           "https://attest.rta.lat/store", "https://attest.rta.lat/article"]


def main(argv: list[str]) -> int:
    urls = argv[1:] or DEFAULT
    code, text = indexnow.send(urls)
    print(f"IndexNow: HTTP {code} · отправлено {len(urls)} адресов")
    if text:
        print(text[:300])
    return 0 if code in (200, 202) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
