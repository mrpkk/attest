#!/usr/bin/env python3
"""Отправка страниц сайта в IndexNow (Bing, Яндекс).

Зачем: 20.10.2026 проверка `site:attest.rta.lat` показала, что сайта нет
в индексе ни у Яндекса, ни у Bing — sitemap сам по себе недостаточен.
IndexNow сообщает об URL напрямую; ключ-файл отдаёт сам сервис attest.

    python3 tools/indexnow-submit.py              # все URL из sitemap
    python3 tools/indexnow-submit.py --url /hi    # только один путь
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.request
import xml.etree.ElementTree as ET

HOST = "attest.rta.lat"
KEY = "79b5d8b3abc6edc97859cc7c3f6d85de"
KEY_LOCATION = f"https://{HOST}/{KEY}.txt"
ENDPOINTS = (
    "https://api.indexnow.org/indexnow",
    "https://www.bing.com/indexnow",
    "https://yandex.com/indexnow",
)


def sitemap_urls() -> list[str]:
    # Cloudflare отдаёт 403 на голый python-urllib (BIC), поэтому UA обязателен.
    req = urllib.request.Request(
        f"https://{HOST}/sitemap.xml",
        headers={"User-Agent": f"attest-indexnow/1.0 (+https://{HOST}/)"})
    with urllib.request.urlopen(req, timeout=20) as r:
        xml = r.read().decode("utf-8")
    root = ET.fromstring(xml)
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    return [loc.text.strip() for loc in root.findall(".//sm:loc", ns) if loc.text]


def submit(urls: list[str]) -> list[tuple[str, int, str]]:
    payload = json.dumps({
        "host": HOST, "key": KEY, "keyLocation": KEY_LOCATION, "urlList": urls,
    }).encode("utf-8")
    out = []
    for endpoint in ENDPOINTS:
        req = urllib.request.Request(
            endpoint, data=payload, method="POST",
            headers={"Content-Type": "application/json; charset=utf-8"})
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                body = r.read().decode("utf-8", "ignore")[:120]
                out.append((endpoint, r.status, body))
        except Exception as e:                      # сеть/4xx — не роняем отчёт
            out.append((endpoint, -1, str(e)[:120]))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", action="append", help="путь или полный URL (можно несколько)")
    args = ap.parse_args()
    urls = ([u if u.startswith("http") else f"https://{HOST}{u}" for u in args.url]
            if args.url else sitemap_urls())
    if not urls:
        print("URL не найдены — sitemap пуст?")
        return
    print(f"URL к отправке: {len(urls)}")
    for endpoint, status, body in submit(urls):
        ok = "✓" if status in (200, 202) else "×"
        print(f"{ok} {endpoint} → {status} {body}")


if __name__ == "__main__":
    main()
