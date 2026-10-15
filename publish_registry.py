#!/usr/bin/env python3
"""Публикация сервера в официальный реестр MCP.

Реестр — канонический индекс экосистемы: Glama, Smithery и остальные
каталоги строят выдачу поверх него. Попадание сюда даёт больше, чем
отдельная подача в каждый каталог.

Токен реестра живёт пять минут, поэтому обмен повторяется на каждый
запуск: держать долгоживущий токен в файле незачем.

Использование:
    python3 publish_registry.py attest
    python3 publish_registry.py drift
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.modelcontextprotocol.io"
ENV = Path.home() / ".env"
STATE = Path("/tmp/opencode/registry-jwt")
SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"

SERVERS = {
    "attest": {
        "name": "io.github.mrpkk/attest",
        "title": "attest — verification for AI agent artifacts",
        "description": (
            "Verify an AI agent artifact: schema, emptiness, provenance and "
            "mandate authority, Ed25519-signed."
        ),
        "url": "https://attest.rta.lat/mcp",
        "websiteUrl": "https://attest.rta.lat/",
        "repository": "https://github.com/mrpkk/attest",
        "version": "0.1.0",
    },
    "drift": {
        "name": "io.github.mrpkk/drift",
        "title": "drift — mandate enforcement for AI agents",
        "description": (
            "Block an action a signed mandate does not permit: amount, "
            "payee, audience, currency, window, intent."
        ),
        "url": "https://drift.rta.lat/mcp",
        "websiteUrl": "https://drift.rta.lat/",
        "repository": "https://github.com/mrpkk/drift",
        "version": "0.1.0",
    },
}


def _env_value(key: str) -> str:
    for line in ENV.read_text(encoding="utf-8").splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit(f"в .env нет {key}")


def _post(url: str, payload: dict, token: str = "") -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            raw = resp.read().decode("utf-8", "ignore")
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "ignore")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"error": raw[:300]}
    except Exception as exc:  # noqa: BLE001
        return 0, {"error": f"{type(exc).__name__}: {exc}"}


def _jwt() -> str:
    """Обмен GitHub-токена на JWT реестра. Живёт пять минут."""
    code, data = _post(f"{REGISTRY}/v0.1/auth/github-at",
                       {"github_token": _env_value("GITHUB_TOKEN_OPENCODEDEV")})
    token = data.get("registry_token") or ""
    if not token:
        raise SystemExit(f"обмен не дал токен: {code} {json.dumps(data)[:220]}")
    return token


def manifest(key: str) -> dict:
    s = SERVERS[key]
    return {
        "$schema": SCHEMA,
        "name": s["name"],
        "title": s["title"],
        "description": s["description"],
        "version": s["version"],
        "websiteUrl": s["websiteUrl"],
        "repository": {"url": s["repository"], "source": "github"},
        "remotes": [{
            "type": "streamable-http",
            "url": s["url"],
            # Рукопожатие и список инструментов бесплатны: каталог должен
            # иметь право убедиться, что сервер жив, не платя квоты.
            "headers": [{"name": "X-ATTEST-NOTE",
                         "value": "discovery is free; tools/call is metered"}]
            if key == "attest" else None,
        }],
    }


def main() -> None:
    key = sys.argv[1] if len(sys.argv) > 1 else "attest"
    if key not in SERVERS:
        raise SystemExit(f"неизвестный сервер: {key}")
    doc = manifest(key)
    # заголовок без мусора: None в массиве ломает схему
    doc["remotes"][0] = {k: v for k, v in doc["remotes"][0].items() if v}

    print(f"  {doc['name']} v{doc['version']} → {doc['remotes'][0]['url']}")
    code, data = _post(f"{REGISTRY}/v0.1/validate", doc)
    print(f"  validate: {code} {json.dumps(data)[:200]}")
    if code not in (200, 201):
        print("  публикация не выполнена: документ не прошёл проверку")
        return

    code, data = _post(f"{REGISTRY}/v0.1/publish", doc, _jwt())
    print(f"  publish : {code}")
    if code in (200, 201):
        print("  ОПУБЛИКОВАНО")
        for k in ("name", "version", "state", "id"):
            if k in data:
                print(f"    {k}: {data[k]}")
    else:
        print("  отказ:", json.dumps(data)[:300])


if __name__ == "__main__":
    main()