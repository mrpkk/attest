"""Документация /docs/api не должна ссылаться на несуществующие пути."""
from __future__ import annotations

import re
from pathlib import Path

from attest.docs_api import EXTRA_ENDPOINTS

ROOT = Path(__file__).resolve().parents[1]
SERVICE = (ROOT / "attest" / "service.py").read_text(encoding="utf-8")
ROUTES = set(re.findall(r'path == "(/[^"]*)"', SERVICE)) | set(
    m for group in re.findall(r'path in \(([^)]*)\)', SERVICE)
    for m in re.findall(r'"(/[^"]*)"', group))


def test_every_documented_path_exists_in_service():
    missing = []
    for key in EXTRA_ENDPOINTS:
        path = key.split(" ", 1)[1]
        if path not in ROUTES:
            missing.append(path)
    assert not missing, f"в документации есть пути, которых нет в сервисе: {missing}"


def test_scan_health_stats_are_documented():
    joined = " ".join(EXTRA_ENDPOINTS)
    for path in ("/api/scan", "/health", "/stats"):
        assert path in joined, path
