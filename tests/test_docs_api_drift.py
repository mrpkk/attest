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


#: Публичные маршруты, которые сознательно не в API-документации: это страницы для людей,
#: SEO-лендинги и админка. Список явный, чтобы новый маршрут нельзя было спрятать молчанием.
NOT_API_DOCS = {
    "/", "/hi", "/demo", "/plans", "/article", "/catalogs", "/start", "/privacy",
    "/health", "/deny-evidence", "/eu-ai-act-evidence", "/mcp-security-pass", "/eu-ai-act",
    "/mcp-security", "/trust-desk", "/proof-of-place", "/suite.json", "/scan", "/free-scan",
    "/docs/scan", "/docs/api", "/sample-audit", "/verify-receipt", "/store", "/review",
    "/pay", "/pricing", "/subscribe", "/login", "/logout", "/admin", "/stats",
    # страницы и ассеты, не API
    "/docs", "/hub", "/tools", "/receipts", "/checkpoints", "/deny", "/scitt", "/thanks",
    "/feedback", "/feedback.js", "/favicon.ico", "/og.png", "/robots.txt", "/sitemap.xml",
    "/eu-ai-act-evidence/sample.pdf",
    # заказы конкретных продуктов: описаны на своих страницах
    "/api/audit-intent", "/api/eu-ai-act/order", "/api/mcp-security/order",
    "/api/proof-of-place/order", "/api/proof-of-place/build", "/api/trust-desk/order",
    "/pay/claim", "/pay/enot", "/pay/enot/notify",
    # служебные .well-known: перечислены в /suite.json и llms.txt
    "/.well-known/agent-card.json", "/.well-known/glama.json",
    "/.well-known/mcp/server-card.json", "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp", "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp", "/.well-known/x402", "/.well-known/x402.json",
}


def test_every_public_service_route_is_documented_or_explicitly_excluded():
    """Обратная сторона дрейфа: новый публичный маршрут нельзя оставить без описания."""
    from attest.docs_api import EXTRA_ENDPOINTS

    documented = {key.split(" ", 1)[1] for key in EXTRA_ENDPOINTS}
    undocumented = {
        r for r in ROUTES
        if r not in documented and r not in NOT_API_DOCS
        and not r.startswith("/mcp/") and not r.startswith("/auth/")
        and "{" not in r
    }
    assert not undocumented, (
        "маршруты есть в сервисе, но не в /docs/api и не в списке исключений: "
        f"{sorted(undocumented)}")
