"""`/docs/api`: эндпоинты из схемы, лимиты, ошибки и рабочие curl.

22.11.2026: `/docs` объяснял, что доказывает квитанция, но не давал ни одной
команды, ни лимитов, ни формата ошибок — интегратор угадывал и жёг квоту.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.docs_api import openapi_paths, page_html  # noqa: E402
from attest.service import _sitemap  # noqa: E402


def test_every_openapi_path_is_documented():
    """Схема и документация не должны разъезжаться: новый путь без строки — красный тест."""
    html = page_html()
    missing = [p for p in openapi_paths() if p not in html]
    assert not missing, f"не документированы: {missing}"


def test_mcp_and_human_pages_are_documented():
    """JSON-RPC и страницы оплаты не попадают в openapi — но знать о них нужно."""
    html = page_html()
    assert "POST /mcp" in html
    assert "tools/list" in html and "tools/call" in html
    assert "/verify-receipt" in html and "/pay" in html


def test_limits_are_stated_with_numbers():
    html = page_html()
    assert "5 per day" in html
    assert "$0.005" in html
    assert "99 USDC" in html and "49 USDC" in html


def test_error_contract_explains_402_free_ways():
    html = page_html()
    for code in ("400", "402", "413", "429", "500"):
        assert f"<code>{code}</code>" in html, code
    assert "free_pack" in html and "human_review" in html and "pay_human" in html


def test_curl_examples_are_complete_commands():
    html = page_html()
    assert html.count("curl -s -X POST https://attest.rta.lat/") >= 3
    assert "X-PAYMENT" in html


def test_docs_api_is_linked_and_indexed():
    xml = _sitemap()
    assert "<loc>https://attest.rta.lat/docs/api</loc>" in xml
    src = (ROOT / "attest" / "service.py").read_text(encoding="utf-8")
    assert 'href="/docs/api"' in src
