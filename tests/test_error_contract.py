"""Контракт ошибки в /docs/api: обещанные поля должны быть в реальных телах ответов.

26.11.2026: страница говорила «error contract», а тела были `{"error": "текст"}` — клиент
не мог отличить «повтори» от «исправь запрос», не читая английский текст.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.docs_api import ERRORS  # noqa: E402
from attest.service import AttestHandler  # noqa: E402


def test_err_body_has_the_documented_fields():
    body = AttestHandler._err_body("INVALID_JSON", "JSON parse failed", hint="исправьте тело")
    assert body["code"] == "INVALID_JSON"
    assert body["retryable"] is False
    assert body["hint"]
    assert set(body) == {"error", "code", "retryable", "hint"}


def test_retryable_is_explicit_for_rate_limit_style_errors():
    body = AttestHandler._err_body("RATE_LIMITED", "too many", retryable=True)
    assert body["retryable"] is True


def test_code_parsing_errors_are_declared_in_the_docs():
    text = " ".join(f"{code} {why}" for code, why in ERRORS)
    for needle in ("INVALID_JSON", "NOT_AN_OBJECT", "BODY_TOO_LARGE", "retryable"):
        assert needle in text, needle


def test_every_documented_status_is_a_real_number():
    codes = {int(code) for code, _ in ERRORS if code.isdigit()}
    assert {400, 402, 404, 413, 429, 500} <= codes
