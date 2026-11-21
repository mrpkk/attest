"""Сторож продуктов: касса + реальная доставка, и честная метка «не собран».

22.11.2026: Site Guard продавался, а его проверки жили в отдельном таймере; Sheet
Doctor — скрипт без сторожа; Channel Vault продавался через waitlist. Общего взгляда
на «жив ли продукт» не было.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_spec = importlib.util.spec_from_file_location("products_watchdog",
                                               ROOT / "scripts" / "products_watchdog.py")
pw = importlib.util.module_from_spec(_spec)
sys.modules["products_watchdog"] = pw
_spec.loader.exec_module(pw)


def test_all_four_products_are_watched():
    assert set(pw.PRODUCTS) == {"site-guard-year", "sheet-doctor",
                               "doc-answer-box", "channel-vault-export"}
    assert pw.PRODUCTS["channel-vault-export"] == "not_built"


def test_site_guard_and_sheet_doctor_are_really_executed(monkeypatch):
    """Не «касса 200», а реальные проверки: сайты отвечают, скрипт чистит файл."""
    monkeypatch.setattr(pw, "http_code", lambda url, timeout=15: 200)
    monkeypatch.setattr(pw, "site_guard_ok", lambda: (True, "3 сайтов отвечают"))
    monkeypatch.setattr(pw, "sheet_doctor_ok", lambda: (True, '{"rows_in": 6}'))
    res = pw.check_products()
    assert res["ok"] is True
    assert "3 сайтов" in res["products"]["site-guard-year"]["detail"]
    assert "rows_in" in res["products"]["sheet-doctor"]["detail"]


def test_broken_cashier_page_is_a_failure(monkeypatch):
    def code(url, timeout=15):
        return 404 if "site-guard-year" in url else 200

    monkeypatch.setattr(pw, "http_code", code)
    monkeypatch.setattr(pw, "site_guard_ok", lambda: (True, "ok"))
    monkeypatch.setattr(pw, "sheet_doctor_ok", lambda: (True, "ok"))
    res = pw.check_products()
    assert res["ok"] is False and "site-guard-year" in res["broken"]


def test_not_built_product_does_not_count_as_broken(monkeypatch):
    """Waitlist — это решение, а не сбой: тревожить владельца из-за него нельзя."""
    def code(url, timeout=15):
        return 200 if "channel-vault" in url else 500

    monkeypatch.setattr(pw, "http_code", code)
    monkeypatch.setattr(pw, "site_guard_ok", lambda: (True, "ok"))
    monkeypatch.setattr(pw, "sheet_doctor_ok", lambda: (True, "ok"))
    res = pw.check_products()
    assert "channel-vault-export" not in res["broken"]
    assert "not_built" == res["products"]["channel-vault-export"]["kind"]


def test_alert_only_on_state_change(tmp_path, monkeypatch):
    sent: list[str] = []
    sender = lambda text: (sent.append(text), (True, ""))[1]  # noqa: E731
    monkeypatch.setattr(pw, "check_products",
                        lambda: {"products": {}, "broken": {"x": {"cashier": 500, "detail": ""}},
                                 "ok": False})
    state = tmp_path / "s.json"
    pw.run_once(state, send=sender)
    pw.run_once(state, send=sender)
    assert len(sent) == 1 and "сломано" in sent[0]

    monkeypatch.setattr(pw, "check_products", lambda: {"products": {}, "broken": {}, "ok": True})
    pw.run_once(state, send=sender)
    assert len(sent) == 2 and "снова" in sent[1]


def test_state_keeps_per_product_status(tmp_path, monkeypatch):
    monkeypatch.setattr(pw, "check_products",
                        lambda: {"products": {"site-guard-year": {"cashier": 200, "ok": True,
                                                                  "kind": "site_guard", "detail": "ok"}},
                                 "broken": {}, "ok": True})
    state = tmp_path / "s.json"
    pw.run_once(state, send=lambda text: (True, ""))
    saved = json.loads(state.read_text())
    assert saved["status"] == "ok" and saved["products"]["site-guard-year"]["cashier"] == 200
