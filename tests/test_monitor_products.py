"""Мониторинг продуктов: падение одной ссылки видно, алерт один на проход."""
from __future__ import annotations

import importlib.util
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mp", BASE / "scripts" / "monitor_products.py")
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)


def test_all_ok_when_every_url_200():
    res = mp.run("http://a", "http://n", fetch=lambda url, timeout=8: (200, ""))
    assert res["ok"] and res["down"] == 0 and res["checked"] == len(mp.PRODUCTS)


def test_one_failure_is_reported_with_name():
    def fetch(url, timeout=8):
        return (404, "http_404") if "sheet-doctor" in url else (200, "")
    res = mp.run("http://a", "http://n", fetch=fetch)
    assert not res["ok"] and res["down"] == 1
    bad = [r for r in res["rows"] if not r["ok"]][0]
    assert bad["name"] == "Sheet Doctor" and bad["code"] == 404


def test_network_error_is_down_not_crash():
    res = mp.run("http://a", "http://n", fetch=lambda url, timeout=8: (0, "TimeoutError"))
    assert res["down"] == len(mp.PRODUCTS)


def test_products_cover_four_named_offers():
    names = [n for n, _ in mp.PRODUCTS]
    for offer in ("Site Guard", "Sheet Doctor", "Doc Answer Box", "Founding audit"):
        assert offer in names
