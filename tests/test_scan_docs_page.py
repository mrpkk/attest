"""Страница /docs/scan: четыре обязательных блока и лимит, совпадающий с кодом."""
from __future__ import annotations

from pathlib import Path

from attest.product_pages import scan_docs_page
from attest.service import FREE_DAILY_LIMIT

ROOT = Path(__file__).resolve().parents[1]


def test_docs_scan_has_all_four_blocks():
    html = scan_docs_page()
    for block in ("What is checked", "Limits, exactly", "Example of what a reply looks like",
                  "What the scan does not do"):
        assert block in html, block


def test_docs_scan_states_real_free_limit():
    html = scan_docs_page()
    assert f"Free limit: {FREE_DAILY_LIMIT} scans per day" in html
    assert "__FREE_LIMIT__" not in html


def test_docs_scan_page_in_sitemap_and_linked():
    from attest.service import _sitemap
    assert "<loc>https://attest.rta.lat/docs/scan</loc>" in _sitemap()
    assert 'href="/docs/scan' in (ROOT / "attest" / "scan.py").read_text(encoding="utf-8")


def test_checks_on_page_come_from_the_single_code_list():
    """Страница не может пообещать проверку, которой нет в free_scan.CHECKS (26.11.2026)."""
    from attest.free_scan import CHECKS

    html = scan_docs_page()
    for check in CHECKS:
        assert check["title"] in html, f"проверка {check['key']} пропала со страницы"
        assert check["means"] in html, f"у {check['key']} разошлось описание"
    titles = [c["title"] for c in CHECKS]
    assert len(titles) == len(set(titles)) == 6


def test_page_says_checks_are_read_by_a_person():
    """Все шесть проверок сейчас human-reviewed — это должно быть сказано, а не подразумеваться."""
    from attest.free_scan import CHECK_STATUS

    assert CHECK_STATUS == "manual"
    html = scan_docs_page()
    assert "read by a person on your file" in html
    assert "no score" in html


def test_size_limit_matches_the_parser():
    """«200 KB» на странице — это ровно тот лимит, который стоит в коде."""
    from attest.free_scan import MAX_CSV_BYTES

    html = scan_docs_page()
    assert f"{MAX_CSV_BYTES // 1024} KB" in html


def test_page_stays_light():
    assert len(scan_docs_page().encode("utf-8")) < 30_000


def test_docs_scan_has_hindi_and_russian_blocks():
    """Индия — первый класс интерфейса: страница без хинди не считается готовой."""
    from attest.service import FREE_DAILY_LIMIT

    html = scan_docs_page()
    assert "हिन्दी — सारांश" in html, "нет блока на хинди"
    assert "Русский — коротко" in html, "нет блока на русском"
    hindi = html.split("हिन्दी — सारांश")[1].split("Русский")[0]
    russian = html.split("Русский — коротко")[1]
    for block, label in ((hindi, "hi"), (russian, "ru")):
        assert str(FREE_DAILY_LIMIT) in block, f"{label}: лимит не совпадает с кодом"
        assert "6" in block, f"{label}: не названо число проверок"
        assert "200" in block, f"{label}: не назван размер файла"


def test_all_three_languages_agree_on_numbers():
    """Числа в трёх языках должны совпадать, иначе перевод врёт."""
    html = scan_docs_page()
    assert html.count(str(__import__("attest.service", fromlist=["FREE_DAILY_LIMIT"]).FREE_DAILY_LIMIT)) >= 3
    assert html.count("200 KB") + html.count("200 КБ") >= 2
