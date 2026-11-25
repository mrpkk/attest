"""Страница /scan должна отвечать на запрос «MCP server scan» текстом, а не только формой."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _scan_html() -> str:
    """HTML страницы /scan без шаблонных подстановок."""
    from attest import scan as scan_page

    page = getattr(scan_page, "SCAN_HTML", None) or getattr(scan_page, "PAGE", None)
    if page is None:                      # страница собирается функцией
        fn = [v for k, v in vars(scan_page).items() if k.lower().endswith("page") and callable(v)]
        assert fn, "не нашёл, чем собирается страница"
        page = fn[0]()
    return page


def test_page_has_enough_text_to_be_found():
    html = _scan_html()
    text = re.sub(r"<(script|style).*?</\1>", " ", html, flags=re.S)
    words = re.sub(r"<[^>]+>", " ", text).split()
    assert len(words) >= 650, f"{len(words)} слов — страница остаётся тонкой для поиска"


def test_page_names_the_query_and_answers_comparison():
    html = _scan_html().lower()
    assert "mcp server scan" in html
    assert "vulnerability scanner" in html, "должно быть сравнение, а не только описание"
    assert "how often to scan" in html, "ответ на «когда это делать» — часть запроса"


def test_comparison_does_not_overclaim():
    """Скан — не аудит и не замена ревью: это должно быть сказано на странице."""
    html = _scan_html().lower()
    assert "does not remove the review" in html or "not a security audit" in html
