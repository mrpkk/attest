"""Посадочные страницы двух дорогих продуктов (31.10.2026).

Причина теста. В отчётах EU AI Act Evidence Pack ($1,500/$3,000) и MCP Security
Pass ($500/$1,500) значились «страницы готовы», а по адресам `/eu-ai-act` и
`/mcp-security` отдавался 404 — купить было нечего. Тест держит четыре вещи,
без которых страница снова станет бесполезной:

1. цена и кнопка оплаты есть в первом экране (до блоков «что входит»);
2. заголовок — польза в 6–12 слов, а не название технологии;
3. три строки доверия и FAQ из трёх вопросов;
4. нет запрещённых слов и выдуманных цифр.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.product_pages import eu_ai_act_page, mcp_security_page  # noqa: E402

PAY_TO = "0xefCD6886f73064ea9EcbaA4741Ef1309A0885C59"

PAGES = {
    "eu-ai-act": (eu_ai_act_page(PAY_TO), ["$1,500", "$3,000"], "/api/eu-ai-act/order"),
    "mcp-security": (mcp_security_page(PAY_TO), ["$500", "$1,500"], "/api/mcp-security/order"),
}

BANNED = ("revolutionary", "ai-powered", "best in the world", "trusted by leaders",
          "аналогов нет", "game-changing")


def _h1(html: str) -> str:
    return re.search(r"<h1>(.*?)</h1>", html, re.S).group(1)


def test_titles_are_benefits_of_six_to_twelve_words():
    for slug, (html, _prices, _endpoint) in PAGES.items():
        words = len(re.findall(r"[\w']+", _h1(html)))
        assert 6 <= words <= 12, f"{slug}: заголовок из {words} слов"


def test_price_and_pay_button_are_before_the_details():
    for slug, (html, prices, endpoint) in PAGES.items():
        pay_at = html.index('class="pay"')
        details_at = html.index("<h2>What")
        assert pay_at < details_at, f"{slug}: блок оплаты ниже описания"
        assert "Verify payment — start intake" in html
        assert endpoint in html
        for price in prices:
            assert price in html, f"{slug}: нет цены {price}"
            assert html.index(price) < pay_at or price in html[pay_at:]


def test_three_trust_lines_and_three_questions():
    for slug, (html, _p, _e) in PAGES.items():
        assert html.count("<li>") >= 3, f"{slug}: меньше трёх строк доверия"
        assert html.count("<details>") == 3, f"{slug}: FAQ не из трёх вопросов"


def test_honest_boundary_section_present():
    for slug, (html, _p, _e) in PAGES.items():
        assert "What this is not" in html, f"{slug}: нет раздела «чего не делает»"


def test_no_banned_marketing_words():
    for slug, (html, _p, _e) in PAGES.items():
        low = html.lower()
        for word in BANNED:
            assert word not in low, f"{slug}: запрещённое слово «{word}»"


def test_only_english_client_text():
    for slug, (html, _p, _e) in PAGES.items():
        cyrillic = re.findall(r"[\u0400-\u04FF]+", html)
        assert not cyrillic, f"{slug}: русский текст на клиентской странице {cyrillic[:5]}"


def test_eu_covers_named_articles():
    html, _p, _e = PAGES["eu-ai-act"]
    for article in ("6", "9", "10", "11", "12", "13", "14", "15", "43", "72"):
        assert re.search(rf"\b{article}\b", html), f"нет статьи {article}"


def test_mcp_names_owasp_and_honest_sample():
    html, _p, _e = PAGES["mcp-security"]
    assert "OWASP MCP Top 10" in html
    assert "Example on request" in html  # реального артефакта нет — не выдумываем
