"""Форма бесплатного скана без GitHub (S6.5, 18.11.2026).

Держит четыре вещи, без которых форма снова станет пустой страницей:
1. заявка сохраняется с почтой, хешем и числом строк, а сам CSV — файлом 0600;
2. мусорный адрес, пустой CSV, файл больше 200 КБ и строка данных вместо
   заголовка отклоняются до записи (иначе человек ждёт разбора, которого не будет);
3. недостающие колонки называются в ответе, а не превращаются в отказ;
4. на странице нет GitHub и нет внешних скриптов — вход без регистрации.
"""

from __future__ import annotations

import json
import stat
import threading
import urllib.error
import urllib.request

import pytest

from attest.service import AttestHandler

CSSV = "date,amount,asset,payee,tx_hash\n2026-11-01,0.42,USDC,api.vendor.example,0xabc123\n"


@pytest.fixture(scope="module")
def server():
    from http.server import ThreadingHTTPServer

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), AttestHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture()
def paths(tmp_path, monkeypatch):
    leads = tmp_path / "leads.jsonl"
    scans = tmp_path / "free_scans"
    monkeypatch.setattr(AttestHandler, "leads_path", leads)
    monkeypatch.setattr(AttestHandler, "free_scans_dir", scans)
    return leads, scans


def post(base: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(f"{base}/api/free-scan", data=json.dumps(body).encode(),
                                 method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_page_has_the_form_and_no_github(server):
    with urllib.request.urlopen(f"{server}/free-scan", timeout=10) as r:
        html = r.read().decode("utf-8")
        assert r.status == 200
    assert 'id="email"' in html and 'id="csv"' in html and 'id="csvfile"' in html
    assert "Request free scan" in html
    # Слово «GitHub» в тексте есть только как обещание «без него»; ссылки,
    # входа через GitHub и обращений к api.github.com быть не должно.
    assert "github.com" not in html.lower() and "oauth" not in html.lower()
    assert "https://github" not in html.lower()
    assert "business day" in html
    assert "<script src" not in html, "внешних скриптов нет"


def test_valid_request_is_stored(server, paths):
    leads, scans = paths
    status, data = post(server, {"email": "team@example.com", "csv": CSSV,
                                 "note": "double payments"})
    assert status == 200 and data["ok"] is True
    assert data["request_id"].startswith("fs_")
    assert data["rows"] == 1 and data["missing"] == []
    assert "business day" in data["message"]

    lines = leads.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["product"] == "free_scan"
    assert record["email"] == "team@example.com"
    assert record["note"] == "double payments"
    assert record["rows"] == 1
    assert record["columns"] == ["date", "amount", "asset", "payee", "tx_hash"]
    assert len(record["csv_sha256"]) == 64
    assert "2026-11-01" not in json.dumps(record), "содержимое CSV в журнал не пишем"
    assert "ip" not in record

    stored = scans / f"{data['request_id']}.csv"
    assert stored.read_text(encoding="utf-8") == CSSV
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600


def test_invalid_email_is_rejected(server, paths):
    leads, scans = paths
    status, data = post(server, {"email": "not-an-email", "csv": CSSV})
    assert status == 400 and "email" in data["error"]
    assert not leads.exists() and not scans.exists()


def test_empty_csv_is_rejected(server, paths):
    leads, _scans = paths
    status, data = post(server, {"email": "team@example.com", "csv": "   \n\n"})
    assert status == 400 and "empty" in data["error"].lower()
    assert not leads.exists()


def test_oversized_csv_is_rejected(server, paths):
    leads, _scans = paths
    big = "amount\n" + "1\n" * (110 * 1024)  # ~220 КБ, больше лимита
    status, data = post(server, {"email": "team@example.com", "csv": big})
    assert status == 400 and "200 KB" in data["error"]
    assert not leads.exists()


def test_csv_with_data_as_first_row_is_rejected(server, paths):
    leads, _scans = paths
    status, data = post(server, {"email": "team@example.com",
                                 "csv": "2026-11-01,0.42,USDC,acme,0xabc\n"})
    assert status == 400 and "header" in data["error"]
    assert not leads.exists()


def test_header_without_rows_is_rejected(server, paths):
    _leads, _scans = paths
    status, data = post(server, {"email": "team@example.com", "csv": "date,amount\n"})
    assert status == 400 and "no rows" in data["error"]


def test_missing_columns_are_named_not_fatal(server, paths):
    leads, _scans = paths
    status, data = post(server, {"email": "team@example.com",
                                 "csv": "when,value\n2026-11-01,42\n"})
    assert status == 200 and data["ok"] is True
    assert set(data["missing"]) == {"date", "amount", "asset", "payee", "tx_hash"}
    assert "date" in data["message"]
    assert len(leads.read_text(encoding="utf-8").strip().splitlines()) == 1


def test_page_shows_what_was_already_read(tmp_path):
    """Страница обязана показать прочитанное, а не только «заявка принята».

    21.11.2026: API возвращал rows/columns/missing, страница их выбрасывала —
    6194 просмотра, 1 заявка. Человек не видел, что файл вообще разобрали.
    """
    from attest import product_pages

    html = product_pages.free_scan_page()
    assert "j.rows" in html and "j.columns" in html
    assert "j.missing" in html
    assert "Request id" in html


def test_page_offers_a_synthetic_sample():
    """Без файла под рукой шаг «пришлите CSV» невыполним — даём пример формата."""
    from attest import product_pages

    html = product_pages.free_scan_page()
    assert "sample-spend.csv" in html
    assert "data:text/csv" in html
    assert "Download a synthetic sample" in html
    # пример обязан быть помечен как синтетический: это не чьи-то расходы
    assert "synthetic" in html


def test_scan_docs_page_says_what_is_checked_and_what_is_not():
    """«Пришлите CSV» без границ — просьба поверить на слово.

    21.11.2026: документации скана не было; человек не знал ни лимитов, ни того,
    что скан не является аудитом.
    """
    from attest import product_pages

    html = product_pages.scan_docs_page()
    assert "200 KB" in html and "one business day" in html
    assert "What the scan does not do" in html
    assert "Duplicates" in html and "Failed but charged" in html
    assert "not the $199 audit" in html.lower()
    assert "synthetic" in html.lower()
    assert "/free-scan" in html          # путь к форме есть на странице


def test_scan_docs_page_is_served(server):
    """Страница должна реально отдаваться: 200 и текст про лимиты."""
    import urllib.request

    with urllib.request.urlopen(f"{server}/docs/scan", timeout=10) as r:
        assert r.status == 200
        body = r.read().decode("utf-8")
    assert "How the free scan works" in body
    assert "200 KB" in body


def test_scan_page_links_to_the_docs(server):
    """Со страницы скана — ссылка на документацию, иначе её никто не найдёт."""
    import urllib.request

    with urllib.request.urlopen(f"{server}/free-scan", timeout=10) as r:
        body = r.read().decode("utf-8")
    assert 'href="/docs/scan' in body      # теперь с меткой ?ref=scan-page


def test_scan_docs_has_open_graph_and_faq_markup():
    """Страница должна выглядеть как страница, когда её пересылают, и отвечать
    на вопросы поисковика — без разметки её просто не показывают в выдаче."""
    import json

    from attest import product_pages

    html = product_pages.scan_docs_page()
    assert 'property="og:title"' in html and 'property="og:url"' in html
    assert 'name="twitter:card"' in html
    start = html.index('application/ld+json') + len('application/ld+json">')
    data = json.loads(html[start:html.index('</script>', start)])
    assert data["@type"] == "FAQPage" and len(data["mainEntity"]) >= 5


def test_scan_docs_has_a_path_to_the_paid_step():
    from attest import product_pages

    html = product_pages.scan_docs_page()
    assert "/plans?ref=docs-scan" in html
    assert "$199" in html
    assert "Within one business day" in html      # таймлайн, а не только лимиты
