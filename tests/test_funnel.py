"""Воронка «бесплатный скан → заявка на аудит»: считаем, а не угадываем.

Зачем: 130 просмотров и ноль клиентов уже были. Без отдельного счётчика сканов и
нажатий «аудит $199» невозможно отличить «никто не пришёл» от «пришли, получили
скан и не дошли до оплаты» — а это два разных решения.
"""

from __future__ import annotations

import json
import threading
import urllib.request

import pytest

from attest.metrics import Metrics


def _metrics(tmp_path, monkeypatch):
    """Счётчики в памяти + свой файл состояния: боевые цифры тесты не трогают."""
    import attest.metrics as m

    monkeypatch.setattr(m, "STATE_PATH", tmp_path / "metrics.json")
    met = Metrics()
    monkeypatch.setattr(m, "METRICS", met)
    return met


def test_free_scan_and_audit_intent_are_counted_separately(tmp_path, monkeypatch):
    met = _metrics(tmp_path, monkeypatch)
    met.free_scan()
    met.free_scan()
    met.audit_intent()
    snap = met.snapshot()
    assert snap["free_scans"] == 2
    assert snap["audit_intents"] == 1
    assert snap["free_scan_to_audit"] == "0.500"


def test_conversion_is_dash_when_nothing_scanned(tmp_path, monkeypatch):
    met = _metrics(tmp_path, monkeypatch)
    assert met.snapshot()["free_scan_to_audit"] == "—"


def test_counters_survive_reload(tmp_path, monkeypatch):
    met = _metrics(tmp_path, monkeypatch)
    met.free_scan()
    met.save()
    again = Metrics()
    again.load()
    assert again.snapshot()["free_scans"] == 1


def test_disabled_metrics_do_not_count(tmp_path, monkeypatch):
    met = _metrics(tmp_path, monkeypatch)
    met.enabled = False
    met.free_scan()
    met.audit_intent()
    assert met.snapshot()["free_scans"] == 0


@pytest.fixture(scope="module")
def server():
    from http.server import ThreadingHTTPServer

    from attest.service import AttestHandler

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), AttestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_funnel_endpoint_reports_the_numbers(server):
    with urllib.request.urlopen(f"{server}/api/funnel", timeout=10) as r:
        assert r.status == 200
        data = json.loads(r.read().decode())
    for key in ("views", "free_scans", "audit_intents", "paid_actions"):
        assert key in data, key
    assert isinstance(data["free_scans"], int)


def test_audit_intent_beacon_is_accepted(server):
    req = urllib.request.Request(f"{server}/api/audit-intent", data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.status == 204


def test_plans_page_carries_the_beacon(server):
    with urllib.request.urlopen(f"{server}/plans", timeout=10) as r:
        html = r.read().decode()
    assert "/api/audit-intent" in html, "кнопка аудита должна сообщать о нажатии"


# ── следующий шаг после бесплатного скана ─────────────────────────────────

CSV = "date,amount,asset,payee,tx_hash\n2026-11-01,0.42,USDC,api.vendor.example,0xabc123\n"


def test_free_scan_page_offers_the_audit_with_beacon(server):
    with urllib.request.urlopen(f"{server}/free-scan", timeout=10) as r:
        html = r.read().decode()
    assert 'id="after-scan"' in html, "после скана должен быть виден следующий шаг"
    assert "/api/audit-intent" in html and "199" in html


def test_scan_response_carries_next_step(server, tmp_path, monkeypatch):
    """Ответ скана обязан называть платный шаг: через день это никто не вспомнит."""
    import attest.service as svc

    monkeypatch.setattr(svc.AttestHandler, "leads_path", tmp_path / "leads.jsonl")
    monkeypatch.setattr(svc.AttestHandler, "free_scans_dir", tmp_path / "free_scans")
    body = json.dumps({"email": "buyer@rta.lat", "csv": CSV}).encode()
    req = urllib.request.Request(f"{server}/api/free-scan", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        assert r.status == 200
        data = json.loads(r.read().decode())
    step = data["next_step"]
    assert "plans#audit" in step["audit"] and "agent-spend-audit" in step["pay"]
    assert "no fee" in step["note"].lower()
