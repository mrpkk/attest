"""Алерты и сторож: доставка проверяется живым HTTP-приёмником, а не моком.

21.11.2026: у сервиса не было внешнего взгляда — падение и всплеск 5xx замечал
только тот, кто сам заходил на /health.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import alerts  # noqa: E402

_spec = importlib.util.spec_from_file_location("attest_watchdog", ROOT / "scripts" / "watchdog.py")
wd = importlib.util.module_from_spec(_spec)
sys.modules["attest_watchdog"] = wd
_spec.loader.exec_module(wd)


class _Receiver:
    """Мини-приёмник Slack-webhook: запоминает тело и отвечает 200."""

    def __init__(self) -> None:
        self.bodies: list[dict] = []
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                receiver.bodies.append(json.loads(self.rfile.read(length) or b"{}"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):  # тишина в тестовом выводе
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def test_post_delivers_slack_payload():
    with _Receiver() as rec:
        ok, why = alerts.post("attest: проверка доставки", url=rec.url)
    assert ok is True and why == ""
    assert rec.bodies and "проверка доставки" in rec.bodies[0]["text"]


def test_missing_webhook_is_honest(monkeypatch):
    monkeypatch.delenv(alerts.ENV_KEY, raising=False)
    monkeypatch.setattr(alerts, "_env_value", lambda key: "")
    ok, why = alerts.post("текст")
    assert ok is False and why == "webhook_not_configured"


def test_error_spike_alerts_once_per_window(monkeypatch):
    alerts.reset()
    sent: list[str] = []
    monkeypatch.setattr(alerts, "post", lambda text, url=None: (sent.append(text), (True, ""))[1])
    first = alerts.alert_errors(count=3, now=1000.0, threshold=3)
    assert first["sent"] is True and len(sent) == 1
    again = alerts.alert_errors(count=10, now=1001.0, threshold=3)
    assert again["sent"] is False and again["reason"] == "already_sent"
    later = alerts.alert_errors(count=10, now=1000.0 + alerts.ERROR_WINDOW_SECONDS + 1, threshold=3)
    assert later["sent"] is True and len(sent) == 2


def test_below_threshold_does_not_alert(monkeypatch):
    alerts.reset()
    sent: list[str] = []
    monkeypatch.setattr(alerts, "post", lambda text, url=None: (sent.append(text), (True, ""))[1])
    res = alerts.alert_errors(count=1, now=2000.0, threshold=5)
    assert res["sent"] is False and res["reason"] == "below_threshold" and sent == []


def test_watchdog_alerts_on_change_only(tmp_path):
    sent: list[str] = []
    state = tmp_path / "w.json"

    def bad(url):
        return 503

    def good(url):
        return 200

    wd.run_once(state, probes=bad, send=lambda text: (sent.append(text), (True, ""))[1])
    wd.run_once(state, probes=bad, send=lambda text: (sent.append(text), (True, ""))[1])
    assert len(sent) == 1, "повторное падение не должно спамить"
    assert "503" in sent[0]

    res = wd.run_once(state, probes=good, send=lambda text: (sent.append(text), (True, ""))[1])
    assert res["status"] == "ok" and len(sent) == 2 and "снова" in sent[1]


def test_watchdog_reports_both_checks(tmp_path):
    res = wd.run_once(tmp_path / "w.json", probes=lambda url: 200 if url.endswith("/health") else 500,
                      send=lambda text: (True, ""))
    assert res["status"] == "down"
    assert res["bad"] == {"/stats": 500}


def test_service_reports_5xx_to_alerts():
    """Ответ 5xx должен дёргать алерт: иначе «жив, но не работает» незаметно."""
    src = (ROOT / "attest" / "service.py").read_text(encoding="utf-8")
    assert "alert_errors()" in src
    assert "if status >= 500" in src
