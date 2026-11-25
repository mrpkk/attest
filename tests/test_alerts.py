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


def test_watchdog_reports_every_failing_check(tmp_path):
    res = wd.run_once(tmp_path / "w.json", probes=lambda url: 200 if url.endswith("/health") else 500,
                      send=lambda text: (True, ""))
    assert res["status"] == "down"
    assert set(res["bad"]) == {"/free-scan", "/api/funnel"}


def test_service_reports_5xx_to_alerts():
    """Ответ 5xx должен дёргать алерт: иначе «жив, но не работает» незаметно."""
    src = (ROOT / "attest" / "service.py").read_text(encoding="utf-8")
    assert "alert_errors()" in src
    assert "if status >= 500" in src


def test_health_reports_whether_alerts_can_be_delivered(monkeypatch):
    """Неготовый webhook должен быть виден до аварии, а не выясняться после."""
    monkeypatch.setenv("ATTEST_SLACK_WEBHOOK", "https://hooks.example/abc")
    assert alerts.webhook_configured() is True
    monkeypatch.delenv("ATTEST_SLACK_WEBHOOK", raising=False)
    monkeypatch.setattr(alerts, "_env_value", lambda key: "")
    assert alerts.webhook_configured() is False


def test_watchdog_probes_the_sale_path_not_only_health():
    """Упавшая страница скана — потерянный покупатель, даже если /health отвечает."""
    assert "/free-scan" in wd.CHECKS
    assert "/api/funnel" in wd.CHECKS


def test_watchdog_reports_which_sale_path_check_failed(tmp_path):
    codes = {"/health": 200, "/free-scan": 500, "/api/funnel": 200}

    def probe(url):
        for path, code in codes.items():
            if url.endswith(path):
                return code
        return 0

    res = wd.run_once(tmp_path / "w.json", probes=probe, send=lambda text: (True, ""))
    assert res["status"] == "down"
    assert res["bad"] == {"/free-scan": 500}


def test_alert_down_sends_once_per_cooldown(monkeypatch):
    from attest import alerts
    alerts.reset()
    sent = []
    monkeypatch.setattr(alerts, "post", lambda text, url=None, timeout=10: (sent.append(text), (True, ""))[1])
    assert alerts.alert_down("health недоступен", now=1000.0)["sent"] is True
    assert alerts.alert_down("снова", now=1100.0)["reason"] == "already_sent"
    assert alerts.alert_down("снова", now=2000.0)["sent"] is True
    assert len(sent) == 2 and "DOWN" in sent[0]


def test_status_reports_webhook_and_timestamps(monkeypatch):
    from attest import alerts
    alerts.reset()
    monkeypatch.setattr(alerts, "webhook_configured", lambda: True)
    st = alerts.status()
    assert st["webhook_configured"] is True and st["last_error_alert_at"] is None


def _flaky_receiver(statuses):
    """Приёмник, который первые ответы отдаёт не-200 — проверяем повтор."""
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            code = statuses[min(len(seen), len(statuses) - 1)]
            seen.append(code)
            self.send_response(code)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/hook", seen


def test_transient_failure_is_retried_once():
    """503 у приёмника — алерт повторяется: потерянный алерт это тишина вместо тревоги."""
    server, url, seen = _flaky_receiver([503, 200])
    try:
        ok, why = alerts.post("attest: повтор", url=url, retry_delay=0.01)
    finally:
        server.shutdown()
        server.server_close()
    assert (ok, why) == (True, "")
    assert seen == [503, 200], "вторая попытка должна быть после 503"


def test_client_error_is_not_retried():
    """400 — это наша ошибка в формате, повтор ничего не даст и только тратит время."""
    server, url, seen = _flaky_receiver([400, 200])
    try:
        ok, why = alerts.post("attest: неверный запрос", url=url, retry_delay=0.01)
    finally:
        server.shutdown()
        server.server_close()
    assert ok is False and why == "http_400"
    assert seen == [400], "на 4xx повтора быть не должно"


def test_watchdog_is_scheduled_not_just_written():
    """Сторож, которого никто не запускает, — это файл, а не алерт (26.11.2026)."""
    unit = (ROOT / "deploy" / "attest-watchdog.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "attest-watchdog.timer").read_text(encoding="utf-8")
    assert "scripts/watchdog.py" in unit
    assert "OnUnitActiveSec=5min" in timer
    assert "WantedBy=timers.target" in timer


def test_products_monitor_alerts_on_change_not_every_pass(tmp_path):
    """Таймер запускает новый процесс: без файла состояния алерт уходил бы каждые 10 минут."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("monitor_products",
                                                  ROOT / "scripts" / "monitor_products.py")
    mp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mp)

    sent: list[str] = []
    orig_alert = mp.alert
    mp.alert = lambda failed: (sent.append(",".join(r["name"] for r in failed)), {"sent": True})[1]
    import attest.alerts as real_alerts
    orig_post = real_alerts.post
    real_alerts.post = lambda text, url=None, **kw: (sent.append("recovered"), (True, ""))[1]

    down = {"ok": False, "rows": [{"name": "Site Guard", "url": "u", "code": 503, "ok": False}]}
    up = {"ok": True, "rows": [{"name": "Site Guard", "url": "u", "code": 200, "ok": True}]}
    state = tmp_path / "s.json"

    assert mp.notify(down, state_path=state, now=1000.0)["sent"] is True
    assert mp.notify(down, state_path=state, now=1060.0)["reason"] == "already_reported"
    assert mp.notify(down, state_path=state, now=1000.0 + 6 * 3600)["sent"] is True
    assert mp.notify(up, state_path=state, now=1000.0 + 7 * 3600)["sent"] is True, "возврат — одно сообщение"
    assert mp.notify(up, state_path=state, now=1000.0 + 8 * 3600)["reason"] == "state_changed"
    mp.alert = orig_alert
    real_alerts.post = orig_post
    assert sent == ["Site Guard", "Site Guard", "recovered"]


def test_monitor_covers_the_three_products_directly():
    import importlib.util

    spec = importlib.util.spec_from_file_location("monitor_products2",
                                                  ROOT / "scripts" / "monitor_products.py")
    mp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mp)
    names = " ".join(n for n, _ in mp.PRODUCTS)
    for name in ("Site Guard", "Sheet Doctor", "Doc Answer Box"):
        assert name in names
    assert "product=site-guard-year" in dict((n, u) for n, u in mp.PRODUCTS)["Site Guard"]


def test_products_timer_exists():
    unit = (ROOT / "deploy" / "attest-products.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "attest-products.timer").read_text(encoding="utf-8")
    assert "monitor_products.py" in unit and "--alert" in unit
    assert "OnUnitActiveSec=10min" in timer
