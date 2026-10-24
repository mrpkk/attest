"""CI-проверка артефактов: отказ и ошибка сети не должны выглядеть как «принято»."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts.verify_artifacts import verify_one


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        verdict = "reject" if "empty" in json.dumps(body.get("artifact", {})) else "accept"
        out = json.dumps({"verdict": verdict, "trust_score": 70 if verdict == "reject" else 100,
                          "reason": "form is valid but the artifact is empty"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def endpoint():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/verify"
    httpd.shutdown()
    httpd.server_close()


def _file(tmp_path: Path, name: str, payload: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_reject_is_reported_as_reject(tmp_path, endpoint):
    p = _file(tmp_path, "a.json", {"findings": ["empty"]})
    r = verify_one(p, None, endpoint)
    assert r["verdict"] == "reject" and r["trust_score"] == 70


def test_accept_is_reported_as_accept(tmp_path, endpoint):
    p = _file(tmp_path, "b.json", {"findings": ["one", "two"]})
    assert verify_one(p, None, endpoint)["verdict"] == "accept"


def test_broken_json_is_an_error_not_an_accept(tmp_path, endpoint):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    r = verify_one(p, None, endpoint)
    assert r["verdict"] == "error" and "JSON" in r["reason"]


def test_unreachable_endpoint_is_an_error(tmp_path):
    p = _file(tmp_path, "c.json", {"a": 1})
    r = verify_one(p, None, "http://127.0.0.1:9/verify")
    assert r["verdict"] == "error"
