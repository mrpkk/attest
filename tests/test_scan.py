"""Скан MCP-сервера: анализ находок и устойчивость к кривым ответам."""
import json
import urllib.error

import pytest

from attest import scan


def _tool(name, desc="", **extra):
    t = {"name": name, "description": desc}
    t.update(extra)
    return t


def test_money_tools_are_high_finding():
    r = scan.analyze([_tool("pay_invoice"), _tool("read_file")])
    titles = [f["title"] for f in r["findings"]]
    assert any("деньги" in t for t in titles)
    assert r["money_tools"] == ["pay_invoice"]
    assert r["verdict"] == "needs attention"


def test_write_tools_detected():
    r = scan.analyze([_tool("delete_user"), _tool("update_record")])
    assert r["write_tools"] == ["delete_user", "update_record"]
    assert any("меняют состояние" in f["title"] for f in r["findings"])


def test_missing_annotations_counted():
    r = scan.analyze([_tool("a"), _tool("b", annotations={"readOnlyHint": True})])
    assert r["annotated"] == 1
    assert any("без аннотаций" in f["title"] for f in r["findings"])


def test_controls_lower_risk_and_clear_findings():
    tools = [_tool("read_doc", "reads with budget limit and kill switch, receipt audit",
                   annotations={"readOnlyHint": True}),
             _tool("pay_x", "pays within budget limit; kill switch; receipt audit",
                   annotations={"destructiveHint": True})]
    r = scan.analyze(tools)
    assert r["controls"]["budget"] and r["controls"]["kill"] and r["controls"]["receipt"]
    assert not any("бюджет" in f["title"] for f in r["findings"])
    assert not any("kill-switch" in f["title"] for f in r["findings"])
    assert r["score"] == 35  # только money-находка
    assert r["verdict"] == "looks controlled"


def test_empty_tools_no_crash():
    r = scan.analyze([])
    assert r["tools"] == 0 and r["findings"]
    assert r["score"] <= 100


def test_fetch_tools_uses_initialize_and_list(monkeypatch):
    calls = []

    def fake_rpc(url, payload, session=""):
        calls.append(payload.get("method"))
        if payload.get("method") == "initialize":
            return {"result": {"serverInfo": {"name": "x"}}}, "sid-1"
        return {"result": {"tools": [_tool("pay")]}}, "sid-1"

    monkeypatch.setattr(scan, "_rpc", fake_rpc)
    tools = scan.fetch_tools("https://example.test/mcp")
    assert tools[0]["name"] == "pay"
    assert "initialize" in calls and "tools/list" in calls


def test_fetch_tools_reports_bad_endpoint(monkeypatch):
    def fake_rpc(url, payload, session=""):
        raise urllib.error.HTTPError(url, 405, "no", None, None)

    monkeypatch.setattr(scan, "_rpc", fake_rpc)
    with pytest.raises(RuntimeError) as e:
        scan.fetch_tools("https://example.test/mcp")
    assert "405" in str(e.value)


def test_scan_page_is_html():
    html = scan.scan_page()
    assert "<form" in html and "/api/scan" in html and "Scan" in html
