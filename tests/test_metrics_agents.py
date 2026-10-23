"""Кто к нам стучится: человек, краулер, скрипт или шлюз каталога.

708 «direct» просмотров не отвечали на главный вопрос воронки — есть ли
среди них живые люди. Считаем семейство клиента по User-Agent, но храним
только семейство: полный UA — это отпечаток, а не метрика.
"""
from __future__ import annotations

import importlib

import attest.metrics as metrics


def test_businessmcp_gateway_is_recognised_before_crawler():
    # Их шлюз может представляться ботом; порядок проверок важнее полноты.
    assert metrics.agent_family("BusinessMCP/1.0 (bot; +https://businessmcp.com)") == "businessmcp"


def test_googlebot_is_crawler_even_though_it_says_mozilla():
    ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    assert metrics.agent_family(ua) == "crawler"


def test_curl_and_httpx_are_scripts():
    assert metrics.agent_family("curl/8.5.0") == "script"
    assert metrics.agent_family("python-httpx/0.27.0") == "script"


def test_real_browser_is_browser():
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/138.0 Safari/537.36"
    assert metrics.agent_family(ua) == "browser"


def test_empty_user_agent_is_none_not_other():
    assert metrics.agent_family(None) == "none"
    assert metrics.agent_family("   ") == "none"


def test_metrics_count_agents_by_family():
    m = metrics.Metrics()
    browser = "Mozilla/5.0 (X11; Linux x86_64) Chrome/138.0 Safari/537.36"
    m.view("/", agent=browser)
    m.view("/", agent=browser)
    m.check("direct", paid=False, client="ip:1.2.3.4", agent="curl/8.5.0")
    assert m.snapshot()["agents"] == {"browser": 2, "script": 1}


def test_agents_survive_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(metrics, "STATE_PATH", tmp_path / "metrics.json")
    m = metrics.Metrics()
    m.check("direct", paid=False, agent="curl/8.5.0")
    m.save()

    fresh = metrics.Metrics()
    fresh.load()
    assert fresh.snapshot()["agents"] == {"script": 1}
