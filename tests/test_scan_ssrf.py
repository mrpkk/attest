"""Скан не должен превращаться в SSRF-прокси.

22.11.2026: `fetch_tools` ходил по любому URL — значит через `/api/scan` можно было
постучаться в кассу на 127.0.0.1:8291, в админки и в метаданные облака
(`169.254.169.254`). Для сервиса, который продаёт доверие, это дыра не в коде, а в
самой идее.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import scan as scan_mod  # noqa: E402


def _fake_resolver(mapping: dict[str, str]):
    def getaddrinfo(host, port, *args, **kwargs):
        addr = mapping.get(host)
        if addr is None:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]
    return getaddrinfo


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8291/pay/health",
    "http://127.0.1.1/",
    "http://localhost/x",
    "http://LOCALHOST:8000/mcp",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/mcp",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://[::1]:8000/",
    "http://[fe80::1]/",
    "http://0.0.0.0/",
])
def test_internal_addresses_are_refused(url):
    with pytest.raises(RuntimeError):
        scan_mod.assert_public_url(url)


def test_domain_that_resolves_to_private_ip_is_refused(monkeypatch):
    """DNS-имя, указывающее внутрь, — тот же SSRF, только в другой одежде."""
    monkeypatch.setattr(scan_mod.socket, "getaddrinfo",
                        _fake_resolver({"evil.example": "10.1.2.3"}))
    with pytest.raises(RuntimeError):
        scan_mod.assert_public_url("http://evil.example/mcp")


def test_public_host_is_allowed(monkeypatch):
    monkeypatch.setattr(scan_mod.socket, "getaddrinfo",
                        _fake_resolver({"api.example.com": "93.184.216.34"}))
    scan_mod.assert_public_url("https://api.example.com/mcp")


def test_localhost_com_domain_is_refused():
    """`localhost.localhost` и подобные не должны проскакивать по суффиксу."""
    with pytest.raises(RuntimeError):
        scan_mod.assert_public_url("http://foo.localhost/mcp")


def test_non_http_scheme_is_refused():
    for url in ("file:///etc/passwd", "ftp://example.com/x", "gopher://example.com/"):
        with pytest.raises(RuntimeError):
            scan_mod.assert_public_url(url)


def test_redirects_are_not_followed():
    """Редирект — обход проверки адреса; сканер за ним не идёт."""
    handler = scan_mod._NoRedirect()          # noqa: SLF001
    with pytest.raises(Exception):
        handler.redirect_request(None, None, 302, "Found", {}, "http://127.0.0.1/")


def test_scan_endpoint_refuses_internal_url():
    from fastapi import FastAPI  # noqa: F401 — сервис на stdlib, проверяем через метод
    from attest.service import AttestHandler  # noqa: F401

    with pytest.raises(RuntimeError):
        scan_mod.scan("http://127.0.0.1:8291/pay/health")
