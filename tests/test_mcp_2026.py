"""S7: MCP 2026-07-28 — stateless ядро.

Гейт: инструмент вызывается без рукопожатия; версия приходит заголовком и
возвращается; старый клиент получает свою версию обратно.
"""

from __future__ import annotations

import json

from attest import mcp


def verify(artifact, schema, source):
    return {"verdict": "accept", "trust_score": 100, "reason": "ok"}


def rpc(method, params=None, ident=1):
    return {"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}}


def test_tool_call_works_without_initialize():
    """Stateless: клиент 2026-07-28 не делает рукопожатия вообще."""
    reply = mcp.handle_request(rpc("tools/call", {"name": "verify_artifact",
                                                  "arguments": {"artifact": {"a": 1}}}), verify)
    assert "result" in reply, reply


def test_new_protocol_version_is_default():
    reply = mcp.handle_request(rpc("initialize", {"protocolVersion": "2026-07-28"}), verify)
    assert reply["result"]["protocolVersion"] == "2026-07-28"


def test_legacy_client_gets_its_own_version_back():
    reply = mcp.handle_request(rpc("initialize", {"protocolVersion": "2025-06-18"}), verify)
    assert reply["result"]["protocolVersion"] == "2025-06-18", \
        "ответ «я новее» старый клиент читает как отказ"


def test_header_version_wins_over_body():
    reply = mcp.handle_request(rpc("initialize", {"protocolVersion": "2025-06-18"}), verify,
                               protocol_version="2026-07-28")
    assert reply["result"]["protocolVersion"] == "2026-07-28"


def test_unknown_client_gets_the_conservative_version():
    """Регрессия на реальную потерю канала.

    Glama не поддерживает 2026-07-28. Когда сервер отвечал на незнакомую версию
    самой новой, каталог объявлял коннектор нерабочим и опускал его в выдаче.
    Незнакомому клиенту отвечаем самым осторожным, а не самым свежим.
    """
    reply = mcp.handle_request(rpc("initialize", {"protocolVersion": "1999-01-01"}), verify)
    assert reply["result"]["protocolVersion"] == mcp.LEGACY_PROTOCOL_VERSION
    assert reply["result"]["protocolVersion"] != mcp.PROTOCOL_VERSION


def test_empty_version_also_gets_the_conservative_one():
    reply = mcp.handle_request(rpc("initialize", {}), verify)
    assert reply["result"]["protocolVersion"] == mcp.LEGACY_PROTOCOL_VERSION


def test_oldest_supported_version_is_accepted():
    reply = mcp.handle_request(rpc("initialize", {"protocolVersion": "2025-03-26"}), verify)
    assert reply["result"]["protocolVersion"] == "2025-03-26"


def test_respond_passes_the_version_through():
    raw = json.dumps(rpc("initialize", {"protocolVersion": "2025-06-18"})).encode()
    status, body = mcp.respond(raw, verify, protocol_version="2026-07-28")
    assert status == 200
    assert json.loads(body)["result"]["protocolVersion"] == "2026-07-28"


def test_no_session_identifier_is_required_or_emitted():
    """В 2026-07-28 сессии нет: сервер не должен её требовать."""
    reply = mcp.handle_request(rpc("tools/list"), verify)
    assert "result" in reply
    assert "sessionId" not in json.dumps(reply)
