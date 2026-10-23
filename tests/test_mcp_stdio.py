"""stdio-транспорт MCP: то же поведение, что у HTTP, но для контейнерных каталогов.

Glama запускает сервер как `mcp-proxy -- <cmd>` и ждёт JSON-RPC по строке на
stdin/stdout. Проверяем ровно то, на чём такой транспорт ломается: рукопожатие,
список инструментов, уведомления без ответа и пустые строки.
"""
from __future__ import annotations

import io
import json

from attest.mcp_stdio import serve_stream


def _replies(out: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in out.getvalue().strip().split("\n") if line.strip()]


def test_stdio_answers_initialize_and_tools_list():
    stdin = io.StringIO(
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
    )
    out = io.StringIO()
    serve_stream(stdin, out)
    replies = _replies(out)
    assert replies[0]["result"]["serverInfo"]["name"] == "attest"
    names = [tool["name"] for tool in replies[1]["result"]["tools"]]
    assert "verify_artifact" in names
    assert "verify_artifact_batch" in names


def test_blank_lines_are_not_messages():
    out = io.StringIO()
    serve_stream(io.StringIO("\n\n   \n"), out)
    assert out.getvalue() == ""


def test_notification_gets_no_reply():
    out = io.StringIO()
    serve_stream(io.StringIO('{"jsonrpc":"2.0","method":"notifications/initialized"}\n'), out)
    assert out.getvalue() == ""
