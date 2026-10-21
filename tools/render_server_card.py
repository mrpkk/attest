#!/usr/bin/env python3
"""Собрать статическую карточку сервера для каталогов MCP.

Зачем: Smithery (и другие каталоги) сканируют сервер, чтобы взять из него
список инструментов. Если скан не проходит (авторизация, таймаут, защита),
каталог просит статическую карточку — обычный JSON по адресу
`/.well-known/mcp/server-card.json`.

Карточка собирается из тех же описаний, что отдаёт живой `/mcp`
(attest.mcp.VERIFY_TOOL и соседи), поэтому она не может разойтись с
сервером: забытое описание здесь означало бы расхождение с листингом.

Запуск: python3 tools/render_server_card.py
Результат: attest/server_card.py (модуль с JSON) + server-card.json в корне.
"""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import mcp  # noqa: E402


def build_card() -> dict:
    tools = []
    for tool in (mcp.VERIFY_TOOL, mcp.BATCH_TOOL, mcp.BRIDGE_TOOL):
        tools.append({
            "name": tool["name"],
            "description": tool["description"],
            "inputSchema": tool["inputSchema"],
            "annotations": tool.get("annotations", {}),
        })
    return {
        "serverInfo": {"name": mcp.SERVER_NAME, "version": mcp.SERVER_VERSION},
        "authentication": {"required": False, "schemes": []},
        "tools": tools,
        "resources": [],
        "prompts": [],
    }


def main() -> None:
    card = build_card()
    text = json.dumps(card, ensure_ascii=False, indent=2) + "\n"
    (ROOT / "attest" / "server_card.py").write_text(
        '"""Статическая карточка сервера для каталогов MCP.\n\n'
        "Генерируется tools/render_server_card.py — не править руками.\n"
        '"""\n\n'
        "SERVER_CARD = " + repr(text) + "\n",
        encoding="utf-8",
    )
    (ROOT / "server-card.json").write_text(text, encoding="utf-8")
    print(f"  server-card.json: {len(text)} байт, инструментов: {len(card['tools'])}")


if __name__ == "__main__":
    main()
