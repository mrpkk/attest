"""MCP по stdio — транспорт для каталогов, которые собирают сервер в контейнере.

Зачем отдельный вход: HTTP-сервис слушает порт 8185 и отдаёт `/mcp`, а Glama
оборачивает команду в `mcp-proxy -- ...` и ждёт JSON-RPC в stdin/stdout. Логика
не дублируется: тот же `mcp.respond`, другой транспорт. Так каталог получает
рабочий сервер и может поставить оценку качества инструментов.

Запуск: `python -m attest.mcp_stdio`.
"""
from __future__ import annotations

import sys
from typing import IO

from .core import attest
from .mcp import respond


def _verify(artifact, schema, source):
    return attest(artifact, schema, source=source)


def serve_stream(reader: IO[str], writer: IO[str]) -> None:
    """Читать по строке, отвечать по строке. Пустая строка — не сообщение."""
    for line in reader:
        raw = line.strip()
        if not raw:
            continue
        answer = respond(raw.encode("utf-8"), _verify)
        if answer is None:
            continue
        _, body = answer
        writer.write(body.decode("utf-8") + "\n")
        writer.flush()


def main() -> int:
    serve_stream(sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
