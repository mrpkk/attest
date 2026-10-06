"""MCP-интерфейс к attest: проверка артефактов как инструмент агента.

Зачем это отдельным модулем, а не ещё одной страницей: почти все крупные
реестры агентов (Glama, Smithery, mcp.so, ClawHub) принимают **только MCP**.
Без этого интерфейса продукт физически некуда заявить, кроме x402-каталога.
То есть отсутствие MCP — не украшение, а заблокированный канал дистрибуции.

Реализован подмножество протокола: JSON-RPC 2.0 поверх HTTP, методы
`initialize`, `tools/list`, `tools/call`. Ничего лишнего — ни SSE, ни
многопользовательских сессий: листинг требует корректной работы этих трёх
методов, а не полноты спецификации.

Инструмент один и он бесплатный в рамках общего тарифа: проверка стоит клиенту
ноль до исчерпания дневного лимита.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "attest"
SERVER_VERSION = "0.1.0"

# Описание инструмента. Показывается агенту в списке — по нему модель решает,
# стоит ли инструмент вызывать. Поэтому описано человеческим языком, а не
# «verifier(bool)»: агент читает описания, а не сигнатуры.
VERIFY_TOOL: dict[str, Any] = {
    "name": "verify_artifact",
    # Аннотации обязательны: Anthropic не примет листинг без них, Smithery и
    # Cursor рисуют их бейджами. Наш инструмент ничего не меняет — он только
    # читает, поэтому readOnlyHint=true, и это же важно сказать агенту явно.
    "title": "Проверка артефакта агента",
    "annotations": {
        "title": "Проверка артефакта агента",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "description": (
        "Проверить артефакт, полученный от ИИ-агента, до выплаты: инъекции "
        "в данные, нарушения схемы, опасные команды, происхождение. "
        "Возвращает вердикт accept/review/reject, доверие 0-100, конкретные "
        "находки и подпись. Проверка по правилам, без LLM: одинаковый артефакт "
        "даёт одинаковый результат. Используйте перед принятием работы от "
        "другого агента и перед оплатой."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "artifact": {
                "description": "Артефакт агента: объект, массив или строка.",
            },
            "schema": {
                "type": "object",
                "description": "Необязательная JSON Schema, которой артефакт должен удовлетворять.",
            },
            "source": {
                "type": "string",
                "description": "Откуда артефакт — для записи в аттестации.",
            },
        },
        "required": ["artifact"],
        "additionalProperties": False,
    },
}

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL = -32603

MAX_ARTIFACT_BYTES = 256 * 1024


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def as_dict(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return error


BRIDGE_TOOL: dict[str, Any] = {
    "name": "bridge_check",
    "title": "Мост: задача → работа → деньги",
    "annotations": {
        "title": "Мост: задача → работа → деньги",
        # Не read-only: инструмент двигает состояние сделки и бюджет.
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "description": (
        "Провести сделку через мост: заказчик ставит задачу с бюджетом в "
        "эскроу, агент сдаёт артефакт, мост проверяет его и выпускает "
        "подписанный RECEIPT. Бюджет отпускается только после проверки. "
        "RECEIPT проверяется третьей стороной без доступа к мосту — это то, "
        "что делает слой переносимым между агентом, заказчиком и страховщиком. "
        "Действия: job (создать), deliver (сдать и проверить), release "
        "(принять), refund (отклонить), verify (проверить чужой receipt), "
        "trust (репутация). Используйте, когда агент берёт оплачиваемую задачу "
        "или когда нужно доказать третьей стороне, что работа выполнена."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["job", "deliver", "release", "refund", "verify", "trust"],
                "description": "Что сделать.",
            },
            "job_id": {"type": "string", "description": "ID задачи (кроме job)."},
            "agent": {"type": "string", "description": "Идентификатор агента."},
            "title": {"type": "string", "description": "Что нужно сделать (для job)."},
            "spec": {"type": "object", "description": "Спецификация результата (для job)."},
            "amount_minor": {
                "type": "integer",
                "description": "Бюджет в минорных единицах, 1 USDC = 1000000.",
            },
            "client": {"type": "string", "description": "Кто заказчик (для job)."},
            "artifact": {"description": "Артефакт агента (для deliver)."},
            "receipt": {"type": "object", "description": "Чужой receipt (для verify)."},
            "db": {"type": "string", "description": "Путь к базе моста."},
        },
        "required": ["action"],
    },
}


def _result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, error: RpcError) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": error.as_dict()}


def handle_request(
    message: Mapping[str, Any],
    verify: Callable[..., Any],
    bridge: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Обработать одно JSON-RPC сообщение.

    `verify` — функция проверки; подставляется снаружи, чтобы MCP-слой не
    зависел от HTTP-сервиса и проверялся в одиночку.
    `bridge` — действие моста (опционально, добавлено 06.10.2026): тот же
    приём, MCP-слой не знает про деньги и файлы.
    """
    if not isinstance(message, Mapping) or message.get("jsonrpc") != "2.0":
        return _error(
            message.get("id") if isinstance(message, Mapping) else None,
            RpcError(JSONRPC_INVALID_REQUEST, "ожидается JSON-RPC 2.0"),
        )
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}
    if not isinstance(params, Mapping):
        return _error(request_id, RpcError(JSONRPC_INVALID_PARAMS, "params должны быть объектом"))

    try:
        if method == "initialize":
            return _result(request_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            })
        if method == "tools/list":
            return _result(request_id, {"tools": [VERIFY_TOOL, BRIDGE_TOOL]})
        # Пустые списки вместо «метод не найден»: так требуют все сканеры
        # каталогов. Отсутствие этих методов читается как сломанный сервер и
        # портит карточку листинга, хотя инструменты при этом работают.
        if method == "resources/list":
            return _result(request_id, {"resources": []})
        if method == "prompts/list":
            return _result(request_id, {"prompts": []})
        if method == "resources/templates/list":
            return _result(request_id, {"resourceTemplates": []})
        if method == "tools/call":
            return _result(request_id, _call_tool(params, verify, bridge))
        if method in ("notifications/initialized", "ping"):
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        return _error(
            request_id,
            RpcError(JSONRPC_METHOD_NOT_FOUND, f"метод {method!r} не поддерживается"),
        )
    except RpcError as exc:
        return _error(request_id, exc)
    except Exception as exc:  # noqa: BLE001
        return _error(request_id, RpcError(JSONRPC_INTERNAL, f"внутренняя ошибка: {exc}"))


def _call_tool(
    params: Mapping[str, Any],
    verify: Callable[..., Any],
    bridge: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, Mapping):
        raise RpcError(JSONRPC_INVALID_PARAMS, "arguments должны быть объектом")
    if name == BRIDGE_TOOL["name"]:
        if bridge is None:
            raise RpcError(
                JSONRPC_METHOD_NOT_FOUND,
                "инструмент bridge_check недоступен: мост не подключён",
            )
        return _call_bridge(arguments, bridge)
    if name != VERIFY_TOOL["name"]:
        raise RpcError(JSONRPC_METHOD_NOT_FOUND, f"инструмент {name!r} не существует")
    if "artifact" not in arguments:
        raise RpcError(JSONRPC_INVALID_PARAMS, 'нужен аргумент "artifact"')

    encoded = json.dumps(arguments["artifact"], ensure_ascii=False, default=str)
    if len(encoded.encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise RpcError(
            JSONRPC_INVALID_PARAMS,
            f"артефакт больше {MAX_ARTIFACT_BYTES} байт",
            {"bytes": len(encoded.encode('utf-8'))},
        )

    schema = arguments.get("schema")
    source = arguments.get("source")
    source = source if isinstance(source, str) and source.strip() else "mcp"
    result = verify(
        arguments["artifact"],
        schema if isinstance(schema, Mapping) else None,
        source=str(source)[:200],
    )
    payload = result.as_dict() if hasattr(result, "as_dict") else dict(result)
    # Структурированный вывод: агенту не нужно вытаскивать вердикт из текста.
    return {
        "content": [
            {
                "type": "text",
                "text": (
                    f"{payload['verdict'].upper()} · доверие "
                    f"{payload['trust_score']:.0f}/100 · {payload['reason']}"
                ),
            }
        ],
        "structuredContent": payload,
        "isError": payload["verdict"] == "reject",
    }


def _call_bridge(arguments: Mapping[str, Any], bridge: Callable[..., Any]) -> dict[str, Any]:
    """Провести действие моста и вернуть агенту структурированный результат.

    Мост сознательно вынесен в колбэк: MCP-слой не знает про деньги и
    файлы, он знает про контракт «дай действие, верни результат». Так его
    можно подключить к любому хранилищу, включая тестовое.
    """
    action = arguments.get("action")
    if action not in ("job", "deliver", "release", "refund", "verify", "trust"):
        raise RpcError(JSONRPC_INVALID_PARAMS, f"неизвестное действие {action!r}")

    kwargs = {k: v for k, v in arguments.items() if k != "action"}
    try:
        result = bridge(action=action, **kwargs)
    except TypeError as exc:
        raise RpcError(JSONRPC_INVALID_PARAMS, f"неверные аргументы: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        raise RpcError(JSONRPC_INTERNAL, f"мост: {exc}") from exc

    payload = result if isinstance(result, dict) else {"result": str(result)}
    is_error = action == "deliver" and payload.get("verdict", {}).get("accepted") is False
    return {
        "content": [
            {
                "type": "text",
                "text": str(payload.get("summary") or f"{action}: выполнено"),
            }
        ],
        "structuredContent": payload,
        "isError": bool(is_error),
    }


def parse_body(raw: bytes) -> dict[str, Any] | list[dict[str, Any]]:
    """Разобрать тело: одиночный запрос или пакет."""
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RpcError(JSONRPC_PARSE_ERROR, f"не разобрал JSON: {exc}") from exc
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        if not all(isinstance(item, dict) for item in parsed):
            raise RpcError(JSONRPC_INVALID_REQUEST, "в пакете не только объекты")
        return parsed
    raise RpcError(JSONRPC_INVALID_REQUEST, "ожидался объект или массив")


def respond(
    raw: bytes,
    verify: Callable[..., Any],
    bridge: Callable[..., Any] | None = None,
) -> tuple[int, bytes] | None:
    """Полный цикл: тело → ответ. `None` означает «ответ не требуется»."""
    try:
        message = parse_body(raw)
    except RpcError as exc:
        return 200, json.dumps(_error(None, exc)).encode()
    if isinstance(message, list):
        if not message:
            return 200, json.dumps(_error(None, RpcError(JSONRPC_INVALID_REQUEST, "пустой пакет"))).encode()
        replies = [handle_request(item, verify, bridge) for item in message]
        replies = [item for item in replies if "id" in item or item.get("id") is not None]
        return 200, json.dumps(replies).encode()
    reply = handle_request(message, verify, bridge)
    if message.get("id") is None:
        return None
    return 200, json.dumps(reply).encode()