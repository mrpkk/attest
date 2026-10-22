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
    "title": "Verify an AI agent artifact",
    "annotations": {
        "title": "Verify an AI agent artifact",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "description": (
        "Verify an artifact produced by an AI agent before accepting or "
        "paying for it. Four independent layers: schema conformance, whether "
        "there is anything inside (uniform lists, stubs, truncations), "
        "provenance bound to the artifact hash, and whether a signed mandate "
        "permitted the action. Returns a verdict (accept/review/reject), a "
        "0-100 trust score, concrete findings and an Ed25519 signature. "
        "Rule-based, no LLM: the same artifact always yields the same "
        "result. Use before accepting work from another agent and before "
        "payment."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "artifact": {
                "description": "The agent artifact: object, array or string.",
            },
            "schema": {
                "type": "object",
                "description": "Optional JSON Schema the artifact must satisfy.",
            },
            "source": {
                "type": "string",
                "description": "Where the artifact came from, recorded in the attestation.",
            },
        },
        "required": ["artifact"],
        "additionalProperties": False,
    },
}

BATCH_TOOL: dict[str, Any] = {
    "name": "verify_artifact_batch",
    "title": "Verify a batch of AI agent artifacts",
    "annotations": {
        "title": "Verify a batch of AI agent artifacts",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "description": (
        "Verify several artifacts at once — a scan report, a list of findings, "
        "a set of tool descriptions. One call, one verdict per artifact, plus "
        "a summary of how many were accepted, need review, or were rejected. "
        "Use when an agent produced a batch (twenty findings from a security "
        "scan, for example) and each of them has to be checked before the "
        "work is paid for."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "artifacts": {
                "type": "array",
                "description": "The artifacts to verify: objects, arrays or strings.",
            },
            "schema": {
                "type": "object",
                "description": "Optional JSON Schema every artifact must satisfy.",
            },
            "source": {
                "type": "string",
                "description": "Where the artifacts came from, recorded in the attestations.",
            },
        },
        "required": ["artifacts"],
        "additionalProperties": False,
    },
}

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL = -32603

MAX_ARTIFACT_BYTES = 256 * 1024
# Пачка: сколько артефактов за один вызов. Больше — расточительно
# для обеих сторон: клиент платит за каждый, а ответ растёт линейно.
MAX_BATCH_ITEMS = 50


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
    "title": "Bridge: task to work to money",
    "annotations": {
        "title": "Bridge: task to work to money",
        # Не read-only: инструмент двигает состояние сделки и бюджет.
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "description": (
        "Settle a job between two agents through an escrow bridge. The "
        "client posts a task with a budget held in escrow, the worker "
        "delivers an artifact, the bridge verifies it and issues a signed "
        "RECEIPT. The budget is released only after verification passes. "
        "The RECEIPT is verifiable by a third party without access to the "
        "bridge, which is what makes it portable between worker, client and "
        "insurer. Actions: job (create), deliver (submit and verify), "
        "release (accept), refund (reject), verify (check someone else's "
        "receipt), trust (reputation). Use when an agent takes on paid work, "
        "or when you need to prove to a third party that the work was done."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["job", "deliver", "release", "refund", "verify", "trust"],
                "description": "What to do.",
            },
            "job_id": {"type": "string", "description": "Job ID (any action except job)."},
            "agent": {"type": "string", "description": "Agent identifier."},
            "title": {"type": "string", "description": "What needs to be done (for job)."},
            "spec": {"type": "object", "description": "Expected result specification (for job)."},
            "amount_minor": {
                "type": "integer",
                "description": "Budget in minor units; 1 USDC = 1000000.",
            },
            "client": {"type": "string", "description": "Who the client is (for job)."},
            "artifact": {"description": "The agent artifact (for deliver)."},
            "receipt": {"type": "object", "description": "A third party receipt (for verify)."},
            "db": {"type": "string", "description": "Path to the bridge database."},
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
            # Инструмент, который нельзя вызвать, не должен попадать в листинг:
            # сканер каталога вызывает всё подряд и читает ошибку вызова как
            # «сервер сломан» (так bridge_check выпал из листинга Smithery).
            tools = [VERIFY_TOOL, BATCH_TOOL]
            if bridge is not None:
                tools.append(BRIDGE_TOOL)
            return _result(request_id, {"tools": tools})
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


def _call_batch(arguments: Mapping[str, Any],
                verify: Callable[..., Any]) -> dict[str, Any]:
    """Проверить пачку артефактов одним вызовом.

    Один вердикт на артефакт плюс сводка. Агенту важно видеть, что именно
    плохое, а не только счётчик, поэтому в structuredContent — полный
    список результатов.
    """
    artifacts = arguments.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise RpcError(JSONRPC_INVALID_PARAMS,
                       'нужен непустой массив "artifacts"')
    if len(artifacts) > MAX_BATCH_ITEMS:
        raise RpcError(
            JSONRPC_INVALID_PARAMS,
            f"в пачке {len(artifacts)} артефактов, максимум {MAX_BATCH_ITEMS}",
        )
    schema = arguments.get("schema")
    source = arguments.get("source")
    source = source if isinstance(source, str) and source.strip() else "mcp-batch"

    results = []
    summary = {"accept": 0, "review": 0, "reject": 0}
    for index, artifact in enumerate(artifacts):
        encoded = json.dumps(artifact, ensure_ascii=False, default=str)
        if len(encoded.encode("utf-8")) > MAX_ARTIFACT_BYTES:
            raise RpcError(
                JSONRPC_INVALID_PARAMS,
                f"артефакт [{index}] больше {MAX_ARTIFACT_BYTES} байт",
                {"index": index, "bytes": len(encoded.encode("utf-8"))},
            )
        result = verify(
            artifact,
            schema,
            source=str(source)[:200],
        )
        payload = result.as_dict() if hasattr(result, "as_dict") else dict(result)
        verdict = str(payload.get("verdict", ""))
        if verdict in summary:
            summary[verdict] += 1
        results.append(payload)

    worst = "reject" if summary["reject"] else ("review" if summary["review"]
                                                else "accept")
    return {
        "content": [
            {
                "type": "text",
                "text": (
                    f"{worst.upper()} · {summary['accept']} принято, "
                    f"{summary['review']} на проверку, {summary['reject']} отклонено "
                    f"из {len(results)}"
                ),
            }
        ],
        "structuredContent": {"results": results, "summary": summary,
                              "verdict": worst, "count": len(results)},
        "isError": worst == "reject",
    }


def _tool_error(message: str) -> dict[str, Any]:
    """Ошибка ВЫПОЛНЕНИЯ инструмента — это результат с isError, а не
    протокольная ошибка.

    Разница видна клиенту: JSON-RPC error (-32601/-32602) читается как
    «сервер сломан», а результат с isError — как «инструмент сказал, что
    не может». По спецификации MCP протокольная ошибка означает, что запрос
    нельзя было понять (неизвестный инструмент, битый JSON), а всё, что
    случилось уже внутри инструмента, — это содержимое ответа.

    Именно на этом различии построен комментарий Arhan Canli к статье
    на dev.to (22.10.2026): его find_tool падал на "constructor" раньше,
    чем успевал собрать результат, и клиент видел -32603 вместо ответа.
    """
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


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
            # Инструмент объявлен в tools/list, значит вызов обязан вернуть
            # результат. -32601 здесь читался как «сервер сломан», и из-за
            # этого bridge_check выпадал из листингов каталогов.
            return _tool_error(
                "bridge_check недоступен: мост не подключён к этому развёртыванию. "
                "Используйте verify_artifact или verify_artifact_batch."
            )
        return _call_bridge(arguments, bridge)
    if name == BATCH_TOOL["name"]:
        return _call_batch(arguments, verify)
    if name != VERIFY_TOOL["name"]:
        raise RpcError(JSONRPC_METHOD_NOT_FOUND, f"no such tool: {name!r}")
    if "artifact" not in arguments:
        return _tool_error('нужен аргумент "artifact"')

    encoded = json.dumps(arguments["artifact"], ensure_ascii=False, default=str)
    if len(encoded.encode("utf-8")) > MAX_ARTIFACT_BYTES:
        return _tool_error(
            f"артефакт больше {MAX_ARTIFACT_BYTES} байт "
            f"({len(encoded.encode('utf-8'))})"
        )

    schema = arguments.get("schema")
    source = arguments.get("source")
    source = source if isinstance(source, str) and source.strip() else "mcp"
    result = verify(
        arguments["artifact"],
        schema,
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