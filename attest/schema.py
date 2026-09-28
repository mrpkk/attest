"""Валидация артефакта по схеме.

Минимальный валидатор JSON-Schema-подобного контракта, без зависимостей.
Покрывает то, что реально ломается в потоке агент -> инструмент -> агент:
неверные типы, отсутствующие поля, лишние поля, переполнение строк,
и «тихий» сдвиг схемы (поле сменило тип, но ответ 200).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_STRING = 200_000
MAX_DEPTH = 12
MAX_ITEMS = 10_000


@dataclass
class SchemaViolation:
    path: str
    rule: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "rule": self.rule, "detail": self.detail}


def _type_ok(value: Any, expected: str) -> bool:
    match expected:
        case "string":
            return isinstance(value, str)
        case "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        case "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        case "boolean":
            return isinstance(value, bool)
        case "null":
            return value is None
        case "array":
            return isinstance(value, list)
        case "object":
            return isinstance(value, dict)
        case _:
            return True


def _validate(value: Any, schema: dict[str, Any], path: str, depth: int, out: list[SchemaViolation]) -> None:
    if depth > MAX_DEPTH:
        out.append(SchemaViolation(path, "depth", f"превышена глубина {MAX_DEPTH}"))
        return

    expected = schema.get("type")
    if isinstance(expected, str) and not _type_ok(value, expected):
        out.append(SchemaViolation(path, "type", f"ожидался {expected}, получен {type(value).__name__}"))
        return
    if isinstance(expected, list) and not any(_type_ok(value, t) for t in expected):
        out.append(SchemaViolation(path, "type", f"ожидался один из {expected}, получен {type(value).__name__}"))
        return

    if isinstance(value, str):
        if len(value) > MAX_STRING:
            out.append(SchemaViolation(path, "size", f"строка {len(value)} > {MAX_STRING}"))
        pattern = schema.get("pattern")
        if pattern:
            try:
                if not re.search(pattern, value):
                    out.append(SchemaViolation(path, "pattern", f"не совпало с /{pattern}/"))
            except re.error:
                pass
        enum = schema.get("enum")
        if isinstance(enum, list) and value not in enum:
            out.append(SchemaViolation(path, "enum", f"значение не входит в enum[{len(enum)}]"))
        return

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            out.append(SchemaViolation(path, "minimum", f"{value} < {schema['minimum']}"))
        if "maximum" in schema and value > schema["maximum"]:
            out.append(SchemaViolation(path, "maximum", f"{value} > {schema['maximum']}"))
        return

    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            out.append(SchemaViolation(path, "size", f"элементов {len(value)} > {MAX_ITEMS}"))
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for i, item in enumerate(value[:1000]):
                _validate(item, item_schema, f"{path}[{i}]", depth + 1, out)
        return

    if isinstance(value, dict):
        props: dict[str, Any] = schema.get("properties", {})
        required: list[str] = schema.get("required", [])
        additional = schema.get("additionalProperties", True)

        for key in required:
            if key not in value:
                out.append(SchemaViolation(f"{path}.{key}", "required", "обязательное поле отсутствует"))

        for key, sub in props.items():
            if key in value:
                _validate(value[key], sub, f"{path}.{key}", depth + 1, out)

        if additional is False:
            for key in value:
                if key not in props:
                    out.append(SchemaViolation(f"{path}.{key}", "additionalProperties", "лишнее поле"))


def _basic_invariants(artifact: Any, path: str, depth: int, out: list[SchemaViolation]) -> None:
    """Инварианты, которые проверяются даже без схемы.

    Агент не должен получить пустоту, мегабайтную простыню или структуру
    на 50 уровней вложенности — это всё способы сломать контекст.
    """
    if depth > MAX_DEPTH:
        out.append(SchemaViolation(path, "depth", f"превышена глубина {MAX_DEPTH}"))
        return
    if isinstance(artifact, str):
        if len(artifact) > MAX_STRING:
            out.append(SchemaViolation(path, "size", f"строка {len(artifact)} > {MAX_STRING}"))
    elif isinstance(artifact, list):
        if len(artifact) > MAX_ITEMS:
            out.append(SchemaViolation(path, "size", f"элементов {len(artifact)} > {MAX_ITEMS}"))
        for i, item in enumerate(artifact[:200]):
            _basic_invariants(item, f"{path}[{i}]", depth + 1, out)
    elif isinstance(artifact, dict):
        for k, v in artifact.items():
            _basic_invariants(v, f"{path}.{k}", depth + 1, out)


def validate_against_schema(artifact: Any, schema: dict[str, Any] | None) -> list[SchemaViolation]:
    """Проверить артефакт по схеме. Пустая схема = проверка только базовых инвариантов."""
    out: list[SchemaViolation] = []

    if schema:
        _validate(artifact, schema, "$", 0, out)
    else:
        _basic_invariants(artifact, "$", 0, out)

    if artifact is None:
        out.append(SchemaViolation("$", "null", "артефакт пуст — агент получит ничего"))
    elif isinstance(artifact, str) and not artifact.strip():
        out.append(SchemaViolation("$", "empty", "пустая строка"))
    elif isinstance(artifact, (list, dict)) and not artifact:
        out.append(SchemaViolation("$", "empty", "пустая структура"))

    return out
