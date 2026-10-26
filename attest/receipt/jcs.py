"""Канонический JSON по RFC 8785 (JCS) для профиля квитанций.

Зачем свой, а не `json.dumps(sort_keys=True)`: JCS требует сортировки ключей
по единицам кода UTF-16, а Python сортирует по кодовым точкам. Для строк вне
BMP (эмодзи, редкие иероглифы) порядок разный, и два «канонических» документа
дают разные байты — а значит разные хеши и подписи. Это не теория: расхождение
в сортировке делает квитанцию непроверяемой вторым верификатором.

Профиль квитанций (`noa.receipt/0.1`) допускает только целые числа в
диапазоне |n| ≤ 2^53-1. Дробное число — не «сложный случай», а нарушение
профиля, поэтому оно отвергается на разборе, а не форматируется.

Модуль без внешних зависимостей намеренно: проверка должна работать через
годы без установки пакетов.
"""

from __future__ import annotations

import json
from typing import Any

MAX_INT = 2**53 - 1
FORBIDDEN_KEYS = {"__proto__", "prototype", "constructor"}


class CanonicalError(ValueError):
    """Документ не может быть канонизирован по RFC 8785 + профилю."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalError(f"duplicate member name: {key!r}")
        if key in FORBIDDEN_KEYS:
            raise CanonicalError(f"forbidden member name: {key!r}")
        out[key] = value
    return out


def _constant(name: str) -> Any:
    raise CanonicalError(f"non-finite number in JSON: {name}")


def loads(text: str) -> Any:
    """Разобрать JSON, отвергая то, что ломает проверку до всякой схемы.

    Три отказа на границе разбора, а не после:
      * дубли имён (иначе last-wins прячет подмену);
      * `__proto__`/`prototype`/`constructor` — в части хостов они меняют
        поведение объекта ещё до валидации;
      * NaN/Infinity — не JSON и не число профиля.
    """
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)


def _check_string(s: str) -> None:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalError(f"unpaired surrogate in string: {exc.reason}") from exc


def _escape(s: str) -> str:
    out = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _sort_key(key: str) -> bytes:
    """Порядок по единицам кода UTF-16 — как в ECMAScript, а не по точкам."""
    return key.encode("utf-16-be", "surrogatepass")


def dumps(value: Any) -> str:
    """Каноническая сериализация. Отвергает всё, что профиль не допускает."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise CanonicalError(f"integer out of range: {value}")
        return str(value)
    if isinstance(value, float):
        raise CanonicalError("non-integer number: the profile allows integers only")
    if isinstance(value, str):
        _check_string(value)
        return _escape(value)
    if isinstance(value, list):
        return "[" + ",".join(dumps(v) for v in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalError("object member names must be strings")
            if key in FORBIDDEN_KEYS:
                raise CanonicalError(f"forbidden member name: {key!r}")
            _check_string(key)
        ordered = sorted(value.items(), key=lambda kv: _sort_key(kv[0]))
        return "{" + ",".join(f"{_escape(k)}:{dumps(v)}" for k, v in ordered) + "}"
    raise CanonicalError(f"type not representable in JSON: {type(value).__name__}")
