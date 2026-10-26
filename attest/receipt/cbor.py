"""Детерминированный CBOR: ровно тот поднабор, который нужен конверту.

Зачем свой: конверт COSE по профилю обязан быть детерминированно закодирован
(§4.1), а `pip install cbor2` в проверяющем — это зависимость, которой через
год может не быть. Профиль требует также **отвергать** недетерминированное
кодирование, а не молча чинить: иначе две реализации по-разному считают байты.

Правила детерминированности (RFC 8949 §4.2.1):
  * аргумент кодируется shortest form;
  * ключи карты идут в порядке байтового сравнения их собственных кодировок;
  * indefinite-length запрещён;
  * дубли ключей запрещены.

Поддержано: целые, байтовые строки, текстовые строки, массивы, карты, теги,
true/false/null. Дробей нет — профиль квитанций их не допускает.
"""

from __future__ import annotations

from typing import Any


class CBORError(ValueError):
    """Документ не является детерминированным CBOR нужного поднабора."""


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise CBORError("integer too large for CBOR")


def dumps(value: Any) -> bytes:
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(dumps(v) for v in value)
    if isinstance(value, dict):
        encoded = [(dumps(k), dumps(v)) for k, v in value.items()]
        encoded.sort(key=lambda kv: kv[0])
        return _head(5, len(encoded)) + b"".join(k + v for k, v in encoded)
    if isinstance(value, Tag):
        return _head(6, value.number) + dumps(value.value)
    raise CBORError(f"type not supported: {type(value).__name__}")


class Tag:
    __slots__ = ("number", "value")

    def __init__(self, number: int, value: Any) -> None:
        self.number = number
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Tag) and (self.number, self.value) == (other.number, other.value)

    def __repr__(self) -> str:
        return f"Tag({self.number}, {self.value!r})"


def _loads(data: bytes, pos: int) -> tuple[Any, int]:
    if pos >= len(data):
        raise CBORError("truncated input")
    initial = data[pos]
    major, info = initial >> 5, initial & 0x1F
    pos += 1

    def argument() -> tuple[int, int]:
        nonlocal pos
        if info < 24:
            return info, pos
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if info not in sizes:
            raise CBORError(f"indefinite length or reserved info {info} is not allowed")
        size = sizes[info]
        raw = data[pos:pos + size]
        if len(raw) != size:
            raise CBORError("truncated argument")
        value = int.from_bytes(raw, "big")
        if info == 24 and value < 24:
            raise CBORError("non-shortest integer encoding")
        if info == 25 and value < 0x100:
            raise CBORError("non-shortest integer encoding")
        if info == 26 and value < 0x10000:
            raise CBORError("non-shortest integer encoding")
        if info == 27 and value < 0x100000000:
            raise CBORError("non-shortest integer encoding")
        return value, pos + size

    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info == 22:
            return None, pos
        raise CBORError(f"simple value {info} not supported")

    value, pos = argument()

    if major == 0:
        return value, pos
    if major == 1:
        return -1 - value, pos
    if major == 2:
        raw = data[pos:pos + value]
        if len(raw) != value:
            raise CBORError("truncated byte string")
        return raw, pos + value
    if major == 3:
        raw = data[pos:pos + value]
        if len(raw) != value:
            raise CBORError("truncated text string")
        try:
            return raw.decode(), pos + value
        except UnicodeDecodeError as exc:
            raise CBORError("text string is not UTF-8") from exc
    if major == 4:
        items = []
        for _ in range(value):
            item, pos = _loads(data, pos)
            items.append(item)
        return items, pos
    if major == 5:
        pairs: dict[Any, Any] = {}
        last_key_bytes: bytes | None = None
        for _ in range(value):
            start = pos
            key, pos = _loads(data, pos)
            key_bytes = data[start:pos]
            if last_key_bytes is not None and key_bytes <= last_key_bytes:
                raise CBORError("map keys are not in deterministic order")
            last_key_bytes = key_bytes
            if key in pairs:
                raise CBORError("duplicate map key")
            item, pos = _loads(data, pos)
            pairs[key] = item
        return pairs, pos
    if major == 6:
        inner, pos = _loads(data, pos)
        return Tag(value, inner), pos
    raise CBORError(f"unsupported major type {major}")


def loads(data: bytes) -> Any:
    value, pos = _loads(data, 0)
    if pos != len(data):
        raise CBORError("trailing bytes after the CBOR item")
    return value
