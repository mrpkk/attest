#!/usr/bin/env python3
"""Детектор пустоты: артефакт проходит валидацию, но содержания в нём нет.

Зачем это отдельный модуль. `attest` проверяет форму и подпись: типы
на месте, схема соблюдена, ключ верный. Всё это говорит, что артефакт
правильно **оформлен**, и ничего — что в нём есть смысл.

Именно сюда попадает самый частый сбой агентов: пять одинаковых пунктов
вместо пяти разных. Такие артефакты проходят любую валидацию по схеме,
потому что форма у них безупречна.

Поэтому здесь только измеримые сигналы. «Мне кажется, ответ бессмысленный»
не проверяем — такого теста нет и быть не может. Всё, что ниже, можно
показать проверяющему и поспорить с выводом.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

# Маркеры-заглушки. Текст, которым заполняют поле, чтобы оно «было».
STUB_WORDS = {
    "todo", "tbd", "fixme", "fix later", "xxx", "yyy", "zzz", "placeholder",
    "changeme", "change me", "fill in", "fill me", "insert here", "your value",
    "your_value", "value here", "example", "sample", "dummy", "lorem ipsum",
    "not applicable", "n/a", "na", "none set", "unset", "unknown value",
    "string", "integer", "boolean", "some text", "some value", "test",
    "test value", "test data", "foo", "bar", "baz", "asdf", "qwerty",
    "在这里", "占位", "待填", "示例", "测试",
}

# Обрезанный вывод: агент упёрся в лимит и не сказал об этом прямо.
TRUNCATION = (
    "...", "…", "[truncated]", "(truncated)", "[cut off]", "<truncated>",
    "output limit", "max tokens", "[...]", "<!--", "continued",
)

WORD = re.compile(r"[a-zA-Zа-яА-ЯёЁ]{2,}")


@dataclass(frozen=True)
class EmptinessSignal:
    kind: str
    severity: str          # high | medium | low
    where: str
    evidence: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "severity": self.severity,
                "where": self.where, "evidence": self.evidence,
                "detail": self.detail}


def _leaf_text(value: Any) -> str:
    """Строка из значения любого типа — чтобы искать заглушки одинаково."""
    if isinstance(value, str):
        return value
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def _walk(node: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield f"{path}.{k}", v
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield f"{path}[{i}]", v
            yield from _walk(v, f"{path}[{i}]")


def _stub_hits(text: str) -> list[str]:
    """Слова-заглушки, найденные в строке.

    Строка целиком равная заглушке — сильный сигнал. Заглушка внутри
    осмысленного предложения — слабый: в тексте есть слово «example»,
    но это не значит, что поле пустое.
    """
    low = text.strip().lower()
    if not low:
        return []
    exact = {s for s in STUB_WORDS if low == s or low.rstrip(".!") == s}
    found = set(exact)
    if len(found) < len(low.split()) or not found:
        found |= {s for s in STUB_WORDS if re.search(rf"\b{re.escape(s)}\b", low)}
    return sorted(found)


def _scan_stub(node: Any, path: str, where: str) -> list[EmptinessSignal]:
    text = _leaf_text(node)
    hits = _stub_hits(text)
    if not hits:
        return []
    stripped = text.strip().lower().rstrip(".!")
    only = stripped in {s for s in STUB_WORDS}
    return [EmptinessSignal(
        kind="stub_value",
        severity="high" if only else "low",
        where=where,
        evidence=text.strip()[:60] or "(пусто)",
        detail=("поле целиком состоит из заглушки" if only
                else "встречается слово-заглушка: " + ", ".join(hits[:3])),
    )]


def _scan_blank(node: Any, path: str, where: str) -> list[EmptinessSignal]:
    out = []
    if isinstance(node, str) and not node.strip():
        out.append(EmptinessSignal(
            "blank_string", "medium", where, repr(node)[:60],
            "строка без символов — форма соблюдена, содержания нет"))
    if isinstance(node, list) and not node:
        out.append(EmptinessSignal(
            "empty_list", "medium", where, "[]", "пустой список"))
    if isinstance(node, dict) and not node:
        out.append(EmptinessSignal(
            "empty_object", "medium", where, "{}", "пустой объект"))
    return out


def _scan_truncation(node: Any, path: str, where: str) -> list[EmptinessSignal]:
    text = _leaf_text(node)
    stripped = text.strip()
    if len(stripped) < 3:
        return []
    tail = stripped[-3:]
    marks = [m for m in TRUNCATION if m == stripped or m in tail]
    if not marks:
        return []
    return [EmptinessSignal(
        "truncated", "high", where, stripped[-50:],
        "вывод обрезан на границе лимита: последние символы — " + ", ".join(marks[:2]))]


def _uniform_ratio(value: Any) -> tuple[float, int] | None:
    """Доля одинаковых элементов в списке — для плоских списков строк.

    Пять пунктов, где четыре совпадают дословно, — это не результат,
    это заполнитель. Возвращает (доля, размер).
    """
    if not isinstance(value, list) or len(value) < 3:
        return None
    texts = [_leaf_text(v).strip() for v in value]
    if any(not t for t in texts):
        texts = [t for t in texts if t]
    if len(texts) < 3:
        return None
    top = max(set(texts), key=texts.count)
    return texts.count(top) / len(texts), len(texts)


def _scan_uniform(node: Any, path: str, where: str) -> list[EmptinessSignal]:
    ratio = _uniform_ratio(node)
    if not ratio:
        return []
    share, size = ratio
    if share <= 0.5 or size < 3:
        return []
    # Порог — строго больше половины. В списке выводов одинаковые строки
    # почти всегда означают заполнитель: если половина пунктов совпадает
    # дословно, это не «совпадение», а отсутствие работы. Одиночное
    # совпадение (2 из 5) пропускаем — это может быть честный ответ.
    sev = "high" if share >= 0.9 else "medium"
    return [EmptinessSignal(
        "uniform_list", sev, where,
        f"{int(share * size)} из {size} элементов совпадают",
        f"список наполнен копиями: доля одинаковых {share:.0%}. "
        "Схема соблюдена, но элементы не различаются")]


def _scan_repetition(node: Any, path: str, where: str) -> list[EmptinessSignal]:
    """Одно слово или короткая фраза повторяется много раз подряд."""
    text = _leaf_text(node)
    words = WORD.findall(text.lower())
    if len(words) < 12:
        return []
    unique = len(set(words)) / len(words)
    if unique > 0.35:
        return []
    return [EmptinessSignal(
        "repetitive_text", "medium", where,
        f"{len(words)} слов, уникальных {unique:.0%}",
        "уникальных слов меньше трети — текст почти наверняка заполнен повтором")]


def _scan_default(node: Any, path: str, where: str, schema: Any) -> list[EmptinessSignal]:
    """Обязательное поле заполнено значением по умолчанию из схемы."""
    if not isinstance(node, dict) or not isinstance(schema, dict):
        return []
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []
    required = set(schema.get("required") or [])
    out = []
    for key, spec in props.items():
        if key not in node or not isinstance(spec, dict):
            continue
        default = spec.get("default")
        if default is None or key not in required:
            continue
        if node[key] == default and _leaf_text(default).strip():
            out.append(EmptinessSignal(
                "schema_default", "medium", f"{where}.{key}",
                str(default)[:60],
                "обязательное поле не заполнено: стоит значение по умолчанию из схемы"))
    return out


def _signals_for(node: Any, path: str, where: str) -> list[EmptinessSignal]:
    out = _scan_blank(node, path, where)
    if not isinstance(node, (dict, list)):
        out += _scan_stub(node, path, where)
        out += _scan_truncation(node, path, where)
        out += _scan_repetition(node, path, where)
    if isinstance(node, list):
        out += _scan_uniform(node, path, where)
    return out


def scan_for_emptiness(artifact: Any, schema: dict[str, Any] | None = None
                      ) -> list[EmptinessSignal]:
    """Сигналы пустоты по всему артефакту.

    Возвращает пустой список, если измеримых признаков не найдено.
    Отсутствие сигналов не означает осмысленности — означает лишь, что
    грубые признаки не сработали. Это разные вещи, и путать их нельзя.
    """
    out: list[EmptinessSignal] = []
    for path, value in _walk(artifact):
        out += _signals_for(value, path, path)
    if isinstance(artifact, dict):
        out += _scan_default(artifact, "$", "$", schema)
        props = schema.get("properties") if isinstance(schema, dict) else None
        if isinstance(props, dict):
            for key, spec in props.items():
                if key in artifact and isinstance(spec, dict) and "enum" in spec:
                    allowed = spec.get("enum")
                    if isinstance(allowed, list) and len(allowed) > 1:
                        first = allowed[0]
                        if artifact[key] == first:
                            out.append(EmptinessSignal(
                                "enum_first_value", "low", f"$.{key}",
                                str(first)[:60],
                                "поле стоит на первом значении перечисления — "
                                "часто признак невыбранного варианта"))
    return _dedupe(out)


def _dedupe(signals: list[EmptinessSignal]) -> list[EmptinessSignal]:
    seen: dict[tuple[str, str, str], EmptinessSignal] = {}
    order = {"high": 0, "medium": 1, "low": 2}
    for s in signals:
        key = (s.kind, s.where, s.evidence)
        prev = seen.get(key)
        if prev is None or order[s.severity] < order[prev.severity]:
            seen[key] = s
    return sorted(seen.values(),
                  key=lambda s: (order[s.severity], s.kind, s.where))


def emptiness_score(signals: list[EmptinessSignal]) -> float:
    """0.0 — признаков нет, 1.0 — артефакт пуст по форме.

    Считается по худшему сигналу с затуханием: одно `high` не приравнивается
    к пяти `low`, но пять `medium` дают больше, чем одно.
    """
    if not signals:
        return 0.0
    weight = {"high": 1.0, "medium": 0.45, "low": 0.15}
    best = max(weight[s.severity] for s in signals)
    rest = sum(weight[s.severity] for s in signals[1:])
    return round(min(1.0, best + rest * 0.12), 3)


def emptiness_verdict(score: float, signals: list[EmptinessSignal]) -> str:
    """Вердикт с честной оговоркой: это не приговор содержанию.

    `VALID_BUT_EMPTY` означает «форма в порядке, содержание подозрительно»,
    а не «содержание отсутствует». Разница принципиальна: подозрение
    требует внимания человека, приговор — проверки.
    """
    if score >= 0.8:
        return "VALID_BUT_EMPTY"
    if score >= 0.35:
        return "THIN_CONTENT"
    return "CONTENT_PRESENT"