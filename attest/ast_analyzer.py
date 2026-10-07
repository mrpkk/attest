"""
AST-АНАЛИЗ на настоящем компиляторе solc.

Зачем. Регулярки по исходнику дают ложные срабатывания на строках, на
переименованных переменных и не видят структуру. Сканер из scanner.py —
быстрый фильтр; этот модуль — точный слой, который работает с разбором
компилятора, а не с текстом.

Что меняется с AST:
  · `t.call{value: 1}("")` находится как УЗЕЛ, а не как подстрока
  · вызов в комментарии невозможен by design
  · отличается внешний вызов от внутреннего: внутренний `this.foo()` не
    отдаёт управление наружу и reentrancy через него не проходит
  · видна структура функции: где require, где присваивание состояния
  · видны точные позиции в исходнике (`src`), а не приблизительные

ГРАНИЦА. Если solc недоступен или код не компилируется — модуль возвращает
None, а НЕ пустой результат. «Не смог проверить» и «проверил, чисто» —
разные вещи, и путать их опаснее, чем не проверить вовсе.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

try:
    import solcx
    HAVE_SOLCX = True
except ImportError:                       # pragma: no cover
    solcx = None
    HAVE_SOLCX = False


DEFAULT_SOLC = "0.8.24"

# Функции, отдающие управление наружу. Только они дают вектор reentrancy.
EXTERNAL_CALLS = {"call", "delegatecall", "staticcall", "callcode"}

# Присваивания, меняющие состояние. Их наличие ДО внешнего вызова означает,
# что порядок Checks-Effects-Interactions соблюдён.
STATE_OPS = ("=", "+=", "-=", "*=", "/=")


@dataclass
class AstFinding:
    rule: str
    title: str
    severity: str
    line: int
    column: int
    excerpt: str
    why: str
    fix: str
    confidence: str = "exact"     # exact — подтверждено узлом AST

    def as_dict(self) -> dict:
        return {
            "rule": self.rule, "title": self.title, "severity": self.severity,
            "line": self.line, "column": self.column, "excerpt": self.excerpt,
            "why": self.why, "fix": self.fix, "confidence": self.confidence,
        }


@dataclass
class AstVerdict:
    """Результат AST-разбора. `compiled=False` означает «не проверено»."""

    compiled: bool
    findings: list[AstFinding] = field(default_factory=list)
    error: str = ""
    src_lines: int = 0
    contracts: int = 0
    compiler: str = DEFAULT_SOLC

    @property
    def checked(self) -> bool:
        """Проверено ли. Пустой findings при compiled=False — это НЕ чисто."""
        return self.compiled

    def as_dict(self) -> dict:
        return {
            "compiled": self.compiled,
            "checked": self.checked,
            "error": self.error,
            "contracts": self.contracts,
            "src_lines": self.src_lines,
            "compiler": self.compiler,
            "findings": [f.as_dict() for f in self.findings],
            "disclaimer": (
                "AST-разбор выполнен настоящим компилятором solc, поэтому "
                "находки привязаны к узлам дерева, а не к тексту. "
                "Это НЕ формальная верификация и НЕ замена ручному аудиту."
                if self.compiled else
                "ПРОВЕРКА НЕ ВЫПОЛНЕНА: код не скомпилирован или solc "
                "недоступен. Отсутствие находок здесь НЕ означает безопасность."
            ),
        }

    def summary(self) -> str:
        if not self.compiled:
            return f"НЕ ПРОВЕРЕНО · {self.error or 'компиляция не удалась'}"
        if not self.findings:
            return f"CLEAN · solc {self.compiler} · {self.contracts} контракт(ов), {self.src_lines} строк"
        worst = self.findings[0].severity
        return (f"{worst.upper()} · {len(self.findings)} находок по AST · "
                f"{self.contracts} контракт(ов), {self.src_lines} строк")


# ------------------------------------------------------------ обход дерева

def walk(node: Any) -> Iterator[dict]:
    """Обойти все узлы AST."""
    if isinstance(node, dict):
        # ВАЖНО: solc отдаёт ModifierInvocation БЕЗ nodeType — только
        # kind="modifierInvocation". Обход по одному nodeType его терял,
        # и функция с модификатором onlyOwner выглядела открытой.
        # Проверено на реальном AST solc 0.8.24.
        if "nodeType" in node or "kind" in node:
            yield node
        for v in node.values():
            yield from walk(v)
    elif isinstance(node, list):
        for i in node:
            yield from walk(i)


def _src_to_pos(src: str | int | None) -> tuple[int, int]:
    """`src` = 'offset:length:file'. Отдаём (строка, колонка) в 1-based."""
    if not isinstance(src, str):
        return 0, 0
    try:
        offset = int(src.split(":")[0])
    except (ValueError, IndexError):
        return 0, 0
    return offset, 0          # точный номер строки считаем по исходнику


# ------------------------------------------------------------ сборка AST

def build_ast(source: str, solc_version: str = DEFAULT_SOLC) -> Optional[dict]:
    """
    Скомпилировать и вернуть AST всех контрактов.

    Возвращает None, если solc недоступен или компиляция не удалась.
    """
    if not HAVE_SOLCX:
        return None
    try:
        out = solcx.compile_source(
            source,
            output_values=["ast"],
            solc_version=solc_version,
        )
    except Exception:                      # noqa: BLE001
        return None
    if not out:
        return None
    contracts = {}
    for key, val in out.items():
        if isinstance(val, dict) and "ast" in val:
            name = key.split(":")[-1]
            contracts[name] = val["ast"]
    return contracts or None


# ------------------------------------------------------------ анализ

def _line_of(source: str, offset: int) -> int:
    if offset <= 0:
        return 0
    return source.count("\n", 0, offset) + 1


def _text_at(source: str, node: dict) -> str:
    src = node.get("src")
    if not isinstance(src, str):
        return ""
    try:
        off, ln = src.split(":")[0], src.split(":")[1]
        return source[int(off): int(off) + int(ln)].strip()[:140]
    except (ValueError, IndexError):
        return ""


def _function_scope(ast: dict) -> dict[str, list[dict]]:
    """Собрать узлы по функциям: функция → её потомки."""
    scopes: dict[str, list[dict]] = {}
    for fn in (n for n in walk(ast) if n.get("nodeType") == "FunctionDefinition"):
        name = fn.get("name") or ("constructor" if fn.get("kind") == "constructor"
                                  else "fallback")
        # Модификаторы (onlyOwner и т.п.) живут в отдельном ключе
        # FunctionDefinition, а НЕ внутри body. Если брать только body,
        # ModifierInvocation теряется и функция с гвардом выглядит открытой.
        # Поэтому обходим сам узел функции целиком.
        scopes[name] = list(walk(fn))
    return scopes


def _has_guard(scope: list[dict], keywords: tuple[str, ...]) -> bool:
    """Есть ли в теле функции guard: require с проверкой, либо onlyOwner."""
    for n in scope:
        if n.get("nodeType") == "ModifierInvocation" or \
                n.get("kind") == "modifierInvocation":
            # modifierName — не строка, а узел IdentifierPath с ключом name.
            # Проверено на реальном AST solc 0.8.24.
            mn = n.get("modifierName") or {}
            mname = mn.get("name") if isinstance(mn, dict) else mn
            if (mname or "").lower() in keywords:
                return True
        if n.get("nodeType") == "FunctionCall" and \
                (n.get("expression", {}).get("nodeType") == "Identifier"
                 and n["expression"].get("name") in ("require", "assert")):
            return True
    return False


def _state_change_before(scope: list[dict], call_offset: int) -> bool:
    """Было ли изменение состояния ДО внешнего вызова (порядок CEI)."""
    for n in scope:
        off, _ = _src_to_pos(n.get("src"))
        if off <= 0 or off >= call_offset:
            continue
        if n.get("nodeType") != "ExpressionStatement":
            continue
        for sub in walk(n):
            if sub.get("nodeType") == "Assignment":
                op = sub.get("operator", "")
                if any(o in op for o in STATE_OPS):
                    return True
    return False


def _result_checked_after(scope: list[dict], call_offset: int) -> bool:
    """Проверяется ли результат вызова ПОСЛЕ него (require(ok))."""
    for n in scope:
        off, _ = _src_to_pos(n.get("src"))
        if off <= call_offset:
            continue
        if n.get("nodeType") == "FunctionCall":
            expr = n.get("expression", {})
            if expr.get("nodeType") == "Identifier" and \
                    expr.get("name") in ("require", "assert"):
                args = n.get("arguments", [])
                if args:
                    ident = next((walk(a) for a in args), None)
                    if ident is not None:
                        first = next(iter(ident), None)
                        if first and first.get("nodeType") == "Identifier":
                            return True
    return False


def analyze(source: str, solc_version: str = DEFAULT_SOLC) -> AstVerdict:
    """Полный AST-анализ исходника."""
    src_lines = len(source.split("\n"))

    if not HAVE_SOLCX:
        return AstVerdict(False, error="solcx не установлен", src_lines=src_lines)
    contracts = build_ast(source, solc_version)
    if contracts is None:
        return AstVerdict(False, error="компиляция не удалась",
                          src_lines=src_lines, compiler=solc_version)

    findings: list[AstFinding] = []
    total_contracts = 0

    for name, ast in contracts.items():
        total_contracts += 1
        scopes = _function_scope(ast)

        # --- 1. Внешние вызовы: reentrancy и непроверяемый результат
        #
        # Ищем MemberAccess, а не FunctionCall: в solc 0.8 низкоуровневый
        # вызов `t.call{value: x}("")` разбирается как
        #   FunctionCall(kind=functionCallOptions)
        #     └─ expression: MemberAccess(memberName="call", expression=Identifier)
        # То есть `call` — это MemberAccess, а не expression внешнего FunctionCall.
        for fn_name, scope in scopes.items():
            for n in scope:
                if n.get("nodeType") != "MemberAccess":
                    continue
                mname = n.get("memberName")
                if mname not in EXTERNAL_CALLS:
                    continue
                # внутренний вызов this.foo() управление не отдаёт
                base = n.get("expression", {})
                if base.get("nodeType") == "Identifier" and \
                        base.get("name") in ("this", "super"):
                    continue

                n = dict(n)
                n.setdefault("src", n.get("src"))
                off, _ = _src_to_pos(n.get("src"))
                line = _line_of(source, off)
                excerpt = _text_at(source, n)

                if mname in ("call", "delegatecall", "callcode"):
                    if not _state_change_before(scope, off):
                        findings.append(AstFinding(
                            "reentrancy-ast",
                            "Внешний вызов без изменения состояния перед ним",
                            "critical", line, 0, excerpt,
                            "Подтверждено узлом AST: перед внешним вызовом нет "
                            "присваивания в состояние. Атакующий получает "
                            "управление до обновления баланса.",
                            "Checks-Effects-Interactions: перенести изменение "
                            "состояния выше вызова. Добавить reentrancy-guard.",
                        ))

                if mname in ("call", "delegatecall", "staticcall"):
                    if not _result_checked_after(scope, off):
                        findings.append(AstFinding(
                            "unchecked-call-ast",
                            "Возвращаемое значение низкоуровневого вызова не проверяется",
                            "critical", line, 0, excerpt,
                            "Подтверждено узлом AST: после вызова нет require "
                            "с проверкой результата. Молчаливая потеря средств.",
                            "require(ok, 'call failed') сразу после вызова.",
                        ))

        # --- 2. selfdestruct / tx.origin
        for n in walk(ast):
            if n.get("nodeType") == "FunctionCall":
                expr = n.get("expression", {})
                nm = expr.get("name") or expr.get("memberName")
                off, _ = _src_to_pos(n.get("src"))
                line = _line_of(source, off)
                if nm == "selfdestruct":
                    findings.append(AstFinding(
                        "selfdestruct-ast", "selfdestruct в коде контракта",
                        "critical", line, 0, _text_at(source, n),
                        "Подтверждено узлом AST. Контракт можно уничтожить "
                        "в любой момент; в наших сетях это необратимо.",
                        "Убрать. Для сгорания токенов использовать burn в ERC-20.",
                    ))
            if n.get("nodeType") == "MemberAccess" and n.get("memberName") == "origin":
                off, _ = _src_to_pos(n.get("src"))
                line = _line_of(source, off)
                findings.append(AstFinding(
                    "tx-origin-ast", "Использован tx.origin",
                    "critical", line, 0, _text_at(source, n),
                    "Подтверждено узлом AST. Родственная функция может вызвать "
                    "вашу от имени владельца и обойти проверку прав.",
                    "Заменить на msg.sender.",
                ))

        # --- 3. Вывод средств без проверки прав
        for fn_name, scope in scopes.items():
            if not any(k in fn_name.lower()
                       for k in ("withdraw", "rescue", "sweep", "drain")):
                continue
            if _has_guard(scope, ("onlyowner", "onlyrole", "requiresauth")):
                continue
            fn_node = next((n for n in walk(ast)
                            if n.get("nodeType") == "FunctionDefinition"
                            and (n.get("name") or "") == fn_name), None)
            if not fn_node:
                continue
            off, _ = _src_to_pos(fn_node.get("src"))
            findings.append(AstFinding(
                "unprotected-withdraw-ast",
                f"Функция {fn_name} выводит средства без проверки прав",
                "critical", _line_of(source, off), 0, _text_at(source, fn_node),
                "Подтверждено узлом AST: в теле функции нет вызова onlyOwner "
                "и нет ни одного require. Любой может вывести средства.",
                "Добавить модификатор onlyOwner или проверку роли.",
            ))

    findings.sort(key=lambda f: ({"critical": 0, "high": 1,
                                 "medium": 2, "low": 3}.get(f.severity, 4),
                                 f.line))
    return AstVerdict(True, findings=findings, src_lines=src_lines,
                      contracts=total_contracts, compiler=solc_version)


def compare(source: str, solc_version: str = DEFAULT_SOLC) -> dict:
    """
    Сравнить регулярки (scanner) и AST. Нужно, чтобы понимать, где
    регулярки ошибаются и насколько AST стоит дороже.
    """
    try:
        from .scanner import check as regex_check
    except ImportError:
        from attest.scanner import check as regex_check

    rx = regex_check(source).as_dict()
    ast = analyze(source, solc_version).as_dict()
    rx_keys = {f["rule"] for f in rx["findings"]}
    ast_keys = {f["rule"] for f in ast["findings"]}
    return {
        "regex": {"находок": len(rx["findings"]), "риск": rx["risk_score"]},
        "ast": {"находок": len(ast["findings"]),
                "проверено": ast["checked"],
                "ошибка": ast["error"]},
        "нашли_оба": sorted(k for k in rx_keys if any(
            k.split("-")[0] in a for a in ast_keys)),
        "нашёл_только_ast": sorted(k for k in ast_keys if not any(
            k.split("-")[0] in r for r in rx_keys)),
        "нашёл_только_regex": sorted(k for k in rx_keys if not any(
            k.split("-")[0] in a for a in ast_keys)),
    }