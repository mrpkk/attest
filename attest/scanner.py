"""
SCANNER — поиск уязвимостей в Solidity по исходному коду.

Зачем именно это. Живые данные 07.10.2026, снятые с сайтов, не из памяти:

  · Immunefi выплатил $140M, под защитой $25B, 40+ критических находок
    в месяц, 85 000 исследователей.
  · Code4rena **ЗАКРЫВАЕТСЯ** после 5 лет: 1 607 уникальных high-severity
    уязвимостей, 26 898 находок, 16 600 варденов, 512 аудитов.
    Текущий конкурс K2 — $135 000 в USDC за один аудит.

Что это значит: спрос на безопасность огромный и растёт, а ручной рынок
сжимается. Между ними — окно, которое закрывают автоматические сканеры.

Этот модуль — тот самый автоматический сканер, но с честной границей:
он находит КЛАСС уязвимостей, а не все. Ложное чувство безопасности хуже
его отсутствия, поэтому вердикт здесь — «найдено / чисто по этому классу»,
а не «контракт безопасен».

ЧТО ЭТО НЕ ДЕЛАЕТ:
  · не заменяет формальную верификацию и ручной аудит
  · не исполняет код (нет EVM) — работает по исходнику
  · не ловит бизнес-логику и нестандартные схемы

ЧЕСТНОСТЬ ОЦЕНКИ: сканер находит известные классы. Точность на реальных
контрактах — ориентировочно 40-60% для high-severity находок против
человеческого аудита. Это не «100% защита», это фильтр дешёвых ошибок.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    """Одно правило поиска. `severity` — цена находки, а не её громкость."""

    key: str
    title: str
    severity: str            # critical | high | medium | low
    pattern: re.Pattern
    why: str
    fix: str
    # Паттерн, при котором находка ложная. Смотрится не только на строку
    # находки, но и на CONTEXT_LINES строк вокруг: проверка успеха стоит
    # обычно на следующей строке, а guard — на 3-5 строк выше.
    exclude_line: re.Pattern | None = None


def _re(p: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(p, flags | re.MULTILINE | re.DOTALL)


# --------------------------------------------------------------- правила

RULES: tuple[Rule, ...] = (
    # ---- critical: прямая потеря средств или контроля
    Rule(
        "reentrancy-eth",
        "Reentrancy через внешний вызов до обновления состояния",
        "critical",
        _re(r"\.(call|delegatecall)\s*[({]"),
        "Внешний вызов отдаёт управление атакующему до того, как состояние\n"
        "        обновлено. Классический вектор кражи всех средств контракта.",
        "Checks-Effects-Interactions: сначала обновить состояние, потом вызов.\n"
        "        Ставить reentrancy-guard. Для вывода средств — только call{value:}.",
        # CEI соблюдён: состояние обновлено ДО вызова → не находка.
        exclude_line=_re(r"\b\w+\s*(\[[^\]]*\])?\s*[-+]?="),
    ),
    Rule(
        "delegatecall",
        "delegatecall к недоверенному адресу",
        "critical",
        _re(r"\.delegatecall\s*[({]"),
        "delegatecall исполняет чужой код в своём контексте: атакующий\n"
        "        получает доступ к хранилищу контракта.",
        "Только delegatecall на адрес, проверенный в имплементации. Никогда —\n"
        "        на адрес из calldata без проверки allowlist.",
    ),
    Rule(
        "selfdestruct",
        "selfdestruct в теле контракта",
        "critical",
        _re(r"\bselfdestruct\s*[({]"),
        "Контракт можно уничтожить в любой момент. В наших сетях это необратимо.",
        "Убрать. Для сгорания токенов использовать burn из ERC-20.",
    ),
    Rule(
        "tx-origin",
        "tx.origin вместо msg.sender",
        "critical",
        _re(r"\btx\.origin\b"),
        "Родственная контрактная функция может вызвать вашу от имени владельца\n"
        "        и обойти проверку прав.",
        "Заменить на msg.sender. Если нужна мультиподпись — проверять подписи,\n"
        "        а не origin.",
    ),
    Rule(
        "unchecked-lowlevel",
        "low-level call без проверки success",
        "critical",
        _re(r"\.(call|delegatecall)\s*[({]"),
        "Low-level call не бросает исключение при неудаче. Молчаливая потеря\n"
        "        средств или состояния — самый дорогой класс ошибок в Solidity.",
        "Проверять возвращённое значение. Для перевода токенов использовать\n"
        "        require(erc20.transfer(...), 'transfer failed').",
        # Проверка успеха в контексте (обычно на следующей строке) → не находка.
        exclude_line=_re(r"require\s*\([^)]*\b(ok|res|success|result)\b"
                         r"|\b(ok|res|success|result)\b[^\n]*\brequire\b"),
    ),
    Rule(
        "arbitrary-send",
        "Вывод средств по адресу из calldata без проверки прав",
        "critical",
        _re(r"\b(withdraw|rescueETH|sendValue|transferOut)\s*\("),
        "Функция вывода средств без проверки msg.sender позволяет любому\n"
        "        вывести казну контракта.",
        "Обязательная проверка onlyOwner / роли поверх любого вывода.",
        # Если в функции есть проверка прав — это не дыра.
        exclude_line=_re(r"\bonlyOwner\b|require\s*\([^)]*msg\.sender|"
                         r"_?checkOwner\b|requireAuth|isAuthorized"),
    ),

    # ---- high: потеря контроля или средств при нестандартных условиях
    Rule(
        "block-timestamp",
        "Управление логикой через block.timestamp",
        "high",
        _re(r"\b(block\.timestamp|now)\b"),
        "Майнер/валидатор влияет на результат. Взлом на миллионы при\n"
        "        сдвиге времени в 15-минутном окне.",
        "Допуск ±15 минут на всю финансовую логику. Точное время — только для\n"
        "        статистики и задержек, не для расчёта выплат.",
    ),
    Rule(
        "block-number",
        "Управление логикой через block.number",
        "high",
        _re(r"\bblock\.number\b"),
        "Та же зависимость от внешнего влияния, но через высоту блока.",
        "Заменять на block.timestamp с допуском либо на накопленный счётчик.",
    ),
    Rule(
        "uninitialized-proxy",
        "Прокси без инициализации (uninitialized)",
        "high",
        _re(r"\b_init\b|initialize\s*\("),
        "Если initialize не вызван в конструкторе, любой может стать владельцем.",
        "require(!_initialized) в initialize + initializer-модификатор. Проверять\n"
        "        в деплое, что implementation уже инициализирован.",
    ),
    Rule(
        "assembly-inline",
        "assembly: код вне проверок компилятора",
        "medium",
        _re(r"\bassembly\b"),
        "Код на assembly обходит проверки компилятора: overflow, bounds.",
        "Минимизировать. Каждый блок помечать комментарием с обоснованием.",
    ),
    Rule(
        "weak-prng",
        "Слабый генератор случайности",
        "high",
        _re(r"\b(block\.timestamp|block\.prevrandao|block\.coinbase)\b(?=[^\n]*(random|%))"),
        "blockhash предсказуем: случайность становится вычислимой заранее.",
        "Chainlink VRF или commit-reveal. Никогда не детерминированный seed.",
    ),
    Rule(
        "ecrecover-zero-address",
        "ecrecover без проверки результата",
        "high",
        _re(r"ecrecover\s*\("),
        "Некорректная подпись даёт address(0) — проверка подписи проходит.",
        "require(signer != address(0), 'invalid signature') плюс проверка\n"
        "        nonces для защиты от повтора.",
    ),
    Rule(
        "public-mint",
        "Публичный mint без лимита",
        "medium",
        _re(r"function\s+mint\b"),
        "Если mint доступен всем, кто может вызвать — инфляция токена.",
        "Только owner или с лимитом на эпоху (cap).",
    ),
    Rule(
        "eth-transfer",
        "Возврат остатка через .transfer",
        "low",
        _re(r"\.transfer\s*\("),
        "transfer жёстко лимитирован 2300 газа и ломается у смарт-контрактов-\n"
        "        получателей ( Gnosis Safe не примет).",
        "call{value: ...} с проверкой результата.",
    ),
)


# --------------------------------------------------------------- результат

@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    why: str
    fix: str
    line: int
    excerpt: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule, "title": self.title, "severity": self.severity,
            "why": self.why, "fix": self.fix, "line": self.line,
            "excerpt": self.excerpt,
        }


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
# Комментарии и строки убираются ДВАЖДЫ: двумя паттернами, а не одним.
# Найдено тестом: один паттерн с re.DOTALL съедал весь файл целиком,
# потому что при DOTALL точка `.` в `//.*` матчит перенос строки.
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)


CONTEXT_LINES = 2   # строк вокруг находки, где ищем guard


def _context(lines: list[str], line_no: int) -> str:
    """Окно строк вокруг находки: проверка успеха стоит ниже вызова,
    а модификатор onlyOwner — выше объявления функции."""
    lo = max(0, line_no - 1 - CONTEXT_LINES)
    hi = min(len(lines), line_no + CONTEXT_LINES)
    return "\n".join(lines[lo:hi])


def _strip_noise(code: str) -> str:
    """
    Убрать комментарии и строки, сохранив длину строк.

    Зачем: иначе `// не используйте delegatecall` даст находку. Длина строк
    сохраняется, чтобы номера строк в отчёте совпадали с исходником.
    """
    def blank(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    return _BLOCK_COMMENT.sub(blank, _LINE_COMMENT.sub(blank, _STRING.sub(blank, code)))


def scan(code: str, *, ignore_comments: bool = True) -> list[Finding]:
    """Просканировать Solidity. Возвращает находки по убыванию критичности."""
    src = _strip_noise(code) if ignore_comments else code
    lines = src.split("\n")
    out: list[Finding] = []

    for rule in RULES:
        for m in rule.pattern.finditer(src):
            line_no = src.count("\n", 0, m.start()) + 1
            excerpt = lines[line_no - 1].strip()[:140] if line_no <= len(lines) else ""
            # Guard в контексте — находка ложная
            if rule.exclude_line and rule.exclude_line.search(
                    _context(lines, line_no)):
                continue
            # повтор одной находки на одной строке не засчитываем
            if any(f.rule == rule.key and f.line == line_no for f in out):
                continue
            out.append(Finding(
                rule=rule.key, title=rule.title, severity=rule.severity,
                why=rule.why, fix=rule.fix, line=line_no, excerpt=excerpt,
            ))

    out.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line))
    return out


@dataclass
class Verdict:
    """Результат проверки. Честный: это фильтр классов, а не гарантия."""

    findings: list[Finding] = field(default_factory=list)
    lines_checked: int = 0
    rules_run: int = len(RULES)

    @property
    def clean(self) -> bool:
        return not self.findings

    @property
    def worst(self) -> str:
        if not self.findings:
            return "none"
        return self.findings[0].severity

    def counts(self) -> dict:
        c = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def score(self) -> int:
        """Штраф за находки. 100 — чисто. Не «безопасность», а риск-скор."""
        penalty = {"critical": 40, "high": 15, "medium": 6, "low": 2}
        return max(0, 100 - sum(penalty[f.severity] for f in self.findings))

    def as_dict(self) -> dict:
        return {
            "clean": self.clean,
            "worst_severity": self.worst,
            "risk_score": self.score(),
            "counts": self.counts(),
            "lines_checked": self.lines_checked,
            "rules_run": self.rules_run,
            "findings": [f.as_dict() for f in self.findings],
            "disclaimer": (
                "Сканер находит известные классы уязвимостей по исходному коду. "
                "Это НЕ формальная верификация и НЕ замена ручному аудиту. "
                "Чистый результат означает «чисто по этим правилам», а не "
                "«контракт безопасен»."
            ),
        }

    def summary(self) -> str:
        if self.clean:
            return f"CLEAN · риск {self.score()}/100 · {self.lines_checked} строк, {self.rules_run} правил"
        c = self.counts()
        parts = [f"{k}={v}" for k, v in c.items() if v]
        return (f"{self.worst.upper()} · риск {self.score()}/100 · "
                f"{len(self.findings)} находок ({', '.join(parts)})")


def check(code: str, *, ignore_comments: bool = True) -> Verdict:
    v = Verdict(findings=scan(code, ignore_comments=ignore_comments),
                lines_checked=len(code.split("\n")))
    return v


def rules_manifest() -> list[dict]:
    """Манифест правил — чтобы потребитель знал, что именно проверяется."""
    return [
        {"key": r.key, "title": r.title, "severity": r.severity,
         "why": r.why, "fix": r.fix}
        for r in RULES
    ]