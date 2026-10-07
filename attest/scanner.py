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

КАК СКАНИРУЕТСЯ (Д8, 07.10.2026): два движка под одними и теми же правилами.
  · AST — solc разбирает исходник в дерево, правила читают структуру:
    вызов, переменную, условие, порядок операторов в функции. Комментарии
    и строки в нём отсутствуют физически, поэтому ложных срабатываний на
    тексте не бывает в принципе.
  · regex — исходное поведение по тексту, остаётся как фолбэк и как режим
    `ignore_comments=False` (искать по сырому тексту явно просили регулярки).
  Выбор: `engine="auto"` (по умолчанию) → AST, если установлен бинарь solc
  и код компилируется, иначе regex. Принято решение (автопилот 07.10):
  solc на лету НЕ скачиваем — это сеть и сюрприз в проде; контракт, который
  не компилируется, всё равно сканируется, а не пропускается молча.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    """Одно правило поиска. `severity` — цена находки, а не её громкость.

    `pattern` принадлежит движку regex. Движок AST читает те же `key`,
    `severity`, `why`, `fix`, но находит место по структуре дерева — см.
    `_AST_RULES` внизу файла.
    """

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

# ИЗМЕРЕНО 07.10.2026 на bhaga-protocol (38 файлов, 12 477 строк):
# 137 из 221 находок регулярок — ложные, 121 из них дали block.timestamp
# в сравнении с ДЕДЛАЙНОМ (claimDeadline, unlockTime, votingDelay).
# Это корректный код: «прошёл ли срок», а не управление финансовой логикой.
# Имена пишутся в разных стилях: claimDeadline, _claimDeadline, unlockTime,
# votingDelay — поэтому (?i:) обязателен, иначе CamelCase не матчится.
# Префикс идентификатора обязателен: claimDeadline, _claimDeadline,
# unlockTime — ключевое слово стоит ВНУТРИ имени, а не в начале.
_DEADLINE = (r"[A-Za-z0-9_$]*(?i:deadline|expir\w*|maturity|end_?time|until"
             r"|closes_?at|unlock_?(time|at|date|ts)|voting_?delay|start_?block|valid_?until)")


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
        # Сравнение с дедлайном — верный код (см. измерение выше).
        # Обосновано измерением на bhaga-protocol (38 файлов, 12 477 строк):
        #   а) timestamp в emit-событии и внутри keccak256 — безобидны,
        #      на средства не влияют;
        #   б) сравнение с ДЕДЛАЙНОМ в любом направлении — это проверка
        #      «прошёл ли срок», а не управление финансовой логикой.
        exclude_line=_re(r"emit\s+\w+\([^)]*block\.[a-z]+|"
                         r"keccak256\s*\([^;]*block\.[a-z]+|"
                         r"%s\s*[<>]=?\s*block\.|"
                         r"block\.[^\n]*[<>]=?\s*\(?\s*%s"
                         % (_DEADLINE, _DEADLINE)),
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
        # Измерение: 3 ложных из-за отсутствия учёта right-above модификатора.
        exclude_line=_re(r"onlyOwner|_?checkOwner|msg\.sender\s*!=|"
                         r"require\s*\([^)]*sender"),
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

RULE_INDEX = {r.key: r for r in RULES}


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


# ---------------------------------------------------------- векторы риска
#
# Доли стоимости потерь по векторам (источники — docs/RISK-SCORE-METHODOLOGY.md):
#   инфраструктура 76% · логика 12% · дизайн 8% · экономика 4%
# (TRM Labs за 2025: code exploits 12,1% стоимости, infrastructure 76%.)
#
# Раньше находка «одна критическая ошибка в коде» и «мультисиг на одном
# ключе» стоили одинаково — для страховщика это неверно: убытки приходят
# из инфраструктуры. Теперь вектор виден в отчёте и в JSON.

VECTOR_INFRA = "infrastructure"
VECTOR_LOGIC = "logic"
VECTOR_DESIGN = "design"
VECTOR_ECONOMIC = "economic"

#: Доля стоимости потерь на вектор. Сумма = 100.
VECTOR_LOSS_SHARE: dict[str, int] = {
    VECTOR_INFRA: 76,
    VECTOR_LOGIC: 12,
    VECTOR_DESIGN: 8,
    VECTOR_ECONOMIC: 4,
}

#: Правило → вектор. Ключи — ровно те, что отдают RULES.
RULE_VECTOR: dict[str, str] = {
    # инфраструктура: компрометация не логики, а контроля
    "tx-origin": VECTOR_INFRA,
    "ecrecover-zero-address": VECTOR_INFRA,
    "uninitialized-proxy": VECTOR_INFRA,
    "delegatecall": VECTOR_INFRA,
    # логика контракта
    "reentrancy-eth": VECTOR_LOGIC,
    "arbitrary-send": VECTOR_LOGIC,
    "public-mint": VECTOR_LOGIC,
    "eth-transfer": VECTOR_LOGIC,
    "unchecked-lowlevel": VECTOR_LOGIC,
    # дизайн: то, что ломает композицию, а не исполнение
    "block-timestamp": VECTOR_DESIGN,
    "block-number": VECTOR_DESIGN,
    "selfdestruct": VECTOR_DESIGN,
    "assembly-inline": VECTOR_DESIGN,
    # экономика: недетерминированность и предсказуемость
    "weak-prng": VECTOR_ECONOMIC,
    # инфраструктура: ключи, роли, мультисиг, политика подписи.
    # Это тот самый слой, который стоит 76% потерь и который не смотрит
    # ни один аудит кода.
    "domain-chain-id": VECTOR_INFRA,
    "domain-verifying-contract": VECTOR_INFRA,
    "domain-mismatch": VECTOR_INFRA,
    "domain-identifiers": VECTOR_INFRA,
    "threshold-invalid": VECTOR_INFRA,
    "threshold-minority": VECTOR_INFRA,
    "threshold-single": VECTOR_INFRA,
    "threshold-all-owners": VECTOR_INFRA,
    "owners-duplicate": VECTOR_INFRA,
    "role-overlap": VECTOR_INFRA,
    "role-single-key": VECTOR_INFRA,
    "upgrade-timelock": VECTOR_INFRA,
    "owner-operator-concentration": VECTOR_INFRA,
    "signature-no-deadline": VECTOR_INFRA,
    "signature-age-long": VECTOR_INFRA,
    "signature-no-nonce": VECTOR_INFRA,
    "signature-expired": VECTOR_INFRA,
}

#: Штраф за находку по severity. Версия весов входит в отчёт: оценка
#: обязана быть воспроизводима — без версии через год нельзя доказать,
#: по каким правилам она считалась.
SCORE_VERSION = "1.0"

SEVERITY_PENALTY: dict[str, int] = {
    "critical": 40, "high": 15, "medium": 6, "low": 2,
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


# --------------------------------------------- движок 1: регулярки (текст)
#
# Видят строку, не видят структуру. Поэтому окно CONTEXT_LINES вокруг
# находки — эвристика, а проверка на три строки ниже вызова уже выпадает.
# Остаётся основным инструментом для кода, который не компилируется, и
# для режима ignore_comments=False.

def _regex_findings(code: str, *, ignore_comments: bool = True) -> list[Finding]:
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

    return out


# ----------------------------------------------- движок 2: solc AST (дерево)
#
# Зачем второй движок. Регулярка не отличает `require(ok)` на строке ниже
# вызова от `require(ok)` в другой функции: окно контекста ±2 строки — это
# эвристика, и на многстрочных конструкциях она даёт ложные срабатывания
# (проверено тестом test_multiline_check_outside_context_window). AST знает
# напрямую, что именно проверяется и в каком порядке выполняются операторы.
#
# Порядок выбора — принято решение (автопилот, 07.10.2026):
#   1. ignore_comments=False → всегда регулярки: запрос «искать по сырому
#      тексту» включает комментарии, а AST их не видит в принципе;
#   2. engine="auto" → AST, если установлен бинарь solc и код компилируется,
#      иначе регулярки;
#   3. engine="regex" / engine="ast" → принудительно; если AST построить
#      нельзя, откат на регулярки: пропущенный контракт хуже неточной
#      находки;
#   4. solc на лету НЕ скачиваем — это сеть и сюрприз в проде. Контракт,
#      который не компилируется (частая ситуация при сканировании чужих
#      репозиториев), всё равно сканируется, а не молча пропускается.

# Какие ключи правил умеет находить AST. Держать в согласии с RULES —
# проверяется тестом test_ast_engine_covers_all_rules.
#
# Ловушки solc AST (найдены 07.10.2026, каждый пункт — молчаливый пропуск):
#   * корень дерева под ключом `ast`, не `AST`;
#   * Assignment: `leftHandSide`/`rightHandSide`, а не `lhs`/`rhs` —
#     читать `lhs` значит не видеть присваиваний состоянию (reentrancy);
#   * вызов вида `to.call{value: v}("")` завёрнут в `FunctionCallOptions`;
#   * падение компиляции — не пропуск файла, а откат на regex.
_AST_RULES = frozenset({
    "reentrancy-eth", "delegatecall", "selfdestruct", "tx-origin",
    "unchecked-lowlevel", "arbitrary-send", "block-timestamp",
    "block-number", "uninitialized-proxy", "assembly-inline", "weak-prng",
    "ecrecover-zero-address", "public-mint", "eth-transfer",
})

_LOWLEVEL = frozenset({"call", "delegatecall"})
# Имена функций вывода средств: regex-правило arbitrary-send смотрит на них
# же, чтобы поведение обоих движков совпадало.
_SEND_FUNCS = frozenset({"withdraw", "rescueeth", "sendvalue", "transferout"})
_GUARD_MODS = frozenset({"onlyowner", "_checkowner", "checkowner",
                         "requireauth", "isauthorized"})
_GUARD_CALLS = frozenset({"require", "assert"})
_RNG_MEMBERS = frozenset({"timestamp", "prevrandao", "coinbase"})


def _solc() -> tuple:
    """(модуль solcx, установленные версии по убыванию) либо (None, [])."""
    try:
        import solcx
        versions = sorted(solcx.get_installed_solc_versions(), reverse=True)
    except Exception:
        return None, []
    return (solcx, versions) if versions else (None, [])


def ast_available() -> bool:
    """Доступен ли движок AST: нужен установленный бинарь solc."""
    return _solc()[0] is not None


@lru_cache(maxsize=64)
def _compile_ast(code: str) -> dict | None:
    """AST единого файла или None: solc нет / код не компилируется.

    Кэш по тексту исходника: один и тот же контракт в тестах и в CLI
    разбирается один раз. Словарь возвращается как есть — вызывающий его
    не мутирует. Причина отказа не разбирается: и синтаксическая ошибка, и
    несовпадение pragma ведут ровно в одно место — к regex-фолбэку.
    """
    solcx, versions = _solc()
    if solcx is None:
        return None
    request = {
        "language": "Solidity",
        "sources": {"input.sol": {"content": code}},
        "settings": {"outputSelection": {"*": {"": ["ast"]}}},
    }
    for version in versions:
        try:
            out = solcx.compile_standard(request, solc_version=version)
        except Exception:
            continue
        # Ключ `ast` (lowercase) — так его отдаёт solc через solcx.
        # Старая попытка читать "AST" молча возвращала None, и движок AST
        # никогда не срабатывал: всё уходило в regex-фолбэк. Найдено
        # проверкой вживую 07.10.2026, держим оба регистра на случай
        # другой обёртки solc.
        source = out.get("sources", {}).get("input.sol", {})
        ast = source.get("ast") or source.get("AST")
        if isinstance(ast, dict):
            return ast
    return None


def _nodes(root) -> Iterable[dict]:
    """Обойти все узлы дерева (dict внутри dict/list)."""
    stack = [root]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            yield current
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _offset(node: dict) -> int:
    """Байтовый оффсет из `src` — solc считает байты, не символы."""
    src = node.get("src")
    if isinstance(src, str):
        try:
            return int(src.split(":", 1)[0])
        except ValueError:
            pass
    return -1


def _parent_map(root: dict) -> dict:
    """id(дочернего) → родитель. AST — дерево, у узла один родитель."""
    parents: dict = {}
    stack = [root]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        for value in node.values():
            if isinstance(value, dict):
                parents[id(value)] = node
                stack.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        parents[id(item)] = node
                        stack.append(item)
    return parents


def _key_of(parent: dict, child: dict) -> str | None:
    """Ключ родителя, по которому лежит ребёнок (нужен для «условие это?»)."""
    for key, value in parent.items():
        if value is child:
            return key
        if isinstance(value, list) and any(item is child for item in value):
            return key
    return None


def _call_target(call: dict) -> dict | None:
    """Выражение-цель вызова, минуя обёртку `FunctionCallOptions`.

    `to.call{value: v}("")` solc разворачивает как
    FunctionCall → FunctionCallOptions → MemberAccess(call), поэтому
    наивный `call["expression"]` возвращает обёртку, а не цель. Без
    разворота такие вызовы не находились вовсе — проверено тестом
    test_multiline_check_outside_context_window.
    """
    expr = call.get("expression")
    while isinstance(expr, dict) and expr.get("nodeType") == "FunctionCallOptions":
        expr = expr.get("expression")
    return expr if isinstance(expr, dict) else None


def _callee(call: dict) -> str:
    """Имя вызываемой функции: `f()` → f, `x.g()` → g, `x.g{value:1}()` → g."""
    expr = _call_target(call)
    if not isinstance(expr, dict):
        return ""
    if expr.get("nodeType") == "MemberAccess":
        return str(expr.get("memberName") or "")
    return str(expr.get("name") or "")


def _identifier_names(root) -> set[str]:
    names: set[str] = set()
    for node in _nodes(root):
        if node.get("nodeType") == "Identifier":
            names.add(str(node.get("name") or ""))
    return names


def _is_block_member(node: dict) -> bool:
    """`block.timestamp` / `block.number` — base обязан быть `block`."""
    if node.get("nodeType") != "MemberAccess":
        return False
    base = node.get("expression") or {}
    return isinstance(base, dict) and base.get("name") == "block"


def _lowlevel_calls(subtree: list[dict]) -> list[dict]:
    calls = []
    for node in subtree:
        if node.get("nodeType") != "FunctionCall":
            continue
        expr = _call_target(node)
        if isinstance(expr, dict) and expr.get("nodeType") == "MemberAccess" \
                and expr.get("memberName") in _LOWLEVEL:
            calls.append(node)
    return calls


def _writes_state(node: dict, locals_: set[str]) -> bool:
    """Присваивание состоянию (не локальной переменной функции)."""
    kind = node.get("nodeType")
    if kind == "Assignment":
        # solc 0.8.x отдаёт leftHandSide/rightHandSide; старые версии — lhs/rhs.
        target = node.get("lhs") or node.get("leftHandSide")
    elif kind == "UnaryOperation" and node.get("operator") in ("++", "--"):
        target = node.get("subExpression")
    else:
        return False
    if not isinstance(target, dict):
        return False
    return not (locals_ & _identifier_names(target))


def _guarded_identifiers(root) -> set[str]:
    """Переменные, чьё значение проверяется в require/assert/if."""
    names: set[str] = set()
    for node in _nodes(root):
        kind = node.get("nodeType")
        if kind == "FunctionCall" and _callee(node) in _GUARD_CALLS:
            for arg in node.get("arguments") or []:
                if isinstance(arg, dict):
                    names |= _identifier_names(arg)
        elif kind == "IfStatement":
            cond = node.get("condition")
            if isinstance(cond, dict):
                names |= _identifier_names(cond)
    return names


def _mentions_msg_sender(node) -> bool:
    for n in _nodes(node):
        if n.get("nodeType") == "MemberAccess" and n.get("memberName") == "sender":
            base = n.get("expression") or {}
            if isinstance(base, dict) and base.get("name") == "msg":
                return True
    return False


def _fn_is_guarded(fn: dict, body: dict) -> bool:
    """Есть ли в функции проверка прав: модификатор, guard-функция или
    require/assert про msg.sender. Аналог exclude_line у regex-правила."""
    for mod in fn.get("modifiers") or []:
        expr = (mod or {}).get("expression") or {}
        if not isinstance(expr, dict):
            continue
        name = str(expr.get("name") or expr.get("memberName") or "").lower()
        if name in _GUARD_MODS:
            return True
    for node in _nodes(body):
        if node.get("nodeType") != "FunctionCall":
            continue
        name = _callee(node).lower()
        if name in _GUARD_MODS:
            return True
        if name in _GUARD_CALLS and any(
                isinstance(a, dict) and _mentions_msg_sender(a)
                for a in node.get("arguments") or []):
            return True
    return False


def _local_names(fn: dict, body: dict) -> set[str]:
    """Параметры и локальные объявления: присваивание им — не состояние."""
    names: set[str] = set()
    for section in (fn.get("parameters") or {}, fn.get("returnParameters") or {}):
        for param in section.get("parameters") or []:
            if isinstance(param, dict) and param.get("name"):
                names.add(param["name"])
    for node in _nodes(body):
        if node.get("nodeType") == "VariableDeclaration" and node.get("name"):
            names.add(node["name"])
    return names


def _result_checked(call: dict, parents: dict, checked: set[str]) -> bool:
    """Проверяется ли результат low-level вызова.

    Три вида проверки, все — по структуре, а не по расстоянию в строках:
      1. сам вызов внутри require/assert/if: `require(a.call(""))`;
      2. результат сохранён в переменную, и эта переменная где-то в функции
         участвует в require/if: `(bool ok,) = a.call(""); require(ok);`
      3. присваивание в существующую переменную, которая так проверяется.
    Возврат результата (`return ok;`) проверкой НЕ считается: иначе ломается
    контракт, где success никем не проверяется — см.
    test_realistic_multicontract_file.
    """
    node = call
    while True:
        parent = parents.get(id(node))
        if parent is None:
            return False
        key = _key_of(parent, node)
        kind = parent.get("nodeType")
        if key == "arguments" and kind == "FunctionCall" \
                and _callee(parent) in _GUARD_CALLS:
            return True
        if key == "condition" and kind == "IfStatement":
            return True
        if key == "initialValue" and kind == "VariableDeclarationStatement":
            names = {d.get("name") for d in parent.get("declarations") or []
                     if isinstance(d, dict) and d.get("name")}
            return bool(names & checked)
        # solc 0.8.x: rightHandSide/leftHandSide; старые версии: rhs/lhs.
        if key in ("rhs", "rightHandSide") and kind == "Assignment":
            lhs = parent.get("lhs") or parent.get("leftHandSide")
            if isinstance(lhs, dict) and (_identifier_names(lhs) & checked):
                return True
        node = parent


def _ast_findings(code: str) -> list[Finding] | None:
    """Находки по AST. None — дерево построить не удалось, нужен regex-фолбэк."""
    tree = _compile_ast(code)
    if tree is None:
        return None

    lines = _strip_noise(code).split("\n")
    raw = code.encode("utf-8", errors="replace")
    out: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def add(key: str, node: dict) -> None:
        rule = RULE_INDEX[key]
        off = _offset(node)
        if off < 0 or off > len(raw):
            return
        # Номер строки — по UTF-8 байтам: src у solc байтовый, а перенос
        # строки занимает ровно один байт в обоих подсчётах.
        line = raw.count(b"\n", 0, off) + 1
        if not 1 <= line <= len(lines):
            return
        if (key, line) in seen:
            return
        seen.add((key, line))
        out.append(Finding(
            rule=rule.key, title=rule.title, severity=rule.severity,
            why=rule.why, fix=rule.fix, line=line,
            excerpt=lines[line - 1].strip()[:140],
        ))

    # ---- правила, которым нужен только узел
    for node in _nodes(tree):
        kind = node.get("nodeType")
        if kind == "Identifier":
            if node.get("name") == "_init":
                add("uninitialized-proxy", node)
        elif kind == "MemberAccess":
            member = node.get("memberName")
            base = node.get("expression") or {}
            is_tx = isinstance(base, dict) and base.get("name") == "tx"
            if member == "origin" and is_tx:
                add("tx-origin", node)
            elif member == "timestamp" and _is_block_member(node):
                add("block-timestamp", node)
            elif member == "number" and _is_block_member(node):
                add("block-number", node)
            # block.timestamp в контексте генератора случайных чисел —
            # отдельное правило weak-prng, оно смотрит на функцию целиком
        elif kind == "FunctionCall":
            name = _callee(node)
            if name == "selfdestruct":
                add("selfdestruct", node)
            elif name == "ecrecover":
                add("ecrecover-zero-address", node)
            elif name == "initialize":
                add("uninitialized-proxy", node)
            expr = _call_target(node) or {}
            if expr.get("nodeType") == "MemberAccess":
                member = expr.get("memberName")
                if member == "delegatecall":
                    add("delegatecall", node)
                elif member == "transfer":
                    add("eth-transfer", node)
        elif kind == "InlineAssembly":
            add("assembly-inline", node)
        elif kind == "FunctionDefinition":
            if node.get("name") == "mint":
                add("public-mint", node)
            elif node.get("name") == "initialize":
                add("uninitialized-proxy", node)

    # ---- правила, которым нужна функция целиком
    for fn in _nodes(tree):
        if fn.get("nodeType") != "FunctionDefinition":
            continue
        body = fn.get("body")
        if not isinstance(body, dict):
            continue
        subtree = list(_nodes(body))
        locals_ = _local_names(fn, body)
        checked = _guarded_identifiers(body)
        parents = _parent_map(body)

        # слабый PRNG: детерминированный источник — только если в этой же
        # функции есть деление по модулю либо переменная про «random»
        uses_rand = False
        for n in subtree:
            if n.get("nodeType") == "BinaryOperation" and n.get("operator") == "%":
                uses_rand = True
                break
            if n.get("nodeType") in ("Identifier", "VariableDeclaration") and \
                    "random" in str(n.get("name") or "").lower():
                uses_rand = True
                break
        if uses_rand:
            for n in subtree:
                if n.get("nodeType") == "MemberAccess" \
                        and n.get("memberName") in _RNG_MEMBERS \
                        and _is_block_member(n):
                    add("weak-prng", n)

        writes = sorted((n for n in subtree if _writes_state(n, locals_)),
                        key=_offset)
        for call in _lowlevel_calls(subtree):
            off = _offset(call)
            # CEI: состояние меняется ПОСЛЕ вызова → управление уходит
            # атакующему, пока балансы ещё не обновлены.
            if any(_offset(w) > off for w in writes):
                add("reentrancy-eth", call)
            if not _result_checked(call, parents, checked):
                add("unchecked-lowlevel", call)

        if str(fn.get("name") or "").lower() in _SEND_FUNCS \
                and not _fn_is_guarded(fn, body):
            add("arbitrary-send", fn)

    return out


# --------------------------------------------------------------- публичное

def _run(code: str, *, ignore_comments: bool,
         engine: str | None) -> tuple[list[Finding], str]:
    """Выбрать движок, прогнать правила, вернуть (находки, кто нашёл).

    Единственное место, где решается AST против regex: и `scan`, и `check`
    идут через него, поэтому вердикт не может разойтись с печатью находок.
    Второй возвращаемый элемент — «ast» либо «regex», то есть кто реально
    сработал, а не кого просили. Он попадает в Verdict и JSON/SARIF: молчаливый
    откат на регулярки — это то, что в отчёте должно быть видно, а не спрятано.
    """
    chosen = (engine or os.environ.get("ATTEST_SCANNER_ENGINE") or "auto")
    chosen = chosen.strip().lower()
    if chosen == "auto" and not ignore_comments:
        # ignore_comments=False — явный запрос искать по сырому тексту,
        # включая комментарии: AST их не видит и просьбу выполнить не может.
        chosen = "regex"

    if chosen in ("auto", "ast"):
        found = _ast_findings(code)
        if found is not None:
            found.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line))
            return found, "ast"
        # Принудительный AST, а дерева нет (нет solc / код не компилируется):
        # откатываемся на регулярки, а не молчим. Пропущенный контракт хуже
        # неточной находки.

    out = _regex_findings(code, ignore_comments=ignore_comments)
    out.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line))
    return out, "regex"


def scan(code: str, *, ignore_comments: bool = True,
         engine: str | None = None) -> list[Finding]:
    """Просканировать Solidity. Возвращает находки по убыванию критичности.

    engine: "auto" (по умолчанию) | "ast" | "regex". Можно закрепить и через
    переменную окружения ATTEST_SCANNER_ENGINE. Какой движок реально
    сработал, видно в `check(...).engine`.
    """
    return _run(code, ignore_comments=ignore_comments, engine=engine)[0]


@dataclass
class Verdict:
    """Результат проверки. Честный: это фильтр классов, а не гарантия."""

    findings: list[Finding] = field(default_factory=list)
    lines_checked: int = 0
    rules_run: int = len(RULES)
    engine: str = "regex"

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

    def penalty_total(self) -> int:
        """Сумма штрафов. В отчёте идёт рядом со score: при насыщении
        (оценка уперлась в 0) по самой оценке нельзя отличить три
        критические находки от двадцати, а по штрафу — можно."""
        return sum(SEVERITY_PENALTY.get(f.severity, 0) for f in self.findings)

    def score(self) -> int:
        """Оценка 0-100, где 100 — чисто. Не «безопасность», а риск-скор."""
        return max(0, 100 - self.penalty_total())

    def vector_scores(self) -> dict[str, int]:
        """Оценка по каждому вектору отдельно: сколько штрафа дал
        инфраструктурный слой, сколько — логика кода. Страховщику
        нужна эта разбивка, а не одно среднее число."""
        out = {v: 100 for v in VECTOR_LOSS_SHARE}
        for f in self.findings:
            v = RULE_VECTOR.get(f.rule, VECTOR_LOGIC)
            out[v] = max(0, out[v] - SEVERITY_PENALTY.get(f.severity, 0))
        return out

    def score_confidence(self) -> str:
        """Насколько оценке можно верить. Непроверенное (unverified) —
        это не «чисто»: пока поля не описаны, часть правил молчала."""
        unv = getattr(self, "unverified", None) or []
        if unv:
            return "low" if len(unv) > 3 else "medium"
        if not self.rules_run:
            return "low"
        return "high"

    def as_dict(self) -> dict:
        return {
            "clean": self.clean,
            "worst_severity": self.worst,
            "risk_score": self.score(),
            "penalty_total": self.penalty_total(),
            "score_version": SCORE_VERSION,
            "score_confidence": self.score_confidence(),
            "vector_scores": self.vector_scores(),
            "vector_loss_share": dict(VECTOR_LOSS_SHARE),
            "counts": self.counts(),
            "lines_checked": self.lines_checked,
            "rules_run": self.rules_run,
            "engine": self.engine,
            "findings": [f.as_dict() for f in self.findings],
            "disclaimer": (
                "Сканер находит известные классы уязвимостей по исходному коду. "
                "Это НЕ формальная верификация и НЕ замена ручному аудиту. "
                "Чистый результат означает «чисто по этим правилам», а не "
                "«контракт безопасен»."
            ),
        }

    def summary(self) -> str:
        # Движок в сводке не для красоты: если solc нет и сработали
        # регулярки, читатель отчёта должен это увидеть, а не догадываться.
        engine = f" · движок {self.engine.upper()}"
        if self.clean:
            return (f"CLEAN · оценка {self.score()}/100 (100 = чисто) · "
                    f"{self.lines_checked} строк, {self.rules_run} правил{engine}")
        c = self.counts()
        parts = [f"{k}={v}" for k, v in c.items() if v]
        return (f"{self.worst.upper()} · оценка {self.score()}/100 (100 = чисто) · "
                f"{len(self.findings)} находок ({', '.join(parts)}){engine}")


def check(code: str, *, ignore_comments: bool = True,
          engine: str | None = None) -> Verdict:
    findings, used = _run(code, ignore_comments=ignore_comments, engine=engine)
    return Verdict(findings=findings,
                   lines_checked=len(code.split("\n")),
                   engine=used)


def rules_manifest() -> list[dict]:
    """Манифест правил — чтобы потребитель знал, что именно проверяется."""
    return [
        {"key": r.key, "title": r.title, "severity": r.severity,
         "why": r.why, "fix": r.fix}
        for r in RULES
    ]