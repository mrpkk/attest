"""Д8: статический анализ через solc AST — многстрочные конструкции.

Зачем отдельный файл. Регулярки видят строку, не видят структуру: окно
guard'а — ±2 строки (`CONTEXT_LINES`), и как только вызов занимает несколько
строк, проверка результата уезжает за границу окна. AST знает напрямую,
что именно проверяется и в каком порядке выполняются операторы, поэтому
ложного срабатывания на «проверка была, просто дальше по коду» не бывает.

Тест ловит три разные поломки:
  1. ложное срабатывание regex на многстрочной конструкции;
  2. молчаливый откат в regex, когда AST «доступен» (так было: solc отдаёт
     ключ `ast`, а код читал `AST` — и движок никогда не срабатывал);
  3. молчаливый пропуск настоящей reentrancy: solc отдаёт `leftHandSide`,
     код читал `lhs`, и `_writes_state` всегда возвращал False.
"""

import pytest

from attest.scanner import _ast_findings, _regex_findings, ast_available, scan

pytestmark = pytest.mark.skipif(
    not ast_available(), reason="solc не установлен — движок AST недоступен")

# Контракт компилируем (иначе AST не построится), вызовы — многстрочные.
#   payout    — проверка `require(ok)` на строке ВНЕ окна ±2 от вызова:
#               regex обязан соврать, AST обязан молчать.
#   payoutBad — проверки нет вообще: оба движка обязаны найти.
MULTILINE = """
pragma solidity ^0.8.20;

contract MultilineChecked {
    address payable public treasury;

    function payout(address payable to, uint256 amount) external {
        (bool ok, ) = to.call{
            value: amount
        }("");
        require(ok, "transfer failed");
    }

    function payoutBad(address payable to, uint256 amount) external {
        (bool ok, ) = to.call{
            value: amount
        }("");
        ok = ok;
    }
}
"""


def test_ast_engine_actually_builds_tree():
    """Движок AST строит дерево, а не молча откатывается в regex.

    Регрессия: ключ `ast` против `AST` — при несовпадении `_ast_findings`
    возвращал None и все проверки ниже проходили бы на regex-фолбэке,
    то есть ничего не проверяли бы.
    """
    assert _ast_findings(MULTILINE) is not None, \
        "AST не построился — движок молча ушёл в regex"


def test_multiline_check_outside_context_window():
    """Проверка результата за границей окна ±2 строк: FP есть у regex,
    у AST его нет."""
    # regex: вызов на строке 8, require(ok) на строке 11 — вне окна,
    # поэтому ложное срабатывание unchecked-lowlevel.
    regex_lines = {f.line for f in _regex_findings(MULTILINE)
                   if f.rule == "unchecked-lowlevel"}
    assert 8 in regex_lines

    # AST: `ok` в payout проверяется require'ом в той же функции —
    # находки на строке 8 нет (на строке 15, где проверки нет вовсе, есть).
    ast_lines = {f.line for f in _ast_findings(MULTILINE)
                 if f.rule == "unchecked-lowlevel"}
    assert 8 not in ast_lines, \
        "AST не должен находить unchecked там, где результат проверен"


def test_ast_finds_real_unchecked_multiline_call():
    """Позитивный контроль: там, где проверки действительно нет, AST
    находит — иначе тест выше проходил бы на пустом наборе находок."""
    ast = _ast_findings(MULTILINE)
    unchecked = [f for f in ast if f.rule == "unchecked-lowlevel"]
    assert len(unchecked) == 1
    # Единственная настоящая находка — вызов в payoutBad (строка 15).
    assert unchecked[0].line == 15


def test_engines_disagree_on_multiline():
    """Разница движков на одном и том же коде — суть Д8: AST точнее."""
    regex = scan(MULTILINE, engine="regex")
    tree = scan(MULTILINE, engine="ast")
    assert len(tree) < len(regex), \
        "AST должен отдавать меньше находок за счёт снятия ложных"


def test_auto_engine_uses_ast_when_available():
    """auto-режим выбирает AST, если solc есть и код компилируется."""
    auto = scan(MULTILINE)
    tree = scan(MULTILINE, engine="ast")
    assert [(f.rule, f.line) for f in auto] == [(f.rule, f.line) for f in tree]


# Нарушение Checks-Effects-Interactions: состояние пишется ПОСЛЕ вызова.
# Регрессия 07.10.2026: solc отдаёт `leftHandSide`, а код читал `lhs` —
# `_writes_state` всегда False, и AST не находил настоящую reentrancy.
CEI_VIOLATION = """
pragma solidity ^0.8.20;

contract CeiViolation {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "denied");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""


def test_ast_finds_reentrancy_when_state_written_after_call():
    """AST обязан видеть `balances[x] -= v` после вызова (правило critical)."""
    ast = _ast_findings(CEI_VIOLATION)
    assert ast is not None
    keys = {f.rule for f in ast}
    assert "reentrancy-eth" in keys, \
        "присваивание состоянию после вызова не найдено — сломан _writes_state"


def test_regex_misses_that_reentrancy():
    """Фолбэк-регулярки такое окно не видят — это и есть цена fallback.

    Окно ±2 строки подавляет находку, увидев присваивание рядом, хотя порядок
    операторов обратный. Ставим в фикстуру как документацию границы regex.
    """
    regex = _regex_findings(CEI_VIOLATION)
    assert "reentrancy-eth" not in {f.rule for f in regex}
    # Разница движков на одном коде — суть Д8.
    assert {f.rule for f in _ast_findings(CEI_VIOLATION)} - \
        {f.rule for f in regex}
