"""Тесты AST-анализа. Ключевое: «не проверено» ≠ «проверено, чисто»."""

import pytest

from attest.ast_analyzer import analyze, build_ast, compare, HAVE_SOLCX

pytestmark = pytest.mark.skipif(not HAVE_SOLCX, reason="solcx недоступен")


REENTRANCY = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Bank {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"""

SAFE_CEI = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Bank {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "no funds");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
"""

DESTRUCT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C { function kill() public { selfdestruct(payable(msg.sender)); } }
"""

TX_ORIGIN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
    address owner;
    function check() public view returns (bool) { return tx.origin == owner; }
}
"""

NO_GUARD_WITHDRAW = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
    mapping(address => uint256) public balances;
    function withdraw(uint256 a) public { balances[msg.sender] -= a; }
}
"""

GUARDED_WITHDRAW = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    mapping(address => uint256) public balances;
    function withdraw(uint256 a) public onlyOwner { balances[msg.sender] -= a; }
}
"""


# ------------------------------------------------------------ базовый разбор

def test_ast_builds():
    ast = build_ast(REENTRANCY)
    assert ast is not None
    assert "Bank" in ast


def test_verdict_is_checked():
    v = analyze(REENTRANCY)
    assert v.compiled is True
    assert v.checked is True


def test_contracts_counted():
    v = analyze(REENTRANCY)
    assert v.contracts == 1
    assert v.src_lines > 0


# ------------------------------------------------------------ обнаружение

def test_finds_reentrancy():
    v = analyze(REENTRANCY)
    assert "reentrancy-ast" in {f.rule for f in v.findings}


def test_finds_unchecked_call():
    assert "unchecked-call-ast" in {f.rule for f in analyze(REENTRANCY).findings}


def test_finds_selfdestruct():
    assert "selfdestruct-ast" in {f.rule for f in analyze(DESTRUCT).findings}


def test_finds_tx_origin():
    assert "tx-origin-ast" in {f.rule for f in analyze(TX_ORIGIN).findings}


def test_finds_unprotected_withdraw():
    assert "unprotected-withdraw-ast" in {f.rule for f in analyze(NO_GUARD_WITHDRAW).findings}


# ---------------------------------------------- главное: отличие от регулярок

def test_safe_cei_contract_is_clean():
    """Ключевое отличие AST: порядок Checks-Effects-Interactions виден
    по дереву, а не по тексту. Регулярка ругается, AST — нет."""
    v = analyze(SAFE_CEI)
    assert v.findings == [], [f.rule for f in v.findings]


def test_guarded_withdraw_is_clean():
    v = analyze(GUARDED_WITHDRAW)
    assert "unprotected-withdraw-ast" not in {f.rule for f in v.findings}


def test_line_numbers_are_real():
    """Номер строки обязан совпасть с реальным местом в исходнике."""
    v = analyze(DESTRUCT)
    f = next(x for x in v.findings if x.rule == "selfdestruct-ast")
    src = DESTRUCT.split("\n")
    assert "selfdestruct" in src[f.line - 1]


def test_findings_sorted_by_severity():
    v = analyze(REENTRANCY)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    seq = [order[f.severity] for f in v.findings]
    assert seq == sorted(seq)


def test_confidence_is_exact():
    for f in analyze(REENTRANCY).findings:
        assert f.confidence == "exact"


# ----------------------------------------------------- честность отказа

def test_broken_source_is_not_clean():
    """Не скомпилировалось — это НЕ «чисто». Разница принципиальна."""
    v = analyze("contract Broken { this is not solidity }")
    assert v.compiled is False
    assert v.checked is False
    assert v.findings == []
    assert "НЕ ПРОВЕРЕНО" in v.summary()


def test_empty_source_not_clean():
    v = analyze("")
    assert v.checked is False


def test_disclaimer_differs_by_state():
    ok = analyze(SAFE_CEI).as_dict()["disclaimer"]
    bad = analyze("contract {").as_dict()["disclaimer"]
    assert "выполнен настоящим компилятором" in ok
    assert "НЕ ВЫПОЛНЕНА" in bad


def test_disclaimer_warns_absence_is_not_safety():
    bad = analyze("contract {").as_dict()["disclaimer"]
    assert "НЕ означает безопасность" in bad


# ------------------------------------------------------------ сравнение

def test_compare_reports_both_layers():
    r = compare(REENTRANCY)
    assert "regex" in r and "ast" in r
    assert r["ast"]["проверено"] is True


def test_compare_handles_uncompilable():
    r = compare("contract {")
    assert r["ast"]["проверено"] is False
    assert r["ast"]["ошибка"]