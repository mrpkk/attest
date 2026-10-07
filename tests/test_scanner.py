"""Тесты сканера уязвимостей. Каждый вектор — реальный класс из продакшена."""

import pytest

from attest.scanner import (
    check, scan, rules_manifest, RULES, Verdict, SEVERITY_ORDER,
)

VULNERABLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vulnerable {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    function ownerOnly() public {
        if (tx.origin == owner) { doThing(); }
    }

    function random() public view returns (uint) {
        return uint(block.timestamp) % 100;
    }

    function raw(address a, bytes memory d) public {
        a.call(d);
    }
}
"""

CLEAN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Safe {
    address public immutable owner;
    mapping(address => uint256) public balances;
    bool private locked;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function withdraw(uint256 amount) external {
        // проверка прав обязательна для вывода средств
        require(msg.sender == owner || balances[msg.sender] >= amount, "denied");
        // проверки эффектов ДО взаимодействий — порядок CEI соблюдён
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function deposit() external payable { balances[msg.sender] += msg.value; }
    function version() external pure returns (uint) { return 1; }
}
"""


# ------------------------------------------------------------ поиск

def test_finds_reentrancy():
    keys = {f.rule for f in scan(VULNERABLE)}
    assert "reentrancy-eth" in keys


def test_finds_selfdestruct():
    assert "selfdestruct" in {f.rule for f in scan(VULNERABLE)}


def test_finds_tx_origin():
    assert "tx-origin" in {f.rule for f in scan(VULNERABLE)}


def test_finds_unchecked_call():
    keys = {f.rule for f in scan(VULNERABLE)}
    assert "unchecked-lowlevel" in keys or "unchecked-call-return" in keys


def test_finds_block_timestamp():
    assert "block-timestamp" in {f.rule for f in scan(VULNERABLE)}


def test_clean_contract_has_no_critical():
    v = check(CLEAN)
    assert not [f for f in v.findings if f.severity == "critical"]


def test_vulnerable_contract_is_not_clean():
    v = check(VULNERABLE)
    assert not v.clean
    assert v.worst in ("critical", "high")


# ------------------------------------------------------------ честность

def test_comments_are_not_findings():
    """Правило: предупреждение в комментарии — не уязвимость."""
    # В комментарии — настоящий вызов со скобками, иначе проверять нечего.
    code = """
    // НЕ используйте так: target.delegatecall(data)
    /* запрещено: selfdestruct(payable(msg.sender)); */
    contract C { function ok() public pure returns (uint) { return 1; } }
    """
    assert scan(code) == [], "в комментарии не должно быть находок"
    found = scan(code, ignore_comments=False)
    assert {f.rule for f in found} >= {"delegatecall"}, "без очистки — должны найти"


def test_strings_are_not_code():
    code = 'contract C { string s = "selfdestruct and delegatecall"; }'
    assert "selfdestruct" not in {f.rule for f in scan(code)}


def test_line_numbers_are_correct():
    findings = scan(VULNERABLE)
    assert all(f.line > 0 for f in findings)
    from attest.scanner import _strip_noise
    # Номера строк считаются ПО ОЧИЩЕННОМУ источнику: комментарии и
    # строковые литералы затираются пробелами с сохранением длин, поэтому
    # номер строки совпадает, а содержимое — нет.
    lines = _strip_noise(VULNERABLE).split("\n")
    assert len(lines) == len(VULNERABLE.split("\n"))
    for f in findings:
        assert 1 <= f.line <= len(lines)
        assert f.excerpt == lines[f.line - 1].strip()[:140]


# ------------------------------------------------------- оценка риска

def test_score_degrades_with_findings():
    assert check(CLEAN).score() > check(VULNERABLE).score()
    assert check(CLEAN).score() == 100


def test_score_never_negative():
    many = "\n".join(["selfdestruct(payable(msg.sender));" for _ in range(20)])
    assert check(many).score() >= 0


def test_counts_by_severity():
    c = check(VULNERABLE).counts()
    assert set(c) == set(SEVERITY_ORDER)
    assert c["critical"] >= 1


def test_sorted_by_severity_first():
    fs = scan(VULNERABLE)
    scores = [SEVERITY_ORDER[f.severity] for f in fs]
    assert scores == sorted(scores, reverse=True)


# ------------------------------------------------------------ контракт

def test_disclaimer_present():
    """Чистый результат не должен читаться как гарантия безопасности."""
    d = check(CLEAN).as_dict()
    assert "disclaimer" in d
    assert "НЕ формальная верификация" in d["disclaimer"]


def test_manifest_lists_all_rules():
    m = rules_manifest()
    assert len(m) == len(RULES)
    assert {x["key"] for x in m} == {r.key for r in RULES}
    for item in m:
        assert item["why"] and item["fix"]


def test_every_rule_has_severity_and_help():
    for r in RULES:
        assert r.severity in SEVERITY_ORDER
        assert len(r.why) > 20, r.key
        assert len(r.fix) > 20, r.key


def test_as_dict_shape():
    d = check(VULNERABLE).as_dict()
    for k in ("clean", "worst_severity", "risk_score", "counts",
              "lines_checked", "rules_run", "findings", "disclaimer"):
        assert k in d


def test_summary_is_readable():
    s = check(VULNERABLE).summary()
    assert "риск" in s and "находок" in s
    assert "CLEAN" in check(CLEAN).summary()


# ------------------------------------------------------------ устойчивость

def test_empty_and_broken_input():
    assert check("").clean
    assert check("contract C {").clean          # синтаксис не наш слой
    assert check("}" * 500).clean
    assert check(" ").clean


def test_unicode_does_not_crash():
    assert isinstance(check("контракт { } контракт").clean, bool)


def test_realistic_multicontract_file():
    src = """
    pragma solidity ^0.8.0;
    interface IERC20 { function transfer(address,uint256) external returns (bool); }
    contract Token is IERC20 {
        address public owner;
        constructor() { owner = msg.sender; }
        function transfer(address to, uint256 v) external returns (bool) {
            (bool ok, ) = to.call(abi.encodeWithSignature("f()"));
            return ok;
        }
    }
    contract Vault {
        function sweep(address payable to) external {
            to.transfer(address(this).balance);
        }
    }
    """
    keys = {f.rule for f in scan(src)}
    assert len(keys) >= 2