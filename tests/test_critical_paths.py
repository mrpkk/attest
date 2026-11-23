"""Критичные пути: ключ выдан → проверяется → расходует квоту → чужой ключ отклонён.

Проверяем стыки, а не отдельные функции: именно там ломается при правках.
"""
from __future__ import annotations

import importlib

from attest import apikeys


def _fresh(tmp_path, monkeypatch):
    mod = importlib.reload(apikeys)
    key_path = tmp_path / "api_keys.jsonl"
    monkeypatch.setattr(mod, "KEYS_PATH", key_path)
    return mod


def test_issue_verify_and_consume(tmp_path, monkeypatch):
    mod = _fresh(tmp_path, monkeypatch)
    rec = mod.issue(plan="pack", subject="buyer@example.com", tx="0xabc", days=30, calls_limit=2)
    key = rec["key"]
    assert mod.verify(key)["plan"] == "pack"
    assert mod.consume(key) is not None
    assert mod.consume(key) is not None
    assert mod.consume(key) is None            # квота исчерпана
    assert mod.consume("dn_not_a_real_key") is None


def test_key_of_other_subject_is_not_accepted(tmp_path, monkeypatch):
    mod = _fresh(tmp_path, monkeypatch)
    first = mod.issue(plan="pack", subject="a@example.com", tx="0x1", days=30)["key"]
    second = mod.issue(plan="pack", subject="b@example.com", tx="0x2", days=30)["key"]
    assert mod.verify(first)["subject"] == "a@example.com"
    assert mod.verify(second)["subject"] == "b@example.com"
    assert mod.verify("dn_" + "0" * 48) is None


def test_expired_key_is_rejected(tmp_path, monkeypatch):
    mod = _fresh(tmp_path, monkeypatch)
    key = mod.issue(plan="pack", subject="c@example.com", tx="0x3", days=-1)["key"]
    assert mod.verify(key) is None
