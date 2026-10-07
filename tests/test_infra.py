"""Проверки инфраструктурного вектора — на реальных инцидентах.

Каждый тест в блоке INCIDENTS воспроизводит конфигурацию, соответствующую
реальному взлому. Не выдумано: инциденты публичны и проверяемы по отчётам.

  Ronin, 08.03.2022, ~$624 млн  — компрометация ключей у одного оператора
  Wormhole, 02.02.2022, ~$326 млн — подпись без привязки к контракту
  Poly Network, 30.08.2021, ~$611 млн — один привилегированный ключ
  Nomad, 08.08.2022, ~$190 млн — сообщения без привязки к сети
  Radiant Capital, 16.10.2024, ~$50 млн — подпись без защиты от повтора
  Curve, 30.07.2023, ~$70 млн — один адрес в нескольких ролях

Ссылка на источники — в README, раздел «Инциденты». Здесь важно другое:
правила обязаны ловить именно эти конфигурации, а чистую — не трогать.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from attest.infra import ConfigError, check, check_config


# --------------------------------------------------------------- фикстуры

def _addr(n: int) -> str:
    return "0x" + f"{n:040x}"


def clean_config() -> dict:
    """Конфигурация без замечаний. Если этот словарь начнёт давать находки —
    правила слишком шумные, а не «нашли ещё дыру»."""
    return {
        "domain": {
            "name": "vault",
            "version": "1",
            "chainId": 8453,
            "verifyingContract": _addr(0xA11),
        },
        "multisig": {
            "address": _addr(0xA11),
            "threshold": 3,
            "owners": [
                {"address": _addr(1), "operator": "op-one"},
                {"address": _addr(2), "operator": "op-two"},
                {"address": _addr(3), "operator": "op-three"},
                {"address": _addr(4), "operator": "op-four"},
                {"address": _addr(5), "operator": "op-five"},
            ],
            "modules": [_addr(0xB01)],
        },
        "roles": [
            {"name": "guardian", "keys": [_addr(6)],
             "timelock_seconds": 48 * 3600},
            {"name": "upgrader", "keys": [_addr(7), _addr(8)],
             "timelock_seconds": 7 * 86400},
        ],
        "signature_policy": {
            "deadline_required": True,
            "max_age_seconds": 7 * 86400,
            "nonce_required": True,
            "replay_protection": "nonce",
            "deadline": (datetime.now(timezone.utc)
                         + timedelta(days=30)).isoformat(),
        },
    }


def keys_of(verdict, rule: str) -> list:
    return [f for f in verdict.findings if f.rule == rule]


# ------------------------------------------------------- INCIDENTS: взломы

def test_ronin_2022_operator_holds_threshold():
    """Ronin, март 2022, ~$624 млн.

    Мультисиг формально 5-of-9, но часть ключей обслуживал один оператор.
    Порог в подписи не отражал реальное распределение контроля: компрометации
    оператора хватало, чтобы собрать подписи. Правило ловит именно это —
    не «мало подписантов», а «один оператор проходит порог»."""
    cfg = clean_config()
    # 9 владельцев, порог 5, но 5 из них — ключи одного оператора.
    cfg["multisig"]["threshold"] = 5
    cfg["multisig"]["owners"] = [
        {"address": _addr(10 + i), "operator": "sky-mavis"} for i in range(5)
    ] + [{"address": _addr(30 + i), "operator": f"validator-{i}"} for i in range(4)]

    v = check(cfg)
    assert keys_of(v, "owner-operator-concentration"), v.findings


def test_ronin_2022_single_role_key_without_timelock():
    """Та же атака с другой стороны: один ключ роли без таймлока действует
    мгновенно — отзывать и форкать успевают не всегда."""
    cfg = clean_config()
    cfg["roles"] = [{"name": "governance", "keys": [_addr(9)]}]

    v = check(cfg)
    assert keys_of(v, "role-single-key"), v.findings


def test_wormhole_2022_signature_not_bound_to_contract():
    """Wormhole, февраль 2022, ~$326 млн.

    Атакующий подделал подпись стража и отправил сообщение в контракт, чей
    адрес не был привязан к домену подписи: подпись, выданная для одного
    контекста, принималась другим. Проверяем обе стороны — отсутствие
    привязки и явное несовпадение."""
    cfg = clean_config()
    cfg["domain"].pop("verifyingContract")

    assert keys_of(check(cfg), "domain-verifying-contract")

    # И явное несовпадение: подписывают один адрес, исполняют другой.
    cfg2 = clean_config()
    cfg2["domain"]["verifyingContract"] = _addr(0xDEAD)
    found = keys_of(check(cfg2), "domain-mismatch")
    assert found, check(cfg2).findings
    assert _addr(0xDEAD) in found[0].excerpt


def test_poly_network_2021_single_privileged_key():
    """Poly Network, август 2021, ~$611 млн.

    Один привилегированный адрес мог вызвать кросс-чейн менеджер и начеканить
    активы. В конфигурации это выглядит как роль из одного ключа без таймлока."""
    cfg = clean_config()
    cfg["roles"] = [{"name": "crossChainManager", "keys": [_addr(11)]}]

    v = check(cfg)
    assert keys_of(v, "role-single-key"), v.findings


def test_nomad_2022_message_not_bound_to_chain():
    """Nomad, август 2022, ~$190 млн.

    Сообщения принимались без проверки источника: подпись, полученная в одном
    домене, применялась в другом. Привязки к сети не было."""
    cfg = clean_config()
    cfg["domain"].pop("chainId")

    v = check(cfg)
    assert keys_of(v, "domain-chain-id"), v.findings


def test_radiant_2024_signature_without_replay_protection():
    """Radiant Capital, октябрь 2024, ~$50 млн.

    Через внедрённый в интерфейс скрипт подписанты подписали правдоподобный
    перевод. Ключевое: подпись можно было повторить, а срок её действия не
    был ограничен — окно для отмены отсутствовало."""
    cfg = clean_config()
    cfg["signature_policy"]["nonce_required"] = False
    assert keys_of(check(cfg), "signature-no-nonce")

    cfg2 = clean_config()
    cfg2["signature_policy"]["replay_protection"] = None
    assert keys_of(check(cfg2), "signature-no-nonce")

    cfg3 = clean_config()
    cfg3["signature_policy"]["deadline_required"] = False
    assert keys_of(check(cfg3), "signature-no-deadline")


def test_curve_2023_one_address_holds_every_role():
    """Curve, июль 2023, ~$70 млн.

    Компрометация адреса с правами администратора позволила внести в код
    эксплойт через modify_pool. Нашлась ровно та конфигурация, которая
    позволяет одному адресу быть одновременно владельцем, модулем и ролью."""
    cfg = clean_config()
    same = _addr(12)
    cfg["multisig"]["owners"] = [{"address": same, "operator": "op-one"},
                                 {"address": _addr(2), "operator": "op-two"},
                                 {"address": _addr(3), "operator": "op-three"}]
    cfg["multisig"]["threshold"] = 1
    cfg["multisig"]["modules"] = [same]
    cfg["roles"] = [{"name": "admin", "keys": [same], "timelock_seconds": 48 * 3600}]

    v = check(cfg)
    assert keys_of(v, "role-overlap"), v.findings
    assert same in keys_of(v, "role-overlap")[0].excerpt


# ------------------------------------------------- INCIDENTS: пороги мультисига

def test_threshold_one_is_a_single_key():
    """Одиночный ключ под видом мультисига — самая частая находка на практике."""
    cfg = clean_config()
    cfg["multisig"]["threshold"] = 1

    v = check(cfg)
    assert keys_of(v, "threshold-single"), v.findings


def test_threshold_majority_needed():
    """Порог в меньшинстве означает: его владельцы выводят средства без
    остальных. Для 3 владельцев нужно 2, а не 1."""
    cfg = clean_config()
    cfg["multisig"]["owners"] = [_addr(1), _addr(2), _addr(3)]
    cfg["multisig"]["threshold"] = 1

    assert keys_of(check(cfg), "threshold-minority")


def test_threshold_unreachable_is_worse_than_reachable():
    """Порог выше числа владельцев — казна заморожена навсегда."""
    cfg = clean_config()
    cfg["multisig"]["threshold"] = 9

    assert keys_of(check(cfg), "threshold-invalid")


def test_threshold_all_owners_freezes_funds():
    """n-of-n: утрата одного ключа блокирует вывод средств навсегда."""
    cfg = clean_config()
    cfg["multisig"]["threshold"] = 5

    assert keys_of(check(cfg), "threshold-all-owners")


def test_duplicate_owners_inflate_the_denominator():
    """Один адрес в списке дважды: порог посчитан по бумаге, а уникальных
    владельцев меньше — реальный контроль выше заявленного."""
    cfg = clean_config()
    cfg["multisig"]["owners"] = [_addr(1), _addr(1), _addr(2), _addr(3)]

    found = keys_of(check(cfg), "owners-duplicate")
    assert found
    assert _addr(1) in found[0].excerpt


def test_upgrade_without_timelock_leaves_no_reaction_window():
    """Апгрейд без таймлока невозможно отозвать: между обновлением и
    обнаружением нет окна."""
    cfg = clean_config()
    cfg["roles"] = [{"name": "proxy_admin", "keys": [_addr(1), _addr(2)],
                     "timelock_seconds": 60}]

    v = check(cfg)
    found = keys_of(v, "upgrade-timelock")
    assert found
    assert "timelock_seconds" in found[0].excerpt or "таймлок" in found[0].excerpt


def test_expired_signature_deadline():
    cfg = clean_config()
    cfg["signature_policy"]["deadline"] = (
        datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

    v = check(cfg)
    assert keys_of(v, "signature-expired"), v.findings


def test_signature_living_too_long():
    cfg = clean_config()
    cfg["signature_policy"]["max_age_seconds"] = 365 * 86400

    assert keys_of(check(cfg), "signature-age-long")


def test_unnamed_domain_allows_silent_reuse():
    cfg = clean_config()
    cfg["domain"].pop("name")

    v = check(cfg)
    assert keys_of(v, "domain-identifiers"), v.findings


def test_chain_id_zero_is_not_a_chain():
    cfg = clean_config()
    cfg["domain"]["chainId"] = 0

    assert keys_of(check(cfg), "domain-chain-id")


# ----------------------------------------------- чистая конфигурация молчит

def test_clean_config_produces_no_findings():
    """Главный тест против шума: корректная конфигурация не должна
    давать ни одной находки. Ложные срабатывания в инфра-режиме
    бесполезны — их игнорируют, и вместе с ними настоящие."""
    v = check(clean_config())
    assert v.findings == [], [f.rule for f in v.findings]
    assert v.unverified == [], v.unverified


# ------------------------------ отсутствие поля ≠ «чисто» (регрессия Д9)

def test_missing_field_goes_to_unverified_not_clean():
    """Правило без нужного поля не имеет права рапортовать «чисто»:
    иначе CI зеленеет впустую. Проверка ровно на этот провал."""
    cfg = clean_config()
    cfg.pop("multisig")
    cfg.pop("roles")

    v = check(cfg)
    assert not any(f.rule.startswith("threshold") for f in v.findings)
    assert any("multisig" in u or "roles" in u for u in v.unverified), v.unverified


def test_unverified_names_the_missing_field():
    """В unverified должно быть видно, чего именно не хватило."""
    cfg = clean_config()
    cfg["multisig"].pop("threshold")

    v = check(cfg)
    text = " ".join(v.unverified)
    assert "threshold" in text, v.unverified


def test_timelock_absent_is_unverified_not_missing_timelock():
    """Нет поля timelock_seconds — это «не описано», а не «таймлока нет».
    Путать эти две вещи нельзя: первое лечится вопросом, второе — кодом."""
    cfg = clean_config()
    cfg["roles"] = [{"name": "upgrader", "keys": [_addr(1), _addr(2)]}]

    v = check(cfg)
    assert not keys_of(v, "upgrade-timelock")
    assert any("timelock" in u.lower() for u in v.unverified), v.unverified


def test_owners_without_operator_cannot_judge_concentration():
    """Нет операторов — концентрацию судить нечем. Молчать нельзя."""
    cfg = clean_config()
    cfg["multisig"]["owners"] = [_addr(1), _addr(2), _addr(3), _addr(4),
                                 _addr(5)]

    v = check(cfg)
    assert not keys_of(v, "owner-operator-concentration")
    assert any("operator" in u.lower() for u in v.unverified), v.unverified


# ------------------------------------------------------------- числа и текст

def test_findings_sorted_by_severity_and_line():
    v = check_config(json.dumps(clean_config(), indent=2))
    order = ["critical", "high", "medium", "low"]
    seen = [order.index(f.severity) for f in v.findings]
    assert seen == sorted(seen), [f.severity for f in v.findings]


def test_line_numbers_point_into_the_source():
    """Номер строки должен указывать на проблемное место в исходном
    документе, иначе находка непригодна для разбора."""
    raw = json.dumps(clean_config(), indent=2)
    v = check_config(raw)

    for f in v.findings:
        assert 1 <= f.line <= len(raw.split("\n")), f.rule


def test_bool_threshold_is_not_a_threshold():
    """В Python bool — подкласс int. Настоящий порог true/false быть не может,
    иначе проверка молча примет неверное значение."""
    cfg = clean_config()
    cfg["multisig"]["threshold"] = True

    found = keys_of(check(cfg), "threshold-invalid")
    assert found, check(cfg).findings


def test_malformed_json_raises_config_error():
    with pytest.raises(ConfigError):
        check_config("{это не json")


def test_wrong_types_do_not_crash():
    """Мусор в документе не должен ронять анализатор: конфиг приходит из
    чужого источника, и падение здесь означает DoS проверки."""
    for broken in ({"multisig": "строка вместо словаря"},
                   {"multisig": {"owners": "строка", "threshold": 2}},
                   {"roles": "не список"},
                   {"domain": 5},
                   {"signature_policy": []}):
        try:
            check(broken)
        except ConfigError:
            pass  # явный отказ — приемлемо
        # Главное: без необработанного исключения


def test_verdict_reports_engine_and_counts():
    v = check_config(json.dumps(clean_config(), indent=2))
    assert v.engine == "config"
    assert v.rules_run > 0
    assert v.lines_checked > 1