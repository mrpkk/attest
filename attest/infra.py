"""
INFRA — проверка конфигурации инфраструктуры: домен мультисигна, пороги,
разделение ролей, сроки подписи.

Д10, 07.10.2026. Второй вектор потерь. По данным из канон-спеки (Хакен,
CertiK): ~76% стоимости краж приходится на инфраструктуру — подписи, ключи,
конфигурацию мультисигов; ~12% — на код контрактов. Сканер кода
(scanner.py) этот вектор физически не видит: он читает .sol, а мультисиг
живёт в домене подписи, распределении ключей, порогах и таймлоках. Внутри
DeFi по Immunefi 89% потерь — логика протокола, то есть код: там работает
scanner.py. Этот модуль закрывает ту часть, что не покрыта кодом.

ЧЕТЫРЕ ИЗМЕРЕНИЯ, каждое — свой блок правил:

  1. домен мультисигна — EIP-712 domain: chainId, verifyingContract,
     name/version. Домен — это то, что подписчики считают объектом
     подписи. Рассинхрон домена и исполняющего контракта = подписывали
     одно, ушло другое.
  2. thresholds — N-of-M: порог существует и собирается, не меньше
     большинства, не единица, без дублей владельцев, с запасом на утерю.
  3. разделение ролей — один адрес не сидит одновременно в нескольких
     привилегированных группах; ключевая роль без таймлока; владельцы,
     сконцентрированные у одного оператора.
  4. сроки подписи — дедлайн обязателен, возраст подписи ограничен,
     nonce обязателен, просроченная подпись = находка.

ВХОД — декларативный JSON, который команда выписывает о своей
конфигурации. Принято решение (автопилот 07.10.2026): ончейн-инспекция
(адрес Safe → нода → владельцы и порог прямо из цепи) — отдельный скоуп
с другими зависимостями (RPC, нода, сеть); здесь проверяется документ.
Называется это честно: проверка документа, а не цепи.

ЧЕСТНОСТЬ (наследие Д8: «не смог проверить» ≠ «чисто»):
  · поле/измерение, нужное правилу, в документе отсутствует → правило
    уходит в `unverified`, вердикт НЕ чист, код возврата 1. Молчаливый
    пропуск хуже находки.
  · JSON не разобрался → `ConfigError`, код возврата 2 — отказ проверки,
    а не «чисто» и не «находка».
  · отсутствие срока подписи или nonce — это НЕ «не проверено», а
    находка: в реальном мире незаданный срок = бессрочная подпись.
  · значения берутся из документа: подделай документ — подделай аудит.
    Это граница метода, она указана в disclaimere вердикта.

ИНЦИДЕНТЫ, на которых правила проверяются тестами (tests/test_infra.py).
Конфигурации в тестах — реконструкция ОПИСАННОГО ПУБЛИЧНО свойства
инцидента, а не полная копия; формулировки честности — в самих тестах:
  · Harmony Horizon, 06.2022, ~$100M — мультисиг 2-of-5: меньшинство
    извлекало средства;
  · Ronin, 03.2022, ~$625M — 5-of-9: маленький пул валидаторов, ключи
    сконцентрированы у нескольких операторов;
  · Multichain, 07.2023, ~$126M — скомпрометированы ключи админ-роли
    без таймлока;
  · Bybit (Safe), 02.2025, ~$1.46B — подписывали одно, исполнялось
    другое (рассинхрон домена/адреса — проверяемый симптом класса);
  · бессрочные подписи — публичного инцидента не привязываем: правило
    закрывает класс replay, в тестах синтетический конфиг.

ЧТО ЭТО НЕ ДЕЛАЕТ:
  · не ходит в сеть и не поднимает владельцев из цепи;
  · не проверяет, что ключи РЕАЛЬНО распределены (документ против
    реальности — вне скоупа);
  · не заменяет аудит мультисига и операционную безопасность ключей.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .scanner import SEVERITY_ORDER, Finding, Verdict

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_UPGRADEISH = re.compile(r"upgrade|admin|proxy|implementation|owner|guard"
                         r"|root|super", re.IGNORECASE)
_TTL_MS = 48 * 3600          # минимум таймлока для апгрейд-роли — 48 часов
_MAX_AGE_MS = 30 * 86400     # допустимый возраст подписи — 30 дней


class ConfigError(ValueError):
    """Вход не разобран: отказ проверки, а не находка и не «чисто»."""


# ---------------------------------------------------------------- пути

def _get(cfg: dict, path: str):
    """Взять значение по точечному пути. Возвращает (значение, найдено)."""
    cur = cfg
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None, False
    return cur, True


def _locate(raw: str, path: str) -> int:
    """Номер строки ключа из пути в исходном JSON. 1, если не нашли.

    Нужен, чтобы находка указывала на строку документа, а не на единицу:
    отчёт и SARIF читаются людьми, а им нужна точка в файле.
    """
    pos = 0
    idx = -1
    for part in path.split("."):
        idx = raw.find(f'"{part}"', pos)
        if idx < 0:
            break
        pos = idx + len(part) + 2
    if idx < 0:
        return 1
    return raw.count("\n", 0, idx) + 1


def _owners(cfg: dict) -> list[str]:
    """Список адресов владельцев: строки или объекты {address, operator}."""
    owners, ok = _get(cfg, "multisig.owners")
    if not ok or not isinstance(owners, list):
        return []
    out = []
    for e in owners:
        if isinstance(e, str):
            out.append(e.lower())
        elif isinstance(e, dict) and isinstance(e.get("address"), str):
            out.append(e["address"].lower())
    return out


def _is_int(v) -> bool:
    # bool — подкласс int в Python: true не бывает порогом подписей.
    return isinstance(v, int) and not isinstance(v, bool)


def _is_addr(v) -> bool:
    return isinstance(v, str) and bool(_ADDRESS.match(v))


# ------------------------------------------------------------ вспомогательное

# Сигнатура проверки: деталь находки (строка для excerpt) | None | UNVERIFIED.
UNVERIFIED = object()


def _parse_deadline(v):
    """Разобрать дедлайн: unix-время (int) или ISO-8601. None = не разобрано."""
    if _is_int(v):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    if isinstance(v, str):
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


# ----------------------------------------------------------------- правила

@dataclass(frozen=True)
class InfraRule:
    """Правило конфигурации. `requires` — пути без которых применять его
    нечестно: поля нет → правило в `unverified`, а не «чисто»."""

    key: str
    title: str
    severity: str
    why: str
    fix: str
    requires: tuple[str, ...]
    check: Callable[[dict], "str | None | object"]


def _domain_chain_id(cfg: dict):
    v, ok = _get(cfg, "domain.chainId")
    if not ok:
        return "domain.chainId отсутствует — подписи переносятся между цепями"
    if not _is_int(v) or v == 0:
        return f"domain.chainId = {v!r} — домен не привязан к конкретной сети"
    return None


def _domain_verifying_contract(cfg: dict):
    v, ok = _get(cfg, "domain.verifyingContract")
    if not ok:
        return "domain.verifyingContract отсутствует — подпись действует для любого контракта"
    if not _is_addr(v):
        return f"domain.verifyingContract = {v!r} — не адрес"
    return None


def _domain_mismatch(cfg: dict):
    dom = str(_get(cfg, "domain.verifyingContract")[0]).lower()
    ms = str(_get(cfg, "multisig.address")[0]).lower()
    if dom != ms:
        return (f"домен подписывает {dom}, исполняет {ms} — "
                f"подписывали одно, уходит другое")
    return None


def _domain_identifiers(cfg: dict):
    name, ok_name = _get(cfg, "domain.name")
    ver, ok_ver = _get(cfg, "domain.version")
    if not ok_name or not isinstance(name, str) or not name:
        return "domain.name отсутствует — домен не зафиксирован"
    if not ok_ver or not isinstance(ver, str) or not ver:
        return "domain.version отсутствует — версия домена не зафиксирована"
    return None


def _threshold_invalid(cfg: dict):
    th = _get(cfg, "multisig.threshold")[0]
    owners = _get(cfg, "multisig.owners")[0]
    if not _is_int(th) or th <= 0:
        return f"multisig.threshold = {th!r} — не положительное целое"
    if not isinstance(owners, list) or not owners:
        return "multisig.owners пуст — порог не на чем собрать"
    if th > len(owners):
        return f"multisig.threshold = {th} при {len(owners)} владельцах — мультисиг не соберётся никогда"
    return None


def _threshold_minority(cfg: dict):
    th = _get(cfg, "multisig.threshold")[0]
    owners = _owners(cfg)
    if not _is_int(th) or th <= 0 or len(owners) < 2:
        return None
    if th <= len(owners) // 2:
        return (f"multisig.threshold = {th} из {len(owners)} — меньшинство "
                f"владельцев может вывести средства")
    return None


def _threshold_single(cfg: dict):
    th = _get(cfg, "multisig.threshold")[0]
    if _is_int(th) and th == 1:
        return (f"multisig.threshold = 1 при {len(_owners(cfg))} владельцах — "
                f"по факту это одиночный ключ, а не мультисиг")
    return None


def _threshold_all_owners(cfg: dict):
    th = _get(cfg, "multisig.threshold")[0]
    owners = _owners(cfg)
    if _is_int(th) and owners and th == len(owners) and len(owners) >= 3:
        return (f"multisig.threshold = n-of-n ({th} из {len(owners)}) — "
                f"утрата одного ключа блокирует казну")
    return None


def _owners_duplicate(cfg: dict):
    owners = _owners(cfg)
    seen, dups = set(), set()
    for a in owners:
        (dups if a in seen else seen).add(a)
    if dups:
        return f"multisig.owners: дубли — {', '.join(sorted(dups))}"
    return None


def _role_overlap(cfg: dict):
    groups: dict[str, set[str]] = {"owners": set(_owners(cfg))}
    mods, ok = _get(cfg, "multisig.modules")
    if ok and isinstance(mods, list):
        groups["modules"] = {str(m).lower() for m in mods
                             if isinstance(m, str)}
    roles = _get(cfg, "roles")[0]
    for r in roles:
        if not isinstance(r, dict):
            continue
        keys = r.get("keys")
        name = r.get("name", "?")
        if isinstance(keys, list):
            groups[f"role {name}"] = {str(k).lower() for k in keys
                                      if isinstance(k, str)}
    where: dict[str, list[str]] = {}
    for gname, addrs in groups.items():
        for a in addrs:
            where.setdefault(a, []).append(gname)
    for addr, gs in where.items():
        if len(gs) >= 2:
            return f"{addr} одновременно в: {', '.join(gs)} — одна утечка = весь контроль"
    return None


def _role_single_key(cfg: dict):
    for r in _get(cfg, "roles")[0]:
        if not isinstance(r, dict):
            continue
        keys = r.get("keys")
        if isinstance(keys, list) and len(keys) == 1:
            tl = r.get("timelock_seconds")
            if not _is_int(tl) or tl <= 0:
                name = r.get("name", "?")
                return (f"роль «{name}»: один ключ и нет таймлока — "
                        f"скомпрометированный ключ действует мгновенно")
    return None


def _upgrade_timelock(cfg: dict):
    for r in _get(cfg, "roles")[0]:
        if not isinstance(r, dict):
            continue
        name = str(r.get("name", ""))
        if not _UPGRADEISH.search(name):
            continue
        tl = r.get("timelock_seconds")
        if tl is None:
            # Правило про таймлок: поле не описано — проверить нечего,
            # «нет таймлока» мы не утверждаем (это делает role-single-key).
            return UNVERIFIED
        if _is_int(tl) and tl < _TTL_MS:
            return (f"роль «{name}»: таймлок {tl}с меньше {_TTL_MS}с — "
                    f"на реакцию (отзыв, форк) нет окна")
    return None


def _owner_operator_concentration(cfg: dict):
    raw = _get(cfg, "multisig.owners")[0]
    th = _get(cfg, "multisig.threshold")[0]
    ops: dict[str, int] = {}
    for e in raw:
        if not isinstance(e, dict) or not isinstance(e.get("operator"), str):
            # Владельцы описаны без операторов — концентрацию проверить нечем.
            return UNVERIFIED
        ops[e["operator"].lower()] = ops.get(e["operator"].lower(), 0) + 1
    if _is_int(th) and ops:
        op, n = max(ops.items(), key=lambda kv: kv[1])
        if n >= th:
            return (f"оператор «{op}» держит {n} из {len(raw)} ключей при "
                    f"пороге {th} — один скомпрометированный оператор проходит порог")
    return None


def _signature_no_deadline(cfg: dict):
    sp = _get(cfg, "signature_policy")[0]
    if sp.get("deadline_required") is False:
        return "signature_policy.deadline_required = false — подпись бессрочна"
    age = sp.get("max_age_seconds")
    if not _is_int(age) or age <= 0:
        return (f"signature_policy.max_age_seconds = {age!r} — "
                f"срок подписи не задан, то есть не ограничен")
    return None


def _signature_age_long(cfg: dict):
    age = _get(cfg, "signature_policy.max_age_seconds")[0]
    if _is_int(age) and age > _MAX_AGE_MS:
        return (f"max_age_seconds = {age}с ({age // 86400} дней) — "
                f"подпись живёт дольше {_MAX_AGE_MS // 86400} дней")
    return None


def _signature_no_nonce(cfg: dict):
    sp = _get(cfg, "signature_policy")[0]
    if sp.get("nonce_required") is False:
        return "signature_policy.nonce_required = false — повтор подписи возможен"
    replay = sp.get("replay_protection")
    if replay in (None, "", "none"):
        return "signature_policy.replay_protection не задан — защиты от повтора нет"
    return None


def _signature_expired(cfg: dict):
    dl = _get(cfg, "signature_policy.deadline")[0]
    dt = _parse_deadline(dl)
    if dt is None:
        return UNVERIFIED
    if dt.timestamp() < time.time():
        return f"signature_policy.deadline = {dl!r} — подпись просрочена"
    return None


INFRA_RULES: tuple[InfraRule, ...] = (
    # ---- 1. домен мультисигна
    InfraRule(
        "domain-chain-id",
        "EIP-712 домен без chainId или с chainId = 0",
        "high",
        "Домен без привязки к сети позволяет перенести подпись в другую "
        "цепь: подписанное для одной сети исполняется в другой.",
        "Фиксировать chainId в домене подписи ( Safe: domain с chainId "
        "конкретной сети ), не 0 и не «auto».",
        ("domain",),
        _domain_chain_id,
    ),
    InfraRule(
        "domain-verifying-contract",
        "Домен подписи без verifyingContract",
        "high",
        "Без verifyingContract подпись формально годится для любого "
        "контракта: её можно перенаправить на другую цель.",
        "Фиксировать verifyingContract = адресу мультисигна в домене "
        "EIP-712.",
        ("domain",),
        _domain_verifying_contract,
    ),
    InfraRule(
        "domain-mismatch",
        "Домен подписи указывает на другой контракт, чем исполняющий мультисиг",
        "critical",
        "Подписчики считают объектом подписи один адрес, исполнение "
        "проходит на другом. Класс «подписывали одно — ушло другое»: "
        "симптом инцидента Bybit/Safe (02.2025).",
        "verifyingContract в домене обязан совпадать с адресом мультисигна, "
        "который исполняет транзакцию. Сверять при каждой смене домена.",
        ("domain.verifyingContract", "multisig.address"),
        _domain_mismatch,
    ),
    InfraRule(
        "domain-identifiers",
        "Домен подписи без name/version",
        "low",
        "Незафиксированные name/version делают домен неоднозначным: "
        "разные реализации подпишут по-разному и перепутают подписи.",
        "Фиксировать name и version домена (например Safe 1.3.0) явно.",
        ("domain",),
        _domain_identifiers,
    ),
    # ---- 2. thresholds
    InfraRule(
        "threshold-invalid",
        "Порог подписей не собирается",
        "critical",
        "Порог не число, не положителен или больше числа владельцев: "
        "транзакции не соберутся никогда или соберутся не так, как "
        "записано в документе.",
        "threshold — целое от 1 до числа владельцев, owners не пуст.",
        ("multisig.threshold", "multisig.owners"),
        _threshold_invalid,
    ),
    InfraRule(
        "threshold-minority",
        "Порог позволяет меньшинству вывести средства",
        "critical",
        "N-of-M, где N ≤ M/2: меньшинство владельцев (или один "
        "скомпрометированный узел с этой долей) проходит порог. "
        "Harmony Horizon, 06.2022, ~$100M: мультисиг 2-of-5.",
        "Порог — больше половины владельцев, с запасом на компрометацию "
        "одного-двух ключей.",
        ("multisig.threshold", "multisig.owners"),
        _threshold_minority,
    ),
    InfraRule(
        "threshold-single",
        "Порог = 1: мультисиг на бумаге, одиночный ключ по факту",
        "high",
        "При пороге 1 защита равна одному ключу, а число владельцев "
        "создаёт ложное чувство распределения.",
        "Порог ≥ 2 и не меньше большинства владельцев.",
        ("multisig.threshold",),
        _threshold_single,
    ),
    InfraRule(
        "threshold-all-owners",
        "Порог n-of-n без запаса на утерю ключа",
        "medium",
        "Все владельцы обязательны: утеря любого одного ключа "
        "безвозвратно блокирует казну (противоположная крайность — "
        "проблема доступности, а не кражи).",
        "Оставить запас: n-of-m, где m > n, либо резервный ключ-절차",
        ("multisig.threshold", "multisig.owners"),
        _threshold_all_owners,
    ),
    InfraRule(
        "owners-duplicate",
        "Один и тот же адрес дважды в списке владельцев",
        "critical",
        "Дубль раздувает число владельцев: порог «из 9» собирается "
        "фактически меньшей группой.",
        "Убрать дубли, оставить уникальные адреса.",
        ("multisig.owners",),
        _owners_duplicate,
    ),
    # ---- 3. разделение ролей
    InfraRule(
        "role-overlap",
        "Один адрес в нескольких привилегированных ролях",
        "critical",
        "Владелец, модуль и ключ роли в одном адресе: утечка одного "
        "ключа даёт весь набор прав одновременно — разделение ролей "
        "отсутствует.",
        "Развести адреса по ролям: апгрейд, вывод, пауза — разные ключи "
        "и разные операторы.",
        ("roles", "multisig.owners"),
        _role_overlap,
    ),
    InfraRule(
        "role-single-key",
        "Привилегированная роль на одном ключе без таймлока",
        "high",
        "Один ключ и нулевое окно реакции: скомпрометированный ключ "
        "действует мгновенно и необратимо. Multichain, 07.2023, "
        "~$126M: потеря ключей админ-роли без таймлока.",
        "Минимум два ключа в роли ИЛИ таймлок ≥ 48ч с мониторингом "
        "очереди.",
        ("roles",),
        _role_single_key,
    ),
    InfraRule(
        "upgrade-timelock",
        "Апгрейд-роль с таймлоком меньше 48 часов",
        "high",
        "Апгрейд без окна в 48 часов оставляет операторам нет времени "
        "заметить вредоносный апгрейд и отозвать ключи: инциденты "
        "категории «скомпрометирован апгрейд» закрываются только "
        "окном реакции.",
        "Таймлок ≥ 48ч на апгрейд/админ-роль, с уведомлениями по всей "
        "очереди. Поле не задано → правило помечено «не проверено».",
        ("roles",),
        _upgrade_timelock,
    ),
    InfraRule(
        "owner-operator-concentration",
        "Владельцы сконцентрированы у одного оператора",
        "critical",
        "Ключи распределены формально, но физически у одной "
        "организации: компрометация одного оператора проходит порог. "
        "Ronin, 03.2022, ~$625M: 5-of-9 на маленьком пуле валидаторов.",
        "Разнести операторов так, чтобы у одного оператора ключей было "
        "меньше порога. Поле operator не задано → правило «не проверено».",
        ("multisig.owners", "multisig.threshold"),
        _owner_operator_concentration,
    ),
    # ---- 4. сроки подписи
    InfraRule(
        "signature-no-deadline",
        "Подпись без срока действия",
        "high",
        "Незаданный срок = бессрочная подпись: утечка подписи остаётся "
        "действительной неограниченно долго, а не до истечения окна.",
        "deadline_required = true и max_age_seconds > 0 (сутки-двое для "
        "операционных подписей).",
        ("signature_policy",),
        _signature_no_deadline,
    ),
    InfraRule(
        "signature-age-long",
        "Слишком длинный срок жизни подписи",
        "medium",
        "Подпись, действующая неделями, переживает ротацию ключей и "
        "окно реагирования на инцидент.",
        "max_age_seconds ≤ 30 суток, для операционных подписей — часы.",
        ("signature_policy.max_age_seconds",),
        _signature_age_long,
    ),
    InfraRule(
        "signature-no-nonce",
        "Нет защиты от повтора подписи (nonce)",
        "high",
        "Без nonce или replay-защиты одна и та же подпись применима "
        "повторно: перехваченная подпись переиспользуется.",
        "nonce_required = true и явный replay_protection (nonce/seq).",
        ("signature_policy",),
        _signature_no_nonce,
    ),
    InfraRule(
        "signature-expired",
        "Просроченная подпись в конфигурации",
        "critical",
        "Дедлайн уже в прошлом: подпись не должна была быть принята. "
        "Если она в конфигурации — либо проверка срока не работает, "
        "либо исполняется заведомо недействительный документ.",
        "Обновить подпись до срока действия; проверять deadline на "
        "стороне приёма, а не только на стороне подписи.",
        ("signature_policy.deadline",),
        _signature_expired,
    ),
)


def infra_rules_manifest() -> list[dict]:
    """Манифест правил конфигурации — для `--rules` и SARIF."""
    return [
        {"key": r.key, "title": r.title, "severity": r.severity,
         "why": r.why, "fix": r.fix}
        for r in INFRA_RULES
    ]


# --------------------------------------------------------------- вердикт

@dataclass
class ConfigVerdict(Verdict):
    """Вердикт по конфигурации. `unverified` — правила, которым не хватило
    полей документа. Пока оно не пусто — вердикт не чист: «не смог
    проверить» ≠ «чисто»."""

    unverified: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.findings and not self.unverified

    def as_dict(self) -> dict:
        d = super().as_dict()
        d["unverified"] = list(self.unverified)
        d["disclaimer"] = (
            "Проверяется декларативный документ конфигурации, а не "
            "ончейн-состояние: значения берутся из того, что выписали вы. "
            "«Не проверено» (unverified) означает отсутствие полей и НЕ "
            "считается чистым результатом. Это не формальная верификация "
            "и не замена аудиту мультисига."
        )
        return d

    def summary(self) -> str:
        engine = f" · движок {self.engine.upper()}"
        if self.clean:
            return (f"CLEAN · риск {self.score()}/100 · "
                    f"{self.lines_checked} строк, {self.rules_run} правил{engine}")
        c = self.counts()
        parts = [f"{k}={v}" for k, v in c.items() if v]
        if self.findings:
            head = (f"{self.worst.upper()} · риск {self.score()}/100 · "
                    f"{len(self.findings)} находок ({', '.join(parts)})")
        else:
            head = (f"НЕ ПРОВЕРЕНО · риск {self.score()}/100 · "
                    f"0 находок (поля документа отсутствуют)")
        if self.unverified:
            head += f" · без полей: {len(self.unverified)}"
        return head + engine


# --------------------------------------------------------------- проверка

def check_config(raw: str) -> ConfigVerdict:
    """Разобрать JSON-документ конфигурации и проверить его.

    ConfigError — вход не разобран: вызывающая сторона отдаёт код 2.
    """
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"JSON не разобран: {exc}") from exc
    if not isinstance(cfg, dict):
        raise ConfigError("в корне нужен JSON-объект, а не "
                          f"{type(cfg).__name__}")
    return check(cfg, raw=raw)


def check(cfg: dict, *, raw: str | None = None) -> ConfigVerdict:
    """Проверить словарь конфигурации. `raw` — исходный текст для номеров
    строк; без него берётся каноничная сериализация."""
    raw = raw if raw is not None else json.dumps(cfg, ensure_ascii=False,
                                                 indent=2)
    findings: list[Finding] = []
    unverified: list[str] = []

    for rule in INFRA_RULES:
        missing = [p for p in rule.requires if not _get(cfg, p)[1]]
        if missing:
            unverified.append(f"{rule.key} — нет поля: {', '.join(missing)}")
            continue
        detail = rule.check(cfg)
        if detail is UNVERIFIED:
            unverified.append(f"{rule.key} — исходные данные не описаны в документе")
            continue
        if detail:
            findings.append(Finding(
                rule=rule.key, title=rule.title, severity=rule.severity,
                why=rule.why, fix=rule.fix,
                line=_locate(raw, rule.requires[0]),
                excerpt=str(detail)[:200],
            ))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line))
    return ConfigVerdict(
        findings=findings,
        lines_checked=len(raw.split("\n")),
        rules_run=len(INFRA_RULES),
        engine="config",
        unverified=unverified,
    )
