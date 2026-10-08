"""Доказуемость состояния агента: журнал, replay и подпись снимка.

Зачем это в том же пакете, а не отдельным продуктом: механизм один и тот же,
что в `attest` — «проверь, прежде чем поверишь». Объект другой (не артефакт
и не код, а состояние агента), но доказательство устроено так же: подпись
источника плюс проверка, что с момента подписи ничего не изменилось
незаметно. Отдельный продукт был бы тем же кодом под другим именем.

Что даёт:
    log     — append-only журнал решений агента
    replay  — воспроизведение состояния из журнала
    snapshot— подписанный снимок состояния в момент T
    verify  — проверка, что состояние не искажено

Чего НЕ даёт (важно не перепутать):
    * Это не ZK: проверяющий видит журнал целиком.
    * Это не доказательство корректности решений: replay доказывает, что
      состояние получено из этого журнала, а не что решения были верными.
    * Подпись защищает от подмены после подписания, но не от подписи
      поддельного состояния владельцем ключа. Это доверие к держателю
      ключа, и скрыть его нельзя.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

# --------------------------------------------------------------- канонизация

def canonical(value: Any) -> bytes:
    """Байтовое представление, однозначное для любого значения.

    Порядок ключей фиксирован, разделители без пробелов — иначе одно и то
    же состояние даст разные хэши и подпись перестанет проверяться.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


# ------------------------------------------------------------------- журнал

class JournalError(ValueError):
    """Журнал нарушен. Это отказ проверки, а не пустой результат."""


@dataclass(frozen=True)
class Event:
    """Одно решение агента. `seq` жёсткий: порядок часть состояния."""
    seq: int
    kind: str
    payload: Any
    at: float

    def as_dict(self) -> dict:
        return {"seq": self.seq, "kind": self.kind,
                "payload": self.payload, "at": self.at}


@dataclass
class StateLog:
    """Append-only журнал. Изменить записанное нельзя, только дописать."""
    events: list[Event] = field(default_factory=list)
    agent_id: str = ""

    def append(self, kind: str, payload: Any, *, at: float | None = None) -> Event:
        if not kind or not isinstance(kind, str):
            raise JournalError(f"kind должен быть непустой строкой, получено {kind!r}")
        ev = Event(seq=len(self.events), kind=kind, payload=payload,
                   at=at if at is not None else time.time())
        self.events.append(ev)
        return ev

    def head(self) -> str:
        """Хэш цепочки. Меняется при любой правке любого события."""
        h = b"\x00" * 32
        for ev in self.events:
            h = hashlib.sha256(h + canonical(ev.as_dict())).digest()
        return "sha256:" + h.hex()

    def to_list(self) -> list[dict]:
        """Копия журнала для выгрузки.

        Именно копия: если отдать внутренние словари, любой вызывающий
        код изменит журнал в обход append() и подписи — и проверка
        перестанет что-либо значить. Найдено тестом на подделку.
        """
        return copy.deepcopy([ev.as_dict() for ev in self.events])

    @classmethod
    def from_list(cls, items: list[dict], *, agent_id: str = "") -> "StateLog":
        """Разобрать журнал обратно. Порядок по seq, а не по порядку
        в списке: переставленные события — это попытка подмены."""
        if not isinstance(items, list):
            raise JournalError(f"ожидался список событий, получено {type(items).__name__}")
        events: list[Event] = []
        for i, raw in enumerate(items):
            if not isinstance(raw, dict):
                raise JournalError(f"событие #{i}: ожидался объект, получено {type(raw).__name__}")
            for field_name in ("seq", "kind", "payload", "at"):
                if field_name not in raw:
                    raise JournalError(f"событие #{i}: нет поля «{field_name}»")
            events.append(Event(seq=raw["seq"], kind=raw["kind"],
                                payload=raw["payload"], at=raw["at"]))
        for i, ev in enumerate(events):
            if ev.seq != i:
                raise JournalError(
                    f"нарушен порядок журнала: на позиции {i} событие seq={ev.seq}. "
                    f"События обязаны идти по возрастанию seq — иначе это не тот "
                    f"журнал, который был подписан")
        return cls(events=events, agent_id=agent_id)

    def check_chain(self) -> tuple[bool, str]:
        """Целостность нумерации. Не криптография — просто порядок."""
        for i, ev in enumerate(self.events):
            if ev.seq != i:
                return False, f"seq={ev.seq} на позиции {i}"
        return True, "ok"


# -------------------------------------------------------------------- replay

def replay(log: StateLog, *,
           reduce: Callable[[dict, Any], Any],
           initial: Any = None) -> Any:
    """Воспроизвести состояние из журнала.

    `reduce(state, event_dict) -> state`. Чистая функция от состояния и
    события: иначе replay даст не то, что было, и проверка станет
    фикцией. Мутация состояния внутри reduce делает результат
    зависимым от порядка вызовов — это ломает проверку.
    """
    ok, why = log.check_chain()
    if not ok:
        raise JournalError(f"журнал не цел: {why}")
    state = initial
    for ev in log.events:
        state = reduce(state, ev.as_dict())
    return state


# ------------------------------------------------------------------ снимок

@dataclass
class Snapshot:
    """Подписанный снимок состояния в момент T."""
    snapshot_id: str
    agent_id: str
    seq: int
    state: Any
    state_digest: str
    log_head: str
    at: float
    mac: str = ""

    def as_dict(self) -> dict:
        return {"snapshot_id": self.snapshot_id, "agent_id": self.agent_id,
                "seq": self.seq, "state": self.state,
                "state_digest": self.state_digest,
                "log_head": self.log_head, "at": self.at, "mac": self.mac}


def _key_from_env() -> bytes:
    import os
    key = os.getenv("ATTEST_STATE_KEY", "")
    if not key:
        raise JournalError(
            "ATTEST_STATE_KEY не задан: без ключа снимок нельзя подписать. "
            "Пустой ключ означал бы подпись, которую подделает кто угодно.")
    return key.encode("utf-8")


def sign_snapshot(log: StateLog, state: Any, *, key: bytes | None = None,
                  at: float | None = None) -> Snapshot:
    key = key if key is not None else _key_from_env()
    state_digest = digest(state)
    snap = Snapshot(
        snapshot_id= uuid.uuid4().hex,
        agent_id= log.agent_id,
        seq= len(log.events),
        state= state,
        state_digest= state_digest,
        log_head= log.head(),
        at= at if at is not None else time.time(),
    )
    snap.mac = hmac.new(key, _mac_payload(snap), hashlib.sha256).hexdigest()
    return snap


def _mac_payload(snap: Snapshot) -> bytes:
    """Подписываются только поля, которые нельзя поменять на месте.

    `state` не подписывается: большой payload в MAC не нужен, его заменяет
    `state_digest`. `seq` и `log_head` подписываются обязательно — иначе
    можно предъявить снимок от другого момента времени.
    """
    return canonical({
        "snapshot_id": snap.snapshot_id,
        "agent_id": snap.agent_id,
        "seq": snap.seq,
        "state_digest": snap.state_digest,
        "log_head": snap.log_head,
        "at": snap.at,
    })


def verify_snapshot(snap: Snapshot, *, key: bytes | None = None) -> bool:
    key = key if key is not None else _key_from_env()
    expected = hmac.new(key, _mac_payload(snap), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, snap.mac)


# ------------------------------------------------- полная проверка состояния

@dataclass
class StateVerdict:
    """Итог проверки. `ok` означает «журнал даёт этот снимок», а не
    «агент поступил правильно»."""
    ok: bool
    reasons: list[str] = field(default_factory=list)
    replayed_state: Any = None
    snapshot: Snapshot | None = None

    def as_dict(self) -> dict:
        return {"ok": self.ok, "reasons": list(self.reasons),
                "replayed_state": self.replayed_state,
                "snapshot": self.snapshot.as_dict() if self.snapshot else None}


def verify_state(log: StateLog, snap: Snapshot, *,
                 reduce: Callable[[dict, Any], Any],
                 initial: Any = None,
                 key: bytes | None = None) -> StateVerdict:
    """Проверить, что состояние снимка получается из журнала.

    Четыре независимые проверки, каждая может провалиться сама:
    подпись, порядок журнала, соответствие seq, соответствие состояния.
    """
    reasons: list[str] = []

    if not verify_snapshot(snap, key=key):
        reasons.append("подпись снимка не сходится — снимок изменён или подписан чужим ключом")

    ok_chain, why = log.check_chain()
    if not ok_chain:
        reasons.append(f"журнал не цел: {why}")

    if len(log.events) != snap.seq:
        reasons.append(f"в журнале {len(log.events)} событий, а снимок сделан на {snap.seq}")

    if log.head() != snap.log_head:
        reasons.append("хэш журнала не совпадает со снимком: журнал дописан или переписан")

    replayed = None
    if ok_chain:
        try:
            replayed = replay(log, reduce=reduce, initial=initial)
        except JournalError as exc:
            reasons.append(f"replay невозможен: {exc}")
        else:
            if digest(replayed) != snap.state_digest:
                reasons.append("состояние из replay не равно состоянию снимка")

    return StateVerdict(ok=not reasons, reasons=reasons,
                        replayed_state=replayed, snapshot=snap)