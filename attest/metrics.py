#!/usr/bin/env python3
"""Метрики: откуда пришёл клиент и сколько денег принёс.

Зачем это нужно раньше остального. Мы уже получили 130 посетителей витрины
и ноль клиентов — и не смогли ответить, почему: не было ни одной цифры,
которая отличает «пришли и ушли» от «пришли и заплатили». Подача в каталог
без счётчиков — это трата времени вслепую: сработало или нет, узнать нечем.

Что считается:

  listing_views          — показы страницы без обращения к API
  checks_total           — все обращения к проверке
  checks_free / checks_paid — чем закончилось: бесплатным тарифом или оплатой
  paid_actions           — успешные оплаты: единственная метрика денег
  revenue_atoms          — сколько атомов USDC получено
  repeat_usage_7d        — кошельки, заплатившие дважды в пределах недели
  channels               — какой источник привёл каждое обращение

Откуда берётся источник. Все каталоги, куда подаёмся, добавляют
параметр к ссылке. Мы читаем `?ref=` и заголовок `Referer`, потому что
часть каталогов параметр не поддерживает и ссылается как есть.

Что НЕ делается: не пишем IP, не пишем тело запроса. Единственное, что
связано с клиентом, — адрес кошелька из подписанной авторизации: для него
хранятся только время первой и последней оплаты и счётчик. Этого хватает,
чтобы отличить возврат от случайного захода, и мало для профилирования.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

STATE_PATH = Path(os.environ.get(
    "ATTEST_METRICS_PATH",
    str(Path.home() / ".local/share/attest/metrics.json")))

# Каталоги, куда подаёмся. Ссылку с таким `ref` даём в листинге — тогда
# видно, какой канал привёл человека, а не только что «кто-то пришёл».
# Как часто счётчики сбрасываются на диск. Проверки идут пачками, платежи
# сохраняются всегда и независимо от этого числа.
SAVE_THROTTLE_SEC = 2.0

# Сколько кошельков-плательщиков помним для repeat_usage_7d. Потолок — как
# у каналов: адрес приходит от клиента, память не должна расти бесконечно.
MAX_PAYERS = 512

# Окно «вернулся ли клиент»: повторная оплата не позже недели после первой.
REPEAT_WINDOW_SEC = 7 * 86400

# Потраченные nonce платежей. Раньше жили только в памяти обработчика:
# перезапуск сервиса возвращал их к жизни, и оплаченный платёж можно было
# предъявить второй раз. Подкласс set — потому что payment.py зовёт .add()
# и проверяет вхождение; менять этот интерфейс ради персистентности не нужно.
NONCES_PATH = STATE_PATH.with_name("nonces.json")


class SpentNonces(set):
    """Множество потраченных nonce, переживающее перезапуск."""

    SAVE_THROTTLE_SEC = 1.0

    def __init__(self, path: Path | None = None) -> None:
        super().__init__()
        self._path = path
        self._last_save = 0.0
        self._load()

    def _load(self) -> None:
        if not self._path:
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(data, list):
            super().update(str(n) for n in data)
        elif isinstance(data, dict) and isinstance(data.get("seen"), list):
            super().update(str(n) for n in data["seen"])

    def _save(self, force: bool = False) -> None:
        if not self._path:
            return
        now = time.time()
        if not force and now - self._last_save < self.SAVE_THROTTLE_SEC:
            return
        self._last_save = now
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(sorted(self), ensure_ascii=False),
                           encoding="utf-8")
            tmp.replace(self._path)
        except OSError as exc:
            print(f"attest: потраченные nonce не сохранены: {exc}")

    def add(self, nonce: str) -> None:      # type: ignore[override]
        was_new = nonce not in self
        super().add(nonce)
        if was_new:
            self._save()

    def update(self, *args, **kwargs) -> None:   # type: ignore[override]
        super().update(*args, **kwargs)
        self._save()


_SPENT: SpentNonces | None = None


def spent_nonces() -> SpentNonces:
    """Потраченные nonce — один объект на процесс, читается с диска однажды."""
    global _SPENT
    if _SPENT is None:
        _SPENT = SpentNonces(NONCES_PATH)
    return _SPENT

# Потолок на число каналов: `ref` приходит от клиента.
MAX_CHANNELS = 512

KNOWN_CHANNELS = (
    "apify", "apilayer", "dify", "rapidapi", "glama", "smithery",
    "mcpso", "businessmcp", "pulsemcp", "windmill", "storebot",
    "producthunt", "laborx", "devto", "hn", "github",
)


@dataclass
class Metrics:
    """Счётчики событий. Потокобезопасны: сервис многопоточный."""

    views: dict[str, int] = field(default_factory=dict)
    checks: dict[str, int] = field(default_factory=dict)
    paid: dict[str, int] = field(default_factory=dict)
    revenue_atoms: int = 0
    # Заявки на пакет раннего доступа (лид-магнит). Считаем, но не храним
    # почту в метриках — она лежит отдельно, в leads.jsonl.
    leads: int = 0
    # Кошелёк → [первая оплата, последняя оплата, сколько всего]. Только
    # время и счётчик: этого хватает для repeat_usage_7d и мало для профиля.
    payers: dict[str, list] = field(default_factory=dict)
    first_event: float = 0.0
    last_event: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    # Тесты бьют по тому же глобальному счётчику, что и боевой сервис, и
    # раньше накручивали «direct» (298 из 304 «проверок» 20.10.2026).
    # ATTEST_METRICS=0 отключает запись; чтение остаётся.
    enabled: bool = True
    _last_save: float = field(default=0.0, repr=False)

    # ---- запись -------------------------------------------------------

    def view(self, channel: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._bounded(self.views, channel)
            self._touch()
        self._save_if_due()

    def check(self, channel: str, paid: bool) -> None:
        if not self.enabled:
            return
        key = f"{channel}:{'paid' if paid else 'free'}"
        with self._lock:
            self._bounded(self.checks, key)
            if paid:
                self._bounded(self.paid, channel)
            self._touch()
        # Проверок много, а ценность каждой события невелика — пишем с
        # троттлингом, иначе каждый вызов ударяет по диску.
        self._save_if_due()

    def lead(self) -> None:
        """Одна заявка на пакет раннего доступа."""
        if not self.enabled:
            return
        with self._lock:
            self.leads += 1
            self._touch()
        self.save()

    def payment(self, channel: str, atoms: int, payer: str | None = None) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.revenue_atoms += max(0, atoms)
            self._bounded(self.paid, channel)
            if payer:
                self._note_payer(str(payer))
            self._touch()
        # Деньги сохраняем сразу и без троттлинга: потерянная на перезапуске
        # выручка — это не «неточная метрика», а потерянные деньги.
        self.save()

    def _note_payer(self, payer: str) -> None:
        """Запомнить оплату кошелька: [первая, последняя, сколько раз].

        pop+вставка = «видели только что»: вытесняется самый давний, как и
        у каналов. Без адреса повтор не отличить от нового клиента — а это
        единственный вопрос, на который отвечает repeat_usage_7d.
        """
        now = time.time()
        key = payer[:64]
        row = self.payers.pop(key, None)
        if row is None:
            self.payers[key] = [now, now, 1]
        else:
            row[1] = now
            row[2] = int(row[2]) + 1
            self.payers[key] = row
        if len(self.payers) > MAX_PAYERS:
            self.payers.pop(next(iter(self.payers)), None)

    def _touch(self) -> None:
        now = time.time()
        if not self.first_event:
            self.first_event = now
        self.last_event = now

    def _bounded(self, table: dict[str, int], channel: str) -> None:
        """Счётчик канала с потолком по числу ключей.

        `ref` приходит от клиента: без ограничения тысяча запросов с
        разными `ref` превращают словарь в память на вырост. Старые каналы
        вытесняются, а не игнорируются — иначе метрика замрёт молча.
        """
        # Перенос в конец = «только что видели». Вытесняем самый давний,
        # а не самый редкий: иначе живой канал с малым счётчиком исчезнет
        # раньше, чем заведомый мусор.
        previous = table.pop(channel, 0)
        table[channel] = previous + 1
        if len(table) > MAX_CHANNELS:
            table.pop(next(iter(table)), None)

    def _save_if_due(self) -> None:
        with self._lock:
            now = time.time()
            if now - self._last_save < SAVE_THROTTLE_SEC:
                return
            self._last_save = now
        self.save()

    # ---- чтение -------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            free = sum(v for k, v in self.checks.items() if k.endswith(":free"))
            paid = sum(v for k, v in self.checks.items() if k.endswith(":paid"))
            repeat_usage_7d = sum(
                1 for first, last, n in self.payers.values()
                if int(n) >= 2 and (float(last) - float(first)) <= REPEAT_WINDOW_SEC)
            return {
                "listing_views": dict(sorted(self.views.items())),
                "listing_views_total": sum(self.views.values()),
                "checks_total": free + paid,
                "checks_free": free,
                "checks_paid": paid,
                "successful_paid_actions": sum(self.paid.values()),
                "revenue_atoms": self.revenue_atoms,
                "revenue_usdc": f"{self.revenue_atoms / 1_000_000:.6f}",
                "repeat_usage_7d": repeat_usage_7d,
                "unique_payers": len(self.payers),
                "leads_total": self.leads,
                "by_channel": dict(sorted(self.paid.items())),
                "since": self.first_event,
                "last_event": self.last_event,
            }

    # ---- хранение -----------------------------------------------------

    def load(self) -> None:
        """Поднять счётчики с диска.

        Сервис перезапускается при каждой правке — если счётчики живут
        только в памяти, история обнуляется и метрика врёт в меньшую
        сторону ровно в тот момент, когда она нужна.
        """
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        self.views = {str(k): int(v) for k, v in (data.get("views") or {}).items()}
        self.checks = {str(k): int(v) for k, v in (data.get("checks") or {}).items()}
        self.paid = {str(k): int(v) for k, v in (data.get("paid") or {}).items()}
        self.payers = {
            str(k): [float(v[0]), float(v[1]), int(v[2])]
            for k, v in (data.get("payers") or {}).items()
            if isinstance(v, (list, tuple)) and len(v) == 3}
        self.revenue_atoms = int(data.get("revenue_atoms") or 0)
        self.leads = int(data.get("leads") or 0)
        self.first_event = float(data.get("first_event") or 0)
        self.last_event = float(data.get("last_event") or 0)

    def save(self) -> None:
        with self._lock:
            self._last_save = time.time()
            payload = {
                "views": self.views, "checks": self.checks,
                "paid": self.paid, "revenue_atoms": self.revenue_atoms,
                "payers": self.payers, "leads": self.leads,
                "first_event": self.first_event, "last_event": self.last_event,
            }
        try:
            STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = STATE_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False),
                           encoding="utf-8")
            tmp.replace(STATE_PATH)
        except OSError as exc:
            print(f"attest: метрики не сохранены: {exc}")


def channel_of(query: str, referer: str | None) -> str:
    """Определить источник обращения.

    Сначала `ref` из ссылки: его мы контролируем в листинге. Потом
    Referer — часть каталогов параметр не поддерживает. Если ни того,
    ни другого — `direct`, и это тоже полезная цифра: значит человек
    пришёл сам, а не из каталога.
    """
    try:
        params = parse_qs(urlparse(query).query)
    except ValueError:
        params = {}
    ref = (params.get("ref") or [""])[0].strip().lower()
    if ref:
        return ref[:32]

    if referer:
        try:
            host = urlparse(referer).netloc.lower().removeprefix("www.")
        except ValueError:
            host = ""
        for known in KNOWN_CHANNELS:
            if known in host:
                return known
        if host:
            return host[:32]
    return "direct"


METRICS = Metrics(enabled=os.environ.get("ATTEST_METRICS", "1") != "0")
METRICS.load()
