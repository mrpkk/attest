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
  channels               — какой источник привёл каждое обращение

Откуда берётся источник. Все каталоги, куда мы подаёмся, добавляют
параметр к ссылке. Мы читаем `?ref=` и заголовок `Referer`, потому что
часть каталогов параметр не поддерживает и ссылается как есть.

Что НЕ делается: не пишем IP, не пишем тело запроса, не строим профиль
клиента. Считаем события, а не людей.
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
    first_event: float = 0.0
    last_event: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _last_save: float = field(default=0.0, repr=False)

    # ---- запись -------------------------------------------------------

    def view(self, channel: str) -> None:
        with self._lock:
            self._bounded(self.views, channel)
            self._touch()
        self._save_if_due()

    def check(self, channel: str, paid: bool) -> None:
        key = f"{channel}:{'paid' if paid else 'free'}"
        with self._lock:
            self._bounded(self.checks, key)
            if paid:
                self._bounded(self.paid, channel)
            self._touch()
        # Проверок много, а ценность каждой события невелика — пишем с
        # троттлингом, иначе каждый вызов ударяет по диску.
        self._save_if_due()

    def payment(self, channel: str, atoms: int) -> None:
        with self._lock:
            self.revenue_atoms += max(0, atoms)
            self._bounded(self.paid, channel)
            self._touch()
        # Деньги сохраняем сразу и без троттлинга: потерянная на перезапуске
        # выручка — это не «неточная метрика», а потерянные деньги.
        self.save()

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
            return {
                "listing_views": dict(sorted(self.views.items())),
                "listing_views_total": sum(self.views.values()),
                "checks_total": free + paid,
                "checks_free": free,
                "checks_paid": paid,
                "successful_paid_actions": sum(self.paid.values()),
                "revenue_atoms": self.revenue_atoms,
                "revenue_usdc": f"{self.revenue_atoms / 1_000_000:.6f}",
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
        self.revenue_atoms = int(data.get("revenue_atoms") or 0)
        self.first_event = float(data.get("first_event") or 0)
        self.last_event = float(data.get("last_event") or 0)

    def save(self) -> None:
        with self._lock:
            self._last_save = time.time()
            payload = {
                "views": self.views, "checks": self.checks,
                "paid": self.paid, "revenue_atoms": self.revenue_atoms,
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


METRICS = Metrics()
METRICS.load()
