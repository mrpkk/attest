"""Бесплатный скан расходов агента без GitHub: почта + CSV (S6.5, 18.11.2026).

Зачем. Аудит за $500 начинается с «пришлите месяц логов». Требовать GitHub на
первом шаге — значит терять тех, кто ещё не готов ничего показывать: у человека
есть выгрузка из биллинга агента, и он хочет знать, что мы в ней увидим. Здесь
входная дверь дешевле: адрес, файл, одна кнопка.

Что делает модуль. Проверяет CSV **до** записи, кладёт заявку в `leads.jsonl`
(только метаданные: почта, хеш, число строк, колонки — не содержимое) и
сохраняет сам файл рядом с правами 0600: без файла разбор сделать нечем, а
хранить его в журнале заявок значит смешать персональные данные с метриками.

Граница доверия здесь — чужие байты и чужой адрес:
* размер ограничен 200 КБ до разбора (иначе один POST занимает диск);
* заголовок обязателен: строка данных, принятая за заголовок, даёт отчёт о
  колонках, которых нет, и человек получает бессмысленный ответ;
* содержимое не печатается в лог и не попадает в `leads.jsonl`.

`shortcut: нет лимита заявок на клиента — добавить, когда появится поток.`
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import secrets
import time
from pathlib import Path

#: Сколько байт CSV принимаем. Месяц расходов одного агента — это десятки
#: килобайт; 200 КБ с запасом, и при этом влезает в общий лимит тела запроса.
MAX_CSV_BYTES = 200 * 1024

#: Колонки, которые делают разбор дешёвым. Не обязательны: отчёт скажет,
#: чего не хватает, вместо того чтобы отказать на входе.
EXPECTED_COLUMNS = ("date", "amount", "asset", "payee", "tx_hash")

#: Значения, по которым видно, что первая строка — данные, а не заголовок.
_DATA_CELL = re.compile(r"^(-?\d+(\.\d+)?|\d{4}-\d{2}-\d{2}.*|0x[0-9a-fA-F]+)$")


class ScanError(ValueError):
    """Отказ до записи. Текст читает человек, поэтому он без кодов."""


def _norm(cell: str) -> str:
    """Заголовок к единому виду: `Tx Hash`, `tx-hash`, `TX_HASH` — одно и то же."""
    return " ".join(cell.strip().lower().replace("-", "_").split())


def _has_header(cells: list[str]) -> bool:
    """Есть ли в первой строке признак заголовка.

    Известное имя колонки — да. Иначе смотрим, не данные ли это: число, дата
    или хеш в первой строке означают, что заголовка нет и разбор будет врать.
    """
    if any(cell in EXPECTED_COLUMNS for cell in cells):
        return True
    return not any(_DATA_CELL.match(cell) for cell in cells if cell)


def parse_csv(raw: str) -> dict[str, object]:
    """Проверить CSV и вернуть только то, что нужно для записи и ответа."""
    if not isinstance(raw, str) or not raw.strip():
        raise ScanError("CSV is empty")
    encoded = raw.encode("utf-8")
    if len(encoded) > MAX_CSV_BYTES:
        raise ScanError(f"CSV is larger than {MAX_CSV_BYTES // 1024} KB")
    try:
        rows = list(csv.reader(io.StringIO(raw)))
    except csv.Error as exc:
        raise ScanError(f"CSV could not be parsed: {exc}") from exc
    rows = [row for row in rows if any(cell.strip() for cell in row)]
    if not rows:
        raise ScanError("CSV is empty")
    header = [_norm(cell) for cell in rows[0]]
    if not _has_header(header):
        raise ScanError(
            "the first row does not look like a header; expected column names such as "
            + ", ".join(EXPECTED_COLUMNS)
        )
    if len(rows) < 2:
        raise ScanError("CSV has a header but no rows")
    columns = [cell for cell in header if cell]
    missing = [name for name in EXPECTED_COLUMNS if name not in set(header)]
    return {
        "columns": columns,
        "missing": missing,
        "rows": len(rows) - 1,
        "csv_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def store(raw: str, meta: dict[str, object], leads_path: Path, scans_dir: Path) -> str:
    """Сохранить заявку: файл 0600 рядом, метаданные — строкой в `leads.jsonl`."""
    request_id = "fs_" + secrets.token_hex(8)
    scans_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(scans_dir, 0o700)
    path = scans_dir / f"{request_id}.csv"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(raw)
    record = {"ts": int(time.time()), "product": "free_scan", "request_id": request_id,
              **meta}
    leads_path.parent.mkdir(parents=True, exist_ok=True)
    with leads_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return request_id
