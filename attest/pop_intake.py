#!/usr/bin/env python3
"""Приём ZIP с фото для Proof of Place: архив → отчёт `pop/1` → файл на 24 часа.

Зачем модуль. `pop_build.build()` работает с папкой на диске, а покупатель
приходит из браузера с ZIP. Разница не косметическая: ZIP — это чужие байты,
которые распаковываются на нашем сервере. Здесь граница доверия и все проверки,
которые она требует:

* **zip-slip.** Имя внутри архива не путь, а заявление: `../../etc/passwd`
  распаковался бы поверх системы. Абсолютные пути, `..`, обратные слеши и
  симлинки отвергаются до записи, а путь дополнительно проверяется на
  принадлежность каталогу распаковки.
* **zip-bomb.** 25 МБ сжатого архива разворачиваются в гигабайты. Лимит на
  сумму распакованного (200 МБ) и на число файлов (200) — до чтения данных.
* **чужой файл.** Только JPEG, PNG и HEIC: расширение + настоящий тип по
  сигнатуре (для фото это сильнее заголовка Content-Type, который клиент
  присылает сам про себя).

Ключ подписи берётся из `signing.KEY_PATH`: отчёт подписывает сервис, а не
клиент — иначе подпись доказывала бы, что документ подписал сам себя.

Хранение: `data/pop/<report_id>/report.json`, 24 часа, без БД. Имя отчёта
генерирует `pop_build` (`pop_` + 16 hex), и при скачивании оно проверяется
регуляркой — значит подставить путь через URL нельзя.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from . import signing
from .pop_build import build

#: Лимит ZIP-файла. 25 МБ — это 30–60 фото с телефона; больше не нужно, чтобы
#: собрать отчёт по одному объекту, а каждый лишний мегабайт — время разбора.
MAX_ZIP_BYTES = 25 * 1024 * 1024
#: Сколько файлов внутри архива вообще может быть фото одного объекта.
MAX_FILES = 200
#: Сумма распакованных байт. Ограничивает zip-bomb: 25 МБ → 200 МБ максимум.
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
#: Сколько живёт готовый отчёт. Через сутки он удаляется, а не «лежит где-то».
REPORT_TTL_SECONDS = 24 * 3600

#: Каталог хранения. Вне репозитория по умолчанию не уходит: `data/` рядом
#: с кодом, чтобы бэкап и права были те же, что у самого сервиса.
POP_DATA = Path(os.environ.get(
    "ATTEST_POP_DATA",
    Path(__file__).resolve().parent.parent / "data" / "pop",
))

REPORT_ID_RE = re.compile(r"^pop_[0-9a-f]{16}$")

JPEG_MAGIC = b"\xff\xd8\xff"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
#: Бренды HEIF, которые пишут телефоны: HEIC (Apple), HEVC/MIF1 (Android).
HEIC_BRANDS = frozenset({b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx",
                         b"heif", b"mif1", b"msf1"})

#: Расширение → (приемлемые Content-Type, проверка сигнатуры).
ALLOWED = {
    ".jpg": ({"image/jpeg", "image/jpg", "image/pjpeg"}, JPEG_MAGIC),
    ".jpeg": ({"image/jpeg", "image/jpg", "image/pjpeg"}, JPEG_MAGIC),
    ".png": ({"image/png", "image/x-png"}, PNG_MAGIC),
    ".heic": ({"image/heic", "image/heif", "image/heic-sequence",
               "image/heif-sequence"}, b"ftyp"),
}

ZIP_TYPES = frozenset({"application/zip", "application/x-zip-compressed",
                       "application/octet-stream"})


class IntakeError(Exception):
    """Отказ с HTTP-статусом: клиенту нужно знать, что именно не так."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# --- multipart -------------------------------------------------------------

_BOUNDARY_RE = re.compile(r'boundary="?([^";,]+)"?', re.I)
_NAME_RE = re.compile(r'\bname="([^"]*)"', re.I)
_FILENAME_RE = re.compile(r'\bfilename="([^"]*)"', re.I)


def parse_multipart(body: bytes, content_type: str) -> dict[str, tuple[str, str, bytes]]:
    """Разобрать `multipart/form-data` в `имя → (filename, content_type, bytes)`.

    Свой разбор вместо `cgi.FieldStorage` (удалён в Python 3.13) и вместо
    зависимости ради двух полей. Граница по RFC 2046 не встречается в теле
    по построению, поэтому разделение по ней корректно.
    """
    if "multipart/form-data" not in (content_type or "").lower():
        raise IntakeError(400, "expected multipart/form-data with a ZIP and a claim")
    match = _BOUNDARY_RE.search(content_type)
    if not match:
        raise IntakeError(400, "multipart/form-data without a boundary")
    delimiter = b"--" + match.group(1).strip().encode("latin-1")

    fields: dict[str, tuple[str, str, bytes]] = {}
    for chunk in body.split(delimiter)[1:]:
        if chunk.startswith(b"--"):
            break  # закрывающая граница
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        head, separator, data = chunk.partition(b"\r\n\r\n")
        if not separator:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]

        text = head.decode("utf-8", "replace")
        name_match = _NAME_RE.search(text)
        if not name_match:
            continue
        filename_match = _FILENAME_RE.search(text)
        ctype = ""
        for line in text.split("\r\n"):
            if line.lower().startswith("content-type:"):
                ctype = line.split(":", 1)[1].strip().lower()
        fields[name_match.group(1)] = (
            filename_match.group(1) if filename_match else "",
            ctype,
            data,
        )
    if not fields:
        raise IntakeError(400, "the multipart body has no fields")
    return fields


# --- ZIP -------------------------------------------------------------------

def _safe_name(raw: str) -> str:
    """Имя внутри архива → безопасный относительный путь или отказ.

    Проверка до записи: после записи проверять поздно, файл уже лёг.
    """
    if not raw or raw.startswith("/") or "\\" in raw or re.match(r"^[A-Za-z]:", raw):
        raise IntakeError(400, f"unsafe path in the archive: {raw!r}")
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise IntakeError(400, f"unsafe path in the archive: {raw!r}")
    return "/".join(parts)


def _check_type(ext: str, blob: bytes, name: str) -> None:
    """Настоящий тип по сигнатуре. Расширение и байты обязаны совпадать."""
    if ext == ".heic":
        ok = (len(blob) >= 12 and blob[4:8] == b"ftyp"
              and blob[8:12] in HEIC_BRANDS)
    else:
        ok = blob.startswith(ALLOWED[ext][1])
    if not ok:
        raise IntakeError(
            400, f"{name}: the file content is not {ext.lstrip('.').upper()} "
                 f"(the extension and the bytes disagree)")


def extract_zip(data: bytes, dest: Path) -> list[str]:
    """Распаковать архив в `dest`, вернув имена файлов. Всё чужое — отказ."""
    if len(data) > MAX_ZIP_BYTES:
        raise IntakeError(413, f"the ZIP is larger than {MAX_ZIP_BYTES} bytes")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IntakeError(400, f"not a readable ZIP: {exc}") from exc

    with archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if not infos:
            raise IntakeError(400, "the ZIP contains no files")
        if len(infos) > MAX_FILES:
            raise IntakeError(
                400, f"the ZIP contains {len(infos)} files, the limit is {MAX_FILES}")
        total = sum(info.file_size for info in infos)
        if total > MAX_UNCOMPRESSED_BYTES:
            raise IntakeError(
                400, f"uncompressed size is {total} bytes, the limit is "
                     f"{MAX_UNCOMPRESSED_BYTES}")

        root = dest.resolve()
        names: list[str] = []
        seen: set[str] = set()
        for info in infos:
            if info.flag_bits & 0x1:
                raise IntakeError(400, f"{info.filename}: encrypted entries are not accepted")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise IntakeError(400, f"{info.filename}: symlinks are not accepted")
            name = _safe_name(info.filename)
            if name in seen:
                raise IntakeError(400, f"{name}: duplicate entry in the ZIP")
            seen.add(name)

            ext = Path(name).suffix.lower()
            if ext not in ALLOWED:
                raise IntakeError(
                    400, f"{name}: only JPEG, PNG and HEIC photos are accepted")
            blob = archive.read(info)
            _check_type(ext, blob, name)

            target = (root / name).resolve()
            if root not in target.parents:
                raise IntakeError(400, f"unsafe path in the archive: {name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
            names.append(name)
    return names


# --- хранение --------------------------------------------------------------

def purge(data_dir: Path | None = None, *, now: float | None = None) -> int:
    """Удалить отчёты старше суток. Возвращает число удалённых.

    Удаляются только каталоги с нашим форматом имени: чужое в `data/pop`
    не наше, и сносить его по расписанию нельзя.
    """
    root = Path(data_dir or POP_DATA)
    if not root.is_dir():
        return 0
    moment = time.time() if now is None else now
    removed = 0
    for entry in root.iterdir():
        if not entry.is_dir() or not REPORT_ID_RE.fullmatch(entry.name):
            continue
        try:
            age = moment - entry.stat().st_mtime
        except OSError:
            continue
        if age > REPORT_TTL_SECONDS:
            shutil.rmtree(entry, ignore_errors=True)
            removed += 1
    return removed


def report_path(report_id: str, data_dir: Path | None = None,
                *, now: float | None = None) -> Path:
    """Путь к готовому отчёту или отказ: 404 — нет, 410 — истёк срок."""
    if not REPORT_ID_RE.fullmatch(report_id or ""):
        raise IntakeError(404, "no such report")
    path = Path(data_dir or POP_DATA) / report_id / "report.json"
    if not path.is_file():
        raise IntakeError(404, "no such report")
    moment = time.time() if now is None else now
    if moment - path.stat().st_mtime > REPORT_TTL_SECONDS:
        shutil.rmtree(path.parent, ignore_errors=True)
        raise IntakeError(410, "the report has expired: reports are kept for 24 hours")
    return path


# --- приём -----------------------------------------------------------------

def intake(raw_body: bytes, content_type: str, *, key_path: Path | None = None,
           data_dir: Path | None = None, now: float | None = None) -> dict[str, Any]:
    """ZIP + заявка → подписанный отчёт, сохранённый на 24 часа.

    Возвращает ответ API: id, вердикт, ссылку на скачивание и сам отчёт —
    чтобы страница показала вердикт без второго запроса.
    """
    fields = parse_multipart(raw_body, content_type)
    upload = fields.get("zip") or fields.get("photos") or fields.get("file")
    if upload is None:
        raise IntakeError(400, 'field "zip" with the archive is required')
    filename, declared_type, blob = upload
    if filename and not filename.lower().endswith(".zip"):
        raise IntakeError(400, "upload the photos as a .zip archive")
    if declared_type and declared_type not in ZIP_TYPES:
        raise IntakeError(400, f"the upload is not a ZIP: {declared_type}")

    claim_field = fields.get("claim")
    if claim_field is None:
        raise IntakeError(400, 'field "claim" with the JSON request is required')
    try:
        claim = json.loads(claim_field[2].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeError(400, f"the claim is not valid JSON: {exc}") from exc
    if not isinstance(claim, dict):
        raise IntakeError(400, "the claim must be a JSON object")

    root = Path(data_dir or POP_DATA)
    root.mkdir(parents=True, exist_ok=True)
    purge(root, now=now)

    moment = time.time() if now is None else now
    with tempfile.TemporaryDirectory(dir=root, prefix="upload_") as temporary:
        photos = Path(temporary) / "photos"
        photos.mkdir()
        names = extract_zip(blob, photos)
        try:
            report = build(photos, claim, Path(key_path or signing.KEY_PATH))
        except ValueError as exc:
            raise IntakeError(400, str(exc)) from exc
        except FileNotFoundError as exc:
            raise IntakeError(503, f"signing is not configured: {exc}") from exc

    report_id = str(report.get("report_id") or "")
    if not REPORT_ID_RE.fullmatch(report_id):
        raise IntakeError(500, "the report was built without a usable id")

    folder = root / report_id
    folder.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    stored = folder / "report.json"
    stored.write_text(payload, encoding="utf-8")
    os.utime(stored, (moment, moment))  # срок считается от сборки, а не от чтения

    return {
        "ok": True,
        "report_id": report_id,
        "verdict": report["verdict"],
        "files": len(names),
        "download_url": f"/api/proof-of-place/report/{report_id}",
        "expires_in_hours": REPORT_TTL_SECONDS // 3600,
        "report": report,
    }
