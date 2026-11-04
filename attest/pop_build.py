#!/usr/bin/env python3
"""Proof of Place: сборка отчёта `pop/1` из фотографий клиента и `claim.json`.

    python -m attest.pop_build --photos DIR --claim claim.json \
        --key private.hex --out report.json

Путь целиком: фото клиента → хеши → сверка с заявкой → подписанный отчёт,
который проверяется командой `python -m attest.pop_verify report.json --key`.

Что делает:

1. **content** — sha256 и размер каждого файла в папке; EXIF читается, если он
   есть, и не выдумывается, если его нет.
2. **position** — координаты из EXIF GPS и время съёмки `DateTimeOriginal`
   сверяются с заявленными в `claim.json`; расхождение пишется с дельтой в
   метрах и минутах, а не словами «не совпало».
3. **independent** — независимая съёмка (спутник, партнёр). Если её не было,
   слой прямо говорит `not_available`. Изобретать источник нельзя: отчёт, где
   независимый слой нарисован, хуже отчёта без него.
4. **immutability** — цепочка `prev_hash` → `hash` из `pop.seal()`, подпись
   Ed25519 из `pop.sign()`.

Чего не делает: не доказывает право собственности, не проверяет, что GPS не
подделан, и не считает, что `confirmed` означает «всё правда». `confirmed`
разрешён только когда сошлись все четыре слоя, включая независимый.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from PIL import Image

from .pop import sign
from .signing import public_key as _public_key

# Допуски. Не «на глаз», а из физики заявки:
#
# * **500 м по координатам.** Экран телефона даёт 5–20 м, но заявленная точка —
#   это обычно центр участка, а не место, где стоял фотограф. Участок 40 га
#   имеет сторону ~630 м, поэтому «та же точка» честно расходится на сотни
#   метров. 500 м пропускает сдвиг внутри участка и ловит переезд на другой
#   объект: два разных квартала или два разных поля так не совпадут.
# * **2 часа по времени.** `DateTimeOriginal` не несёт зоны, а часы камеры не
#   синхронизированы: отставание на час-два — обычное дело, смена дня — уже
#   другой объект. Двое суток съёмки в один допуск не влезают намеренно.
COORD_TOLERANCE_M = 500
TIME_TOLERANCE_MIN = 120

#: Точность GPS, если камера её не сообщила (тег GPSHPositioningError пуст).
#: Не измерение, а допущение — оно уходит в `limits` отчёта.
GPS_ASSUMED_ACCURACY_M = 10

IMAGE_SUFFIXES = frozenset({".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp"})

GPS_IFD = 0x8825
EXIF_IFD = 0x8769
TAG_MAKE, TAG_MODEL = 271, 272
TAG_DATETIME_ORIGINAL = 36867
GPS_LAT_REF, GPS_LAT, GPS_LON_REF, GPS_LON, GPS_ACCURACY = 1, 2, 3, 4, 31

LIMITS = (
    "GPS coordinates in EXIF can be spoofed: a camera, an app or a file editor "
    "can write any position; they are not proof of place",
    "sha256 proves the file did not change after hashing, not where it was taken",
    "EXIF DateTimeOriginal carries no timezone: it is compared as wall-clock time",
)

NOT_CHECKED = ("ownership", "interior", "the site outside the frame")


# --- файлы и EXIF ----------------------------------------------------------


def _files(root: Path) -> list[Path]:
    """Файлы папки без служебных (`.DS_Store`), в устойчивом порядке."""
    if not root.is_dir():
        raise ValueError(f"photos: not a directory: {root}")
    found = [p for p in root.rglob("*")
             if p.is_file() and not p.name.startswith(".")]
    if not found:
        raise ValueError(f"photos: no files in {root}")
    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def _degrees(value: Any, ref: Any) -> float | None:
    """Градусы из EXIF-тройки (градусы, минуты, секунды) и ссылки N/S/E/W."""
    if value is None:
        return None
    try:
        parts = [float(part) for part in value]
    except (TypeError, ValueError):
        return None
    if len(parts) == 2:
        parts.append(0.0)
    if len(parts) != 3:
        return None
    number = parts[0] + parts[1] / 60 + parts[2] / 3600
    if isinstance(ref, str) and ref.strip().upper() in {"S", "W"}:
        number = -number
    return number


def _exif_time(value: Any) -> datetime | None:
    try:
        return datetime.strptime(str(value).strip(), "%Y:%m:%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def read_exif(path: Path) -> dict[str, Any]:
    """GPS, время съёмки и камера из файла. Пустой словарь — EXIF нет.

    Чужой файл — граница доверия: повреждённый EXIF не должен ломать сборку
    отчёта, он должен означать «данных нет».
    """
    if path.suffix.lower() not in IMAGE_SUFFIXES:
        return {}
    try:
        with Image.open(path) as image:
            exif = image.getexif()
            gps = exif.get_ifd(GPS_IFD)
            sub = exif.get_ifd(EXIF_IFD)
            make, model = exif.get(TAG_MAKE), exif.get(TAG_MODEL)
    except Exception:  # noqa: BLE001 - битый EXIF = нет EXIF, а не падение
        return {}

    out: dict[str, Any] = {}
    lat = _degrees(gps.get(GPS_LAT), gps.get(GPS_LAT_REF))
    lon = _degrees(gps.get(GPS_LON), gps.get(GPS_LON_REF))
    if lat is not None and lon is not None and -90 <= lat <= 90 \
            and -180 <= lon <= 180:
        out["lat"], out["lon"] = lat, lon
        accuracy = gps.get(GPS_ACCURACY)
        if isinstance(accuracy, (int, float)) and not isinstance(accuracy, bool) \
                and accuracy >= 0:
            out["accuracy_m"] = int(round(accuracy))
    captured = _exif_time(sub.get(TAG_DATETIME_ORIGINAL))
    if captured is not None:
        out["captured_at"] = captured
    for key, value in (("make", make), ("model", model)):
        if isinstance(value, str) and value.strip():
            out[key] = value.strip()
    return out


# --- заявка ----------------------------------------------------------------


def _coord(value: Any, name: str) -> str | None:
    """Координата десятичной строкой. Кривой ввод — отказ, а не «не заявлено».

    Молча проглоченная опечатка (`lat: "52,1"`) дала бы отчёт `insufficient`
    вместо ошибки ввода, и клиент искал бы причину в наших фото.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"claim: {name} must be a number, not a boolean")
    try:
        number = Decimal(str(value).strip())
    except InvalidOperation as exc:
        raise ValueError(f"claim: {name} is not a number: {value!r}") from exc
    if not number.is_finite():
        raise ValueError(f"claim: {name} is not finite: {value!r}")
    return str(number)


def _claim_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "claim: captured_at is required (RFC 3339 with a zone), "
            "e.g. 2026-11-02T11:20:00Z")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"claim: captured_at is not RFC 3339: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("claim: captured_at needs a zone, e.g. 2026-11-02T11:20:00Z")
    return parsed


def _subject(claim: dict) -> dict[str, str]:
    source = claim.get("subject")
    if isinstance(source, str):
        source = {"ref": source}
    if source is None:
        source = {}
    if not isinstance(source, dict):
        raise ValueError("claim: subject must be an object or a string")
    text = claim.get("claim") or claim.get("description") or source.get("claim")
    if text is not None and not isinstance(text, str):
        raise ValueError("claim: the claim text must be a string")
    subject = {
        "type": str(source.get("type") or "site"),
        "ref": str(source.get("ref") or "").strip(),
        "claim": str(text or "").strip(),
    }
    for field in ("ref", "claim"):
        if not subject[field]:
            raise ValueError(f"claim: subject.{field} is required")
    return subject


def _claimed_position(claim: dict) -> dict[str, Any] | None:
    location = claim.get("location")
    if location is None:
        return None
    if not isinstance(location, dict):
        raise ValueError("claim: location must be an object with lat and lon")
    lat = _coord(location.get("lat"), "location.lat")
    lon = _coord(location.get("lon"), "location.lon")
    if lat is None and lon is None:
        return None
    if lat is None or lon is None:
        raise ValueError("claim: location needs both lat and lon")
    out: dict[str, Any] = {"lat": lat, "lon": lon}
    accuracy = location.get("accuracy_m")
    if isinstance(accuracy, int) and not isinstance(accuracy, bool) and accuracy >= 0:
        out["accuracy_m"] = accuracy
    return out


# --- сверка ----------------------------------------------------------------


def distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> int:
    """Расстояние по большому кругу в метрах, округлённое до целого."""
    radius = 6_371_000
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return round(2 * radius * math.asin(math.sqrt(a)))


def _wall_clock_minutes(claim_time: datetime, exif_time: datetime) -> int:
    """Расхождение времени в минутах, наблюдаемое минус заявленное.

    `DateTimeOriginal` не несёт зоны: сравниваем настенные показания камеры с
    настенным временем заявки. Предположение о зоне камеры — в `limits`, иначе
    сравнение молча считало бы её UTC.
    """
    delta = exif_time - claim_time.replace(tzinfo=None)
    return round(delta.total_seconds() / 60)


def _verdict(coord_delta_m: int | None, time_delta_min: int | None,
             discrepancies: list[dict], independent: dict) -> str:
    """Правила вердикта. Порядок важен: `contradicted` сильнее всего.

    * координаты разошлись больше допуска — `contradicted`, даже если время
      сошлось: объект не тот;
    * независимый источник говорит `mismatch` — тоже `contradicted`;
    * сравнивать нечего ни по месту, ни по времени — `insufficient`;
    * `confirmed` только когда сошлись координаты, время и все слои, включая
      независимый. Без независимой съёмки потолок — `partial`: слой
      `not_available` не подтверждает место, и `pop.verify()` справедливо
      не принимает такой отчёт как `confirmed`.
    """
    if coord_delta_m is not None and coord_delta_m > COORD_TOLERANCE_M:
        return "contradicted"
    if independent["result"] == "mismatch":
        return "contradicted"
    if coord_delta_m is None and time_delta_min is None:
        return "insufficient"
    if (coord_delta_m is not None and coord_delta_m <= COORD_TOLERANCE_M
            and time_delta_min is not None
            and abs(time_delta_min) <= TIME_TOLERANCE_MIN
            and not discrepancies
            and independent["result"] == "match"):
        return "confirmed"
    return "partial"


def _position_result(coord_delta_m: int | None, has_gps: bool) -> str:
    """`not_available` — измеренного места нет; `unknown` — есть, но сверить не с чем."""
    if coord_delta_m is not None:
        return "match" if coord_delta_m <= COORD_TOLERANCE_M else "mismatch"
    return "unknown" if has_gps else "not_available"


def _independent_layer(source: dict | None) -> dict:
    """Независимая съёмка. Нет данных — так и пишем, без источника-заглушки."""
    if not source:
        return {"name": "independent", "source": "none",
                "result": "not_available",
                "note": "not available: no independent capture "
                        "(satellite or partner) was used"}
    if not isinstance(source, dict):
        raise ValueError("independent: must be a JSON object")
    result = source.get("result")
    if result not in {"match", "mismatch"}:
        raise ValueError("independent: result must be 'match' or 'mismatch'")
    name = str(source.get("source") or "").strip()
    if not name:
        raise ValueError("independent: source is required, e.g. sentinel-2")
    layer: dict[str, Any] = {"name": "independent", "source": name,
                             "result": result}
    for field in ("provider", "captured_at", "asset_ref"):
        value = source.get(field)
        if value:
            layer[field] = str(value)
    if "captured_at" in layer:
        try:
            parsed = datetime.fromisoformat(
                layer["captured_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(
                "independent: captured_at is not RFC 3339") from exc
        if parsed.tzinfo is None:
            raise ValueError("independent: captured_at needs a zone")
    return layer


# --- сборка ----------------------------------------------------------------


def build(photos: Path, claim: dict, key_path, *,
          independent: dict | None = None,
          issued_at: str | None = None,
          report_id: str | None = None) -> dict:
    """Собрать и подписать отчёт. Возвращает готовый `pop/1` как dict."""
    root = Path(photos)
    subject = _subject(claim)
    claim_time = _claim_time(claim.get("captured_at"))
    claimed = _claimed_position(claim)

    files: list[dict] = []
    observed: dict[str, Any] | None = None   # первый файл с GPS
    observed_file: str | None = None
    timed: dict[str, Any] | None = None      # первый файл со временем съёмки
    any_exif: dict[str, Any] | None = None
    for path in _files(root):
        name = path.relative_to(root).as_posix()
        with path.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        files.append({"name": name, "bytes": path.stat().st_size,
                      "sha256": digest})
        exif = read_exif(path)
        if not exif:
            continue
        any_exif = any_exif or exif
        if observed is None and "lat" in exif:
            observed, observed_file = exif, name
        if timed is None and "captured_at" in exif:
            timed = exif

    coord_delta_m = None
    if claimed and observed:
        coord_delta_m = distance_m(
            float(claimed["lat"]), float(claimed["lon"]),
            observed["lat"], observed["lon"])

    time_delta_min = None
    if timed:
        time_delta_min = _wall_clock_minutes(claim_time, timed["captured_at"])

    independent_layer = _independent_layer(independent)

    discrepancies: list[dict] = []
    if coord_delta_m is not None and coord_delta_m > COORD_TOLERANCE_M:
        discrepancies.append({
            "field": "location",
            "claimed": f"{claimed['lat']}, {claimed['lon']}",
            "observed": f"{observed['lat']:.6f}, {observed['lon']:.6f}",
            "delta": f"{coord_delta_m} m (tolerance {COORD_TOLERANCE_M} m)",
        })
    if time_delta_min is not None and abs(time_delta_min) > TIME_TOLERANCE_MIN:
        discrepancies.append({
            "field": "captured_at",
            "claimed": claim.get("captured_at"),
            "observed": timed["captured_at"].strftime("%Y-%m-%dT%H:%M:%S"),
            "delta": f"{time_delta_min} min (tolerance {TIME_TOLERANCE_MIN} min)",
        })
    if independent_layer["result"] == "mismatch":
        discrepancies.append({
            "field": "independent",
            "claimed": "the site in the claim",
            "observed": independent_layer.get("asset_ref")
                        or independent_layer["source"],
            "delta": "independent source disagrees with the claimed site",
        })

    # Слой position описывает обе стороны отдельно: что заявлено и что найдено.
    if observed and "lat" in observed:
        source = "gps"
    elif any_exif:
        source = "exif"
    else:
        source = "none"

    position: dict[str, Any] = {
        "name": "position",
        "source": source,
        "result": _position_result(coord_delta_m, bool(observed)),
    }
    if claimed:
        position["declared"] = dict(claimed)
    if observed and "lat" in observed:
        accuracy = observed.get("accuracy_m")
        position["observed"] = {
            "lat": f"{observed['lat']:.6f}",
            "lon": f"{observed['lon']:.6f}",
            "accuracy_m": accuracy if accuracy is not None
                          else GPS_ASSUMED_ACCURACY_M,
            "file": observed_file,
        }
    if coord_delta_m is not None:
        position["delta_m"] = coord_delta_m
    if time_delta_min is not None:
        position["time_delta_min"] = time_delta_min
    position["checks"] = ["sha256", "range", "distance_m", "time_window"]
    position["note"] = ("GPS can be spoofed: a match means the file agrees with "
                        "the claim, not that the place is true")

    if timed:
        position["captured_at"] = timed["captured_at"].strftime(
            "%Y-%m-%dT%H:%M:%S")
    if any_exif and ("make" in any_exif or "model" in any_exif):
        position["camera"] = " ".join(
            part for part in (any_exif.get("make"), any_exif.get("model"))
            if part)

    # Место отчёта: измеренное, если оно есть, иначе заявленное. `basis`
    # оставляет читателю возможность отличить одно от другого без догадок.
    if observed and "lat" in observed:
        accuracy = observed.get("accuracy_m")
        location = {"lat": f"{observed['lat']:.6f}",
                    "lon": f"{observed['lon']:.6f}",
                    "accuracy_m": accuracy if accuracy is not None
                                  else GPS_ASSUMED_ACCURACY_M,
                    "basis": "exif_gps"}
    else:
        location = {"lat": claimed["lat"], "lon": claimed["lon"],
                    "accuracy_m": claimed.get("accuracy_m", 0),
                    "basis": "claimed"}

    limits = list(LIMITS)
    if source == "gps" and "accuracy_m" not in (observed or {}):
        limits.append(f"the camera reported no GPS accuracy: "
                      f"{GPS_ASSUMED_ACCURACY_M} m is an assumption, not a measurement")
    if location["basis"] == "claimed":
        limits.append("location repeats the claim: it was not measured, "
                      "accuracy_m is 0 because nothing was measured")
    if independent_layer["result"] == "not_available":
        limits.append("no independent source was used: the report cannot confirm "
                      "the place, only the files")
    if len(files) > 1:
        limits.append("only the first photo with GPS metadata was compared; "
                      "photos that disagree with each other are not cross-checked")
    limits.append(f"tolerances: coordinates {COORD_TOLERANCE_M} m, "
                  f"capture time {TIME_TOLERANCE_MIN} min")

    not_checked = list(NOT_CHECKED)
    if independent_layer["result"] == "not_available":
        not_checked.append("independent capture (satellite or partner)")

    issuer = claim.get("issuer")
    if not isinstance(issuer, dict) or not str(issuer.get("key_id") or "").strip():
        issuer = {
            "name": str((issuer or {}).get("name") or "attest pop_build"),
            "key_id": "ed25519:"
                      + hashlib.sha256(_public_key(key_path)).hexdigest()[:16],
        }

    capture_text = claim.get("captured_at")
    if not isinstance(capture_text, str):
        capture_text = claim_time.isoformat()

    report: dict[str, Any] = {
        "v": "pop/1",
        "kind": "report",
        "report_id": report_id or f"pop_{uuid.uuid4().hex[:16]}",
        "issued_at": issued_at or datetime.now(timezone.utc).replace(
            microsecond=0).isoformat(),
        "issuer": issuer,
        "subject": subject,
        "captured_at": capture_text,
        "location": location,
        "layers": [
            {"name": "content", "source": "client", "result": "pass",
             "files": files,
             "checks": ["sha256"] + (["exif_present"] if any_exif else []),
             "note": ""},
            position,
            independent_layer,
            {"name": "immutability", "algo": "sha256"},
        ],
        "discrepancies": discrepancies,
        "verdict": _verdict(coord_delta_m, time_delta_min, discrepancies,
                            independent_layer),
        "limits": limits,
        "not_checked": not_checked,
    }
    window = claim.get("window")
    if isinstance(window, dict) and window:
        report["window"] = window
    return sign(report, key_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m attest.pop_build",
        description="Build and sign a pop/1 report from photos and a claim.")
    parser.add_argument("--photos", required=True, help="directory with photos")
    parser.add_argument("--claim", required=True, help="claim.json")
    parser.add_argument("--key", required=True, help="Ed25519 private key file")
    parser.add_argument("--out", required=True, help="report.json to write")
    parser.add_argument("--independent",
                        help="JSON with an independent source result "
                             "(source, result, provider, captured_at, asset_ref)")
    args = parser.parse_args(argv)

    try:
        claim = json.loads(Path(args.claim).read_text(encoding="utf-8"))
        if not isinstance(claim, dict):
            raise ValueError("claim: the file is not a JSON object")
        independent = None
        if args.independent:
            independent = json.loads(
                Path(args.independent).read_text(encoding="utf-8"))
        report = build(Path(args.photos), claim, Path(args.key),
                       independent=independent)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    Path(args.out).write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8")
    print(f"report:  {args.out}")
    print(f"verdict: {report['verdict']}")
    print(f"discrepancies: {len(report['discrepancies'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
