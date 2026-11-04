"""Тесты сборки `pop/1`: фото клиента → подписанный отчёт.

Гейт из задачи: четыре вердикта на синтетических фото с EXIF и без, и каждый
собранный отчёт обязан приниматься `pop.verify()` с pinned-ключом. Фикстуры
пишут EXIF настоящим Pillow, а не подменяют чтение: тест, который подменяет
парсер, проверяет свою подмену, а не файл.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.pop import verify  # noqa: E402
from attest.pop_build import (  # noqa: E402
    COORD_TOLERANCE_M,
    GPS_ASSUMED_ACCURACY_M,
    TIME_TOLERANCE_MIN,
    build,
)
from attest.signing import generate_keypair  # noqa: E402
from attest.signing import public_key as pub  # noqa: E402

CLAIM_LAT, CLAIM_LON = 52.123456, 4.654321
CLAIM_TIME = "2026-11-02T11:20:00Z"
EXIF_TIME = "2026:11:02 11:20:00"


@pytest.fixture(scope="module")
def key(tmp_path_factory):
    path = tmp_path_factory.mktemp("pop_build") / "issuer.key"
    generate_keypair(path)
    return path


def hexkey(path) -> str:
    return pub(path).hex()


def photo(path: Path, *, lat=None, lon=None, when=None, accuracy=None) -> Path:
    """JPEG с GPS и/или временем съёмки. Без аргументов — файл без EXIF."""
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGB", (16, 16), (30, 40, 50))
    if lat is None and when is None:
        image.save(path)
        return path
    exif = Image.Exif()
    exif[271], exif[272] = "TestMake", "TestModel"
    if when:
        exif.get_ifd(0x8769)[36867] = when
    if lat is not None:
        gps = exif.get_ifd(0x8825)
        for tag, ref_tag, value, positive, negative in (
                (2, 1, lat, "N", "S"), (4, 3, lon, "E", "W")):
            degrees = int(abs(value))
            minutes = int((abs(value) - degrees) * 60)
            seconds = (abs(value) - degrees - minutes / 60) * 3600
            gps[ref_tag] = positive if value >= 0 else negative
            gps[tag] = (float(degrees), float(minutes), round(seconds, 6))
        if accuracy is not None:
            gps[31] = float(accuracy)
    image.save(path, exif=exif.tobytes())
    return path


def claim(**overrides) -> dict:
    data = {
        "subject": {"type": "parcel", "ref": "client-ref-1"},
        "claim": "40 ha, solar farm, operational",
        "location": {"lat": str(CLAIM_LAT), "lon": str(CLAIM_LON)},
        "captured_at": CLAIM_TIME,
    }
    data.update(overrides)
    return data


def independent(result="match") -> dict:
    return {"source": "sentinel-2", "provider": "Copernicus",
            "captured_at": "2026-11-02T11:20:00Z", "asset_ref": "S2B_1",
            "result": result}


def photos_of(tmp_path: Path, **kwargs) -> Path:
    folder = tmp_path / "photos"
    photo(folder / "site.jpg", **kwargs)
    return folder


class TestVerdicts:
    def test_confirmed_when_all_four_layers_agree(self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT, lon=CLAIM_LON,
                           when=EXIF_TIME, accuracy=8)
        report = build(folder, claim(), key, independent=independent())
        assert report["verdict"] == "confirmed"
        assert report["discrepancies"] == []
        assert [layer.get("result") for layer in report["layers"]] == [
            "pass", "match", "match", None]
        assert verify(report, hexkey(key)) == "ok"

    def test_partial_without_independent_layer(self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT, lon=CLAIM_LON,
                           when=EXIF_TIME)
        report = build(folder, claim(), key)
        # GPS и время сошлись, но независимой съёмки не было: потолок partial.
        assert report["verdict"] == "partial"
        assert report["layers"][2]["result"] == "not_available"
        assert "no independent source was used" in " ".join(report["limits"])
        assert verify(report, hexkey(key)) == "ok"

    def test_contradicted_when_coordinates_differ_beyond_tolerance(
            self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT + 0.016, lon=CLAIM_LON,
                           when=EXIF_TIME)  # ~1.8 км севернее заявленного
        report = build(folder, claim(), key)
        assert report["verdict"] == "contradicted"
        assert report["layers"][1]["result"] == "mismatch"
        assert report["layers"][1]["delta_m"] > COORD_TOLERANCE_M
        assert [d["field"] for d in report["discrepancies"]] == ["location"]
        assert "m (tolerance" in report["discrepancies"][0]["delta"]
        assert verify(report, hexkey(key)) == "ok"

    def test_insufficient_without_exif(self, key, tmp_path):
        folder = photos_of(tmp_path)  # PNG/JPEG без EXIF
        report = build(folder, claim(), key)
        assert report["verdict"] == "insufficient"
        assert report["layers"][1]["result"] == "not_available"
        assert report["layers"][1]["source"] == "none"
        assert verify(report, hexkey(key)) == "ok"


class TestTolerances:
    def test_inside_coordinate_tolerance_is_not_a_discrepancy(self, key, tmp_path):
        # 0.0036° по широте ≈ 400 м — внутри допуска.
        folder = photos_of(tmp_path, lat=CLAIM_LAT + 0.0036, lon=CLAIM_LON,
                           when=EXIF_TIME)
        report = build(folder, claim(), key, independent=independent())
        assert report["layers"][1]["delta_m"] < COORD_TOLERANCE_M
        assert report["discrepancies"] == []
        assert report["verdict"] == "confirmed"

    def test_outside_coordinate_tolerance_is_contradicted(self, key, tmp_path):
        # 0.005° ≈ 557 м — за допуском.
        folder = photos_of(tmp_path, lat=CLAIM_LAT + 0.005, lon=CLAIM_LON,
                           when=EXIF_TIME)
        report = build(folder, claim(), key)
        assert report["layers"][1]["delta_m"] > COORD_TOLERANCE_M
        assert report["verdict"] == "contradicted"

    def test_inside_time_tolerance_is_confirmed(self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT, lon=CLAIM_LON,
                           when="2026:11:02 12:50:00")  # +90 минут
        report = build(folder, claim(), key, independent=independent())
        assert report["layers"][1]["time_delta_min"] == 90
        assert report["verdict"] == "confirmed"

    def test_outside_time_tolerance_is_partial(self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT, lon=CLAIM_LON,
                           when="2026:11:01 19:20:00")  # -16 часов
        report = build(folder, claim(), key, independent=independent())
        assert report["verdict"] == "partial"
        assert abs(report["layers"][1]["time_delta_min"]) > TIME_TOLERANCE_MIN
        assert [d["field"] for d in report["discrepancies"]] == ["captured_at"]
        assert "min (tolerance" in report["discrepancies"][0]["delta"]
        assert verify(report, hexkey(key)) == "ok"


class TestLayers:
    def test_content_hashes_every_file(self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT, lon=CLAIM_LON,
                           when=EXIF_TIME)
        (folder / "notes.txt").write_text("survey notes", encoding="utf-8")
        (folder / ".DS_Store").write_text("junk", encoding="utf-8")
        report = build(folder, claim(), key)
        names = [item["name"] for item in report["layers"][0]["files"]]
        assert names == ["notes.txt", "site.jpg"]
        assert "exif_present" in report["layers"][0]["checks"]
        assert verify(report, hexkey(key)) == "ok"

    def test_exif_time_without_gps_is_a_partial_position(self, key, tmp_path):
        folder = photos_of(tmp_path, when=EXIF_TIME)
        report = build(folder, claim(), key)
        position = report["layers"][1]
        assert position["source"] == "exif"
        assert position["result"] == "not_available"  # GPS в файлах нет
        assert position["captured_at"] == "2026-11-02T11:20:00"
        assert report["verdict"] == "partial"
        assert verify(report, hexkey(key)) == "ok"

    def test_unmeasured_location_is_declared_as_claimed(self, key, tmp_path):
        folder = photos_of(tmp_path)  # EXIF нет
        report = build(folder, claim(), key)
        assert report["location"] == {"lat": str(CLAIM_LAT),
                                      "lon": str(CLAIM_LON),
                                      "accuracy_m": 0, "basis": "claimed"}
        assert "location repeats the claim" in " ".join(report["limits"])

    def test_gps_accuracy_is_not_invented(self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT, lon=CLAIM_LON,
                           when=EXIF_TIME)  # без тега GPSHPositioningError
        report = build(folder, claim(), key)
        assert report["location"]["accuracy_m"] == GPS_ASSUMED_ACCURACY_M
        assert "assumption, not a measurement" in " ".join(report["limits"])

    def test_reported_accuracy_is_used(self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT, lon=CLAIM_LON,
                           when=EXIF_TIME, accuracy=8)
        report = build(folder, claim(), key)
        assert report["location"]["accuracy_m"] == 8
        assert report["layers"][1]["observed"]["accuracy_m"] == 8

    def test_limits_and_not_checked_are_never_empty(self, key, tmp_path):
        folder = photos_of(tmp_path)
        report = build(folder, claim(), key)
        assert report["limits"] and report["not_checked"]
        assert "ownership" in report["not_checked"]


class TestRefusals:
    def test_claim_without_capture_time_is_refused(self, key, tmp_path):
        folder = photos_of(tmp_path)
        broken = claim()
        del broken["captured_at"]
        with pytest.raises(ValueError, match="captured_at is required"):
            build(folder, broken, key)

    def test_claim_without_zone_is_refused(self, key, tmp_path):
        folder = photos_of(tmp_path)
        with pytest.raises(ValueError, match="needs a zone"):
            build(folder, claim(captured_at="2026-11-02T11:20:00"), key)

    def test_broken_coordinate_is_an_error_not_an_absence(self, key, tmp_path):
        folder = photos_of(tmp_path)
        bad = claim(location={"lat": "52,1", "lon": "4.65"})
        with pytest.raises(ValueError, match="location.lat is not a number"):
            build(folder, bad, key)

    def test_empty_folder_is_refused(self, key, tmp_path):
        folder = tmp_path / "empty"
        folder.mkdir()
        with pytest.raises(ValueError, match="no files"):
            build(folder, claim(), key)

    def test_independent_needs_a_source(self, key, tmp_path):
        folder = photos_of(tmp_path)
        with pytest.raises(ValueError, match="source is required"):
            build(folder, claim(), key, independent={"result": "match"})


class TestCli:
    def test_cli_report_is_accepted_by_verify(self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT, lon=CLAIM_LON,
                           when=EXIF_TIME)
        claim_path = tmp_path / "claim.json"
        claim_path.write_text(json.dumps(claim()), encoding="utf-8")
        report_path = tmp_path / "report.json"
        out = subprocess.run(
            [sys.executable, "-m", "attest.pop_build",
             "--photos", str(folder), "--claim", str(claim_path),
             "--key", str(key), "--out", str(report_path)],
            cwd=ROOT, capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        assert "verdict: partial" in out.stdout
        assert verify(report_path.read_text(encoding="utf-8"),
                      hexkey(key)) == "ok"

    def test_cli_refuses_a_broken_claim(self, key, tmp_path):
        folder = photos_of(tmp_path)
        claim_path = tmp_path / "claim.json"
        claim_path.write_text('{"subject": {"ref": "x"}}', encoding="utf-8")
        out = subprocess.run(
            [sys.executable, "-m", "attest.pop_build",
             "--photos", str(folder), "--claim", str(claim_path),
             "--key", str(key), "--out", str(tmp_path / "r.json")],
            cwd=ROOT, capture_output=True, text=True)
        assert out.returncode == 2
        assert "error:" in out.stderr
        assert not (tmp_path / "r.json").exists()

    def test_report_changed_after_build_is_tampered(self, key, tmp_path):
        folder = photos_of(tmp_path, lat=CLAIM_LAT, lon=CLAIM_LON,
                           when=EXIF_TIME)
        report = build(folder, claim(), key)
        text = json.dumps(report).replace("40 ha", "400 ha")
        assert verify(text, hexkey(key)) == "tampered"
