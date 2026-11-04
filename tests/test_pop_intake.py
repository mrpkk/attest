"""Веб-приём ZIP для Proof of Place (05.11.2026, Агни).

Гейт из задачи — пять вещей, каждая из которых была бы дырой в проде:

1. успешная сборка: ZIP с фото и заявкой → подписанный `pop/1`, принимаемый
   `pop.verify()` с pinned-ключом;
2. zip-slip: `../../evil.jpg` не должен выйти из каталога распаковки;
3. размер: ZIP больше 25 МБ отвергается до разбора;
4. тип: расширение и настоящие байты обязаны совпадать, иначе отказ;
5. HEIC без EXIF: `position=not_available`, а не выдуманные координаты.

Фикстуры пишут настоящий JPEG с EXIF через Pillow: тест, подменяющий парсер,
проверяет подмену, а не файл.
"""

from __future__ import annotations

import io
import json
import pathlib
import sys
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest import pop_intake, signing  # noqa: E402
from attest.pop import verify as pop_verify  # noqa: E402
from attest.pop_intake import (  # noqa: E402
    MAX_ZIP_BYTES,
    IntakeError,
    intake,
    report_path,
)
from attest.signing import generate_keypair, public_key  # noqa: E402

CLAIM_LAT, CLAIM_LON = 52.123456, 4.654321
CLAIM = {
    "subject": {"type": "parcel", "ref": "plot-14"},
    "claim": "40 ha solar farm, operational",
    "location": {"lat": str(CLAIM_LAT), "lon": str(CLAIM_LON)},
    "captured_at": "2026-11-02T11:20:00Z",
}
BOUNDARY = "----popintaketest"


@pytest.fixture()
def key(tmp_path):
    path = tmp_path / "issuer.key"
    generate_keypair(path)
    return path


def jpeg(path: Path, *, lat=None, lon=None, when=None) -> bytes:
    """JPEG с GPS и временем съёмки — настоящий EXIF, записанный Pillow."""
    image = Image.new("RGB", (16, 16), (30, 40, 50))
    if lat is None and when is None:
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG")
        return buffer.getvalue()
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
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", exif=exif.tobytes())
    return buffer.getvalue()


def photo_zip(entries: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blob in entries:
            archive.writestr(name, blob)
    return buffer.getvalue()


def multipart(*, zip_bytes: bytes, claim: dict | None = None,
               filename: str = "photos.zip", zip_type: str = "application/zip",
               claim_text: str | None = None) -> tuple[bytes, str]:
    """Тело multipart/form-data, как его собирает браузер."""
    body = b""
    body += (f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"zip\"; "
             f"filename=\"{filename}\"\r\nContent-Type: {zip_type}\r\n\r\n").encode()
    body += zip_bytes + b"\r\n"
    text = claim_text if claim_text is not None else json.dumps(claim or CLAIM)
    body += (f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"claim\""
             f"\r\nContent-Type: application/json\r\n\r\n").encode()
    body += text.encode("utf-8") + b"\r\n"
    body += f"--{BOUNDARY}--\r\n".encode()
    return body, f"multipart/form-data; boundary={BOUNDARY}"


class TestBuild:
    def test_build_from_zip_returns_a_signed_report(self, key, tmp_path):
        blob = photo_zip([("site.jpg", jpeg(tmp_path / "a.jpg", lat=CLAIM_LAT,
                                           lon=CLAIM_LON,
                                           when="2026:11:02 11:20:00"))])
        body, ctype = multipart(zip_bytes=blob)

        result = intake(body, ctype, key_path=key, data_dir=tmp_path / "data")

        assert result["ok"] is True
        assert result["files"] == 1
        # GPS и время сошлись, независимой съёмки нет: потолок — partial.
        assert result["verdict"] == "partial"
        assert result["download_url"].endswith(result["report_id"])
        report = result["report"]
        assert pop_verify(report, public_key(key).hex()) == "ok"
        stored = tmp_path / "data" / result["report_id"] / "report.json"
        assert json.loads(stored.read_text())["report_id"] == result["report_id"]

    def test_report_download_round_trip_over_http(self, key, tmp_path, monkeypatch):
        monkeypatch.setattr(signing, "KEY_PATH", key)
        monkeypatch.setattr(pop_intake, "POP_DATA", tmp_path / "data")
        from http.server import ThreadingHTTPServer

        from attest.service import AttestHandler

        blob = photo_zip([("site.jpg", jpeg(tmp_path / "b.jpg"))])
        body, ctype = multipart(zip_bytes=blob)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), AttestHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            request = urllib.request.Request(
                base + "/api/proof-of-place/build", data=body,
                headers={"Content-Type": ctype}, method="POST")
            with urllib.request.urlopen(request, timeout=20) as response:
                posted = json.loads(response.read().decode())
            assert posted["ok"] is True

            url = base + posted["download_url"]
            with urllib.request.urlopen(url, timeout=20) as response:
                downloaded = json.loads(response.read().decode())
                disposition = response.headers.get("Content-Disposition", "")
            assert downloaded["report_id"] == posted["report_id"]
            assert "attachment" in disposition

            missing = urllib.request.Request(base + "/api/proof-of-place/report/pop_0000000000000000")
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(missing, timeout=10)
            assert exc.value.code == 404
        finally:
            httpd.shutdown()
            httpd.server_close()


class TestZipSlip:
    def test_parent_traversal_is_refused_and_nothing_escapes(self, key, tmp_path):
        blob = photo_zip([("../../evil.jpg", jpeg(tmp_path / "c.jpg"))])
        body, ctype = multipart(zip_bytes=blob)
        data = tmp_path / "data"

        with pytest.raises(IntakeError) as exc:
            intake(body, ctype, key_path=key, data_dir=data)
        assert exc.value.status == 400
        assert "unsafe path" in exc.value.message
        assert not (tmp_path / "evil.jpg").exists()
        assert not (data.parent / "evil.jpg").exists()

    def test_absolute_path_is_refused(self, key, tmp_path):
        blob = photo_zip([("/etc/passwd.jpg", jpeg(tmp_path / "d.jpg"))])
        body, ctype = multipart(zip_bytes=blob)
        with pytest.raises(IntakeError) as exc:
            intake(body, ctype, key_path=key, data_dir=tmp_path / "data")
        assert exc.value.status == 400
        assert "unsafe path" in exc.value.message

    def test_backslash_path_is_refused(self, key, tmp_path):
        blob = photo_zip([("..\\..\\evil.jpg", jpeg(tmp_path / "e.jpg"))])
        body, ctype = multipart(zip_bytes=blob)
        with pytest.raises(IntakeError) as exc:
            intake(body, ctype, key_path=key, data_dir=tmp_path / "data")
        assert exc.value.status == 400


class TestLimits:
    def test_zip_limit_is_25_mb(self):
        assert MAX_ZIP_BYTES == 25 * 1024 * 1024

    def test_zip_over_the_limit_is_refused_before_unpacking(self, key, tmp_path):
        blob = b"\x00" * (MAX_ZIP_BYTES + 1)
        body, ctype = multipart(zip_bytes=blob)
        with pytest.raises(IntakeError) as exc:
            intake(body, ctype, key_path=key, data_dir=tmp_path / "data")
        assert exc.value.status == 413

    def test_more_than_200_files_is_refused(self, key, tmp_path):
        blob = photo_zip([(f"p{i}.jpg", b"\xff\xd8\xff\x00") for i in range(201)])
        body, ctype = multipart(zip_bytes=blob)
        with pytest.raises(IntakeError) as exc:
            intake(body, ctype, key_path=key, data_dir=tmp_path / "data")
        assert exc.value.status == 400
        assert "200" in exc.value.message


class TestFileTypes:
    def test_png_disguised_as_jpeg_is_refused(self, key, tmp_path):
        buffer = io.BytesIO()
        Image.new("RGB", (4, 4)).save(buffer, format="PNG")
        blob = photo_zip([("site.jpg", buffer.getvalue())])
        body, ctype = multipart(zip_bytes=blob)
        with pytest.raises(IntakeError) as exc:
            intake(body, ctype, key_path=key, data_dir=tmp_path / "data")
        assert exc.value.status == 400
        assert "not JPG" in exc.value.message

    def test_unknown_extension_is_refused(self, key, tmp_path):
        blob = photo_zip([("notes.gif", b"GIF89a")])
        body, ctype = multipart(zip_bytes=blob)
        with pytest.raises(IntakeError) as exc:
            intake(body, ctype, key_path=key, data_dir=tmp_path / "data")
        assert exc.value.status == 400
        assert "JPEG, PNG and HEIC" in exc.value.message

    def test_png_is_accepted(self, key, tmp_path):
        buffer = io.BytesIO()
        Image.new("RGB", (4, 4)).save(buffer, format="PNG")
        blob = photo_zip([("site.png", buffer.getvalue())])
        body, ctype = multipart(zip_bytes=blob)
        result = intake(body, ctype, key_path=key, data_dir=tmp_path / "data")
        assert result["ok"] is True


class TestHeic:
    def test_heic_without_exif_says_not_available(self, key, tmp_path):
        heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic" + b"\x00" * 24
        blob = photo_zip([("IMG_0001.HEIC", heic)])
        body, ctype = multipart(zip_bytes=blob)

        result = intake(body, ctype, key_path=key, data_dir=tmp_path / "data")

        report = result["report"]
        position = next(layer for layer in report["layers"]
                        if layer["name"] == "position")
        assert position["result"] == "not_available"
        assert position["source"] == "none"
        assert "lat" not in position.get("observed", {})
        # Ничего не измерено — вердикт не может быть выше insufficient.
        assert report["verdict"] == "insufficient"
        assert pop_verify(report, public_key(key).hex()) == "ok"


class TestRefusals:
    def test_bad_claim_is_a_400_with_a_reason(self, key, tmp_path):
        blob = photo_zip([("site.jpg", jpeg(tmp_path / "f.jpg"))])
        body, ctype = multipart(zip_bytes=blob, claim={"subject": {"ref": "x"}})
        with pytest.raises(IntakeError) as exc:
            intake(body, ctype, key_path=key, data_dir=tmp_path / "data")
        assert exc.value.status == 400
        assert exc.value.message.startswith("claim:")

    def test_claim_must_be_json(self, key, tmp_path):
        blob = photo_zip([("site.jpg", jpeg(tmp_path / "g.jpg"))])
        body, ctype = multipart(zip_bytes=blob, claim_text="not json")
        with pytest.raises(IntakeError) as exc:
            intake(body, ctype, key_path=key, data_dir=tmp_path / "data")
        assert exc.value.status == 400

    def test_report_id_cannot_choose_a_path(self, tmp_path):
        for bad in ("../../etc/passwd", "pop_x", "", "../pop_0123456789abcdef"):
            with pytest.raises(IntakeError) as exc:
                report_path(bad, tmp_path)
            assert exc.value.status == 404

    def test_report_expires_after_24_hours(self, key, tmp_path):
        blob = photo_zip([("site.jpg", jpeg(tmp_path / "h.jpg"))])
        body, ctype = multipart(zip_bytes=blob)
        result = intake(body, ctype, key_path=key, data_dir=tmp_path / "data",
                        now=1_000_000)
        assert report_path(result["report_id"], tmp_path / "data",
                           now=1_000_000 + 3600).is_file()
        with pytest.raises(IntakeError) as exc:
            report_path(result["report_id"], tmp_path / "data",
                        now=1_000_000 + 24 * 3600 + 1)
        assert exc.value.status == 410
        assert not (tmp_path / "data" / result["report_id"]).exists()
