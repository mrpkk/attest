"""Тесты артефакта Proof of Place и офлайн-проверки.

Гейт из спеки (POP-SPEC §5): честный артефакт принимается, изменённый
байт — `tampered`, чужой ключ — `wrong_key`, без подписи — `unsigned`.
Плюс то, что нельзя проверить глазами: пустые `limits` не подписываются,
удалённый слой и подменённый хеш ломают цепочку, старая отметка истекает,
PDF связан с `pdf_sha256`, а ключ из самого артефакта не принимается.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.pop import canonical, sign, verify  # noqa: E402
from attest.signing import generate_keypair  # noqa: E402
from attest.signing import public_key as pub  # noqa: E402

PDF = b"%PDF-1.7 proof of place\n"


@pytest.fixture(scope="module")
def key(tmp_path_factory):
    path = tmp_path_factory.mktemp("pop") / "issuer.key"
    generate_keypair(path)
    return path


def hexkey(path) -> str:
    return pub(path).hex()


def artifact(**overrides):
    layers = [
        {"name": "content", "source": "client", "result": "pass",
         "files": [{"name": "a.jpg", "bytes": 2483112,
                    "sha256": "a" * 64}],
         "checks": ["sha256", "exif_present"], "note": ""},
        {"name": "position", "source": "client_gps", "result": "weak",
         "declared": {"lat": "52.123456", "lon": "4.654321",
                      "accuracy_m": 8},
         "checks": ["range", "accuracy", "map_match"], "note": "GPS spoofable"},
        {"name": "independent", "source": "sentinel-2",
         "provider": "Copernicus", "captured_at": "2026-11-02T11:20:00Z",
         "asset_ref": "S2B_1", "result": "match"},
        {"name": "immutability", "algo": "sha256"},
    ]
    data = {
        "v": "pop/1",
        "kind": "report",
        "report_id": "pop_test_1",
        "issued_at": "2026-11-07T09:00:00Z",
        "issuer": {"name": "RTA", "key_id": "rta-pop-2026-11"},
        "subject": {"type": "parcel", "ref": "client-ref-1",
                    "claim": "40 ha, solar farm, operational"},
        "window": {"from": "2026-10-01", "to": "2026-11-06"},
        "captured_at": "2026-11-02T11:20:00Z",
        "location": {"lat": "52.123456", "lon": "4.654321",
                     "accuracy_m": 8},
        "layers": layers,
        "discrepancies": [],
        "verdict": "confirmed",
        "limits": ["GPS can be spoofed",
                   "hash proves file unchanged, not place"],
        "not_checked": ["ownership", "interior"],
        "pdf_sha256": hashlib.sha256(PDF).hexdigest(),
    }
    data.update(overrides)
    return data


class TestHonest:
    def test_honest_report_is_ok(self, key):
        signed = sign(artifact(), key)
        assert verify(signed, hexkey(key)) == "ok"

    @pytest.mark.parametrize("form", ["hex", "base64", "prefixed"])
    def test_key_forms(self, key, form):
        raw = pub(key)
        pinned = {"hex": raw.hex(),
                  "base64": base64.b64encode(raw).decode(),
                  "prefixed": "ed25519:" + raw.hex()}[form]
        assert verify(sign(artifact(), key), pinned) == "ok"

    def test_json_text_and_bytes_are_accepted(self, key):
        signed = sign(artifact(), key)
        text = json.dumps(signed)
        assert verify(text, hexkey(key)) == "ok"
        assert verify(text.encode(), hexkey(key)) == "ok"

    def test_canonical_is_stable(self, key):
        signed = sign(artifact(), key)
        assert canonical(signed) == canonical(json.loads(canonical(signed)))

    def test_cli_prints_verdict_and_reason(self, key, tmp_path):
        report = tmp_path / "report.json"
        report.write_text(json.dumps(sign(artifact(), key)), encoding="utf-8")
        keyfile = tmp_path / "public_key.txt"
        keyfile.write_text(hexkey(key), encoding="utf-8")
        out = subprocess.run(
            [sys.executable, "-m", "attest.pop_verify", str(report),
             "--key", str(keyfile)],
            cwd=ROOT, capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        assert "verdict: ok" in out.stdout
        assert "reason:" in out.stdout


class TestForgery:
    def test_changed_byte_is_tampered(self, key):
        signed = sign(artifact(), key)
        # Один байт в подписанном поле: 40 ha → 41 ha.
        tampered = json.dumps(signed).replace("40 ha", "41 ha")
        assert verify(tampered, hexkey(key)) == "tampered"

    def test_changed_layer_hash_is_tampered(self, key):
        signed = sign(artifact(), key)
        signed["layers"][1]["hash"] = "b" * 64
        assert verify(signed, hexkey(key)) == "tampered"

    def test_deleted_layer_is_tampered(self, key):
        signed = sign(artifact(), key)
        signed["layers"].pop(2)
        assert verify(signed, hexkey(key)) == "tampered"

    def test_foreign_key_is_wrong_key(self, key, tmp_path):
        other = tmp_path / "other.key"
        generate_keypair(other)
        signed = sign(artifact(), key)
        result = verify(signed, hexkey(other))
        assert result == "wrong_key"
        assert "pinned" in result.reason

    def test_missing_signature_is_unsigned(self, key):
        signed = sign(artifact(), key)
        del signed["signature"]
        assert verify(signed, hexkey(key)) == "unsigned"

    def test_empty_signature_is_unsigned(self, key):
        signed = sign(artifact(), key)
        signed["signature"] = ""
        assert verify(signed, hexkey(key)) == "unsigned"

    def test_artifact_key_is_not_trusted(self, key, tmp_path):
        # Подпись чужим ключом + заявление pinned-ключа в JSON не даёт ok.
        other = tmp_path / "other.key"
        generate_keypair(other)
        signed = sign(artifact(), other)
        signed["public_key"] = "ed25519:" + hexkey(key)
        assert verify(signed, hexkey(key)) == "tampered"


class TestUnderspecified:
    def test_empty_limits_do_not_pass(self, key):
        signed = sign(artifact(limits=[]), key)
        result = verify(signed, hexkey(key))
        assert result == "tampered"
        assert "limits" in result.reason

    def test_empty_not_checked_do_not_pass(self, key):
        signed = sign(artifact(not_checked=[]), key)
        result = verify(signed, hexkey(key))
        assert result == "tampered"
        assert "not_checked" in result.reason

    def test_confirmed_with_discrepancies_do_not_pass(self, key):
        signed = sign(artifact(discrepancies=[
            {"field": "area_ha", "claimed": "40", "observed": "36.2"}]))
        assert verify(signed, hexkey(key)) == "tampered"


class TestFreshnessAndPdf:
    def test_old_mark_is_expired(self, key):
        signed = sign(artifact(kind="mark",
                               issued_at="2026-11-01T00:00:00Z",
                               valid_for_s=3600), key)
        now = datetime(2026, 11, 2, tzinfo=timezone.utc)
        assert verify(signed, hexkey(key), now=now) == "expired"

    def test_fresh_mark_is_ok(self, key):
        signed = sign(artifact(kind="mark",
                               issued_at="2026-11-01T00:00:00Z",
                               valid_for_s=3600), key)
        now = datetime(2026, 11, 1, 0, 30, tzinfo=timezone.utc)
        assert verify(signed, hexkey(key), now=now) == "ok"

    def test_pdf_is_bound_to_the_report(self, key):
        signed = sign(artifact(), key)
        assert verify(signed, hexkey(key), pdf=PDF) == "ok"
        assert verify(signed, hexkey(key), pdf=PDF + b" ") == "tampered"
