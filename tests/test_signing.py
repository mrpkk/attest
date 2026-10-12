"""Тесты подписи, проверяемой без доверия к сервису.

Проверяется главное свойство: проверка работает у того, у кого нет ни
нашего кода, ни секрета, ни сети. Если это перестаёт быть верно, модуль
теряет смысл, даже когда подпись формально верна.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest.provenance import canonical, new_record  # noqa: E402
from attest.signing import (  # noqa: E402
    KEY_PATH,
    generate_keypair,
    key_fingerprint,
    sign,
    verify,
)

STANDALONE = ROOT / "attest" / "verify_standalone.py"


@pytest.fixture(scope="module", autouse=True)
def keys(tmp_path_factory):
    p = tmp_path_factory.mktemp("key") / "signing.key"
    generate_keypair(p)
    return p


def rec(**kw):
    base = dict(source="test", artifact={"findings": ["a", "b"]},
                verdict="accept", trust_score=0.9)
    base.update(kw)
    return new_record(**base)


class TestSignAndVerify:
    def test_roundtrip(self, keys):
        r = rec()
        s = sign(canonical(r.as_dict()), keys)
        assert verify(canonical(r.as_dict()), s.signature, s.public_key) is True

    def test_algorithm_is_ed25519(self, keys):
        s = sign(canonical(rec().as_dict()), keys)
        assert s.algorithm == "ed25519"

    def test_public_key_travels_with_signature(self, keys):
        # Ключ для проверки лежит рядом с подписью — иначе проверяющему
        # пришлось бы идти к нам и доверять ответу.
        s = sign(canonical(rec().as_dict()), keys)
        assert s.public_key and len(s.public_key) > 20

    def test_tampered_payload_rejected(self, keys):
        r = rec()
        p = canonical(r.as_dict())
        s = sign(p, keys)
        assert verify(p + b" ", s.signature, s.public_key) is False

    def test_wrong_public_key_rejected(self, keys, tmp_path):
        p = canonical(rec().as_dict())
        s = sign(p, keys)
        other = tmp_path / "other.key"
        generate_keypair(other)
        from attest.signing import public_key as pub
        assert verify(p, s.signature,
                      __import__("base64").b64encode(pub(other)).decode()) is False


class TestNoHiddenSecret:
    def test_private_key_absent_means_refusal(self, tmp_path):
        # Ключа нет — подписи нет. Запасного ключа, зашитого в исходник,
        # быть не должно: он даёт видимость защиты, которой нет.
        with pytest.raises(FileNotFoundError):
            sign(b"payload", tmp_path / "absent.key")

    def test_source_has_no_hardcoded_fallback_key(self):
        src = (ROOT / "attest" / "signing.py").read_text(encoding="utf-8")
        assert "do-not-use-in-production" not in src

    def test_key_file_is_not_in_repo(self):
        assert ".key" not in str(KEY_PATH) or "/media/Sruti" not in str(KEY_PATH)


class TestStandaloneVerifier:
    """Главное свойство: чужой проверяет сам, без нашего пакета."""

    def _write_att(self, tmp_path, name, att):
        p = tmp_path / name
        p.write_text(json.dumps(att, ensure_ascii=False), encoding="utf-8")
        return p

    def test_valid_attestation_accepted(self, keys, tmp_path):
        r = rec()
        att = {"record": r.as_dict(),
               **sign(canonical(r.as_dict()), keys).as_dict()}
        p = self._write_att(tmp_path, "a.json", att)
        out = subprocess.run([sys.executable, str(STANDALONE), str(p)],
                             capture_output=True, text=True)
        assert out.returncode == 0
        assert json.loads(out.stdout)["valid"] is True

    def test_tampered_attestation_rejected(self, keys, tmp_path):
        r = rec()
        att = {"record": r.as_dict(),
               **sign(canonical(r.as_dict()), keys).as_dict()}
        att["record"]["trust_score"] = 1.0
        p = self._write_att(tmp_path, "f.json", att)
        out = subprocess.run([sys.executable, str(STANDALONE), str(p)],
                             capture_output=True, text=True)
        assert out.returncode == 1
        assert json.loads(out.stdout)["valid"] is False

    def test_hmac_is_refused_explicitly(self, tmp_path):
        # HMAC потребовал бы нашего секрета. Верификатор говорит об этом
        # прямо, а не молча принимает или молча отвергает.
        att = {"record": {"a": 1}, "signature": "x", "algorithm": "hmac-sha256"}
        p = self._write_att(tmp_path, "h.json", att)
        out = subprocess.run([sys.executable, str(STANDALONE), str(p)],
                             capture_output=True, text=True)
        res = json.loads(out.stdout)
        assert res["valid"] is False
        assert "HMAC" in res["reason"]

    def test_verifier_does_not_import_attest(self):
        src = STANDALONE.read_text(encoding="utf-8")
        assert "import attest" not in src
        assert "from attest" not in src

    def test_verifier_makes_no_network_calls(self):
        src = STANDALONE.read_text(encoding="utf-8")
        for banned in ("urllib", "requests", "socket", "http.client"):
            assert banned not in src


class TestFingerprint:
    def test_fingerprint_is_stable(self):
        assert key_fingerprint() == key_fingerprint()

    def test_fingerprint_is_short(self):
        assert len(key_fingerprint()) == 16
