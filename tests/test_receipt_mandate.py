"""S7: чтение мандата AP2 (SD-JWT).

Гейт: подпись проверяется (EdDSA и ES256), раскрытия собираются, отсутствие
лимитов не выдумывается, срок отдаётся как есть.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

from attest.receipt import mandate as ap2


def b64(raw: bytes) -> str:
    return ap2._b64url_encode(raw)


def make_sd_jwt(priv, *, alg="EdDSA", payload=None, disclosures=None, jwk=None):
    header = {"alg": alg, "typ": "vc+sd-jwt"}
    body = {"iss": "https://issuer.example", "sub": "agent-1", "iat": 1000,
            "exp": 2000, "limits": {"amount_max": 25, "currency": "USDC"}}
    body.update(payload or {})
    h, p = b64(json.dumps(header).encode()), b64(json.dumps(body).encode())
    signing_input = f"{h}.{p}".encode()
    if alg == "EdDSA":
        sig = priv.sign(signing_input)
    else:
        der = priv.sign(signing_input, ECDSA(SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    token = f"{h}.{p}.{b64(sig)}"
    for name, value in (disclosures or []):
        token += "~" + b64(json.dumps(["salt123", name, value]).encode())
    return token + "~"


@pytest.fixture()
def ed_key():
    priv = Ed25519PrivateKey.generate()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64(priv.public_key().public_bytes_raw())}
    return priv, jwk


@pytest.fixture()
def ec_key():
    priv = generate_private_key(SECP256R1())
    nums = priv.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256",
           "x": b64(nums.x.to_bytes(32, "big")), "y": b64(nums.y.to_bytes(32, "big"))}
    return priv, jwk


def test_eddsa_mandate_verifies(ed_key):
    priv, jwk = ed_key
    m = ap2.read(make_sd_jwt(priv), jwk)
    assert m.ok, m.why()
    assert m.status == ap2.VERIFIED
    assert m.issuer == "https://issuer.example"
    assert m.limits == {"amount_max": 25, "currency": "USDC"}


def test_es256_mandate_verifies(ec_key):
    priv, jwk = ec_key
    m = ap2.read(make_sd_jwt(priv, alg="ES256"), jwk)
    assert m.ok, m.why()


def test_wrong_key_does_not_verify(ed_key):
    priv, _ = ed_key
    other = Ed25519PrivateKey.generate()
    wrong = {"kty": "OKP", "x": b64(other.public_key().public_bytes_raw())}
    m = ap2.read(make_sd_jwt(priv), wrong)
    assert not m.ok
    assert m.status == ap2.DECODED_UNVERIFIED


def test_disclosures_are_collected(ed_key):
    priv, jwk = ed_key
    m = ap2.read(make_sd_jwt(priv, disclosures=[("payee", "0xabc"), ("purpose", "data")]), jwk)
    assert m.disclosed == {"payee": "0xabc", "purpose": "data"}


def test_without_a_key_the_result_says_unverified(ed_key):
    priv, _ = ed_key
    m = ap2.read(make_sd_jwt(priv))
    assert m.status == ap2.DECODED_UNVERIFIED
    assert "not verified" in m.why()


def test_missing_limits_are_not_invented(ed_key):
    priv, jwk = ed_key
    m = ap2.read(make_sd_jwt(priv, payload={"limits": None}), jwk)
    assert m.limits == {}
    assert "not invented" in m.why()


def test_expiry_is_reported_not_assumed(ed_key):
    priv, jwk = ed_key
    m = ap2.read(make_sd_jwt(priv), jwk)
    assert ap2.expired(m, now=1500) is False
    assert ap2.expired(m, now=2500) is True
    no_exp = ap2.read(make_sd_jwt(priv, payload={"exp": None}), jwk)
    assert ap2.expired(no_exp, now=10**9) is None, "нет срока — это не «бессрочно»"


def test_malformed_credential_is_reported():
    m = ap2.read("not-a-jwt")
    assert m.status == ap2.MALFORMED
    assert "cannot decode" in m.why()


def test_digest_is_stable_and_salted(ed_key):
    priv, jwk = ed_key
    m = ap2.read(make_sd_jwt(priv), jwk)
    assert ap2.digest(m) == ap2.digest(m)
    assert ap2.digest(m, salt="a") != ap2.digest(m, salt="b")
