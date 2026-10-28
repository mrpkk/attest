"""OIDC: конфигурация, state, домен, проверка ID-токена (29.10.2026)."""

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import algorithms

from attest import oidc


@pytest.fixture()
def provider(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = "test-key"
    monkeypatch.setattr(oidc, "ISSUER", "https://idp.example.com")
    monkeypatch.setattr(oidc, "CLIENT_ID", "client-123")
    monkeypatch.setattr(oidc, "CLIENT_SECRET", "secret")
    monkeypatch.setattr(oidc, "_cache", {
        "discovery": {
            "authorization_endpoint": "https://idp.example.com/auth",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/jwks",
        },
        "jwks": {"keys": [jwk]},
    })
    return key


def _token(key, **overrides):
    now = int(time.time())
    claims = {"iss": "https://idp.example.com", "aud": "client-123",
              "exp": now + 300, "iat": now, "sub": "u1",
              "email": "ada@company.com", "email_verified": True}
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})


def test_status_honest_when_not_configured(monkeypatch):
    monkeypatch.setattr(oidc, "ISSUER", "")
    monkeypatch.setattr(oidc, "CLIENT_ID", "")
    data = oidc.status()
    assert data["configured"] is False
    with pytest.raises(oidc.OIDCError):
        oidc.start_url()


def test_start_url_has_state_and_scopes(provider):
    url = oidc.start_url()
    assert url.startswith("https://idp.example.com/auth?")
    assert "scope=openid" in url and "state=" in url and "client_id=client-123" in url


def test_verify_id_token_accepts_valid(provider):
    claims = oidc.verify_id_token(_token(provider))
    assert claims["email"] == "ada@company.com"


def test_verify_rejects_wrong_audience(provider):
    with pytest.raises(oidc.OIDCError):
        oidc.verify_id_token(_token(provider, aud="other"))


def test_domain_allowlist(provider, monkeypatch):
    monkeypatch.setattr(oidc, "ALLOWED_DOMAINS", {"company.com"})
    assert oidc._domain_allowed("ada@company.com") is True
    assert oidc._domain_allowed("ada@evil.com") is False


def test_state_is_single_use(provider):
    url = oidc.start_url()
    state = url.split("state=")[1].split("&")[0]
    assert oidc._consume_state(state) is True
    assert oidc._consume_state(state) is False


def _entitlement():
    return {"token": "ent_demo", "expires_at": 9999999999}


def test_session_roundtrip(provider):
    token = oidc.issue_session({"email": "ada@company.com", "sub": "u1",
                                "iss": "https://idp.example.com"}, _entitlement())
    data = oidc.verify_session(token)
    assert data and data["email"] == "ada@company.com"
    assert data["entitlement"]["token"] == "ent_demo"


def test_session_tamper_rejected(provider):
    token = oidc.issue_session({"email": "ada@company.com", "sub": "u1",
                                "iss": "https://idp.example.com"}, _entitlement())
    payload, sig = token.split(".", 1)
    tampered = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB") + "." + sig
    assert oidc.verify_session(tampered) is None
