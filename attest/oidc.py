"""OIDC SSO для attest/KARTA (29.10.2026).

Enterprise-требование: вход через корпоративный IdP (Google Workspace, Okta,
Azure AD), без пароля и без локальной учётной записи. После входа выдаётся
тот же entitlement-токен, что и после оплаты — SSO заменяет пароль, а не
право доступа.

Границы: код не хранит пароли и не выдаёт себя за IdP. Если провайдер не
настроен, `/auth/oidc/start` честно отвечает 503, а не делает вид.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional

import jwt

def _agents_env() -> dict[str, str]:
    """Ключи агентских интеграций живут в ~/.env.agents, а не в ~/.env.

    ~/.env перезаписывается другими сессиями; OAuth-клиент там терялся бы.
    ~/.env.agents — отдельный файл с правами 600. Явные переменные окружения
    всё равно главнее файла: прод можно переопределить без правки диска.
    """
    path = Path(os.environ.get("ATTEST_AGENTS_ENV",
                               str(Path.home() / ".env.agents"))).expanduser()
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


_AGENTS = _agents_env()
CLIENT_ID = os.environ.get("ATTEST_OIDC_CLIENT_ID") or _AGENTS.get("GOOGLE_OAUTH_CLIENT_ID", "")
CLIENT_SECRET = (os.environ.get("ATTEST_OIDC_CLIENT_SECRET")
                 or _AGENTS.get("GOOGLE_OAUTH_CLIENT_SECRET", ""))
ISSUER = (os.environ.get("ATTEST_OIDC_ISSUER")
          or ("https://accounts.google.com" if CLIENT_ID else "")).rstrip("/")
REDIRECT_URI = os.environ.get("ATTEST_OIDC_REDIRECT",
                              "https://attest.rta.lat/auth/oidc/callback")
ALLOWED_DOMAINS = {
    d.strip().lower() for d in os.environ.get("ATTEST_OIDC_ALLOWED_DOMAINS", "").split(",") if d.strip()
}
STATE_TTL = 600
SESSION_COOKIE = "attest_session"
SESSION_TTL = 30 * 86400
_states: dict[str, float] = {}
_cache: dict[str, Any] = {}


@dataclass
class OIDCError(Exception):
    message: str
    status: int = 400


def configured() -> bool:
    return bool(ISSUER and CLIENT_ID)


def status() -> dict[str, Any]:
    return {
        "configured": configured(),
        "issuer": ISSUER or None,
        "redirect_uri": REDIRECT_URI,
        "allowed_domains": sorted(ALLOWED_DOMAINS),
        "note": ("SSO is optional: pay-per-call and the free tier keep working without it"
                 if configured() else
                 "SSO is not configured: set ATTEST_OIDC_ISSUER/CLIENT_ID/CLIENT_SECRET to enable"),
    }


def _get_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "attest-oidc/1.0"})
    with urllib.request.urlopen(req, timeout=15) as res:
        return json.loads(res.read())


def discovery() -> dict[str, Any]:
    if not configured():
        raise OIDCError("SSO is not configured", 503)
    key = "discovery"
    if key not in _cache:
        _cache[key] = _get_json(f"{ISSUER}/.well-known/openid-configuration")
    return _cache[key]


def start_url() -> str:
    doc = discovery()
    if not doc.get("authorization_endpoint"):
        raise OIDCError("provider has no authorization_endpoint", 503)
    now = time.time()
    for token, expires in list(_states.items()):
        if expires < now:
            _states.pop(token, None)
    state = secrets.token_urlsafe(24)
    _states[state] = now + STATE_TTL
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }
    return doc["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)


def _consume_state(state: str) -> bool:
    expires = _states.pop(state, None)
    return bool(expires and expires >= time.time())


def _exchange(code: str) -> dict[str, Any]:
    doc = discovery()
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }).encode()
    req = urllib.request.Request(doc["token_endpoint"], data=data,
                                 headers={"content-type": "application/x-www-form-urlencoded",
                                          "User-Agent": "attest-oidc/1.0"})
    with urllib.request.urlopen(req, timeout=20) as res:
        return json.loads(res.read())


def verify_id_token(token: str) -> dict[str, Any]:
    doc = discovery()
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "")
    if alg not in ("RS256", "ES256"):
        raise OIDCError(f"unsupported id_token algorithm: {alg}")
    jwks = _cache.get("jwks")
    if jwks is None:
        jwks = _get_json(doc["jwks_uri"])
        _cache["jwks"] = jwks
    kid = header.get("kid")
    keys = [k for k in jwks.get("keys", []) if not kid or k.get("kid") == kid]
    last_error: Optional[Exception] = None
    for key in keys:
        try:
            public = jwt.PyJWK(key).key
            return jwt.decode(token, public, algorithms=[alg],
                              audience=CLIENT_ID, issuer=ISSUER,
                              options={"require": ["exp", "iss", "aud"]})
        except Exception as exc:  # noqa: BLE001 — пробуем следующий ключ
            last_error = exc
    raise OIDCError(f"id_token verification failed: {last_error}")


def _domain_allowed(email: str) -> bool:
    if not ALLOWED_DOMAINS:
        return True
    domain = email.rsplit("@", 1)[-1].lower()
    return domain in ALLOWED_DOMAINS


def callback(code: str, state: str) -> dict[str, Any]:
    if not configured():
        raise OIDCError("SSO is not configured", 503)
    if not code or not _consume_state(state):
        raise OIDCError("invalid or expired state", 400)
    try:
        tokens = _exchange(code)
    except urllib.error.HTTPError as exc:
        # Google отверг код (истёк, повторно использован, неверный redirect).
        # Это ошибка входа, а не падение сервиса: отвечаем 400 с текстом.
        detail = ""
        try:
            detail = exc.read(300).decode("utf-8", "ignore")
        except Exception:
            pass
        raise OIDCError(f"provider rejected the authorization code: {detail[:160]}", 400) from exc
    except Exception as exc:  # noqa: BLE001 — сеть до IdP
        raise OIDCError(f"cannot reach the identity provider: {exc}", 502) from exc
    id_token = tokens.get("id_token")
    if not id_token:
        raise OIDCError("provider did not return id_token", 400)
    claims = verify_id_token(id_token)
    email = str(claims.get("email") or "").strip().lower()
    if not email or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise OIDCError("provider returned no verified email", 400)
    if not claims.get("email_verified", True):
        raise OIDCError("email is not verified by the provider", 403)
    if not _domain_allowed(email):
        raise OIDCError("email domain is not allowed for this workspace", 403)
    from .entitlement import issue
    entitlement = issue(subject=email, days=30)
    return {"email": email, "subject": claims.get("sub"),
            "issuer": claims.get("iss"), "entitlement": entitlement}


# ── Сессия после входа ───────────────────────────────────────────────────────


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64u(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def issue_session(claims: dict[str, Any], entitlement: dict[str, Any]) -> str:
    """Подписанная сессия: email, sub, exp и entitlement. HttpOnly-cookie."""
    from . import signing
    body = {
        "email": claims.get("email"),
        "sub": claims.get("sub"),
        "iss": claims.get("iss"),
        "exp": int(time.time()) + SESSION_TTL,
        "entitlement": entitlement,
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    sig = signing.sign(payload)
    return _b64u(payload) + "." + _b64u(base64.b64decode(sig.signature))


def verify_session(token: str) -> Optional[dict[str, Any]]:
    if not token or "." not in token:
        return None
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _unb64u(payload_b64)
        signature = base64.b64encode(_unb64u(sig_b64)).decode()
        from . import signing
        if not signing.verify(payload, signature, signing.public_key_b64()):
            return None
        body = json.loads(payload)
    except Exception:  # noqa: BLE001 — битая cookie = нет сессии
        return None
    if int(body.get("exp", 0)) < time.time():
        return None
    return body
