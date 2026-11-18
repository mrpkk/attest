"""VAJRA Root Verdict v1: canonical hash, Ed25519 signature, offline verify.

This is the smallest honest artefact of the VAJRA spec: a verdict that can be
checked without the service. It does not scan a repository yet; scanners are
adapters that produce the claims/findings placed into this envelope.

    python3 -m attest.vajra sign verdict.json --key ~/.local/share/attest/signing.key
    python3 -m attest.vajra verify signed.json --key vajra.pub
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .provenance import canonical
from .signing import sign, verify

STATUSES = {
    "SUPPORTED", "REFUTED", "UNSUPPORTED", "OUT_OF_SCOPE",
    "EXPIRED", "REVOKED", "DISPUTED",
}
REQUIRED = (
    "schema", "id", "subject", "scope", "claims", "findings", "verdict",
    "limits", "rules_version", "issued_at", "expires_at", "revocation_url",
    "verdict_hash", "signature", "algorithm",
)
SIGNED_FIELDS = {
    "schema", "id", "subject", "scope", "claims", "findings", "verdict",
    "limits", "rules_version", "hash_alg", "issued_at", "expires_at",
    "revocation_url", "revoked",
}


class VajraError(ValueError):
    """Malformed or unverifiable verdict."""


def _hash(payload: bytes, alg: str = "sha256") -> str:
    if alg == "sha256":
        return "sha256:" + hashlib.sha256(payload).hexdigest()
    if alg == "blake3":
        try:
            import blake3  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise VajraError("hash_alg=blake3 requires the blake3 package") from exc
        return "blake3:" + blake3.blake3(payload).hexdigest()
    raise VajraError(f"unsupported hash_alg: {alg}")


def signed_payload(verdict: dict[str, Any]) -> bytes:
    """Canonical bytes excluding the envelope fields (signature/key/hash)."""
    body = {k: verdict[k] for k in SIGNED_FIELDS if k in verdict}
    return canonical(body)


def verdict_hash(verdict: dict[str, Any]) -> str:
    return _hash(signed_payload(verdict), verdict.get("hash_alg", "sha256"))


def sign_verdict(verdict: dict[str, Any], key_path: Path | None = None) -> dict[str, Any]:
    """Return a signed copy. The input is not mutated."""
    out = dict(verdict)
    out.setdefault("hash_alg", "sha256")
    out["verdict_hash"] = verdict_hash(out)
    result = sign(signed_payload(out), key_path)
    out["signature"] = result.signature
    out["algorithm"] = result.algorithm
    out["public_key"] = result.public_key
    return out


def _read_key(path: str | Path | None) -> str:
    if not path:
        raise VajraError("external public key required: --key <file|base64>")
    p = Path(path)
    if p.is_file():
        text = p.read_text("utf-8").strip()
    else:
        text = str(path).strip()
    if not text:
        raise VajraError("empty public key")
    # accept a bare base64 key or a JSON {"public_key": "..."} file
    if text.startswith("{"):
        try:
            text = json.loads(text)["public_key"]
        except (KeyError, json.JSONDecodeError) as exc:
            raise VajraError(f"bad key JSON: {exc}") from exc
    try:
        base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise VajraError("public key is not base64") from exc
    return text


def _parse_time(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise VajraError(f"bad timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def verify_verdict(data: dict[str, Any], public_key: str | None = None) -> dict[str, Any]:
    """Verify authenticity and current usability of a Root Verdict.

    `ok` means the artifact is authentic and not expired/revoked. The verdict
    itself may legitimately be UNSUPPORTED — that is a result, not tampering.
    """
    errors: list[str] = []
    for field in REQUIRED:
        if field not in data:
            errors.append(f"missing:{field}")
    if errors:
        return {"ok": False, "reason": "malformed", "errors": errors}

    if data.get("schema") != "vajra/root-verdict/1":
        errors.append("schema")
    if data.get("algorithm") != "ed25519":
        errors.append("algorithm")
    if data.get("verdict") not in STATUSES:
        errors.append("verdict")
    if not data.get("limits"):
        errors.append("limits")
    if data.get("hash_alg", "sha256") not in {"sha256", "blake3"}:
        errors.append("hash_alg")

    try:
        expected_hash = verdict_hash(data)
    except VajraError as exc:
        errors.append(str(exc))
        expected_hash = ""
    if expected_hash and data.get("verdict_hash") != expected_hash:
        errors.append("verdict_hash")

    if data.get("revoked") is True or data.get("verdict") == "REVOKED":
        errors.append("revoked")
    try:
        if _parse_time(data["expires_at"]) <= datetime.now(timezone.utc):
            errors.append("expired")
    except (KeyError, VajraError) as exc:
        errors.append(f"expires_at:{exc}")

    key = _read_key(public_key) if public_key else ""
    if not key:
        errors.append("external_key_required")
        signature_ok = False
    else:
        signature_ok = verify(signed_payload(data), data["signature"], key)
        if not signature_ok:
            errors.append("signature")

    if expected_hash and data.get("verdict_hash") != expected_hash:
        reason = "tampered"
    elif errors and "expired" in errors:
        reason = "expired"
    elif errors and "revoked" in errors:
        reason = "revoked"
    elif errors and "signature" in errors:
        reason = "wrong_key"
    elif errors:
        reason = "invalid"
    else:
        reason = "ok"
    return {
        "ok": not errors,
        "reason": reason,
        "errors": errors,
        "verdict": data.get("verdict"),
        "verdict_hash": expected_hash,
    }


def _read_json(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise VajraError(f"file not found: {p}")
    try:
        data = json.loads(p.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VajraError(f"cannot read JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise VajraError("top-level JSON must be an object")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vajra")
    sub = parser.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="verify a Root Verdict offline")
    v.add_argument("file")
    v.add_argument("--key", required=True, help="external Ed25519 public key (file or base64)")

    s = sub.add_parser("sign", help="sign a Root Verdict")
    s.add_argument("file")
    s.add_argument("--key", default=None, help="Ed25519 private key (default: attest key)")
    s.add_argument("--out", default=None)

    args = parser.parse_args(argv)
    try:
        data = _read_json(args.file)
        if args.cmd == "verify":
            result = verify_verdict(data, args.key)
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result["ok"] else 1
        signed = sign_verdict(data, args.key)
        text = json.dumps(signed, ensure_ascii=False, indent=2, sort_keys=True)
        if args.out:
            Path(args.out).write_text(text + "\n", "utf-8")
        else:
            print(text)
        return 0
    except VajraError as exc:
        print(f"vajra: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
