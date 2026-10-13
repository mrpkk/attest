"""
Verify an AI agent artifact with attest — four layers, one call.

Windmill resource script. Uses only stdlib so it needs no dependencies.

Four questions, four layers, none substituting for another:
  1. form      — does it match the schema?
  2. emptiness  — is there anything inside it?
  3. provenance — what conditions produced it?
  4. authority  — was the action permitted?

The last three are what a schema validator cannot tell you. An agent told
to find five vulnerabilities returns five identical items, and that artifact
passes every schema check because the form is perfect.

Example:
    r = main(
        artifact={"summary": "Analysis complete",
                  "findings": ["reentrancy in withdraw"]},
        source="nightly-audit",
    )
    r["verdict"]          # accept | review | reject
    r["emptiness"]        # CONTENT_PRESENT | THIN_CONTENT | VALID_BUT_EMPTY
    r["generation"]       # CHAIN_VERIFIED | CHAIN_MISMATCH | NO_CHAIN
    r["authority"]        # allowed | rule that denied

To verify a returned attestation without trusting this service:
    attest/verify_standalone.py attestation.json
"""

import urllib.request
import urllib.error
import json as _json
from typing import Any, Optional

ATTEST_URL = "https://attest.rta.lat/verify"


def _post(url: str, payload: dict, timeout: int = 30) -> dict:
    req = urllib.request.Request(
        url,
        data=_json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            # Без User-Agent Cloudflare отвечает 1010 и скрипт не работает
            # ни у кого, кроме тех, кто знает об этом. Проверено: пустой
            # заголовок приводит к ошибке на любом обращении.
            "User-Agent": "windmill-attest-script/1.0 (+https://attest.rta.lat)",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return _json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # An HTTP error body still carries the reason: 402 means a payment
        # is required, 404 means a wrong path. Losing them would leave the
        # caller guessing.
        raw = exc.read().decode("utf-8", "replace")
        try:
            return {"http_status": exc.code, **_json.loads(raw)}
        except _json.JSONDecodeError:
            return {"http_status": exc.code, "error": raw[:200]}


def main(
    artifact: Any,
    source: str = "windmill",
    url: str = ATTEST_URL,
    generation: Optional[dict] = None,
    mandate: Optional[dict] = None,
    action: Optional[dict] = None,
) -> dict:
    """
    Verify an artifact.

    :param artifact: the artifact as a JSON value — dict, list or scalar
    :param source: free-form label telling where it came from
    :param url: attest endpoint; override to point at your own deployment
    :param generation: model, model_version, prompt, parameters,
                       generated_at, generator — bind the artifact to the
                       conditions it came from
    :param mandate: payee_id, audience, max_amount_minor, currency,
                    valid_from, valid_until, allowed_intents
    :param action: payee_id, audience, amount_minor, currency, at, intent

    :return: the full attest response
    :raises ValueError: if neither mandate nor action is a dict
    """
    if (mandate is None) != (action is None):
        raise ValueError(
            "mandate and action must be given together: authority is "
            "checked against a specific action, not in the abstract"
        )
    payload: dict = {"artifact": artifact, "source": source}
    if generation is not None:
        payload["generation"] = generation
    if mandate is not None:
        payload["mandate"] = mandate
        payload["action"] = action
    return _post(url, payload)


def summarize(result: dict) -> str:
    """One line for a log or a Slack message."""
    if "error" in result and "verdict" not in result:
        return f"attest unavailable: {result.get('error', '')[:80]}"
    emp = (result.get("emptiness") or {}).get("verdict", "-")
    auth = result.get("authority") or {}
    allowed = "yes" if auth.get("allowed") else f"no ({auth.get('rule', 'unchecked')})"
    return (
        f"{result.get('verdict', '?').upper()} "
        f"trust={result.get('trust_score', 0):.0f} "
        f"emptiness={emp} authority={allowed}"
    )
