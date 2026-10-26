"""Цепь квитанций и контрольная точка.

Профиль: draft-noa-scitt-ai-agent-receipt, §5.1–5.2.

Главное правило этого модуля — и всего продукта: **отказ одного объекта не
становится находкой о другом.** Чужая или битая контрольная точка означает
«хвост цепи не проверен», а не «цепь подделана». Эталонная реализация нарушает
это в двух измеренных местах (G6, G7): при любой непроверенной точке все пять
верификаторов отвечают TAMPERED на честную цепь.

Шесть условий цепи — свойства НАБОРА, а не отдельной квитанции: каждая запись
по отдельности валидна, а ложь видна только при сравнении. Поэтому они
сообщаются все сразу (G9) и различимо (G10), а не «первое найденное».
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs, schema, verify

CHECKPOINT_DOMAIN = b"NOA-Checkpoint-v0.1-sig:"
CHECKPOINT_SPEC = "noa.checkpoint/0.1"

CONDITIONS = (
    "chain-link-broken",
    "chain-sequence-duplicate",
    "chain-sequence-gap",
    "chain-scope-mismatch",
    "chain-tenant-split",
    "chain-key-discontinuity",
)


@dataclass
class ChainVerdict:
    ok: bool
    conditions: list[str] = field(default_factory=list)
    checkpoint: dict[str, Any] = field(default_factory=dict)
    per_receipt: list[dict[str, Any]] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def why(self) -> str:
        parts = list(self.conditions)
        if self.checkpoint.get("state") == "unusable":
            parts.append(f"checkpoint: {self.checkpoint.get('reason')}")
        return "; ".join(parts)


def checkpoint_input(cp: dict) -> str:
    body = {k: v for k, v in cp.items() if k != "sig"}
    sig = {k: v for k, v in (cp.get("sig") or {}).items() if k != "value"}
    if sig:
        body["sig"] = sig
    return jcs.dumps(body)


def checkpoint_message(cp: dict) -> bytes:
    return CHECKPOINT_DOMAIN + hashlib.sha256(checkpoint_input(cp).encode()).digest()


def sign_checkpoint(cp: dict, private_key) -> dict:
    out = dict(cp)
    sig = dict(out.get("sig") or {})
    sig["alg"] = "ed25519"
    sig.pop("value", None)
    out["sig"] = sig
    sig["value"] = base64.b64encode(private_key.sign(checkpoint_message(out))).decode()
    return out


def _lookup(keyring: dict[str, Any], kid: str) -> list[bytes]:
    value = keyring.get(kid)
    if value is None:
        return []
    if isinstance(value, (bytes, bytearray)):
        return [bytes(value)]
    return [bytes(k) for k in value]


def _checkpoint_state(cp: Any, keyring: dict, chain_id: str, receipts_by_seq: dict[int, dict]) -> dict:
    if cp is None:
        return {"state": "unanswered", "result": None,
                "reason": "no checkpoint supplied: the tail question is unanswered, not clean"}
    if not isinstance(cp, dict):
        return {"state": "unusable", "result": None, "reason": "checkpoint is not an object"}
    if cp.get("spec") != CHECKPOINT_SPEC:
        return {"state": "unusable", "result": None, "reason": "unknown checkpoint spec"}
    if cp.get("chain") != chain_id:
        return {"state": "unusable", "result": None,
                "reason": "checkpoint names another chain: a finding about the checkpoint, not about the chain"}

    body = {k: v for k, v in cp.items() if k != "sig"}
    expected_keys = {"spec", "chain", "highestSeq", "headHash", "ts"}
    if set(body) != expected_keys:
        return {"state": "unusable", "result": None, "reason": "checkpoint carries unexpected members"}
    if not isinstance(cp.get("highestSeq"), int) or cp["highestSeq"] < 0:
        return {"state": "unusable", "result": None, "reason": "highestSeq must be an integer >= 0"}
    if not isinstance(cp.get("headHash"), str) or not schema.HASH_RE.match(cp["headHash"]):
        return {"state": "unusable", "result": None, "reason": "headHash is not sha256:<64 lowercase hex>"}
    ok_ts, why_ts = schema.valid_timestamp(cp.get("ts"))
    if not ok_ts:
        return {"state": "unusable", "result": None, "reason": f"checkpoint ts: {why_ts}"}

    sig = cp.get("sig") or {}
    if sig.get("alg") != "ed25519":
        return {"state": "unusable", "result": None, "reason": "checkpoint sig.alg must be ed25519"}
    try:
        raw_sig = base64.b64decode(str(sig.get("value", "")), validate=True)
    except (binascii.Error, ValueError):
        return {"state": "unusable", "result": None, "reason": "checkpoint signature is not base64"}
    if base64.b64encode(raw_sig).decode() != str(sig.get("value", "")):
        return {"state": "unusable", "result": None, "reason": "checkpoint signature is not canonical base64"}

    candidates = _lookup(keyring, str(sig.get("kid", "")))
    if not candidates:
        return {"state": "unusable", "result": None,
                "reason": "checkpoint-unverified: no key for this kid in the keyring"}
    verified = 0
    for key in candidates:
        key_ok, _ = verify.check_key(key)
        if not key_ok:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(raw_sig, checkpoint_message(cp))
            verified += 1
        except InvalidSignature:
            continue
    if verified == 0:
        return {"state": "unusable", "result": None,
                "reason": "checkpoint-unverified: signature does not verify against this keyring"}
    if verified > 1:
        return {"state": "unusable", "result": None,
                "reason": "checkpoint kid resolves to more than one key: ambiguous"}
    if not receipts_by_seq:
        return {"state": "unusable", "result": None, "reason": "no receipts to compare against"}

    head_seq = max(receipts_by_seq)
    head_hash = (receipts_by_seq[head_seq].get("chain") or {}).get("hash")
    if cp["highestSeq"] == head_seq and cp["headHash"] == head_hash:
        return {"state": "answered", "result": "consistent", "reason": "head matches the checkpoint"}
    anchor = receipts_by_seq.get(cp["highestSeq"])
    if anchor is not None and (anchor.get("chain") or {}).get("hash") == cp["headHash"] and head_seq > cp["highestSeq"]:
        # Цепь выросла после выдачи точки: это расширение, а не конфликт (G7).
        return {"state": "answered", "result": "consistent",
                "reason": f"presented chain extends the checkpoint: seq {cp['highestSeq']} -> {head_seq}"}
    return {"state": "answered", "result": "checkpoint-head-conflict",
            "reason": "presented head and an authenticated checkpoint disagree; the cause is not established"}


def verify_chain(
    receipts: list[dict],
    keyring: dict[str, Any],
    *,
    checkpoint: dict | None = None,
    manifest: dict[str, list[str]] | None = None,
) -> ChainVerdict:
    if not receipts:
        return ChainVerdict(False, ["chain-sequence-gap"], {"state": "unanswered", "result": None,
                                                            "reason": "empty set"}, [], {})

    conditions: set[str] = set()
    per_receipt: list[dict] = []

    # Каждая квитанция проверяется отдельно; непроверенная подпись — это
    # статус записи, а не приговор цепи.
    for receipt in receipts:
        kid = str((receipt.get("sig") or {}).get("kid", ""))
        keys = _lookup(keyring, kid)
        if not keys:
            per_receipt.append({"id": receipt.get("id"), "status": "untrusted",
                                "why": "no key for this kid in the keyring"})
            continue
        if len(keys) > 1:
            # G11: kid, за которым стоит больше одного ключа, не называет
            # сторону. Подпись может сойтись с одним из них, но сама
            # идентификация неоднозначна, и это сообщается отдельным полем.
            outcomes = [verify.verify_receipt(receipt, k) for k in keys]
            ok_count = sum(1 for o in outcomes if o.ok)
            entry = {"id": receipt.get("id"), "kid_ambiguous": True,
                     "why": f"kid {kid!r} resolves to {len(keys)} keys"}
            if ok_count == 0:
                entry.update(status="untrusted", why=entry["why"] + "; no key verifies")
            elif ok_count > 1:
                entry.update(status="ambiguous", why=entry["why"] + f"; {ok_count} keys verify")
            else:
                entry.update(status="valid", why=entry["why"] + "; exactly one verifies")
            per_receipt.append(entry)
            continue
        outcome = verify.verify_receipt(receipt, keys[0])
        per_receipt.append({"id": receipt.get("id"),
                            "status": "valid" if outcome.ok else outcome.status,
                            "why": "" if outcome.ok else outcome.why()})

    seqs = [(r.get("chain") or {}).get("seq") for r in receipts]
    if any(not isinstance(s, int) or isinstance(s, bool) or s < 0 for s in seqs):
        conditions.add("chain-sequence-gap")
        return ChainVerdict(False, sorted(conditions), _checkpoint_state(checkpoint, keyring, "", {}),
                            per_receipt, {"note": "a receipt has no usable chain.seq"})

    if len(set(seqs)) != len(seqs):
        conditions.add("chain-sequence-duplicate")
    if sorted(set(seqs)) != list(range(len(set(seqs)))):
        conditions.add("chain-sequence-gap")

    chains = {(r.get("scope") or {}).get("chain") for r in receipts}
    if len(chains) > 1:
        conditions.add("chain-scope-mismatch")
    chain_id = next(iter(chains)) if len(chains) == 1 else ""

    # Арендатор: отсутствие не сбрасывает сравнение, иначе пропуск поля
    # становится каналом для склейки двух историй.
    tenants = [((r.get("scope") or {}).get("tenant")) for r in receipts if (r.get("scope") or {}).get("tenant") is not None]
    if len(set(tenants)) > 1:
        conditions.add("chain-tenant-split")

    by_agent: dict[str, set[str]] = {}
    for r in receipts:
        agent_id = (r.get("agent") or {}).get("id")
        kid = (r.get("sig") or {}).get("kid")
        if agent_id and kid:
            by_agent.setdefault(str(agent_id), set()).add(str(kid))
    if any(len(kids) > 1 for kids in by_agent.values()):
        conditions.add("chain-key-discontinuity")

    ordered = sorted(receipts, key=lambda r: (r.get("chain") or {}).get("seq", -1))
    for index, receipt in enumerate(ordered):
        chain = receipt.get("chain") or {}
        prev = chain.get("prevHash")
        if index == 0:
            if chain.get("seq") != 0:
                conditions.add("chain-sequence-gap")
            if prev is not None:
                conditions.add("chain-link-broken")
            continue
        prior = (ordered[index - 1].get("chain") or {}).get("hash")
        if prev != prior:
            conditions.add("chain-link-broken")

    by_seq = {(r.get("chain") or {}).get("seq"): r for r in receipts}
    checkpoint_state = _checkpoint_state(checkpoint, keyring, chain_id, by_seq)

    # G16: точка, подписанная доверенным ключом, ещё не привязана к цепи.
    # Право подписи принадлежит тому, кто открыл цепь.
    if manifest is not None and checkpoint_state.get("state") == "answered":
        opener = by_seq.get(0) or {}
        opener_agent = str((opener.get("agent") or {}).get("id", ""))
        cp_kid = str(((checkpoint or {}).get("sig") or {}).get("kid", ""))
        allowed = manifest.get(opener_agent)
        if allowed is not None and cp_kid not in allowed:
            checkpoint_state = {"state": "unusable", "result": None,
                                "reason": "UNTRUSTED: the checkpoint key is not authorized "
                                          "for the agent that opened the chain"}

    ok = not conditions
    ambiguous = [r["id"] for r in per_receipt if r.get("kid_ambiguous")]
    return ChainVerdict(ok, sorted(conditions), checkpoint_state, per_receipt,
                        {"chain": chain_id, "count": len(receipts),
                         "all_conditions_reported": True,
                         "ambiguous_kids": ambiguous})
