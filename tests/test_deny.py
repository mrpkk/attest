"""Deny evidence: подпись, цепочка, фильтр, обнаружение подмены (29.10.2026)."""

from attest import signing
from attest.deny import append, make_event, query, read, verify_log, verify_record


def _event(i=0):
    return make_event(reason="payee not in allowlist", policy_id="E03-allowlist",
                      task_id=f"task_{i}", artifact_hash="sha256:" + "a" * 8,
                      actor="agent:test", meta={"requested": "12.50"})


def test_append_and_verify_chain(tmp_path, monkeypatch):
    path = tmp_path / "deny.jsonl"
    first = append(_event(1), path)
    second = append(_event(2), path)
    assert second["prev"] == first["hash"]
    result = verify_log(read(path))
    assert result["ok"] is True and result["records"] == 2


def test_record_signature_verifies_with_embedded_key(tmp_path):
    record = append(_event(3), tmp_path / "deny.jsonl")
    ok, why = verify_record(record, record["prev"])
    assert ok and why == "ok"
    assert signing.verify(
        __import__("attest.deny", fromlist=["x"])._canonical(
            {k: v for k, v in record.items() if k not in ("hash", "signature", "public_key", "algorithm")}),
        record["signature"], record["public_key"])


def test_tampered_reason_is_located(tmp_path):
    path = tmp_path / "deny.jsonl"
    append(_event(4), path)
    append(_event(5), path)
    records = read(path)
    records[1]["reason"] = "allowed"
    result = verify_log(records)
    assert result["ok"] is False and result["broken_at"] == 1


def test_query_filters_since(tmp_path):
    path = tmp_path / "deny.jsonl"
    append(make_event(reason="old", policy_id="E1", ts="2026-10-01T00:00:00+00:00"), path)
    append(make_event(reason="new", policy_id="E2", ts="2026-10-29T00:00:00+00:00"), path)
    data = query(since="2026-10-20T00:00:00Z", path=path)
    assert data["count"] == 1 and data["events"][0]["policy_id"] == "E2"


def test_event_requires_reason_and_policy():
    for kwargs in ({"reason": "", "policy_id": "E1"}, {"reason": "x", "policy_id": ""}):
        try:
            make_event(**kwargs)
        except ValueError:
            continue
        raise AssertionError("событие без правила или причины не должно создаваться")
