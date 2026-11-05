"""Квитанция платежа: факт из цепи, подпись Ed25519, офлайн-проверка.

Тесты держат две границы, из-за которых продукт теряет смысл:

* квитанция обязана брать сумму и адреса из цепи, а не из запроса;
* проверка обязана отличать порчу байтов (`tampered`) от чужого ключа
  (`wrong_key`) и от отсутствия подписи (`unsigned`).
"""

from __future__ import annotations

import json
import pathlib
import sys
import threading
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from attest import onchain, payment_receipt, signing
from attest.receipt import jcs

PAY_TO = "0xefCD6886f73064ea9EcbaA4741Ef1309A0885C59"
PAYER = "0x1111111111111111111111111111111111111111"
OTHER = "0x" + "22" * 20
TX = "0x" + "ab" * 32
USDC = onchain.USDC_BASE
TOPIC = onchain.TRANSFER_TOPIC
BLOCK_TIME = 1_760_000_000  # 2025-10-09T08:53:20Z


def _log(*, to: str = PAY_TO, amount: int = 9_000_000) -> dict:
    return {
        "address": USDC,
        "topics": [TOPIC, "0x" + "0" * 24 + PAYER[2:], "0x" + "0" * 24 + to[2:]],
        "data": hex(amount),
    }


@pytest.fixture
def rpc(monkeypatch):
    state = {"receipt": {"status": "0x1", "blockNumber": hex(100),
                         "logs": [_log()]}, "head": 105}

    def fake(url, method, params, timeout=20.0):
        if method == "eth_blockNumber":
            return hex(state["head"])
        if method == "eth_getTransactionReceipt":
            return state["receipt"]
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(BLOCK_TIME)}
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(onchain, "_rpc", fake)
    return state


@pytest.fixture
def key(tmp_path):
    info = signing.generate_keypair(tmp_path / "receipt.key")
    return pathlib.Path(info["key_path"]), info["public_key"]


def _issue(key, **kwargs) -> dict:
    path, _ = key
    return payment_receipt.issue(tx_hash=TX, chain="base", subject="Audit of contract 0xabc",
                                 issuer="attest.rta.lat", key_path=path, **kwargs)


def _canonical(receipt: dict) -> bytes:
    return jcs.dumps(receipt).encode()


class TestIssue:
    def test_facts_come_from_the_chain(self, rpc, key):
        receipt = _issue(key)
        assert receipt["spec"] == "receipt/1"
        assert receipt["amount"] == "9.000000"
        assert receipt["from"] == PAYER.lower()
        assert receipt["to"] == PAY_TO.lower()
        assert receipt["block"] == 100
        assert receipt["timestamp"] == "2025-10-09T08:53:20Z"
        assert receipt["asset"] == "USDC"
        assert receipt["chain"] == "base"

    def test_request_cannot_override_the_amount(self, rpc, key):
        """Сумма из запроса не участвует вовсе: иначе подписывали бы заявление."""
        receipt = _issue(key, to=PAY_TO)
        assert receipt["amount"] == "9.000000"

    def test_recipient_is_optional(self, rpc, key):
        receipt = _issue(key)
        assert receipt["to"] == PAY_TO.lower()

    def test_sender_mismatch_is_rejected(self, rpc, key):
        with pytest.raises(payment_receipt.ReceiptRejected, match="sender does not match"):
            _issue(key, payer=OTHER)

    def test_unknown_chain_is_rejected(self, rpc, key):
        path, _ = key
        with pytest.raises(payment_receipt.ReceiptRejected, match="not supported"):
            payment_receipt.issue(tx_hash=TX, chain="tron", subject="x",
                                  issuer="attest.rta.lat", key_path=path)

    def test_missing_subject_is_rejected(self, rpc, key):
        path, _ = key
        with pytest.raises(payment_receipt.ReceiptRejected, match="subject is required"):
            payment_receipt.issue(tx_hash=TX, chain="base", subject="  ",
                                  issuer="attest.rta.lat", key_path=path)

    def test_several_transfers_need_an_explicit_recipient(self, rpc, key):
        rpc["receipt"]["logs"] = [_log(), _log(to=OTHER, amount=1)]
        with pytest.raises(payment_receipt.ReceiptRejected, match="pass `to`"):
            _issue(key)

    def test_explicit_recipient_selects_one_transfer(self, rpc, key):
        rpc["receipt"]["logs"] = [_log(), _log(to=OTHER, amount=1)]
        receipt = _issue(key, to=OTHER)
        assert receipt["to"] == OTHER
        assert receipt["amount"] == "0.000001"


class TestVerify:
    def test_valid_receipt_is_ok(self, rpc, key):
        verdict = payment_receipt.verify(_canonical(_issue(key)))
        assert verdict.status == "ok", verdict.detail
        assert verdict.key_fingerprint

    def test_changed_byte_is_tampered(self, rpc, key):
        receipt = _issue(key)
        receipt["amount"] = "90.000000"
        verdict = payment_receipt.verify(_canonical(receipt))
        assert verdict.status == "tampered"

    def test_changed_subject_is_tampered(self, rpc, key):
        receipt = _issue(key)
        receipt["subject"] = "Something else entirely"
        assert payment_receipt.verify(_canonical(receipt)).status == "tampered"

    def test_foreign_key_is_wrong_key(self, rpc, key, tmp_path):
        receipt = _issue(key)
        _, foreign = signing.generate_keypair(tmp_path / "foreign.key")
        verdict = payment_receipt.verify(_canonical(receipt), expected_key=foreign)
        assert verdict.status == "wrong_key"
        assert verdict.key_fingerprint

    def test_expected_fingerprint_of_the_issuer_is_ok(self, rpc, key):
        receipt = _issue(key)
        _, public = key
        verdict = payment_receipt.verify(_canonical(receipt),
                                         expected_key=payment_receipt.key_fingerprint(public))
        assert verdict.status == "ok"

    def test_no_signature_is_unsigned(self, rpc, key):
        receipt = _issue(key)
        receipt.pop("signature")
        assert payment_receipt.verify(_canonical(receipt)).status == "unsigned"

    def test_no_public_key_is_unsigned(self, rpc, key):
        receipt = _issue(key)
        receipt.pop("public_key")
        assert payment_receipt.verify(_canonical(receipt)).status == "unsigned"

    def test_unknown_field_is_malformed(self, rpc, key):
        receipt = _issue(key)
        receipt["amount_usd"] = "9.00"
        assert payment_receipt.verify(_canonical(receipt)).status == "malformed"

    def test_without_expected_key_the_note_says_what_was_not_checked(self, rpc, key):
        verdict = payment_receipt.verify(_canonical(_issue(key)))
        assert any("compare" in note for note in verdict.notes)

    def test_pretty_printed_receipt_still_verifies_and_says_so(self, rpc, key):
        receipt = _issue(key)
        verdict = payment_receipt.verify(json.dumps(receipt, indent=2))
        assert verdict.status == "ok"
        assert any("not in canonical form" in note for note in verdict.notes)

    def test_garbage_is_malformed_not_ok(self):
        assert payment_receipt.verify(b"not json").status == "malformed"


# --- HTTP ------------------------------------------------------------------

PORT = 8193


@pytest.fixture(scope="module")
def server():
    from http.server import ThreadingHTTPServer

    from attest.service import AttestHandler

    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", PORT), AttestHandler)
    except OSError:
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), AttestHandler)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield base
    httpd.shutdown()
    httpd.server_close()


def _post(url: str, body: dict) -> tuple[int, dict]:
    request = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


class TestHttp:
    def test_issue_then_verify_roundtrip(self, server, rpc, key, monkeypatch):
        path, public = key
        monkeypatch.setattr(signing, "KEY_PATH", path)
        status, body = _post(f"{server}/api/receipt/issue", {
            "tx_hash": TX, "chain": "base", "subject": "Audit of contract 0xabc",
            "amount": "999.000000",  # попытка навязать сумму — обязана игнорироваться
        })
        assert status == 201, body
        assert body["receipt"]["amount"] == "9.000000"
        assert body["price_usd"] == 0.5
        assert body["payment"]["status"] == "not_enforced"

        text = jcs.dumps(body["receipt"])
        status, verdict = _post(f"{server}/api/receipt/verify",
                                {"receipt": text, "expected_key": public})
        assert status == 200
        assert verdict["verdict"] == "ok", verdict

    def test_unknown_transaction_is_422(self, server, rpc):
        rpc["receipt"] = None
        status, body = _post(f"{server}/api/receipt/issue", {
            "tx_hash": TX, "chain": "base", "subject": "Audit",
        })
        assert status == 422
        assert "not found" in body["error"]

    def test_missing_receipt_field_is_400(self, server):
        status, body = _post(f"{server}/api/receipt/verify", {})
        assert status == 400
        assert "receipt" in body["error"]

    def test_page_is_served(self, server):
        with urllib.request.urlopen(f"{server}/verify-receipt", timeout=10) as response:
            html = response.read().decode()
        assert response.status == 200
        assert "Verify a crypto payment receipt" in html
