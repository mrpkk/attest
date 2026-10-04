"""Тесты приёма оплаты: подпись, сумма, получатель, повтор, окно.

Два независимых источника правды используются одновременно:

* `eth_account` как эталонная реализация подписи EIP-712 — наш расчёт
  digest обязан совпасть с ней побайтово;
* собственный код как проверяемый — он не должен доверять ни одному полю,
  пришедшему от клиента.

Ключевой тест `test_digest_matches_reference` ловил бы перестановку полей в
типе EIP-712: хеш получается правдоподобным, но другим, и подпись не сойдётся.
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys

import pytest

from attest.payment import (
    PaymentError,
    PaymentRequirement,
    authorization_digest,
    parse_payment,
    recover_signer,
    verify_payment,
)
from attest.service import TokenDomainUnknown, build_challenge, eip712_domain

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "agentpay"))

eth_account = pytest.importorskip("eth_account", reason="нужен eth-account для проверки подписи")
from eth_account import Account  # noqa: E402
from eth_account.messages import encode_typed_data  # noqa: E402

PAY_TO = "0x" + "aa" * 20
PRICE = 5000
NOW = 1_800_000_000

TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


def challenge(price: int = PRICE):
    _, ch = build_challenge(
        resource="https://attest.example/verify", pay_to=PAY_TO, price_atoms=price
    )
    return ch


def requirement(price: int = PRICE) -> PaymentRequirement:
    return PaymentRequirement.from_challenge(challenge(price))


def _dom():
    from attest.service import USDC_BASE

    return eip712_domain("eip155:8453", USDC_BASE)


def sign(auth: dict, account: Account) -> str:
    dom = _dom()
    signable = encode_typed_data(full_message={
        "types": TYPES,
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": dom.name,
            "version": dom.version,
            "chainId": dom.chain_id,
            "verifyingContract": dom.verifying_contract,
        },
        "message": auth,
    })
    return "0x" + account.sign_message(signable).signature.hex()


def authorization(account: Account, **overrides) -> dict:
    auth = {
        "from": account.address,
        "to": PAY_TO,
        "value": str(PRICE),
        "validAfter": "0",
        "validBefore": str(NOW + 300),
        "nonce": "0x" + "11" * 32,
    }
    auth.update(overrides)
    return auth


def header(auth: dict, signature: str) -> str:
    body = {
        "x402Version": 2,
        "scheme": "exact",
        "network": "eip155:8453",
        "payload": {"signature": signature, "authorization": auth},
    }
    return base64.b64encode(json.dumps(body).encode()).decode()


@pytest.fixture
def payer():
    return Account.from_key("0x" + "7a" * 32)


class TestDigestAgainstReference:
    def test_digest_matches_reference_implementation(self):
        """Побайтовое совпадение с eth_account — иначе подпись не сойдётся."""
        from Crypto.Hash import keccak as K

        req = requirement()
        auth = authorization(Account.from_key("0x" + "7a" * 32))
        mine = authorization_digest(req, auth, _dom())
        signable = encode_typed_data(full_message={
            "types": TYPES,
            "primaryType": "TransferWithAuthorization",
            "domain": {
                "name": "USD Coin", "version": "2", "chainId": 8453,
                "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            },
            "message": auth,
        })
        h = K.new(digest_bits=256)
        h.update(b"\x19" + bytes([1]) + signable.header + signable.body)
        assert mine == h.digest()

    def test_type_string_field_order_is_type_then_name(self):
        """`string name`, а не `name string`: перестановка тихо ломает хеш."""
        from attest.payment import EIP712_DOMAIN_FIELDS

        built = "EIP712Domain(" + ",".join(
            f"{kind} {name}" for name, kind in EIP712_DOMAIN_FIELDS
        ) + ")"
        assert built == (
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        )


class TestSignatureRecovery:
    def test_signer_is_recovered_from_raw_digest_without_eip191(self, payer):
        """Префикс EIP-191 здесь дал бы чужой адрес и отверг бы оплату."""
        req = requirement()
        auth = authorization(payer)
        signature = sign(auth, payer)
        digest = authorization_digest(req, auth, _dom())
        assert recover_signer(digest, signature).lower() == payer.address.lower()

    def test_wrong_length_signature_is_refused(self, payer):
        digest = authorization_digest(requirement(), authorization(payer), _dom())
        for bad in ("0xdead", "0x" + "11" * 64, ""):
            with pytest.raises(PaymentError):
                recover_signer(digest, bad)


class TestVerifyPayment:
    def test_valid_payment_is_accepted(self, payer):
        auth = authorization(payer)
        payment = verify_payment(
            requirement(), header(auth, sign(auth, payer)), _dom(), now=NOW
        )
        assert payment.payer.lower() == payer.address.lower()
        assert payment.amount_atoms == PRICE
        assert payment.pay_to.lower() == PAY_TO.lower()

    def test_signature_of_another_key_is_refused(self, payer):
        other = Account.from_key("0x" + "5b" * 32)
        auth = authorization(payer)
        with pytest.raises(PaymentError, match="подпись принадлежит"):
            verify_payment(requirement(), header(auth, sign(auth, other)), _dom(), now=NOW)

    def test_tampered_amount_is_refused(self, payer):
        auth = authorization(payer)
        signature = sign(auth, payer)
        tampered = dict(auth, value="1")
        with pytest.raises(PaymentError, match="не равна"):
            verify_payment(requirement(), header(tampered, signature), _dom(), now=NOW)

    def test_tampered_payee_is_refused(self, payer):
        auth = authorization(payer)
        signature = sign(auth, payer)
        with pytest.raises(PaymentError, match="адресован"):
            verify_payment(requirement(), header(dict(auth, to="0x" + "bb" * 20), signature), _dom(), now=NOW)

    def test_tampered_nonce_breaks_signature(self, payer):
        auth = authorization(payer)
        signature = sign(auth, payer)
        with pytest.raises(PaymentError):
            verify_payment(
                requirement(), header(dict(auth, nonce="0x" + "22" * 32), signature), _dom(), now=NOW
            )

    def test_expired_payment_is_refused(self, payer):
        auth = authorization(payer, validBefore=str(NOW - 1))
        with pytest.raises(PaymentError, match="просрочена"):
            verify_payment(requirement(), header(auth, sign(auth, payer)), _dom(), now=NOW)

    def test_not_yet_valid_payment_is_refused(self, payer):
        auth = authorization(payer, validAfter=str(NOW + 600))
        with pytest.raises(PaymentError, match="ещё не действует"):
            verify_payment(requirement(), header(auth, sign(auth, payer)), _dom(), now=NOW)

    def test_too_long_window_is_refused(self, payer):
        auth = authorization(payer, validBefore=str(NOW + 100_000))
        with pytest.raises(PaymentError, match="превышает"):
            verify_payment(requirement(), header(auth, sign(auth, payer)), _dom(), now=NOW)

    def test_replayed_nonce_is_refused(self, payer):
        auth = authorization(payer)
        seen: set[str] = set()
        signature = sign(auth, payer)
        verify_payment(requirement(), header(auth, signature), _dom(), now=NOW, seen_nonces=seen)
        with pytest.raises(PaymentError, match="уже использован"):
            verify_payment(requirement(), header(auth, signature), _dom(), now=NOW, seen_nonces=seen)

    def test_wrong_network_is_refused(self, payer):
        auth = authorization(payer)
        signature = sign(auth, payer)
        raw = base64.b64decode(header(auth, signature)).decode()
        body = json.loads(raw)
        body["network"] = "eip155:1"
        with pytest.raises(PaymentError, match="сеть платежа"):
            verify_payment(
                requirement(),
                base64.b64encode(json.dumps(body).encode()).decode(),
                _dom(),
                now=NOW,
            )

    def test_unknown_token_domain_is_refused(self, payer):
        with pytest.raises(TokenDomainUnknown):
            eip712_domain("eip155:8453", "0x" + "11" * 20)


class TestParsePayment:
    def test_empty_header_is_refused(self):
        with pytest.raises(PaymentError, match="пуст"):
            parse_payment("")

    def test_garbage_is_refused(self):
        with pytest.raises(PaymentError):
            parse_payment("не-base64-вовсе!!")

    def test_missing_authorization_is_refused(self, payer):
        body = {"x402Version": 2, "scheme": "exact", "payload": {"signature": "0x" + "11" * 65}}
        with pytest.raises(PaymentError, match="нет авторизации"):
            parse_payment(base64.b64encode(json.dumps(body).encode()).decode())

    def test_missing_field_is_named(self, payer):
        body = {
            "x402Version": 2, "scheme": "exact",
            "payload": {"signature": "0x" + "11" * 65, "authorization": {"from": "0x1"}},
        }
        with pytest.raises(PaymentError, match="'to'"):
            parse_payment(base64.b64encode(json.dumps(body).encode()).decode())

    def test_wrong_scheme_is_refused(self, payer):
        auth = authorization(payer)
        body = {
            "x402Version": 2, "scheme": "permit",
            "payload": {"signature": "0x" + "11" * 65, "authorization": auth},
        }
        with pytest.raises(PaymentError, match="схема"):
            parse_payment(base64.b64encode(json.dumps(body).encode()).decode())

class TestDomainTableDrift:
    """Таблицы доменов в attest и agentpay не должны разъехаться.

    Одинаковые протокольные константы в двух пакетах — это всегда риск: одно
    правится, второе забывают, и подписи перестают сходиться в тишине.
    """

    def test_matches_agentpay_if_available(self):
        try:
            from agentpay import x402 as agent_x402
        except ImportError:
            pytest.skip("agentpay не в пути импорта")
        from attest.service import VERIFIED_DOMAINS

        theirs = {
            (net, asset.lower()): (
                d.name, d.version, d.verifying_contract, d.chain_id
            )
            for (net, asset), d in agent_x402.VERIFIED_DOMAINS.items()
        }
        ours = {
            key: (d.name, d.version, d.verifying_contract, d.chain_id)
            for key, d in VERIFIED_DOMAINS.items()
        }
        assert ours == theirs, f"таблицы доменов разошлись:\nattest: {ours}\nagentpay: {theirs}"


class TestRealV2WireFormat:
    """Формат v2 в том виде, в каком его принимает настоящий фасилитатор.

    Найдено 2026-10-03 проверкой на x402.org/facilitator: в платеже схема,
    сеть, сумма и получатель лежат в блоке `accepted`, а не на верхнем
    уровне. Наш прежний парсер искал их наверху и отверг бы каждую
    настоящую оплату.
    """

    def test_accepted_block_is_parsed(self):
        det = {
            "scheme": "exact", "network": "eip155:84532", "amount": "5000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x" + "aa" * 20, "maxTimeoutSeconds": 300,
            "extra": {"name": "USDC", "version": "2"},
        }
        auth = {
            "from": "0x" + "9c" * 20, "to": "0x" + "aa" * 20, "value": "5000",
            "validAfter": "0", "validBefore": str(NOW + 300), "nonce": "0x" + "4d" * 32,
        }
        body = {
            "x402Version": 2, "accepted": det,
            "payload": {"signature": "0x" + "11" * 65, "authorization": auth},
        }
        payload, parsed_auth, signature = parse_payment(
            base64.b64encode(json.dumps(body).encode()).decode()
        )
        assert parsed_auth["from"] == auth["from"]
        assert signature.startswith("0x")
        from attest.payment import _details

        assert _details(payload)["scheme"] == "exact"
        assert _details(payload)["network"] == "eip155:84532"

    def test_top_level_scheme_still_accepted_for_v1(self):
        """v1 держит поля наверху — отбрасывать его нельзя."""
        payer = Account.from_key("0x" + "7a" * 32)
        auth = authorization(payer)
        body = {
            "x402Version": 1, "scheme": "exact", "network": "eip155:8453",
            "payload": {"signature": sign(auth, payer), "authorization": auth},
        }
        parsed, parsed_auth, _ = parse_payment(
            base64.b64encode(json.dumps(body).encode()).decode()
        )
        from attest.payment import _details

        assert _details(parsed)["scheme"] == "exact"
        assert _details(parsed)["network"] == "eip155:8453"
        assert parsed_auth["to"] == PAY_TO

    def test_v2_payment_without_accepted_is_rejected(self):
        """Нет блока accepted и нет scheme наверху — платёж негоден."""
        auth = {
            "from": "0x" + "9c" * 20, "to": "0x" + "aa" * 20, "value": "5000",
            "validAfter": "0", "validBefore": str(NOW + 300), "nonce": "0x" + "4d" * 32,
        }
        body = {"x402Version": 2, "payload": {"signature": "0x" + "11" * 65, "authorization": auth}}
        with pytest.raises(PaymentError, match="схема"):
            parse_payment(base64.b64encode(json.dumps(body).encode()).decode())


class TestSepoliaDomain:
    """Имя в домене различается между сетями — это подтверждено фасилитатором."""

    def test_mainnet_and_sepolia_names_differ(self):
        from attest.service import USDC_BASE, USDC_BASE_SEPOLIA, eip712_domain

        assert eip712_domain("eip155:8453", USDC_BASE).name == "USD Coin"
        assert eip712_domain("eip155:84532", USDC_BASE_SEPOLIA).name == "USDC"

    def test_mixing_mainnet_domain_into_sepolia_would_break_signature(self):
        """Домен должен подбираться по сети, а не быть единственным константом."""
        from attest.service import TokenDomainUnknown, USDC_BASE, USDC_BASE_SEPOLIA

        with pytest.raises(TokenDomainUnknown):
            eip712_domain("eip155:84532", USDC_BASE.lower())
        assert eip712_domain("eip155:84532", USDC_BASE_SEPOLIA).chain_id == 84532
