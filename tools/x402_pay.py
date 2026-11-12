#!/usr/bin/env python3
"""Плательщик x402: подписать оплату по челленджу и проверить, что деньги дошли.

Зачем. Клиента, который умеет платить нашим серверам, у нас не было: до
13.11.2026 платёж на Base Sepolia делался вручную, а агентские клиенты
(x402-fetch и подобные) на нашем собственном формате челленджа не проверялись.
Этот скрипт делает ровно то, что делает агент: получает 402, читает
`Payment-Required`, подписывает EIP-3009 авторизацию и повторяет запрос с
заголовком `X-PAYMENT`.

Что он доказывает. Полный путь на тестовой сети: челлендж → подпись →
проверка подписи сервером → расчёт фасилитатором → транзакция → чек по
публичной ноде. Газ платит фасилитатор, поэтому плательщику ETH не нужно:
достаточно тестовых USDC.

Живой тест на Base Sepolia (поднимает локальный экземпляр сервиса):

    python3 tools/x402_pay.py --local

Оплатить живой сервис по URL:

    python3 tools/x402_pay.py --url https://attest.rta.lat/verify \
        --artifact '{"summary":"ok","findings":["a"]}'
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASE_SEPOLIA = "eip155:84532"
USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
PAY_TO = "0xefCD6886f73064ea9EcbaA4741Ef1309A0885C59"

#: Типы EIP-3009 — те же, что сервер считает в `attest.payment`.
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


def decode_challenge(raw: str) -> dict[str, Any]:
    padded = raw + "=" * (-len(raw) % 4)
    return json.loads(base64.b64decode(padded).decode("utf-8"))


def chain_id(network: str) -> int:
    if network.startswith("eip155:"):
        return int(network.split(":", 1)[1])
    raise SystemExit(f"сеть {network!r} не в формате eip155:<chainId>")


def build_authorization(requirement: Any, from_addr: str) -> dict[str, str]:
    now = int(time.time())
    return {
        "from": from_addr,
        "to": requirement.pay_to,
        "value": str(requirement.amount_atoms),
        # Окно в 5 минут: клиент не должен получить подпись, которая протухнет
        # в очереди фасилитатора, но и не должен подписать «на вечность».
        "validAfter": str(now - 60),
        "validBefore": str(now + 300),
        "nonce": "0x" + secrets.token_bytes(32).hex(),
    }


def sign_authorization(requirement: Any, auth: dict[str, str],
                       private_key: str, domain: Any) -> str:
    """Подписать авторизацию и **сверить хеш с серверным**.

    Сверка обязательна: если подпись посчитана по другому домену или типу,
    сервис отвергнет её, а фасилитатор — потратит газ. Лучше упасть здесь.
    """
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    from attest import payment as payment_mod

    typed = encode_typed_data(
        domain_data={
            "name": domain.name,
            "version": domain.version,
            "chainId": domain.chain_id,
            "verifyingContract": domain.verifying_contract,
        },
        message_types=TYPES,
        message_data={
            "from": auth["from"],
            "to": auth["to"],
            "value": int(auth["value"]),
            "validAfter": int(auth["validAfter"]),
            "validBefore": int(auth["validBefore"]),
            "nonce": bytes.fromhex(auth["nonce"][2:]),
        },
    )
    server_digest = payment_mod.authorization_digest(requirement, auth, domain)
    # `typed.body` — хеш структуры, а не подписываемый дайджест. Подписывается
    # keccak(0x19 0x01 ‖ домен ‖ структура) — ровно то, что считает сервер.
    from eth_utils import keccak
    client_digest = keccak(b"\x19\x01" + bytes(typed.header) + bytes(typed.body))
    if bytes(client_digest) != server_digest:
        raise SystemExit(
            "EIP-712 digest не совпал с серверным — подпись принята не будет, "
            "газ сгорит впустую"
        )
    signed = Account.sign_message(typed, private_key=private_key)
    signature = signed.signature.hex()
    return signature if signature.startswith("0x") else "0x" + signature


def payment_header(requirement: Any, auth: dict[str, str], signature: str,
                   challenge: dict[str, Any]) -> str:
    """Собрать заголовок оплаты в формате x402 v2.

    В v2 блок требований лежит в `accepted`, а не на верхнем уровне: без него
    фасилитатор отвечает `invalid_payload: accepted: expected object`. Наш
    сервер это понимает (`attest.payment._details`), а фасилитатор — нет.
    """
    accepted = dict((challenge.get("accepts") or [{}])[0])
    payload = {
        "x402Version": 2,
        "resource": challenge.get("resource", {}),
        "accepted": accepted,
        "scheme": accepted.get("scheme", "exact"),
        "network": requirement.network,
        "payload": {"signature": signature, "authorization": auth},
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.b64encode(raw).decode()


def http_json(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def pay(url: str, artifact: dict[str, Any], private_key: str,
        warmup: bool = False) -> dict[str, Any]:
    """Оплатить один вызов и вернуть честный отчёт о том, что произошло."""
    from attest.payment import PaymentRequirement
    from attest.service import eip712_domain

    body = json.dumps({"artifact": artifact, "source": "x402_pay"}).encode()
    if warmup:
        # Бесплатный лимит нельзя обнулить через окружение: `_env_int`
        # считает ноль ошибкой конфигурации. Поэтому лимит выбирается честно —
        # бесплатными вызовами, пока сервис не ответит 402.
        for _ in range(10):
            status, _, _ = http_json(url, body, {"Content-Type": "application/json"})
            if status == 402:
                break
            if status != 200:
                raise SystemExit(f"прогрев не прошёл: статус {status}")
        else:
            raise SystemExit("бесплатный лимит не исчерпан за 10 вызовов — проверить нечего")
    status, headers, raw = http_json(url, body, {"Content-Type": "application/json"})
    report: dict[str, Any] = {"url": url, "first_status": status}
    if status != 402:
        report["result"] = "оплата не потребовалась" if status == 200 else "ошибка"
        report["body"] = raw.decode("utf-8", "replace")[:400]
        return report

    token = headers.get("payment-required")
    challenge = decode_challenge(token) if token else json.loads(raw)
    requirement = PaymentRequirement.from_challenge(challenge)
    domain = eip712_domain(requirement.network, requirement.asset)
    from eth_account import Account
    payer = Account.from_key(private_key).address
    auth = build_authorization(requirement, payer)
    signature = sign_authorization(requirement, auth, private_key, domain)
    report["requirement"] = {
        "network": requirement.network,
        "asset": requirement.asset,
        "amount_atoms": requirement.amount_atoms,
        "pay_to": requirement.pay_to,
        "payer": payer,
    }
    status, headers, raw = http_json(
        url, body,
        {"Content-Type": "application/json",
         "X-PAYMENT": payment_header(requirement, auth, signature, challenge)},
    )
    report["paid_status"] = status
    report["settlement"] = headers.get("x-payment-response", "")[:200]
    try:
        report["body"] = json.loads(raw)
    except Exception:
        report["body"] = raw.decode("utf-8", "replace")[:400]
    return report


def local_server(port: int = 8757) -> str:
    """Локальный экземпляр сервиса на Base Sepolia с нулевым бесплатным лимитом."""
    os.environ.setdefault("ATTEST_FREE_DAILY", "0")
    os.environ.setdefault("ATTEST_PAY_TO", PAY_TO)
    os.environ.setdefault("ATTEST_NETWORK", BASE_SEPOLIA)
    os.environ.setdefault("ATTEST_ASSET", USDC_BASE_SEPOLIA)
    os.environ.setdefault("ATTEST_FACILITATOR", "https://facilitator.payai.network")
    os.environ.setdefault("ATTEST_PRICE_ATOMS", "5000")
    # Нода Base Sepolia: сервер сам читает логи транзакции и выдаёт чек.
    os.environ.setdefault("ATTEST_RPC_URL", "https://sepolia.base.org")

    import threading

    from attest.service import serve

    threading.Thread(target=serve, kwargs={"host": "127.0.0.1", "port": port},
                     daemon=True).start()
    time.sleep(1.5)
    return f"http://127.0.0.1:{port}/verify"


def main() -> None:
    ap = argparse.ArgumentParser(description="оплатить один вызов attest по x402")
    ap.add_argument("--url", default="", help="куда платить; пусто — локальный тестовый сервис")
    ap.add_argument("--artifact", default='{"summary":"живой тест x402","findings":["ok"]}')
    ap.add_argument("--key-env", default="X402_TEST_PAYER_PRIVATE_KEY")
    ap.add_argument("--port", type=int, default=8757)
    args = ap.parse_args()

    if not os.environ.get(args.key_env):
        # Ключи живут в ~/.env, а не в окружении сессии: читаем файл, но
        # не перезаписываем уже заданное переменной.
        try:
            from dotenv import load_dotenv
            load_dotenv(Path.home() / ".env", override=False)
        except Exception as exc:  # нет dotenv — просто сообщим, чего не хватает
            print(f"attest/x402_pay: ~/.env не прочитан: {exc}", file=sys.stderr)
    private_key = os.environ.get(args.key_env) or ""
    if not private_key:
        raise SystemExit(f"нет ключа в окружении: {args.key_env}")
    if not private_key.startswith("0x"):
        private_key = "0x" + private_key

    local = not args.url
    url = args.url or local_server(args.port)
    artifact = json.loads(args.artifact)
    report = pay(url, artifact, private_key, warmup=local)
    print(json.dumps(report, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
