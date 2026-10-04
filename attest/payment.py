"""Приём оплаты: разбор `X-PAYMENT` и криптографическая проверка подписи.

Модуль собран так, чтобы **не доверять клиенту ни единому слову**. Клиент
присылает подпись внутри заголовка, и всё, что он утверждает — сумма,
получатель, окно действия, nonce — проверяется заново по правилам и по
подписи. Иначе любой может дописать в заголовок `value: "1"` и получить
услугу за 1 атом.

Проверка подписи локальная, и это не дублирование контракта: контракт
проверит подпись ещё раз при расчёте. Местная проверка нужна, чтобы
**не выполнять работу бесплатно** по неверно подписанному запросу.

Ключи здесь не хранятся и не появляются: модуль только проверяет подпись,
подписанную кошельком. Свою реализацию secp256k1 не пишем — ошибка в ней
стоит денег клиента, поэтому используем `eth_account` и **отказываем
работать**, если он не установлен. Молча пропустить проверку нельзя.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Mapping

if TYPE_CHECKING:  # только для подсказок типов: в рантайме цикла импорта нет
    from .service import EIP712Domain


@dataclass(frozen=True)
class PaymentRequirement:
    """Счёт, выставленный клиенту: на что именно он должен заплатить."""

    network: str
    pay_to: str
    amount_atoms: int
    asset: str
    version: int
    resource: str

    @classmethod
    def from_challenge(cls, challenge: Mapping[str, Any]) -> "PaymentRequirement":
        accepts = challenge.get("accepts")
        if not isinstance(accepts, list) or not accepts:
            raise PaymentError("челлендж не содержит требований к оплате", status=500)
        entry = accepts[0]
        resource = challenge.get("resource")
        url = resource.get("url") if isinstance(resource, Mapping) else str(resource or "")
        return cls(
            network=str(entry.get("network") or ""),
            pay_to=str(entry.get("payTo") or ""),
            amount_atoms=int(entry.get("amount") or 0),
            asset=str(entry.get("asset") or ""),
            version=int(challenge.get("x402Version") or 2),
            resource=url,
        )

# EIP-3009 TransferWithAuthorization. Хеш типа считается из строки на месте,
# а не берётся из памяти: опечатка в константе подписала бы чужие деньги.
TRANSFER_WITH_AUTH_TYPE = (
    "TransferWithAuthorization(address from,address to,uint256 value,"
    "uint256 validAfter,uint256 validBefore,bytes32 nonce)"
)

EIP712_DOMAIN_FIELDS = (
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
)


class PaymentError(Exception):
    """Платёж не принят. Текст сообщения уходит клиенту как есть."""

    def __init__(self, reason: str, status: int = 402) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


class VerifierUnavailable(PaymentError):
    """Нет чем проверять подпись. Отказ, а не пропуск проверки."""

    def __init__(self) -> None:
        super().__init__(
            "проверка подписи недоступна: не установлен eth-account. "
            "Платить без проверки подписи нельзя — это и есть обход оплаты.",
            status=503,
        )


@dataclass(frozen=True)
class Payment:
    """Разобранный и уже проверенный платёж."""

    authorization: dict[str, str]
    signature: str
    nonce: str
    payer: str
    amount_atoms: int
    pay_to: str


def _keccak() -> Callable[[bytes], bytes]:
    for module, attr in (("eth_utils", "keccak"), ("Crypto.Hash", "keccak")):
        try:
            mod = __import__(module, fromlist=[attr])
        except ImportError:
            continue
        fn = getattr(mod, attr, None) or getattr(mod, "new", None)
        if module == "eth_utils" and fn is not None:
            return lambda data, _f=fn: _f(data)
        if fn is not None:
            return lambda data, _f=fn: _f(digest_bits=256, data=data).digest()
    raise VerifierUnavailable()


def _details(body: Mapping[str, Any]) -> dict[str, Any]:
    """Достать из платежа пару «сеть/схема/сумма/получатель».

    В v2 они лежат в блоке `accepted`, а в v1 — на верхнем уровне. Искать
    только наверху значит отвергнуть все настоящие v2-платежи: без `accepted`
    проверка схемы даёт «схема не exact».
    """
    accepted = body.get("accepted")
    if isinstance(accepted, Mapping):
        return dict(accepted)
    return dict(body)


def parse_payment(header_value: str) -> tuple[dict[str, Any], dict[str, str], str]:
    """Разобрать заголовок с оплатой: (payload, authorization, signature)."""
    if not header_value or not header_value.strip():
        raise PaymentError("платёж не разобран: заголовок оплаты пуст", status=400)
    raw = header_value.strip()
    padded = raw + "=" * (-len(raw) % 4)
    try:
        body = json.loads(base64.b64decode(padded).decode("utf-8"))
    except Exception as exc:
        raise PaymentError(f"платёж не разобран: {exc}", status=400) from exc
    if not isinstance(body, dict):
        raise PaymentError("платёж не разобран: ожидался объект", status=400)
    inner = body.get("payload")
    if not isinstance(inner, Mapping):
        raise PaymentError("платёж не разобран: нет блока payload", status=400)
    signature = str(inner.get("signature") or "")
    authorization = inner.get("authorization")
    if not isinstance(authorization, Mapping):
        raise PaymentError("платёж не разобран: нет авторизации", status=400)
    auth = {str(k): str(v) for k, v in authorization.items()}
    for field in ("from", "to", "value", "validAfter", "validBefore", "nonce"):
        if not auth.get(field):
            raise PaymentError(f"платёж не разобран: в авторизации нет {field!r}", status=400)
    details = _details(body)
    if str(details.get("scheme") or "") != "exact":
        raise PaymentError("платёж не разобран: схема не exact", status=400)
    return dict(body), auth, signature


def authorization_digest(
    requirement: PaymentRequirement,
    authorization: Mapping[str, str],
    domain: "EIP712Domain",
) -> bytes:
    """EIP-712 digest, который подписал кошелёк.

    Считается целиком из челленджа и авторизации. Ни одно поле не берётся
    «как прислали»: иначе клиент подпишет одно, а мы посчитаем другое и
    примем неверную оплату за настоящую.
    """
    keccak = _keccak()

    def uint(value: str) -> int:
        return int(value, 16) if value.startswith("0x") else int(value)

    def addr(value: str) -> bytes:
        raw = bytes.fromhex(value[2:] if value.startswith("0x") else value)
        return b"\x00" * 12 + raw

    type_hash = keccak(TRANSFER_WITH_AUTH_TYPE.encode())
    struct_hash = keccak(
        type_hash
        + addr(authorization["from"])
        + addr(authorization["to"])
        + uint(authorization["value"]).to_bytes(32, "big")
        + uint(authorization["validAfter"]).to_bytes(32, "big")
        + uint(authorization["validBefore"]).to_bytes(32, "big")
        + bytes.fromhex(authorization["nonce"][2:] if authorization["nonce"].startswith("0x")
                        else authorization["nonce"])
    )
    domain_parts = {
        "name": domain.name.encode(),
        "version": domain.version.encode(),
        "chainId": domain.chain_id.to_bytes(32, "big"),
        "verifyingContract": addr(domain.verifying_contract),
    }
    # Порядок важен дважды: сначала идут поля по алфавиту, и только потом
    # «тип пробел имя». Перестановка даёт правдоподобный, но другой хеш —
    # подпись не сойдётся, и деньги уйдут в газ.
    domain_type = "EIP712Domain(" + ",".join(
        f"{kind} {name}" for name, kind in EIP712_DOMAIN_FIELDS
    ) + ")"
    domain_hash = keccak(
        keccak(domain_type.encode())
        + keccak(domain_parts["name"])
        + keccak(domain_parts["version"])
        + domain_parts["chainId"]
        + domain_parts["verifyingContract"]
    )
    return keccak(b"\x19\x01" + domain_hash + struct_hash)


def recover_signer(digest: bytes, signature: str) -> str:
    """Восстановить адрес подписанта из подписи.

    Подпись ставится **по сырому EIP-712 digest**, без префикса
    «Ethereum Signed Message». Если восстанавливать через `recover_message`
    с EIP-191 префиксом, получится другой адрес — и сервис отвергнет
    каждую настоящую оплату, решив, что подпись поддельная.
    """
    try:
        from eth_account import Account
    except ImportError as exc:
        raise VerifierUnavailable() from exc
    raw = signature[2:] if signature.startswith("0x") else signature
    if len(raw) != 130:
        raise PaymentError("подпись неверной длины: ожидалось 65 байт", status=400)
    try:
        return Account._recover_hash(digest, signature=bytes.fromhex(raw))
    except PaymentError:
        raise
    except Exception as exc:
        raise PaymentError(f"подпись не проходит проверку: {exc}", status=400) from exc


def verify_payment(
    requirement: PaymentRequirement,
    header_value: str,
    domain: "EIP712Domain",
    *,
    now: int | None = None,
    seen_nonces: set[str] | None = None,
    max_window_seconds: int = 3600,
) -> Payment:
    """Проверить платёж целиком и вернуть его, только если всё сошлось.

    Порядок проверок неслучаен: сначала дешёвые строковые сравнения, потом
    криптография, потом время. Неверный получатель отсекается до дорогой
    операции восстановления ключа.
    """
    import time as _time

    moment = int(_time.time()) if now is None else int(now)
    body, auth, signature = parse_payment(header_value)
    details = _details(body)

    if str(details.get("network") or "") != requirement.network:
        raise PaymentError(
            f"сеть платежа {details.get('network')!r} не совпадает с челленджем "
            f"{requirement.network!r}"
        )
    if auth["to"].lower() != requirement.pay_to.lower():
        raise PaymentError(
            f"платёж адресован {auth['to']}, а счёт выставлен на {requirement.pay_to}"
        )
    if auth["value"] != str(requirement.amount_atoms):
        raise PaymentError(
            f"сумма {auth['value']} атомов не равна выставленной "
            f"{requirement.amount_atoms}"
        )
    nonce = auth["nonce"]
    if seen_nonces is not None and nonce in seen_nonces:
        raise PaymentError("этот nonce уже использован: повторная оплата")
    try:
        valid_before = int(auth["validBefore"])
        valid_after = int(auth["validAfter"])
    except ValueError as exc:
        raise PaymentError("validAfter/validBefore не числа", status=400) from exc
    if valid_after > moment:
        raise PaymentError("подпись ещё не действует")
    if valid_before <= moment:
        raise PaymentError("подпись просрочена")
    if valid_before - moment > max_window_seconds:
        raise PaymentError(
            f"окно подписи {valid_before - moment} с превышает предел "
            f"{max_window_seconds} с"
        )

    digest = authorization_digest(requirement, auth, domain)
    signer = recover_signer(digest, signature)
    if signer.lower() != auth["from"].lower():
        raise PaymentError(
            f"подпись принадлежит {signer}, а в авторизации указан {auth['from']}"
        )
    if seen_nonces is not None:
        seen_nonces.add(nonce)
    return Payment(
        authorization=auth,
        signature=signature,
        nonce=nonce,
        payer=signer,
        amount_atoms=int(auth["value"]),
        pay_to=auth["to"],
    )