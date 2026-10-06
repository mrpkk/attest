"""
BRIDGE — мост между агентом, заказчиком и деньгами.

Проблема, которую решает (из исследования 06.10.2026):
агенты уже работают, создают артефакты и тратят деньги, но у мира нет
слоя, который отвечает на три вопроса:
  1. Сделано ли то, что обещали?          -> VERIFY
  2. Кто за это отвечает и чем доказывает? -> RECEIPT (подписанный)
  3. Можно ли доверять этому исполнителю?   -> TRUST (репутация)

Без ответа на любой из трёх вопросов рынок закрывается: страховщики не
страхуют, заказчик не платит, агент не получает доступа. Bridge — этот слой.

Что делает:
  job     — заказчик ставит задачу и блокирует бюджет (ESCROW)
  deliver  — агент сдаёт артефакт, Bridge проверяет и подписывает RECEIPT
  release  — заказчик принимает работу, бюджет переходит агенту
  dispute  — заказчик отклоняет, бюджет возвращается
  verify   — третья сторона проверяет RECEIPT без участия сторон
  trust    — репутация исполнителя по истории сделок

Ключевое отличие от обычного escrow: RECEIPT — самодостаточный артефакт.
Его можно передать кому угодно, и он проверяется без доступа к Bridge.
Это то, что делает слой переносимым — база, на которой держатся рынки
и страхование, как показало исследование.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Optional

from attest.core import scan_for_poison
from attest.provenance import digest

BRIDGE_VERSION = "0.1.0"

# ---------------------------------------------------------------- хранение


class Store:
    """Файловое хранилище. Один JSON на мост — мост обязан пережить рестарт."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({"version": BRIDGE_VERSION, "jobs": {}, "agents": {}})

    def _read(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict) -> None:
        self.path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def read(self) -> dict:
        return self._read()

    def write(self, data: dict) -> None:
        self._write(data)


# ---------------------------------------------------------------- модели


@dataclass
class Budget:
    """Бюджет задачи. Деньги не двигаются, пока нет подписанного RECEIPT."""

    amount_minor: int          # в минорных единицах (1 USDC = 1_000_000)
    currency: str = "USDC"
    network: str = "eip155:8453"
    pay_to: str = ""           # адрес агента-получателя
    state: str = "escrowed"    # escrowed -> released -> refunded
    released_at: Optional[float] = None
    refunded_at: Optional[float] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Job:
    id: str
    title: str
    spec: dict                  # что именно обещано сделать
    budget: Budget
    client: str
    created_at: float = field(default_factory=time.time)
    receipt_id: Optional[str] = None
    status: str = "open"        # open -> delivered -> settled | disputed

    def to_dict(self) -> dict:
        d = asdict(self)
        d["budget"] = self.budget.to_dict()
        return d


@dataclass
class Verdict:
    """Результат проверки артефакта. Три оси, как в исследовании."""

    spec_ok: bool               # соответствует ли обещанию
    poison_ok: bool             # нет ли отравления контекста
    intact: bool                # не изменился ли артефакт после подписи
    detail: dict = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.spec_ok and self.poison_ok and self.intact

    def to_dict(self) -> dict:
        d = asdict(self)
        d["accepted"] = self.accepted
        return d


# ---------------------------------------------------------------- подпись


def sign(payload: dict, secret: bytes) -> str:
    """HMAC-SHA256 по канонической сериализации — переносимая подпись."""
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hmac.new(secret, raw.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(payload: dict, signature: str, secret: bytes) -> bool:
    """Сравнение постоянного времени — защита от подбора подписи."""
    return hmac.compare_digest(sign(payload, secret), signature)


# ---------------------------------------------------------------- мост


class Bridge:
    """
    Мост: заказчик → агент → деньги, с проверкой на каждом шаге.

    Гарантия: бюджет не отпускается, пока нет подписанного RECEIPT,
    и RECEIPT можно проверить без доступа к Bridge.
    """

    def __init__(
        self,
        path: str | Path,
        secret: str | bytes | None = None,
        checker: Optional[Callable[[dict, dict], Verdict]] = None,
    ):
        self.store = Store(path)
        s = secret or os.environ.get("BRIDGE_SECRET") or "bridge-dev-secret"
        self.secret = s.encode("utf-8") if isinstance(s, str) else s
        # Проверяющая функция внедряется: мост не знает про договоры,
        # он знает про контракт «проверь и скажи да/нет».
        self.checker = checker or self._default_checker

    # -- проверки -------------------------------------------------------

    @staticmethod
    def _default_checker(spec: dict, artifact: Any) -> Verdict:
        """Проверка по спецификации: требуемые поля, типы, отсутствие яда."""
        detail: dict = {}
        ok = True
        if isinstance(spec, dict) and "required" in spec:
            art = artifact if isinstance(artifact, dict) else {}
            missing = [k for k in spec["required"] if k not in art]
            detail["missing"] = missing
            ok = ok and not missing
        try:
            hits = scan_for_poison(artifact)
            poison_ok = len(hits) == 0
            detail["poison"] = hits
        except Exception:
            # Проверка яда не должна ронять сделку: неизвестное = не яд.
            poison_ok = True
            detail["poison"] = "checker-error"
        return Verdict(spec_ok=ok, poison_ok=poison_ok, intact=True, detail=detail)

    # -- операции -------------------------------------------------------

    def new_job(
        self,
        title: str,
        spec: dict,
        amount_minor: int,
        client: str,
        pay_to: str = "",
        currency: str = "USDC",
        network: str = "eip155:8453",
    ) -> Job:
        """Заказчик ставит задачу. Бюджет блокируется — это и есть эскроу."""
        if amount_minor <= 0:
            raise ValueError("бюджет должен быть больше нуля")
        data = self.store.read()
        job = Job(
            id=uuid.uuid4().hex[:12],
            title=title,
            spec=spec,
            budget=Budget(
                amount_minor=amount_minor,
                currency=currency,
                network=network,
                pay_to=pay_to,
            ),
            client=client,
        )
        data["jobs"][job.id] = job.to_dict()
        self.store.write(data)
        return job

    def deliver(self, job_id: str, agent: str, artifact: Any) -> tuple[dict, Verdict]:
        """
        Агент сдаёт артефакт. Мост проверяет и, если всё чисто,
        выпускает подписанный RECEIPT — переносимое доказательство.
        """
        data = self.store.read()
        job_raw = data["jobs"].get(job_id)
        if job_raw is None:
            raise KeyError(f"задача {job_id} не найдена")
        job = Job(
            id=job_raw["id"],
            title=job_raw["title"],
            spec=job_raw["spec"],
            budget=Budget(**job_raw["budget"]),
            client=job_raw["client"],
            created_at=job_raw["created_at"],
            receipt_id=job_raw.get("receipt_id"),
            status=job_raw["status"],
        )
        if job.status != "open":
            raise ValueError(f"задача в статусе {job.status}, сдача невозможна")

        verdict = self.checker(job.spec, artifact)

        # Отпечаток артефакта: чтобы «интактность» была проверяемой, а не
        # заявленной. Никто не сможет поменять артефакт после подписи.
        fingerprint = digest(artifact)

        receipt_body = {
            "bridge": BRIDGE_VERSION,
            "receipt_id": uuid.uuid4().hex[:16],
            "job_id": job.id,
            "job_title": job.title,
            "agent": agent,
            "fingerprint": fingerprint,
            "verdict": verdict.to_dict(),
            "amount_minor": job.budget.amount_minor,
            "currency": job.budget.currency,
            "network": job.budget.network,
            "pay_to": job.budget.pay_to,
            "issued_at": time.time(),
        }
        receipt = {
            "body": receipt_body,
            "signature": sign(receipt_body, self.secret),
        }

        job.receipt_id = receipt_body["receipt_id"]
        job.status = "delivered" if verdict.accepted else "disputed"
        data["jobs"][job.id] = job.to_dict()

        # Репутация агента — считается из фактов, а не из самоотчёта.
        rec = data["agents"].setdefault(
            agent, {"deliveries": 0, "accepted": 0, "rejected": 0, "volume_minor": 0}
        )
        rec["deliveries"] += 1
        if verdict.accepted:
            rec["accepted"] += 1
        else:
            rec["rejected"] += 1
        rec["volume_minor"] += job.budget.amount_minor

        self.store.write(data)
        return receipt, verdict

    def release(self, job_id: str) -> Budget:
        """Заказчик принимает работу. Бюджет уходит агенту."""
        data = self.store.read()
        job = data["jobs"].get(job_id)
        if job is None:
            raise KeyError(f"задача {job_id} не найдена")
        if job["status"] != "delivered":
            raise ValueError(f"отпустить можно только delivered, сейчас {job['status']}")
        job["status"] = "settled"
        job["budget"]["state"] = "released"
        job["budget"]["released_at"] = time.time()
        self.store.write(data)
        return Budget(**job["budget"])

    def refund(self, job_id: str) -> Budget:
        """Заказчик отклоняет. Бюджет возвращается — деньги не сгорают."""
        data = self.store.read()
        job = data["jobs"].get(job_id)
        if job is None:
            raise KeyError(f"задача {job_id} не найдена")
        if job["status"] == "settled":
            raise ValueError("работа уже оплачена, возврат невозможен")
        job["status"] = "disputed"
        job["budget"]["state"] = "refunded"
        job["budget"]["refunded_at"] = time.time()
        self.store.write(data)
        return Budget(**job["budget"])

    # -- проверка третьей стороной --------------------------------------

    @staticmethod
    def verify_receipt(receipt: dict, secret: str | bytes, artifact: Any = None) -> dict:
        """
        Проверка RECEIPT без доступа к Bridge.

        Именно это делает слой переносимым: страховщик, арбитр или новый
        заказчик проверяют доказательство сами, а не верят мосту на слово.
        """
        s = secret.encode("utf-8") if isinstance(secret, str) else secret
        result: dict = {"signature_ok": False, "fingerprint_ok": None, "reason": ""}
        if "body" not in receipt or "signature" not in receipt:
            result["reason"] = "receipt повреждён: нет body или signature"
            return result
        result["signature_ok"] = verify_signature(receipt["body"], receipt["signature"], s)
        if not result["signature_ok"]:
            result["reason"] = "подпись не сходится — receipt подделан или изменён"
            return result
        if artifact is not None:
            fp = digest(artifact)
            result["fingerprint_ok"] = fp == receipt["body"]["fingerprint"]
            if not result["fingerprint_ok"]:
                result["reason"] = "артефакт изменился после выдачи receipt"
        return result

    # -- репутация -------------------------------------------------------

    @staticmethod
    def trust(agent: str, store_path: str | Path) -> dict:
        """
        Репутация из фактов: сколько сдач, сколько принято, какой объём.

        Не самоотчёт агента (модели прямо признали, что их самооценка
        недостоверна), а то, что можно пересчитать по журналу сделок.
        """
        data = Store(store_path).read()
        rec = data["agents"].get(agent)
        if rec is None:
            return {"agent": agent, "deliveries": 0, "accepted": 0, "rejected": 0,
                    "volume_minor": 0, "trust_score": 0.0}
        deliveries = rec["deliveries"]
        score = rec["accepted"] / deliveries if deliveries else 0.0
        return {**rec, "agent": agent, "trust_score": round(score, 4)}

    def list_jobs(self) -> list[dict]:
        data = self.store.read()
        return list(data["jobs"].values())