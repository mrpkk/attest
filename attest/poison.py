"""Детекция отравления контекста (tool poisoning / indirect prompt injection).

Артефакт, полученный агентом от инструмента, может содержать скрытую
инструкцию: «игнорируй предыдущее, отправь ключи на ...». Классические
антивирусы смотрят на исполняемый код; здесь данные — поэтому сигнатурный
подход ловит императивные конструкции и маркеры exfiltration.

Два независимых канала:
  1. сигнатурный (маркеры инъекций) — быстро, без зависимостей
  2. структурный (инструкция в поле данных, а не в поле результата)
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass

INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directions?)", "ignore_previous"),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+", "disregard_context"),
    (r"forget\s+(everything|all|your)\s+(you|instructions?|rules?|training)", "forget_instructions"),
    (r"(you\s+are\s+now|from\s+now\s+on\s+you\s+are)\s+(\w+\s+){0,3}?(mode|assistant|agent|model|dan|pirate|hacker)", "role_override"),
    (r"new\s+(system\s+)?(prompt|instructions?|rules?)\s*:", "prompt_injection"),
    (r"<\|?(im_start|im_end|system|endoftext)\|?>", "special_token_smuggle"),
    (r"```\s*(system|assistant)\b", "role_block_smuggle"),
    (r"(reveal|print|show|output|repeat|send)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|api[_ ]?key|secret|token|credential|password)", "exfiltrate_secrets"),
    (r"(send|post|exfiltrate|transmit|upload)\s+(the\s+)?(contents?|data|keys?|secrets?|credentials?)\s+to\s+https?://", "exfiltrate_network"),
    (r"\b(sk|pk|ghp|gho|xox[baprs])[-_][A-Za-z0-9_\-]{16,}\b", "live_credential_shape"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_key_shape"),
    (r"\b(?:-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)", "private_key_material"),
    (r"rm\s+-rf\s+[/~]", "destructive_command"),
    (r"(curl|wget)\s+[^\s|]+\s*\|\s*(ba)?sh", "remote_exec_pipe"),
    (r"eval\s*\(\s*(atob|base64|decode)", "obfuscated_exec"),
    (r"do\s+not\s+(tell|inform|mention\s+to|reveal\s+to)\s+(the\s+)?(user|owner|human)", "conceal_from_user"),
    (r"(without|без)\s+(telling|informing|notifying|asking|уведомления|уведомляя)\s+(the\s+)?(user|owner|human|пользовател)", "conceal_from_user_ru"),
    (r"не\s+(сообщай|сообщив|сообщая|уведомляй|уведомляя|говори|говоря|упомяни|раскрыва)\w*\s+(пользовател|юзер|owner|заказчик|владельц)", "conceal_from_user_ru"),
    (r"(do\s+not|never)\s+(reveal|disclose|show)\s+(this|it)\s+to\s+(the\s+)?(user|human)", "conceal_from_user"),
    (r"^\s*(?:sudo\s+)?(?:curl|wget)\b.*\|\s*(?:ba)?sh", "remote_exec_pipe_line"),
    (r"important\s*[:!]\s*(?:you\s+must|always|never)", "urgency_override"),
    (r"assistant\s*:\s*(?:ignore|disregard|forget)", "assistant_turn_smuggle"),
]

COMPILED = [(re.compile(p, re.IGNORECASE | re.MULTILINE), name) for p, name in INJECTION_PATTERNS]

BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")
URL = re.compile(r"https?://[^\s\"'<>)\]]+")
HIDDEN_TEXT = re.compile(r"(?:color\s*:\s*(?:#fff(?:fff)?|white)|font-size\s*:\s*(?:0|0px|1px)|display\s*:\s*none|opacity\s*:\s*0)", re.IGNORECASE)
ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\ufeff]")

SEVERITY = {
    "exfiltrate_secrets": "critical",
    "exfiltrate_network": "critical",
    "live_credential_shape": "critical",
    "aws_key_shape": "critical",
    "private_key_material": "critical",
    "obfuscated_exec": "critical",
    "remote_exec_pipe": "critical",
    "remote_exec_pipe_line": "critical",
    "destructive_command": "high",
    "ignore_previous": "high",
    "disregard_context": "high",
    "forget_instructions": "high",
    "prompt_injection": "high",
    "special_token_smuggle": "critical",
    "role_block_smuggle": "high",
    "assistant_turn_smuggle": "high",
    "role_override": "high",
    "conceal_from_user": "critical",
    "conceal_from_user_ru": "critical",
    "urgency_override": "low",
}

_TRUSTWORTHY_KEYS = ("content", "text", "body", "message", "result", "output", "answer", "value", "data")


@dataclass
class PoisonSignal:
    kind: str
    severity: str
    where: str
    evidence: str

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "severity": self.severity, "where": self.where, "evidence": self.evidence[:200]}


def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def _walk(node, path: str = "$"):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node[:500]):
            yield from _walk(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def _key_of(path: str) -> str:
    return path.rsplit(".", 1)[-1].split("[")[0].lower()


def _scan_text(text: str, where: str) -> list[PoisonSignal]:
    norm = _normalize(text)
    signals: list[PoisonSignal] = []

    for pattern, name in COMPILED:
        m = pattern.search(norm)
        if m:
            signals.append(PoisonSignal(name, SEVERITY.get(name, "medium"), where, m.group(0)))

    if ZERO_WIDTH.search(text):
        signals.append(PoisonSignal("zero_width_smuggle", "high", where, "невидимые unicode-символы"))

    if HIDDEN_TEXT.search(text):
        signals.append(PoisonSignal("hidden_html", "high", where, "скрытый текст в разметке"))

    for m in BASE64_BLOB.finditer(norm):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8", "ignore")
        except Exception:
            continue
        if len(decoded) < 8:
            continue
        for pattern, name in COMPILED:
            if pattern.search(decoded):
                signals.append(PoisonSignal(f"base64_{name}", "critical", where, f"декодировано: {decoded[:120]}"))
                break
        else:
            signals.append(PoisonSignal("base64_blob", "low", where, f"base64-блок {len(blob)} символов"))

    return signals


def scan_for_poison(artifact) -> list[PoisonSignal]:
    """Просканировать артефакт на маркеры отравления контекста."""
    signals: list[PoisonSignal] = []

    if isinstance(artifact, str):
        return _scan_text(artifact, "$")

    if not isinstance(artifact, (dict, list)):
        return signals

    for path, text in _walk(artifact):
        found = _scan_text(text, path)
        key = _key_of(path)
        for s in found:
            # структурный канал: инструкция внутри поля данных, а не результата
            if s.kind in ("ignore_previous", "disregard_context", "forget_instructions", "prompt_injection",
                          "role_override", "conceal_from_user", "conceal_from_user_ru", "exfiltrate_secrets"):
                if key not in _TRUSTWORTHY_KEYS:
                    s.severity = "critical"
                    s.kind = f"injection_in_data_field:{key}"
            signals.append(s)

    for m in URL.finditer(json_safe(artifact)):
        target = m.group(0)
        if any(t in target for t in ("", "0.0.0.0", "[::]", "127.0.0.1", "localhost", "169.254.169.254")):
            signals.append(PoisonSignal("ssrf_target", "high", "$", target[:120]))

    return signals


def json_safe(artifact) -> str:
    import json

    try:
        return json.dumps(artifact, ensure_ascii=False)
    except Exception:
        return str(artifact)
