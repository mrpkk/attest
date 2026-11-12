#!/usr/bin/env python3
"""Secret guard — проверка изменений перед тем, как они станут публичными.

Почему он здесь. 12.11.2026 выяснилось, что внутренние документы и адреса
третьих лиц лежали в публичном репозитории, из которого собирается сайт.
Второй случай — живые токены Telegram, зашитые в код. Оба раза вышло
случайно. Этот скрипт закрывает оба класса:
  * формат ключа/токена в коде,
  * файл .env или его копия в репозитории,
  * чужая почта в публичных файлах.

Запуск:
    python3 scripts/secret_guard.py            # весь репозиторий
    python3 scripts/secret_guard.py --staged   # только то, что идёт в коммит
    python3 scripts/secret_guard.py --diff     # только изменённые строки

Выход: 0 — чисто, 1 — есть находки (коммит блокируется в pre-commit).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Форматы живых секретов. Примеры и заглушки исключены явными проверками ниже.
PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("aws-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("resend-key", re.compile(r"\bre_[A-Za-z0-9]{20,}\b")),
    ("cloudflare-token", re.compile(r"\bv1\.0-[a-f0-9]{40}-[A-Za-z0-9]{30,}\b")),
    ("telegram-bot", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("db-url-with-password", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:/\s]+:[^@\s]+@")),
]
# Явные заглушки и документация — не находки.
PLACEHOLDERS = (
    "EXAMPLE", "example", "AAAA", "aaaa", "xxxx", "XXXX", "your-", "your_",
    "your.", "CHANGEME", "changeme", "REDACTED", "placeholder", "PLACEHOLDER",
    "test", "TEST", "dummy", "DUMMY", "fake", "FAKE", "passwo", "password@",
    "random", "BEGIN RSA PRIVATE KEY-----EXAMPLE", "notarealkey",
)
# Наши собственные адреса — они публичны по природе.
OWN_MAIL = ("maxim.pkk@gmail.com", "wiggle.pkk@gmail.com", "hello@ailegal.legal",
            "hello@rta.lat", "maxim.pkk@gmail.com")
OWN_DOMAINS = ("rta.lat", "ailegal.legal", "0vas.lol", "example.com", "example.org",
               "example.invalid", "noreply.github.com", "users.noreply.github.com",
               "company.com", "email.com", "test.com", "evil.com")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
             ".mypy_cache", ".pytest_cache", "site-packages", ".next"}
BINARY = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".mp4", ".mp3",
          ".zip", ".gz", ".woff", ".woff2", ".ttf", ".so", ".pyc", ".whl", ".lock"}
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Файлы, где чужие адреса — часть содержимого (примеры, каталоги, лицензии).
EMAIL_OK_FILES = ("LICENSE", "CODE_OF_CONDUCT", "CONTRIBUTING", "SECURITY.md",
                  "package-lock.json", "poetry.lock", "Cargo.lock")


def is_placeholder(text: str) -> bool:
    return any(p in text for p in PLACEHOLDERS)


def scan_text(text: str) -> list[str]:
    hits = []
    for name, pat in PATTERNS:
        for m in pat.finditer(text):
            sample = m.group(0)
            if is_placeholder(sample):
                continue
            hits.append(f"{name}: {sample[:28]}…")
    return hits


def scan_emails(text: str, path: str) -> list[str]:
    if any(path.endswith(x) or x in path for x in EMAIL_OK_FILES):
        return []
    out = []
    for m in set(EMAIL.findall(text)):
        low = m.lower()
        if low in OWN_MAIL or any(low.endswith("@" + d) for d in OWN_DOMAINS):
            continue
        out.append(m)
    return out


def git(repo: Path, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          text=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--staged", action="store_true", help="только то, что в индексе")
    ap.add_argument("--diff", action="store_true", help="только изменённые строки")
    ap.add_argument("--emails", action="store_true", help="искать чужие почты")
    ap.add_argument("--root", default=".", help="корень репозитория")
    a = ap.parse_args()
    root = Path(a.root).resolve()

    findings: list[str] = []
    files: list[tuple[str, str]] = []   # (путь, текст)

    if a.staged:
        for line in git(root, "diff", "--cached", "--name-only").splitlines():
            if line.strip():
                files.append((line.strip(), ""))
    elif a.diff:
        for line in git(root, "diff", "--name-only", "HEAD").splitlines():
            if line.strip():
                files.append((line.strip(), ""))
    else:
        for line in git(root, "ls-files").splitlines():
            if line.strip():
                files.append((line.strip(), ""))

    for rel, _ in files:
        p = root / rel
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        name = p.name
        if name == ".env" or (name.startswith(".env.") and not name.endswith((".example", ".sample", ".test", ".dist"))):
            findings.append(f"{rel}: файл с секретами (.env) не должен быть в репозитории")
            continue
        if p.suffix.lower() in BINARY:
            continue
        try:
            if not p.is_file() or p.stat().st_size > 3_000_000:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for h in scan_text(text):
            findings.append(f"{rel}: {h}")
        if a.emails:
            for e in scan_emails(text, rel):
                findings.append(f"{rel}: чужая почта {e}")

    if findings:
        print("SECRET GUARD: коммит заблокирован — найдено:")
        for f in findings:
            print("  •", f)
        print("\nЕсли это ложное срабатывание — добавь значение в scripts/secret_guard.py "
              "(PLACEHOLDERS) и повтори.")
        return 1
    print(f"secret guard: чисто ({len(files)} файлов проверено)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
