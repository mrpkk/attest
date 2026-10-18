"""`python -m attest keygen` — команда, обещанная сообщением об отсутствии ключа.

Если команда исчезнет, а сообщение останется, человек (и CI) потратит время
на команду, которой нет — ровно это случилось 18.10.2026. Ключ и подпись —
одно целое: проверяем создание ключа через настоящий CLI, а не через API.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_keygen_creates_key(tmp_path):
    key = tmp_path / "signing.key"
    env = os.environ.copy()
    env["ATTEST_SIGNING_KEY"] = str(key)
    r = subprocess.run(
        [sys.executable, "-m", "attest", "keygen"],
        capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=60,
    )
    assert r.returncode == 0, r.stderr
    assert key.is_file(), "CLI не создал ключ по ATTEST_SIGNING_KEY"
    assert "ключ создан" in r.stdout
