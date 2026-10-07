"""`python3 -m attest` — точка входа пакета.

Принято решение (автопилот, 07.10.2026, Д10): команда проверки из
PROGRESS.md (`python3 -m attest --help`) раньше падала — у пакета не было
__main__.py. Запуск делегируется в attest.cli (проверка артефактов);
сканер конфигурации и кода — отдельный CLI `python3 audit_cli.py`.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
