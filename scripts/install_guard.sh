#!/usr/bin/env bash
# Установка крюка перед коммитом в текущем репозитории.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$ROOT/.githooks"
cp "$ROOT/scripts/pre-commit.sh" "$ROOT/.githooks/pre-commit"
chmod +x "$ROOT/.githooks/pre-commit"
cd "$ROOT"
git config core.hooksPath .githooks
echo "крюк установлен: $(git config core.hooksPath)"
