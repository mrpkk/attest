#!/bin/sh
# Крюк перед коммитом: не даёт уехать секрету в историю.
# Ставится один раз: bash scripts/install_guard.sh
set -e
ROOT=$(git rev-parse --show-toplevel)
exec python3 "$ROOT/scripts/secret_guard.py" --staged --emails
