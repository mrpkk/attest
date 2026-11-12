#!/usr/bin/env bash
# Живая проверка платёжного рельса: тестовый платёж 0.005 USDC на Base Sepolia.
# Зачем: рельс может «протухнуть» (фасилитатор, лимит тестовых USDC, адрес).
# Проверять обещания нельзя — только живой платёж. Запуск — раз в неделю из cron.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
out=$(timeout 300 python3 tools/x402_pay.py 2>&1)
if echo "$out" | grep -q '"settled": true' && echo "$out" | grep -q '"confirmed_on_chain": true'; then
  echo "$(date -Is) OK $(echo "$out" | grep -o '0x[0-9a-f]\{64\}' | tail -1)"
else
  echo "$(date -Is) FAIL"; echo "$out" | tail -12; exit 1
fi
