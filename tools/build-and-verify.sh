#!/usr/bin/env bash
# Сборка образа attest и проверка, что он РАБОТАЕТ.
#
# «docker build прошёл» ничего не доказывает: образ может не стартовать,
# не иметь зависимости или не пройти healthcheck. Поэтому после сборки
# поднимаем контейнер и бьём по нему живыми запросами, включая MCP-хендшейк.
#
#   tools/build-and-verify.sh
#
# Ключ подписи нужен сервису при старте (attest/signing.py требует его
# наличия и падает без него — это осознанно). Для проверки генерируется
# одноразовый ключ; настоящий в образ не попадает и монтируется снаружи.

set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-attest:local}"
HOST_PORT="${HOST_PORT:-8287}"
CONTAINER="${CONTAINER:-attest-verify}"
KEY_FILE="$(mktemp -t attest-verify-key.XXXXXX)"

fail() { printf '  ПРОВАЛ: %s\n' "$1" >&2; exit 1; }

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -f "$KEY_FILE"
}
trap cleanup EXIT

# Порт должен быть свободен: иначе мы проверим чужой сервис, а не свой.
# Именно так случилось с 8186 — контейнер не стартовал, а ответы шли от
# indra-memory, и «проверка» была выдуманной.
if ss -tln 2>/dev/null | grep -q ":${HOST_PORT} "; then
  fail "порт ${HOST_PORT} уже занят — выбери другой: HOST_PORT=8301 $0"
fi

printf '  1. генерация одноразового ключа подписи\n'
python3 -c "
import sys, pathlib
sys.path.insert(0, '.')
from attest.signing import generate_keypair
generate_keypair(pathlib.Path(sys.argv[1]))
" "$KEY_FILE"
chmod 644 "$KEY_FILE"

printf '  2. сборка образа\n'
docker build -t "$IMAGE" . >/tmp/attest-build.log 2>&1 \
  || { tail -20 /tmp/attest-build.log; fail "сборка не прошла"; }
docker images "$IMAGE" --format '     размер: {{.Size}}'

printf '  3. запуск контейнера\n'
docker run -d --name "$CONTAINER" -p "${HOST_PORT}:8185" \
  -v "${KEY_FILE}:/run/secrets/signing.key:ro" \
  -e ATTEST_SIGNING_KEY=/run/secrets/signing.key \
  "$IMAGE" >/dev/null

ready=""
for _ in $(seq 1 20); do
  sleep 1
  if curl -fsS -m 2 "http://127.0.0.1:${HOST_PORT}/health" >/dev/null 2>&1; then
    ready=1; break
  fi
done
[ -n "$ready" ] || { docker logs "$CONTAINER" | tail -15; fail "сервис не поднялся"; }

printf '  4. живые запросы через порт\n'
mcp() {
  curl -s -m 6 -o /dev/null -w '%{http_code}' -X POST \
    "http://127.0.0.1:${HOST_PORT}/mcp" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -d "$1"
}

check() {
  local name="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    printf '     %-16s %s  ok\n' "$name" "$got"
  else
    fail "${name}: ожидали ${want}, получили ${got}"
  fi
}

check "/health"     "$(curl -s -m 6 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HOST_PORT}/health")"     200
check "/robots.txt" "$(curl -s -m 6 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HOST_PORT}/robots.txt")" 200
check "mcp init"    "$(mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}')" 200
check "mcp list"    "$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')" 200

TOOLS="$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' >/dev/null; \
  curl -s -m 6 -X POST "http://127.0.0.1:${HOST_PORT}/mcp" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("result",{}).get("tools",[])))')"
if [ "${TOOLS:-0}" -ge 1 ]; then
  printf '     %-16s %s инструментов  ok\n' "tools" "$TOOLS"
else
  fail "tools/list вернул пустой список — сервер неполон"
fi

printf '  5. привилегии и healthcheck\n'
USER_NAME="$(docker exec "$CONTAINER" id -un)"
[ "$USER_NAME" != "root" ] || fail "процесс работает от root"
printf '     %-16s %s  ok\n' "user" "$USER_NAME"

sleep 12
HEALTH="$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo нет)"
[ "$HEALTH" = "healthy" ] || fail "Docker HEALTHCHECK: ${HEALTH}"
printf '     %-16s %s  ok\n' "healthcheck" "$HEALTH"

printf '\n  ОБРАЗ ПРОВЕРЕН: собран, запущен, отвечает, MCP работает.\n'