# attest — проверка артефактов ИИ-агентами с оплатой по x402.
#
# Сборка ≠ работа: образ проверяется запросом к /health и живому MCP-хендшейку,
# а не фактом «docker build прошёл».
#
#   docker build -t attest:local .
#   docker run --rm -p 8185:8185 attest:local
#   curl -fsS localhost:8185/health
#
# Пакет намеренно НЕ ставится через `pip install .`: он копируется в /app и
# импортируется оттуда. Установка пакета тянет изолированное окружение
# (setuptools/wheel) и обрывается на таймауте загрузки — лишний шаг без
# пользы.

# ── Сборка зависимостей ───────────────────────────────────────────────────
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=60

# cytoolz и bitarray собираются из исходников — нужен toolchain. Он есть
# только на время сборки и в итоговый образ не попадает.
RUN apt-get update \
 && apt-get install --no-install-recommends -y build-essential \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Рантайм-зависимости. eth_account нужен для подписи платёжных данных,
# cryptography — для Ed25519-подписи entitlement-токенов
# (attest/signing.py). Обе импортируются лениво, но без них сервис
# не стартует: fingerprint() вызывается при описании подписки.
RUN pip install "eth-account>=0.9" "cryptography>=42"


# ── Время выполнения ──────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# curl — для HEALTHCHECK и для ручной проверки образа.
RUN apt-get update \
 && apt-get install --no-install-recommends -y curl \
 && rm -rf /var/lib/apt/lists/*

# Непривилегированный пользователь: процесс не должен работать от root.
RUN useradd --system --create-home --uid 10001 attest

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY --chown=attest:attest attest ./attest
COPY --chown=attest:attest pyproject.toml README.md ./

USER attest

# Порт: на Apify платформа сама задаёт ACTOR_WEB_SERVER_PORT (standby-режим),
# локально работает PORT=8185. Приоритет: ACTOR_WEB_SERVER_PORT → PORT → 8185.
ENV PORT=8185 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8185

# /health проверяет живой HTTP-ответ, а не то, что порт кто-то открыл.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD sh -c 'curl -fsS "http://127.0.0.1:${ACTOR_WEB_SERVER_PORT:-${PORT:-8185}}/health" > /dev/null || exit 1'

# Ключ подписи создаётся при первом старте (идемпотентно: существующий не
# перезаписывается — перегенерация ломала бы ранее выданные подписи).
# Без ключа service.py падает на импорте (entitlement_describe → fingerprint).
CMD ["sh", "-c", "python -m attest keygen > /dev/null && python -c \"from attest.service import serve; import os; port = int(os.environ.get('ACTOR_WEB_SERVER_PORT') or os.environ.get('PORT') or 8185); serve('0.0.0.0', port)\""]