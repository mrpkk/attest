# Подача в Windmill Hub

Дата: 13.10.2026. Проверено: площадка жива, отдаёт 200.

## Что Windmill Hub принимает

По описанию с самой площадки:

> The hub of pre-built scripts, flows, apps, triggers and resource types
> for Windmill — the open-source workflow automation platform.

То есть **скрипты, flow, приложения, триггеры**. Наш скрипт — готовый
resource script на Python, запускается в Windmill без зависимостей.

## Готово

| Файл | Что это |
|---|---|
| `/media/Sruti/iamthat/work/sales/attest/attest/windmill_script.py` | скрипт, проверен живьём |

Скрипт делает живые вызовы к `https://attest.rta.lat` и возвращает четыре слоя проверки. Проверено:

```
ACCEPT trust=100 emptiness=CONTENT_PRESENT authority=yes
ACCEPT trust=100 emptiness=VALID_BUT_EMPTY authority=no (amount)
```

Первая строка — нормальный артефакт в мандате. Вторая — три одинаковые находки и превышение суммы: форма в порядке, но содержания нет и разрешения тоже.

## Одна ошибка, найденная и исправленная по ходу

Скрипт падал с **Cloudflare 1010** на любом обращении: Cloudflare отдаёт эту ошибку клиентам без `User-Agent`. Это сломало бы скрипт **у каждого покупателя**, а не только у нас — в Windmill то же самое.

Заголовок добавлен, скрипт перепроверен на живом сервисе.

Отдельно: `urllib` из стандартной библиотеки нашёлся раньше всех — и именно он показал проблему. Проверка «у себя работает» через `curl` её бы не увидела.

## Куда подавать

Путь подачи на самой площадке не найден — страницы `/submit` нет. Каналы, которые указаны у них на <https://hub.windmill.dev>:

1. **Discord** — https://discord.gg/V7PM2YHsPB
2. **GitHub Discussions** — https://github.com/windmill-labs/windmill/discussions

**Оба требуют твоего аккаунта.** Это то место, где я остановился: записать
сам не могу, публиковать от твоего имени тоже.

## Что написать при подаче

```
Title:    Verify an AI agent artifact — schema, emptiness, provenance, authority
Script:   windmill_script.py
Category: Utility / API client
```

Описание:

```
Validates artifacts coming from AI agents or external tools across four
independent layers:

1. Form — does it match the schema?
2. Emptiness — is there anything inside it? An agent asked to find five
   vulnerabilities returns five identical items, and that passes every
   schema check because the form is perfect.
3. Provenance — the model, prompt, parameters and timestamp bound to the
   artifact hash. Change any link and the binding stops matching.
4. Authority — was the action permitted, according to a signed mandate?

No dependencies. Returns the full response including the Ed25519 signature,
which can be verified independently of this service.

5 free checks per day, then 0.005 USDC per call over x402 on Base mainnet.
Service: https://attest.rta.lat
Source: https://github.com/mrpkk/attest
```

## Почему это стоит делать

Windmill — платформа автоматизации с открытым исходным кодом. Скрипт там
получает **показы в поиске по автоматизации**, а не строчку в общем
каталоге: аудитория ищет «проверить результат агента», а не «ещё один
верификатор».

Конкуренция в Windmill Hub — единицы скриптов про верификацию агентов.
