# Пост в Hacker News — готов, ждёт одного клика

Статья живёт: **https://attest.rta.lat/article**

Публиковать нужно из аккаунта владельца — у меня нет сессии HN, и просить
пароль нельзя. Всё подготовлено, кроме нажатия «submit».

---

## Заголовок

Два варианта. Первый честнее — он про содержание, а не про продукт.

```
Prompt injection scanners should be positional, not phrasal
```

Запасной, если первый не зайдёт:

```
We shipped a deterministic verifier for agent artifacts. Here's the one
bug class we think scanners mostly get wrong.
```

**Не писать** «I built», «launch», «excited» — это рекламный тон, HN его
штрафует.

## Первый комментарий (писать сразу после поста)

HN читает первый комментарий автора раньше самой ссылки. Здесь решается,
оставят ли пост.

```
The short version: we made a scanner that treats the same sentence
differently depending on which JSON field it sits in.

"ignore all previous instructions" in a tool's `description` is critical.
The same string in `content` is high. Same bytes, different blast radius,
because a description is read as configuration while content is quoted
output.

We were about to write a post claiming this survives paraphrase. Then we
tested it before publishing, and:

  "disregard previous context"   → caught
  "disregard the prior context"  → not caught

The regex is `disregard\s+(all\s+)?(previous|…)` — the extra "the" breaks
it. So the honest claim is narrower than the marketing one: position
moderates severity for phrases we already recognise. It does not recognise
phrases we miss. The rules are in poison.py, read them and break them.

Two things worth knowing:

- The field list is role-based, not a magic field. `content, text, body,
  message, result, output, answer, value, data` are result-carrying;
  everything else escalates. That means `source` escalates too, which
  looks wrongest and is deliberate: source code is data that then gets
  fed to a model and executed.

- Nobody has paid for this yet. We built it, we think it's right, we have
  zero demand data. Treat it as a hypothesis worth attacking.

Rules: https://github.com/mrpkk/attest/blob/main/attest/poison.py
API: https://attest.rta.lat · MCP: https://attest.rta.lat/mcp
```

**Зачем первый комментарий так подробен:** он отвечает на «а где доказательства»
до того, как зададут. И честно признаёт слабое место — это резко поднимает
доверие к остальному.

## Что делать, если спросят

| Вопрос | Ответ |
|---|---|
| «Чем это лучше обычного антивируса?» | Четыре слоя, а не сигнатуры: схема, emptiness, provenance, authority. Плюс структурный канал — позиция в документе. |
| «Вы это продаёте?» | Да: 0.005 USDC за проверку поверх x402, либо 9 USDC за 30 дней безлимита. Первые 20 проверок в сутки бесплатно. |
| «Есть аудит?» | Нет. Честно: церемония односторонняя, схема написана нами и нами же проверена. Работаем над этим. |
| «Сколько платящих?» | Ноль. Показываю метрику, а не обещание. |

## Чего не делать

- **Не отвечать на критику сразу.** Дайте комментариям 2–3 часа, потом отвечать.
- **Не спорить с «это не нужно»** — это нормальная позиция, не ошибка.
- **Не вставлять ссылку на покупку в первый комментарий** дважды. Один раз, в конце.
- **Не постить в пятницу вечером.** HN — Eng/UTC-среда и вторник, 08:00–10:00.

## Как отследить результат

Ссылка в посте идёт с меткой, иначе не поймём, откуда пришли:

```
https://attest.rta.lat/article?ref=hn
```

Метрика появится в `/metrics` в поле `hn`. Без метки мы получим трафик и
не узнаем, откуда он — ровно то, из-за чего сейчас 111 показов и ноль
выручки.

Проверить: `curl -s https://attest.rta.lat/metrics | grep -i hn`

---

*Подготовлено 16.10.2026. Статья опубликована по /article, SEO-разметка и
canonical на месте, страница в sitemap.xml.*