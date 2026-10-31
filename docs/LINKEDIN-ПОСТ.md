# Пост в LinkedIn (индийский канал, E6)

Подготовлено 22.10.2026. Публикуется из Tor-инстанса браузера (LinkedIn
не проходит через PAC/xray — проверено: таймаут; через Tor — 200 за 4 с).

## Текст поста (английский)

```
Something I got wrong about prompt-injection scanners, and what I changed
because of it.

A phrase scanner tells you: "this string is suspicious". That is nearly
useless when the string is a legitimate example, a doc snippet, or a line
from a changelog.

What matters is where the string sits:

- a tool description is read as instructions
- an example value is mostly read as data
- an enum value sits in between - it narrows what the model is allowed
  to do

Same bytes, different weight by field. That is the whole idea.

So I built attest: it checks an artifact an agent produced - a scan report,
a structured answer - against its schema, and then looks at what is
actually inside it, not only whether the form is right. Five identical
findings pass every schema validator. That is not a schema problem, that
is a broken agent, and the form will not tell you.

The verdict is Ed25519-signed and verifies offline, so the recipient does
not have to trust this service - only the math.

MCP: https://attest.rta.lat/mcp
HTTP: POST https://attest.rta.lat/verify

5 checks a day, no signup, no card. Purchasing-power pricing for India:
$3 for 30 days.

If your pipeline produces artifacts that an agent (or a payment) will act
on, I would like to hear where your scanners stop. That is where the
interesting bugs live.
```

## Варианты заголовка (первая строка — крючок)

1. `Same bytes, different weight by field: a lesson from building an
   artifact scanner for agents`
2. `A phrase scanner cannot tell a command from a sample. Position can.`
3. `Five identical findings pass every schema validator. That is the bug
   nobody is looking for.`

## Куда ещё постить то же (индийские сообщества)

Публикация в группы LinkedIn требует членства — группы подтверждаются
вручную, поэтому первым идёт пост в ленту, а группы — по мере вступления.

| Сообщество | Ссылка | Что делать |
|---|---|---|
| Agentic AI India (группы LinkedIn) | поиск в LinkedIn: «Agentic AI India», «AI Engineers India», «Generative AI India», «MCP» | вступить → вставить пост |
| AI Engineer (Индия) | https://www.ai.engineer/ | их Discord/рассылка: письмо через форму |
| GDG Cloud Mumbai / Bengaluru | https://gdg.community.dev/ | митап-канал, пост от своего имени |
| r/LocalLLaMA, r/MCP (Reddit) | уже есть r/mcp | дубли не нужны |
| Product Hunt | есть аккаунт? | позже |

## Чего не делаем

- Не постим одно и то же в несколько сабов в один день (с Reddit это
  снимали за спам; здесь та же логика).
- Не обещаем «проверяет всё» — проверка слоистая, и это видно из текста.
- Не упоминаем api.market/цену в долларах без индийской цены: индийский
  покупатель видит $9 и уходит, $3 — другой разговор.
