# Пост в Reddit — готов к вставке

**Куда:** `r/AI_Agents` (r/MCP не грузится — отдаёт пустую страницу).

**Ссылка на редактор:**
```
https://old.reddit.com/r/AI_Agents/submit?selftext=true
```

---

## Заголовок

```
Prompt injection scanners should be positional, not phrasal
```

## Текст

```
Short version: we built a deterministic verifier for agent artifacts, and the bug class that taught us the most was that most injection scanners flatten every string into one category.

"ignore all previous instructions" in a tool's `description` is critical. The model reads a description as its own configuration, not as data. The same string in `content` is quoted output inside a result the agent may only summarise. Same bytes, completely different blast radius.

So we classify JSON fields by role, not by name. Result-carrying fields (`content, text, body, message, result, output, answer, value, data`) don't escalate. Everything else does — including `source`, which looks wrongest and is deliberate: source code is data that then gets fed to a model and compiled, so it sits on the same path to an instruction.

Actual output on one sentence, four fields:

- `description` -> injection_in_data_field:description -> critical
- `name` -> injection_in_data_field:name -> critical
- `source` -> injection_in_data_field:source -> critical
- `content` -> ignore_previous -> high

**The part that killed our marketing claim.** We were about to publish "survives paraphrase". Then we tested before publishing:

    "disregard previous context"   -> caught
    "disregard the prior context"  -> not caught

The regex is `disregard\s+(all\s+)?(previous|...)` — the extra "the" breaks the grammar. So the honest claim is narrower than the one we wanted: **position moderates severity for phrases we already recognise; it does not recognise phrases we miss.** A deterministic scanner with a finite signature set loses to anyone willing to read the source.

The rules are public, so please do read them and break them:
https://github.com/mrpkk/attest/blob/main/attest/poison.py

Full writeup: https://attest.rta.lat/article?ref=reddit
API: https://attest.rta.lat · MCP: https://attest.rta.lat/mcp

Two caveats I would rather state than hide: nobody has paid for this yet (zero demand data, so treat the design as a hypothesis worth attacking), and there is no external audit of the scheme.

If you can find a field where our positional rule gets it backwards, that is the most useful thing you could send.
```

---

## Почему просто не запостить самому

Автоматизация упирается в нехватку памяти: Opera держит **11.6 ГБ**, ядро убивает
процессы Thorium через OOM-киллер (в `dmesg`: `Killed process … (opera)`).
Свежая вкладка Reddit с тяжёлым JS умирает за секунды.

Ручная вставка занимает 30 секунд и не зависит от памяти.

## Проверить результат

```
curl -s https://attest.rta.lat/metrics | grep -i reddit
```

Метка `?ref=reddit` в ссылке на статью считает переходы.
