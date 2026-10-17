# Reddit: что опубликовано (16–17.10.2026)

## Живые публикации

| Что | Адрес |
|---|---|
| Пост | `https://www.reddit.com/r/AI_Agents/comments/1x7uga8/prompt_injection_scanners_should_be_positional/` |
| Комментарий в Weekly Project Display | `https://old.reddit.com/r/AI_Agents/comments/1x5v32d/weekly_thread_project_display/` |

Оба от имени `mrpkk`. Исходный пост **не удалён** (проверено: `removed: false`, score 1).

## Что сказал AutoModerator

> Your post contains a link. If you are submitting a project you've made,
> please find the Weekly Project Display post and post there.

Это **рекомендация, а не удаление**. Правило r/AI_Agents: проекты со ссылками
идут в еженедельный тред. Выполнено — комментарий оставлен там.

## Отправка упёрлась в капчу

Автоматическая отправка получала `That was a tricky one. Why don't you try
that again.` и форму очищало. Плюс на странице присутствовал captcha-элемент.

**Вывод:** Reddit режет автоматическую отправку, капчу проходит только человек.
Скрипт заполняет форму, Submit нажимает владелец.

## Метрики после публикации

Было 111 показов и два канала (`apify`, `dify`). Стало 135 и появились
**`reddit`** и **`hn`** — ссылки со метками заработали.

| Канал | Показов |
|---|---|
| direct | 123 |
| google.com | 4 |
| **reddit** | 3 |
| **hn** | 2 |

Проверок по-прежнему 2, выручка 0. Трафик пришёл, конверсии нет — это
отдельный вопрос, а не повод считать публикацию успешной.

## Грабли на будущее

1. Новый интерфейс Reddit (`www.reddit.com/submit`) борется с автоматизацией:
   вкладка закрывается, поле тела — React `contenteditable`, прямая установка
   значения не срабатывает, нужен `Input.insertText`.
2. `old.reddit.com/r/<sub>/submit?selftext=true` — простая форма, обычные
   `textarea[name=title]` и `textarea[name=text]`, кнопка `button[name=submit]`.
   Работать только через неё.
3. Форма грузится не мгновенно: проверять поля сразу после открытия — значит
   получить «НЕТ ПОЛЕЙ». Пауза 12–14 секунд.
4. `r/MCP` не грузится вообще (страница 69 символов) — вероятно, закрыт для
   этого аккаунта или требует больше кармы.
