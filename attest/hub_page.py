"""Хаб: одна страница со всеми продуктами и входом в скан."""


def hub_page() -> str:
    tools = [
        ("Site Guard", "$49/год", "https://nidhipati.ailegal.legal/pay/card?product=site-guard-year",
         "Uptime, SSL и домен. Алерт в Telegram."),
        ("Channel Vault", "$19", "https://nidhipati.ailegal.legal/pay/card?product=channel-vault-export",
         "Бэкап Telegram-канала в ZIP."),
        ("Doc Answer Box", "$49", "https://nidhipati.ailegal.legal/pay/card?product=doc-answer-box",
         "Вопросы по своим документам с цитатами."),
        ("Sheet Doctor", "$19", "https://nidhipati.ailegal.legal/pay/card?product=sheet-doctor",
         "Чистка Excel/CSV и отчёт."),
    ]
    products = [
        ("attest", "https://attest.rta.lat", "Скан MCP-сервера и проверка артефактов. Бесплатный скан."),
        ("KARTA", "https://karta.rta.lat", "Контроль расходов агента: лимиты, мандаты, квитанции."),
        ("drift", "https://drift.rta.lat", "Политики и kill-switch для платежей агента."),
        ("Nidhipati", "https://nidhipati.ailegal.legal", "Касса и доказательство расходов."),
        ("PRAMANA", "https://pramana.ailegal.legal", "RAG по корпоративным документам с цитатами."),
        ("AIBiz", "https://aibiz.rta.lat", "Разбор бизнес-модели по живым картам."),
        ("crypto MCP", "https://crypto.rta.lat", "Крипто-данные одним ключом для агентов."),
        ("Rigveda", "https://rta.lat/rigveda", "Ведический бот и ежедневная практика."),
    ]
    tcards = "".join(
        f'<div class="c"><b>{t}</b><p class="p">{p}</p><p class="d">{d}</p>'
        f'<a class="b" href="{u}">Купить</a></div>' for t, p, u, d in tools)
    pcards = "".join(
        f'<div class="c"><b>{n}</b><p class="d">{d}</p><a href="{u}">Открыть →</a></div>'
        for n, u, d in products)
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Инструменты для агентов — IndrA</title>
<style>
:root{{color-scheme:dark}}
body{{margin:0;background:#0d1117;color:#e6edf3;font:16px/1.55 system-ui,sans-serif}}
main{{max-width:980px;margin:0 auto;padding:48px 20px}}
h1{{font-size:32px;margin:0 0 6px}} h2{{margin:34px 0 12px;font-size:20px}}
.s{{color:#8b949e;margin:0 0 18px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}
.c{{border:1px solid #30363d;border-radius:12px;padding:14px;background:#161b22}}
.p{{font-size:20px;font-weight:700;margin:2px 0 6px}} .d{{color:#8b949e;font-size:14px;margin:0 0 8px}}
.b{{display:inline-block;padding:8px 12px;border-radius:8px;background:#2f81f7;color:#fff;text-decoration:none}}
a{{color:#58a6ff}}
.scan{{display:inline-block;margin:10px 0 0;padding:12px 18px;border-radius:10px;background:#1f6feb;color:#fff;text-decoration:none;font-weight:600}}
</style></head><body><main>
<h1>Инструменты для агентов</h1>
<p class="s">Проверяем, что агент получил; держим его расходы в рамках; отвечаем по документам с цитатами.</p>
<a class="scan" href="https://attest.rta.lat/scan">Бесплатно: просканировать MCP-сервер →</a>
<h2>Простые продукты</h2><div class="grid">{tcards}</div>
<h2>Продукты</h2><div class="grid">{pcards}</div>
<p class="s" style="margin-top:26px">Оплата картой или USDC. Без подписки там, где можно заплатить разово.</p>
</main></body></html>"""
