"""Страница /tools: четыре «скучных» продукта для стабильного дохода.

Оплата — карта/USDC через Nidhipati (год или разово), без подписки.
"""
from html import escape

CARDS = [
    ("Site Guard — uptime, SSL, домен", "49", "site-guard-year",
     "Проверка сайта каждые 5 минут, срок SSL и домена, алерт в Telegram. Один сайт, 12 месяцев.",
     "Сайт упал — вы узнаёте первым, а не клиент."),
    ("Channel Vault — бэкап Telegram-канала", "19", "channel-vault-export",
     "Полный экспорт постов, медиа и участников в ZIP. Один канал, один экспорт.",
     "Контент канала не теряется вместе с каналом."),
    ("Doc Answer Box — RAG для папки", "49", "doc-answer-box",
     "Загрузите документы — получите ссылку с вопросами и цитатами. Один отдел, первый месяц.",
     "Ответы по своим документам, с цитатой, а не «примерно»."),
    ("Sheet Doctor — чистка Excel/CSV", "19", "sheet-doctor",
     "Дубли, пробелы, даты, битые строки: чистый файл + отчёт. До 50 000 строк.",
     "Таблица, которой можно верить."),
]


def tools_page() -> str:
    cards = []
    for title, price, product, desc, why in CARDS:
        cards.append(f"""<div class="c">
<h2>{escape(title)}</h2>
<p class="p">${escape(price)}</p>
<p>{escape(desc)}</p>
<p class="w">{escape(why)}</p>
<a class="b" href="https://nidhipati.ailegal.legal/pay/card?product={escape(product)}">Оплатить картой</a>
</div>""")
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Простые инструменты — attest</title>
<style>
:root{{color-scheme:dark}}
body{{margin:0;background:#0d1117;color:#e6edf3;font:16px/1.55 system-ui,sans-serif}}
main{{max-width:900px;margin:0 auto;padding:44px 20px}}
h1{{font-size:30px;margin:0 0 6px}} .s{{color:#8b949e;margin:0 0 26px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}}
.c{{border:1px solid #30363d;border-radius:12px;padding:16px;background:#161b22}}
.c h2{{font-size:17px;margin:0 0 4px}} .p{{font-size:22px;font-weight:700;margin:0 0 8px}}
.w{{color:#8b949e;font-size:14px}}
.b{{display:inline-block;margin-top:8px;padding:10px 14px;border-radius:8px;background:#2f81f7;color:#fff;text-decoration:none}}
a{{color:#58a6ff}}</style></head><body><main>
<p><a href="/">← attest</a></p>
<h1>Простые инструменты</h1>
<p class="s">Четыре скучные вещи, которые нужны каждый месяц. Оплата картой или USDC, без подписки.</p>
<div class="grid">{''.join(cards)}</div>
</main></body></html>"""
