#!/usr/bin/env python3
"""Сгенерировать страницу-чеклист каталогов MCP из markdown.

Тот же markdown-рендер, что и у статьи, — иначе две разные разметки
разъедутся, и страница будет выглядеть чужеродно рядом со статьёй.

Запуск: python3 tools/render_catalogs.py
Результат: attest/catalogs.py (модуль с HTML) + catalogs.html в корне репо.
"""

from __future__ import annotations

import pathlib
import sys

from render_article import render  # тот же парсер, что и у статьи

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "MCP-CATALOG-CHECKLIST.md"
TARGET = ROOT / "attest" / "catalogs.py"

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nine reasons your MCP server never shows up in the directories — attest</title>
<meta name="description" content="What actually blocks MCP servers from appearing in directories: the 100-character description limit, empty resources/prompts lists, tool annotations, privacy policy 404, and a placeholder hostname in llms-install.md.">
<meta property="og:title" content="Nine reasons your MCP server never shows up in the directories">
<meta property="og:description" content="Nine checks that decide whether a directory lists your MCP server — with the exact request that broke each one.">
<meta property="og:type" content="article">
<meta property="og:url" content="https://attest.rta.lat/catalogs">
<meta property="og:site_name" content="attest">
<meta property="og:image" content="https://attest.rta.lat/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="https://attest.rta.lat/og.png">
<link rel="canonical" content="https://attest.rta.lat/catalogs">
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; background:#0b0d10; color:#e6e6e6;
         font:16px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
  main {{ max-width: 720px; margin:0 auto; padding: 40px 20px 80px; }}
  h1 {{ font-size:30px; line-height:1.25; margin:0 0 8px; letter-spacing:-.02em; }}
  h2 {{ font-size:21px; margin:38px 0 10px; letter-spacing:-.01em; }}
  h3 {{ font-size:17px; margin:26px 0 8px; }}
  p {{ margin:0 0 15px; }}
  a {{ color:#7fd1b9; }}
  code {{ background:#171b21; padding:2px 5px; border-radius:4px; font-size:.9em;
         font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  pre {{ background:#12161c; border:1px solid #232a33; border-radius:8px;
        padding:13px 15px; overflow:auto; margin:0 0 18px; }}
  pre code {{ background:none; padding:0; font-size:13.5px; line-height:1.5; }}
  ul {{ margin:0 0 16px; padding-left:22px; }}
  li {{ margin:0 0 6px; }}
  blockquote {{ border-left:3px solid #2b3440; margin:0 0 16px; padding:2px 0 2px 15px;
               color:#a9b4c0; }}
  hr {{ border:0; border-top:1px solid #232a33; margin:34px 0; }}
  .cta {{ border:1px solid #232a33; border-radius:10px; padding:16px 18px;
         margin:34px 0 0; background:#10141a; }}
  .cta b {{ color:#7fd1b9; }}
</style>
</head><body><main>
<article>
{body}
<div class="cta">
<b>attest</b> — проверка артефактов, которые агент получает от другого агента:
схема, пустота, привязка к условиям генерации, право действовать по мандату.
Вердикт подписан Ed25519 и проверяется офлайн.<br>
20 проверок в сутки бесплатно и без регистрации, дальше $0.005 за вызов
(x402, USDC в сети Base) или $9 за 30 дней. Для Индии — те же 30 дней за $3.<br>
MCP: <code>https://attest.rta.lat/mcp</code> ·
<a href="https://attest.rta.lat/start">100 бесплатных проверок по заявке</a> ·
<a href="https://attest.rta.lat/demo">демо</a>
</div>
</article>
</main></body></html>
"""


def main() -> None:
    md = SOURCE.read_text(encoding="utf-8")
    body = render(md)
    page = PAGE.format(body=body)
    TARGET.write_text(
        '"""Страница-чеклист каталогов MCP. Генерируется tools/render_catalogs.py."""\n'
        "\n"
        "CATALOGS_HTML = " + repr(page) + "\n",
        encoding="utf-8",
    )
    (ROOT / "catalogs.html").write_text(page, encoding="utf-8")
    print(f"  {TARGET.relative_to(ROOT)}: {len(page)} байт")


if __name__ == "__main__":
    sys.exit(main())
