#!/usr/bin/env python3
"""Собрать страницу статьи из markdown.

Источник правды — `docs/THE-SAME-SENTENCE-DIFFERENT-FIELDS.md`. HTML не
правится руками: он генерируется и коммитится, чтобы текст не разошёлся
в репозитории и на живом домене.

    python3 tools/render_article.py

Конвертер намеренно узкий: под синтаксис этой статьи. Таблицы, блоки кода,
списки, жирный, `код`, ссылки и горизонтальные линии. Всё незнакомое
попадает в текст как есть — лучше показать лишнее, чем потерять смысл.
"""

from __future__ import annotations

import html
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "THE-SAME-SENTENCE-DIFFERENT-FIELDS.md"
TARGET = ROOT / "attest" / "article.py"

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>The same sentence means different things depending on which field it sits in — attest</title>
<meta name="description" content="A prompt-injection scanner that flattens every string will be wrong about almost every interesting case. Position in the document decides severity.">
<link rel="canonical" content="https://attest.rta.lat/article">
<meta property="og:title" content="The same sentence means different things depending on which field it sits in">
<meta property="og:description" content="Why prompt-injection detection must be positional, not phrasal.">
<meta property="og:type" content="article">
<meta property="og:url" content="https://attest.rta.lat/article">
<meta name="twitter:card" content="summary">
<link rel="alternate" type="text/markdown" href="https://raw.githubusercontent.com/mrpkk/attest/main/docs/THE-SAME-SENTENCE-DIFFERENT-FIELDS.md">
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
  table {{ border-collapse:collapse; width:100%; margin:0 0 20px; font-size:14.5px; }}
  th,td {{ border:1px solid #232a33; padding:8px 11px; text-align:left; vertical-align:top; }}
  th {{ background:#141920; font-weight:600; }}
  ul {{ margin:0 0 16px; padding-left:22px; }}
  li {{ margin:0 0 6px; }}
  blockquote {{ border-left:3px solid #2b3440; margin:0 0 16px; padding:2px 0 2px 15px;
                color:#a9b4c0; }}
  hr {{ border:0; border-top:1px solid #232a33; margin:34px 0; }}
  .byline {{ color:#8b97a4; font-size:14px; margin:0 0 30px; }}
  .cta {{ border:1px solid #232a33; border-radius:10px; padding:16px 18px;
          margin:34px 0 0; background:#10141a; }}
  .cta b {{ color:#7fd1b9; }}
</style>
</head><body><main>
<article>
{body}
<div class="cta">
<b>attest</b> — deterministic verifier for agent artifacts: schema, provenance,
signatures, injection scanning, machine-readable verdict.<br>
API <code>https://attest.rta.lat</code> · MCP <code>https://attest.rta.lat/mcp</code><br>
Paid per call over x402, or 9 USDC / 30 days unlimited.
</div>
</article>
</main></body></html>
"""


def inline(text: str) -> str:
    """Сначала экранируем, потом размечаем: иначе теги из текста уедут в HTML."""
    text = html.escape(text, quote=False)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![\w/])https?://([^\s<)]+)", r'<a href="https://\1">\1</a>', text)
    return text


def render(md: str) -> str:
    out: list[str] = []
    lines = md.split("\n")
    i = 0
    first_heading_skipped = False

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped.startswith("```"):
            i += 1
            block = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>" + html.escape("\n".join(block)) + "</code></pre>")
            continue

        if stripped.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i].strip())
                i += 1
            cells = [[c.strip() for c in r.strip("|").split("|")] for r in rows]
            cells = [c for c in cells if not all(set(c) <= {"-", ":", " "} for _ in [0])]
            head, body_rows = cells[0], cells[1:]
            parts = ["<table><thead><tr>"]
            parts += [f"<th>{inline(c)}</th>" for c in head]
            parts.append("</tr></thead><tbody>")
            for r in body_rows:
                parts.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>")
            parts.append("</tbody></table>")
            out.append("".join(parts))
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            level, text = len(m.group(1)), m.group(2)
            if level == 1 and not first_heading_skipped:
                first_heading_skipped = True
                out.append(f"<h1>{inline(text)}</h1>")
                out.append('<p class="byline">By mrpkk · <code>attest</code> · '
                           'verified against live scanner output</p>')
            else:
                out.append(f"<h{level}>{inline(text)}</h{level}>")
            i += 1
            continue

        if stripped in ("---", "***", "___"):
            out.append("<hr>")
            i += 1
            continue

        if stripped.startswith(">"):
            quote = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip().lstrip("> ").rstrip())
                i += 1
            out.append("<blockquote><p>" + inline(" ".join(quote)) + "</p></blockquote>")
            continue

        m = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if m:
            items = []
            while i < len(lines):
                mm = re.match(r"^(\d+)\.\s+(.*)$", lines[i].strip())
                if not mm:
                    break
                items.append(mm.group(2))
                i += 1
            out.append("<ul>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ul>")
            continue

        if stripped.startswith(("- ", "* ")):
            items = []
            while i < len(lines) and re.match(r"^[-*]\s+", lines[i].strip()):
                items.append(re.sub(r"^[-*]\s+", "", lines[i].strip()))
                i += 1
            out.append("<ul>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ul>")
            continue

        para = []
        while i < len(lines) and lines[i].strip() and not re.match(
                r"^(#{1,6}\s|\||```|>|[-*]\s|\d+\.\s)", lines[i].strip()):
            para.append(lines[i].strip())
            i += 1
        out.append("<p>" + inline(" ".join(para)) + "</p>")

    return "\n".join(out)


def main() -> None:
    md = SOURCE.read_text(encoding="utf-8")
    body = render(md)
    page = PAGE.format(body=body)
    TARGET.write_text(
        '"""Страница статьи. Генерируется tools/render_article.py — не править руками."""\n'
        "\n"
        "ARTICLE_HTML = " + repr(page) + "\n",
        encoding="utf-8",
    )
    print(f"  {TARGET.relative_to(ROOT)}: {len(page)} байт, {body.count('<h')} заголовков")


if __name__ == "__main__":
    main()