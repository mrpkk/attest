"""Собрать офлайн-страницу проверки квитанции из одного источника — verify.js.

Зачем сборка, а не руками вписанный скрипт: две копии одного кода расходятся
через неделю, и страница начинает проверять не то, что проверяет библиотека.

Страница обязана работать без сети: JS встроен в файл, ни одного `fetch`,
ни одного внешнего шрифта или картинки. Это проверяется тестом, а не на слово.

Запуск: python3 tools/build_offline_page.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "attest" / "web" / "verify.js"
VECTORS = ROOT / "conformance" / "receipt-vectors.json"
OUT = ROOT / "attest" / "web" / "offline.html"

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify an agent receipt offline — attest</title>
<meta name="description" content="Check an agent action receipt in your browser. No network, no account, no upload: the verifier runs on this page.">
<style>
 body{{background:#0b0d12;color:#e8ecf4;font:16px/1.6 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:36px 20px 80px}}
 h1{{font-size:26px;margin:0 0 8px}} p.s{{color:#96a0ae;margin:0 0 20px}}
 textarea,input{{width:100%;box-sizing:border-box;background:#12161c;color:#e8ecf4;border:1px solid #2a323d;border-radius:8px;padding:10px 12px;font:13px/1.5 ui-monospace,monospace}}
 input{{margin:8px 0}}
 button{{background:#1c6b58;color:#eafff8;border:0;border-radius:8px;padding:11px 18px;font:600 15px system-ui;cursor:pointer;margin:8px 8px 8px 0}}
 button.alt{{background:#22303c}}
 pre{{background:#10141a;border:1px solid #232a33;border-radius:8px;padding:12px;overflow:auto;font-size:13px;min-height:44px}}
 .ok{{color:#7fd1b9}} .bad{{color:#ff9a8b}} .warn{{color:#e8c77f}}
 .note{{color:#8b95a3;font-size:14px}}
</style></head><body>
<h1>Check a receipt without trusting anyone</h1>
<p class="s">This page does the whole job locally: canonical form, schema, recomputed hash, Ed25519
signature. No account, no upload. <strong>The verifier itself makes no network call</strong> — turn off
Wi-Fi and it still works. One honest caveat: on this domain the hosting provider adds its own analytics
beacon. Save the page and open it from disk, and even that disappears.</p>

<label for="receipt">Receipt (canonical JSON, exactly the bytes you received)</label>
<textarea id="receipt" rows="14" spellcheck="false"></textarea>

<label for="key">Public key of the issuer (base64, 32 bytes)</label>
<input id="key" spellcheck="false">

<button onclick="run()">Verify</button>
<button class="alt" onclick="example()">Load the example</button>

<pre id="out">—</pre>
<p class="note" id="caps"></p>
<p class="note" id="size"></p>

<script type="module">
{js}

const EXAMPLE = {example};

capabilities().then((c) => {{
  const el = document.getElementById("caps");
  if (c.ed25519) {{
    el.className = "note ok";
    el.textContent = "Проверка подписи доступна в этом браузере (Ed25519 через WebCrypto).";
  }} else {{
    el.className = "note bad";
    el.textContent = "Этот браузер не умеет Ed25519 (" + c.reason + "). Проверка подписи здесь " +
      "не выполнится — это ограничение браузера, а не приговор квитанции. " +
      "Откройте страницу в Chromium-браузере или проверьте через CLI.";
  }}
}});

window.example = () => {{
  document.getElementById("receipt").value = EXAMPLE.text;
  document.getElementById("key").value = EXAMPLE.key;
  document.getElementById("out").textContent = "—";
}};

window.run = async () => {{
  const out = document.getElementById("out");
  const text = document.getElementById("receipt").value.trim();
  const key = document.getElementById("key").value.trim();
  if (!text || !key) {{ out.className = "warn"; out.textContent = "нужны квитанция и ключ"; return; }}
  out.className = "";
  out.textContent = "проверяю…";
  try {{
    const r = await verifyReceiptText(text, key);
    if (r.ok) {{
      out.className = "ok";
      out.textContent = "VALID\\n" + JSON.stringify({{
        status: r.status,
        note: "подпись, каноничность и хеш сошлись; это не значит, что агент был прав"
      }}, null, 1);
    }} else {{
      out.className = "bad";
      out.textContent = "NOT VALID · " + r.status + "\\n" + r.rejections.join("\\n");
    }}
  }} catch (e) {{
    out.className = "bad";
    out.textContent = "ошибка проверки: " + e.message;
  }}
}};

document.getElementById("size").textContent =
  "Страница целиком: " + (document.documentElement.outerHTML.length / 1024).toFixed(1) + " КБ. Сетевых запросов нет.";
</script>
</body></html>
"""


def main() -> None:
    js = JS.read_text(encoding="utf-8")
    # Встроить как есть, но без export-префиксов: страница использует модуль.
    js = js.replace("export function", "function").replace("export async function", "async function")

    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    valid = next(v for v in data["vectors"] if v["expect_ok"])
    example = {"text": valid["text"], "key": data["public_key"]}

    html = PAGE.format(js=js, example=json.dumps(example, ensure_ascii=False))
    OUT.write_text(html, encoding="utf-8")
    size = len(html.encode())
    print(f"собрано: {OUT} · {size/1024:.1f} КБ")
    if size > 100_000:
        raise SystemExit("страница больше 100 КБ — предел из SPEC")
    if re.search(r"\bfetch\(|XMLHttpRequest|https?://(?!www\.w3\.org)", html):
        raise SystemExit("в странице найден сетевой вызов или внешний URL")


if __name__ == "__main__":
    main()
