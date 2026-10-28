"""HTTP-сервис: клиент проверяет артефакт бесплатно, потом платит за вызов.

Зачем сервис, если есть `attest()`: библиотекой пользуются разработчики, а
проверять чужой артефакт должен заказчик, у которого нет кода. Пока сервиса
не было, продукт был недоступен никому, кроме нас, то есть зарабатывать
на нём было нечем.

Бесплатный тариф — не маркетинг, а проверка спроса: если после N бесплатных
проверок никто не возвращается, товар не нужен, и это дешевле узнать
сейчас, чем после полугода разработки. Лимит считается по адресу клиента
и живёт в памяти процесса: при перезапуске счётчик сбрасывается, что
допустимо для бесплатного тарифа и недопустимо для платного.
"""

from __future__ import annotations

import base64
import json
import os
import hashlib
import hmac
import re
import smtplib
import ssl
import time
from collections import defaultdict
from email.message import EmailMessage
from functools import lru_cache
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import uuid as _uuid
from urllib.parse import parse_qs, urlparse

from . import __version__
from .core import attest, _coerce_json_field
from .metrics import METRICS, STATE_PATH, channel_of, spent_nonces
from .receipt import cose as _cose
from .receipt import log as _tlog


def _tlog_public_key(private_key) -> str:
    """Публичный ключ головы дерева — в base64, чтобы проверяющий не ходил к нам."""
    import base64 as _b64
    return _b64.b64encode(private_key.public_key().public_bytes_raw()).decode()
from .signing import public_key_b64
from . import entitlement
from .entitlement import (HEADER as ENT_HEADER, issue as issue_entitlement,
                          redeem, redeem_entitlement,
                          describe as entitlement_describe)
from .generation import GenerationContext, verify_chain
from .provenance import digest as _digest

_GEN_FIELDS = ("model", "model_version", "prompt", "parameters",
              "generated_at", "generator", "generator_version")
from .emptiness import (emptiness_score, emptiness_verdict,
                           scan_for_emptiness)
from .payment import PaymentError
from . import enot
from . import onchain
from .x402 import atomic_to_usd, agent_card, discovery_document

DEFAULT_FREE_DAILY = 20
# Проверка адреса для заявки: нам не нужен RFC-строгий разбор, нужно
# понять, что адрес похож на почту, и не потерять заявку из-за опечатки.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+\.[A-Za-z]{2,}$")

# Заголовок, которым маркетплейс (api.market) подтверждает свой вызов.
# Секрет задаётся ATTEST_GATEWAY_KEY на сервере; без него заголовок
# игнорируется целиком — «пустой ключ» не должен открывать платный путь.
GATEWAY_HEADER = "X-API-Market-Key"
MAX_BODY_BYTES = 512 * 1024
FREE_TTL_SECONDS = 30 * 24 * 3600

PRICING = {
    "free": {
        "price": "0",
        "unit": "checks per day",
        "what": "full check, no limit on artifact size",
    },
    "per_call": {
        "price": "0.005",
        "currency": "USDC",
        "network": "base",
        "what": "check beyond the free tier, paid per call over x402",
    },
    # Раньше здесь стояло «99 USDC в месяц» без кода приёма: тариф был виден
    # в прайсе и не выдавался. Объявленная цена, которую нельзя оплатить,
    # хуже отсутствующей — покупатель уходит и запоминает.
    "subscription": entitlement_describe(),
}


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


FREE_DAILY_LIMIT = _env_int("ATTEST_FREE_DAILY", DEFAULT_FREE_DAILY)



def _schema_block() -> str:
    """Разметка товара для поиска: тип, имя, цена, где найти."""
    data = {
    "@type": "SoftwareApplication",
    "name": "attest",
    "applicationCategory": "DeveloperApplication",
    "operatingSystem": "Any",
    "description": "Four-layer verification for AI agent artifacts: schema, emptiness, generation conditions and mandate authority. Ed25519-signed and verifiable without trusting the service.",
    "url": "https://attest.rta.lat/",
    "offers": {
        "@type": "AggregateOffer",
        "lowPrice": "0",
        "highPrice": "9",
        "priceCurrency": "USDC"
    }
}
    data["@context"] = "https://schema.org"
    return ('<script type="application/ld+json">'
            + json.dumps(data, ensure_ascii=False) + "</script>")


def _with_schema(html: str) -> str:
    """Вставить разметку в HTML. Идемпотентно: повторный вызов не дублирует."""
    if not isinstance(html, str) or "application/ld+json" in html:
        return html
    block = _schema_block()
    lowered = html.lower()
    for marker in ("</head>", "<body", "</title>"):
        pos = lowered.find(marker)
        if pos != -1:
            return html[:pos] + block + html[pos:]
    import re
    m = re.search(r"<meta[^>]+charset[^>]*>", html, re.IGNORECASE)
    if m:
        return html[:m.end()] + block + html[m.end():]
    return block + html

class FreeTierExhausted(Exception):
    """Бесплатные проверки кончились; дальше — по x402."""

    def __init__(self, used: int, limit: int) -> None:
        super().__init__(f"free limit reached: {used}/{limit}")
        self.used = used
        self.limit = limit


class FreeTier:
    """Счётчик бесплатных проверок: клиент → (день, потрачено).

    Хранится в памяти процесса. Это осознанное ограничение: подделать
    счётчик извне нельзя, но и пережить перезапуск он не может.
    """

    def __init__(self, daily_limit: int = FREE_DAILY_LIMIT) -> None:
        self.daily_limit = daily_limit
        self._used: dict[str, tuple[str, int]] = defaultdict(lambda: ("", 0))

    @staticmethod
    def _day(moment: float | None = None) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(moment))

    def used(self, client: str, now: float | None = None) -> int:
        day, count = self._used[client]
        return count if day == self._day(now) else 0

    def remaining(self, client: str, now: float | None = None) -> int:
        return max(0, self.daily_limit - self.used(client, now))

    def spend(self, client: str, now: float | None = None) -> None:
        """Списать одну проверку или отказать, если лимит кончился."""
        day, count = self._used[client]
        if day != self._day(now):
            count = 0
        if count >= self.daily_limit:
            raise FreeTierExhausted(count, self.daily_limit)
        self._used[client] = (self._day(now), count + 1)

    def reset(self, client: str) -> None:
        self._used.pop(client, None)



_FEEDBACK_JS = r"""
(function(){
  var lang = document.documentElement.lang || "en";
  var hi = lang.indexOf("hi") === 0;
  var T = hi ? {
    q: "क्या यह पेज उपयोगी रहा?",
    up: "हाँ", down: "नहीं", send: "भेजें", thanks: "धन्यवाद!",
    ph: "क्या सुधारना चाहेंगे? (वैकल्पिक)"
  } : {
    q: "Was this page useful?",
    up: "Yes", down: "No", send: "Send", thanks: "Thanks!",
    ph: "What would you improve? (optional)"
  };
  var key = "attest-fb:" + location.pathname;
  try { if (localStorage.getItem(key)) return; } catch (e) {}
  var box = document.createElement("div");
  box.style.cssText = "position:fixed;right:16px;bottom:16px;z-index:9999;background:#141821;border:1px solid #1f242e;border-radius:12px;padding:10px 12px;color:#e8ecf4;font:13px/1.4 system-ui,sans-serif;opacity:.92;max-width:260px;box-shadow:0 8px 24px rgba(0,0,0,.4)";
  box.innerHTML = '<div style="margin-bottom:6px">' + T.q + '</div>';
  var row = document.createElement("div");
  function mk(txt, verdict) {
    var b = document.createElement("button");
    b.textContent = txt;
    b.style.cssText = "margin-right:6px;padding:4px 10px;border-radius:8px;border:1px solid #2a3140;background:#0b0d12;color:#e8ecf4;cursor:pointer";
    b.onclick = function(){ ask(verdict); };
    return b;
  }
  row.appendChild(mk(T.up, "up"));
  row.appendChild(mk(T.down, "down"));
  box.appendChild(row);
  function ask(verdict) {
    var f = document.createElement("div");
    var ta = document.createElement("textarea");
    ta.placeholder = T.ph;
    ta.style.cssText = "width:100%;min-height:48px;margin:8px 0;background:#0b0d12;color:#e8ecf4;border:1px solid #2a3140;border-radius:8px;padding:6px 8px;font:12px/1.4 system-ui,sans-serif;box-sizing:border-box";
    var sb = document.createElement("button");
    sb.textContent = T.send;
    sb.style.cssText = "padding:4px 10px;border-radius:8px;border:1px solid #2a3140;background:#0b0d12;color:#e8ecf4;cursor:pointer";
    sb.onclick = function(){
      fetch("/feedback", {method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({verdict: verdict, comment: ta.value.slice(0, 500), page: location.pathname})
      }).finally(function(){
        try { localStorage.setItem(key, "1"); } catch (e) {}
        box.textContent = T.thanks;
        setTimeout(function(){ box.remove(); }, 2500);
      });
    };
    f.appendChild(ta); f.appendChild(sb);
    box.appendChild(f); ta.focus();
  }
  function mount(){ if (!document.body.contains(box)) document.body.appendChild(box); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount); else mount();
})();
"""

_VERIFY_GET_HTML = """<!doctype html><meta charset=utf-8><title>attest</title>
<style>body{background:#0b0d12;color:#e8ecf4;font:16px/1.6 system-ui,sans-serif;
max-width:720px;margin:60px auto;padding:0 24px}code{background:#141821;padding:2px 6px;
border-radius:5px;color:#f0a35e}.b{background:#141821;border:1px solid #1f242e;border-radius:12px;
padding:18px 20px;margin:18px 0}a{color:#f0a35e}</style>
<h1 style="font-size:24px">/verify accepts POST</h1>
<p>This is an API, not a page. Opening it in a browser sends GET, and the
server replies <code>404</code> &mdash; correctly: there is no artifact to
check in the request.</p>
<div class=b><b>Live example in a browser:</b><br>
<a href="/demo">/demo &mdash; a form where you can check your own artifact</a></div>
<div class=b><b>From a terminal:</b>
<pre style="background:#141821;padding:12px;border-radius:9px;overflow:auto">curl -X POST __BASE__/verify \\
  -H 'Content-Type: application/json' \\
  -d '{"artifact":{"findings":["a finding"]},"source":"demo"}'</pre></div>
"""

DEMO = """<!doctype html><meta charset=utf-8><title>attest — artifact verification demo</title>
<meta name="description" content="Run the four-layer verifier on a live artifact: schema conformance, emptiness, generation provenance and mandate authority, with an Ed25519-signed verdict.">
<meta property="og:title" content="attest — four-layer verification demo">
<meta property="og:description" content="Run the checker on a live artifact and see all four layers in one response.">
<meta property="og:image" content="https://attest.rta.lat/og.png">
<meta property="og:url" content="https://attest.rta.lat/demo">
<meta name="twitter:card" content="summary_large_image">
<link rel="canonical" href="https://attest.rta.lat/demo">
<style>
 body{background:#0b0d12;color:#e8ecf4;font:15px/1.6 system-ui,sans-serif;max-width:900px;margin:48px auto;padding:0 24px}
 h1{font-size:26px;margin-bottom:4px} .s{color:#969eac;font-size:14px}
 .g{display:grid;gap:14px;grid-template-columns:1fr 1fr;margin:22px 0}
 .c{background:#141821;border:1px solid #1f242e;border-radius:12px;padding:16px 18px}
 .c h2{font-size:15px;margin:0 0 10px;color:#f0a35e}
 textarea{width:100%;height:90px;background:#0b0d12;color:#e8ecf4;border:1px solid #2a3140;
   border-radius:8px;padding:10px;font:13px ui-monospace,monospace;box-sizing:border-box}
 input{box-sizing:border-box}
 button{background:#f0a35e;color:#0b0d12;border:0;border-radius:8px;padding:10px 18px;
   font-weight:600;cursor:pointer;margin-top:12px}
 pre{background:#0b0d12;border:1px solid #1f242e;border-radius:10px;padding:14px;
   overflow:auto;font-size:12.5px;max-height:400px;white-space:pre-wrap;word-break:break-word}
 .q{background:#141821;border-left:3px solid #f0a35e;padding:12px 16px;border-radius:8px;margin:18px 0}
 label{display:block;font-size:13px;color:#969eac;margin:10px 0 4px}
</style>
<h1>attest — artifact verification for agents</h1>
<p class=s>__FREE_LIMIT__ free checks per day. Then 0.005 USDC over x402.</p>

<div class=q><b>Four layers, four different questions:</b> is the form right?
is there anything inside it? what conditions produced it? was the action
permitted? Each layer answers only its own question and never substitutes
for the others.</div>

<div class=g>
 <div class=c><h2>1. Artifact — form and emptiness</h2>
  <label>Artifact JSON</label>
  <textarea id="art">{"summary":"Analysis complete","findings":["first finding","second finding","third finding"]}</textarea>
  <button onclick="run()">Check form and emptiness</button>
  <button type="button" onclick="badExample()" title="Same form, no content: every validator passes, the artifact is empty">Try a bad one</button>
  <span id="badhint" style="display:none;color:#f0a35e;font-size:13px">5 identical findings: the schema is perfect, the content is not.</span>
  </div>
  <script>
  function badExample(){
    var f = []; for (var i = 0; i < 5; i++) f.push({rule: "sql-injection", severity: "high", line: 42});
    document.getElementById("art").value = JSON.stringify({summary: "Scan complete", findings: f});
    var h = document.getElementById("badhint"); if (h) h.style.display = "inline";
  }
  </script>
 <div class=c><h2>2. Generation conditions</h2>
  <label>Model</label><input id="model" value="claude-sonnet-4" style="width:100%;background:#0b0d12;color:#e8ecf4;border:1px solid #2a3140;border-radius:8px;padding:8px">
  <label>Prompt</label><input id="prompt" value="Find vulnerabilities in the contract" style="width:100%;background:#0b0d12;color:#e8ecf4;border:1px solid #2a3140;border-radius:8px;padding:8px">
  <button onclick="runGen()">Check and sign</button></div>
 <div class=c><h2>3. Authority — the mandate</h2>
  <label>Action amount (minor units)</label>
  <input id="amt" value="50000" style="width:100%;background:#0b0d12;color:#e8ecf4;border:1px solid #2a3140;border-radius:8px;padding:8px">
  <label>Mandate limit</label>
  <input id="lim" value="100000" style="width:100%;background:#0b0d12;color:#e8ecf4;border:1px solid #2a3140;border-radius:8px;padding:8px">
  <button onclick="runAuth()">Check authority</button></div>
 <div class=c><h2>4. Signature — verify it yourself</h2>
  <p style="font-size:13.5px;color:#969eac;margin:0">Ed25519: the public key
  travels with the attestation. Verification needs neither our service nor a
  secret.</p>
  <pre id="vk" style="max-height:110px">run a check to see the attestation</pre></div>
</div>

<h2>Run it in CI, on every commit</h2>
<p class=s>A check that runs only when someone remembers does not protect a pipeline.
Same four layers, one call per artifact file, the build fails on a rejection.</p>
<pre>- uses: mrpkk/attest@v1
  with:
    paths: 'reports/*.json'
    fail-on: reject</pre>
<p class=s><a href="https://github.com/mrpkk/attest">Action and CLI</a> ·
a network error or an exhausted quota is reported as an error, never as accepted.</p>

<h2 style="font-size:16px;margin-top:28px">Response</h2>
<pre id="out">press any button above</pre>

<script>
const B = location.origin;
async function post(body){
  const r = await fetch(B+"/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  return r.json();
}
function show(d){
  document.getElementById("out").textContent = JSON.stringify(d,null,2);
  if(d.attestation){document.getElementById("vk").textContent =
    JSON.stringify({algorithm:d.attestation.algorithm,public_key:(d.attestation.public_key||"").slice(0,32)+"...",signature:(d.attestation.signature||"").slice(0,32)+"..."},null,2);}
}
function parse(id){ try{return JSON.parse(document.getElementById(id).value)}catch(e){alert("JSON parse failed: "+e.message);throw e} }
async function run(){ show(await post({artifact:parse("art"),source:"demo"})) }
async function runGen(){
  show(await post({artifact:parse("art"),source:"demo",
    generation:{model:document.getElementById("model").value,model_version:"2026-05",
      prompt:document.getElementById("prompt").value,parameters:{temperature:0.2,max_tokens:2000},
      generated_at:Date.now()/1000,generator:"demo"}})) }
async function runAuth(){
  const amt=+document.getElementById("amt").value, lim=+document.getElementById("lim").value;
  show(await post({artifact:parse("art"),source:"demo",
    mandate:{payee_id:"0xAAA",audience:"c7",max_amount_minor:lim,currency:"USDC",valid_from:1000,valid_until:2000000},
    action:{payee_id:"0xAAA",audience:"c7",amount_minor:amt,currency:"USDC",at:1500,intent:"transfer"}})) }
</script>
<script src="/feedback.js" defer></script>
"""

@lru_cache(maxsize=1)
def _mail_credentials() -> tuple[str, str]:
    """EMAIL и MYACCOUNT_GOOGLE из ~/.env.

    Сервис не получает .env от systemd, а пароль почты в unit-файле — худшее
    место для секрета: он попадает в `systemctl cat` и в каждый дамп.
    Читаем файл один раз и держим в памяти процесса.
    """
    env: dict[str, str] = {}
    try:
        text = (Path.home() / ".env").read_text(encoding="utf-8")
    except OSError:
        return "", ""
    for line in text.splitlines():
        m = re.match(r'^([A-Z0-9_]+)=["\']?(.*?)["\']?$', line)
        if m:
            env[m.group(1)] = m.group(2)
    return env.get("EMAIL", ""), env.get("MYACCOUNT_GOOGLE", "").replace(" ", "")


def _send_key_email(to: str, token: str, valid_until: int) -> str:
    """Отправить ключ доступа. Возвращает "" при успехе, иначе причину.

    Заявка на лид-магните обещает ключ — без этой функции обещание остаётся
    обещанием, а человек уходит ждать письмо, которого никто не отправит.
    """
    sender, password = _mail_credentials()
    if not sender or not password:
        return "SMTP не настроен (нет EMAIL или MYACCOUNT_GOOGLE в ~/.env)"
    import datetime as _dt
    until = _dt.datetime.fromtimestamp(valid_until).strftime("%Y-%m-%d")
    body = (
        "Hi,\n\n"
        "Here is the key for 100 artifact checks over 30 days.\n\n"
        f"X-ATTEST-ENTITLEMENT: {token}\n\n"
        "Two ways to use it:\n"
        "1) HTTP: POST https://attest.rta.lat/verify with the header above.\n"
        "2) MCP: https://attest.rta.lat/mcp, tool verify_artifact, same header.\n\n"
        f"The key is signed and valid until {until}. It simply stops working after\n"
        "that date — no auto-renewal, no card on file.\n\n"
        "If a check returns a verdict you disagree with, reply and tell me what it\n"
        "said and what you expected. That is the most useful feedback I can get\n"
        "right now: nobody has paid for this yet, and I would rather fix a wrong\n"
        "verdict than collect a paying customer who does not trust the answer.\n\n"
        "Maksim\nhttps://attest.rta.lat\n"
    )
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = "Your attest key — 100 checks, 30 days"
    msg.set_content(body)
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465,
                              context=ssl.create_default_context(), timeout=20) as smtp:
            smtp.login(sender, password)
            smtp.send_message(msg)
        return ""
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"


_PLANS_HTML = """<!doctype html><html lang="en"><head><meta charset=utf-8>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>attest — pricing</title>
<meta name="description" content="attest pricing: a free verifier, an agent spend audit at $500, a $1,500/mo retainer, and developer access at $0.005 per call or $99 for 30 days.">
<link rel="canonical" href="https://attest.rta.lat/plans">
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.65 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:44px 22px 80px}
 h1{font-size:28px;margin:0 0 6px} h2{font-size:18px;margin:30px 0 10px}
 .s{color:#969eac;margin:0 0 22px}
 .tiers{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));margin:18px 0}
 .t{background:#141821;border:1px solid #232a33;border-radius:12px;padding:16px}
 .t b{display:block;color:#9fb0c4;font-size:13px;text-transform:uppercase;letter-spacing:.04em;margin:0 0 6px}
 .p{font-size:22px;font-weight:600;margin:0 0 6px}
 .hint{color:#8b939f;font-size:14px}
 a{color:#7fd1b9} code{background:#171b21;padding:2px 6px;border-radius:4px;font-size:14px}
 .cta{display:inline-block;background:#1c6b58;color:#eafff8;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:600;margin:8px 0}
 ul{color:#c3cad4} li{margin:0 0 6px}
</style></head><body>
<h1>Pricing</h1>
<p class="s">One ladder, five lines. The verifier is free and stays free; the money is in the
report a human signs and the log that keeps running when nobody watches.</p>

<h2>Start here</h2>
<div class="tiers">
 <div class="t"><b>Audit</b><p class="p">$1,250</p><span class="hint">$500 flat. Ten working days: what your agents actually spent, what they actually got, and one line of evidence per finding. <a href="https://mrpkk.github.io/nidhipati/audit-sample.html">A public sample report</a>.</span></div>
 <div class="t"><b>Retainer</b><p class="p">$1,500/mo</p><span class="hint">After an audit: monthly re-check, new rules, and an alert when the same class of spend comes back.</span></div>
 <div class="t"><b>Enterprise</b><p class="p">On request</p><span class="hint">Private reserve confirmation, white-label receipts, the whole engine behind your brand.</span></div>
</div>
<p class="hint">Why an audit and not a subscription: a subscription asks to be trusted every month;
a report can be read once and checked. If there is nothing to find, the report says so and there is
no fee for finding nothing.</p>

<h2>Developer access</h2>
<p class="s">A check is one artifact verified against one schema. No account, no card, no SDK.
This rail exists for pipelines, not for buyers — it is priced at cost.</p>
<div class="tiers">
 <div class="t"><b>Free</b><p class="p">0 USDC</p><span class="hint">20 checks a day, forever. Full check: schema, emptiness, provenance, authority.</span></div>
 <div class="t"><b>Per call</b><p class="p">0.005 USDC</p><span class="hint">Beyond the free tier, paid over x402 on Base. Three steps: ask, sign, retry.</span></div>
 <div class="t"><b>30 days</b><p class="p">99 USDC</p><span class="hint">No daily cap while the token is valid. One-time prepayment, no auto-renewal.</span></div>
 <div class="t"><b>India (PPP)</b><p class="p">49 USDC</p><span class="hint">Same 30 days, purchasing-power price. <a href="/pay?plan=ppp">Pay</a>.</span></div>
</div>
<a class="cta" href="/start">100 free checks for 30 days</a>
<p class="hint">Or buy 30 days of unlimited checks: 99 USDC (49 for India), paid from any wallet — <a href="/pay">pay with USDC</a>. The transfer is verified on-chain and the token is issued in the same step.</p>
<h2>Why a subscription if a call costs $0.005</h2>
<ul>
 <li>A per-call price is paid every call, and a payment rail takes its share of a small amount. At $0.005 the fee eats most of the value.</li>
 <li>A 30-day token is one payment, then no per-call overhead: the right shape for CI pipelines that check every artifact.</li>
 <li>No recurring charges: when the 30 days run out, access stops. Renewal is an explicit new payment, never a surprise.</li>
</ul>
<h2>Why India has its own price</h2>
<p>A price is a share of a buyer's income. At Western levels most Indian teams cannot
justify a $99 line item for a verification step, and a product nobody can afford is not
a product. The $4 tier is the same 30 days — same four checks, same signed verdict —
at purchasing-power parity.</p>
<h2>What you actually buy</h2>
<p>A verdict you can check without trusting us. Every answer is Ed25519-signed; the
public key fingerprint is published, so a recipient can verify the verdict offline.
The service can be down, the verdict still verifies.</p>
<p class="hint">Not ready to pay? <a href="/review">Send one artifact for a free human review</a>.</p>
<p class="hint">Machine-readable price list: <a href="/pricing">/pricing</a> (JSON) ·
<a href="/privacy">privacy</a> · <a href="/demo">demo</a></p>
</body></html>"""


_START_HTML = """<!doctype html><html lang="en"><head><meta charset=utf-8>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>attest — 100 free checks for 30 days</title>
<meta name="description" content="Early access: 100 artifact checks for 30 days, no card, no signup. For teams that ship artifacts produced by AI agents.">
<link rel="canonical" href="https://attest.rta.lat/start">
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.6 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:44px 22px 80px}
 h1{font-size:28px;margin:0 0 6px} .s{color:#969eac;font-size:15px;margin:0 0 22px}
 .box{background:#141821;border:1px solid #232a33;border-radius:12px;padding:20px;margin:18px 0}
 label{display:block;font-size:14px;color:#c3cad4;margin:14px 0 6px}
 input,textarea{width:100%;box-sizing:border-box;background:#0e1117;color:#e8ecf4;border:1px solid #2b3440;border-radius:8px;padding:11px;font:15px system-ui,sans-serif}
 textarea{min-height:74px;resize:vertical}
 button{margin-top:18px;background:#1c6b58;color:#eafff8;border:0;border-radius:8px;padding:12px 18px;font:600 15px system-ui,sans-serif;cursor:pointer}
 button:hover{background:#22876e}
 .ok{background:#10241d;border:1px solid #1d5a45;color:#9ff0cf;padding:14px;border-radius:8px;margin-top:16px}
 .err{background:#2a1414;border:1px solid #5a1f1f;color:#ffb4b4;padding:14px;border-radius:8px;margin-top:16px}
 code{background:#1b2029;padding:2px 6px;border-radius:5px;font-size:14px}
 a{color:#7fd1b9} .muted{color:#8b939f;font-size:14px}
</style></head><body>
<h1>100 checks, 30 days, no card</h1>
<p class="s">Early access for teams that accept artifacts produced by AI agents.</p>
<div class="box">
<p>Give us an email and we send a signed key that unlocks <strong>100 artifact checks
for 30 days</strong> — no account, no card, no recurring charges. The key goes in
the <code>X-ATTEST-ENTITLEMENT</code> header (HTTP) or the same header over MCP.</p>
<p class="muted">Why free: nobody has paid for this yet. The package is how we find out
whether anyone will — better a hundred real artifacts than a thousand page views.</p>
</div>
<form id="f" onsubmit="return false">
<label for="email">Work email (optional)</label>
<input id="email" type="email" placeholder="you@company.com">
<p class="muted">Without an email the key is shorter (20 checks) and comes back
in this window. With an email you get 100 checks and the key by mail.</p>
<label for="note">What do you verify? (optional, one line)</label>
<textarea id="note" placeholder="e.g. scan results from a security agent before we bill for them"></textarea>
<button onclick="send()">Request access</button>
</form>
<div id="out"></div>
<div class="box">
<p>What you get for the 30 days:</p>
<p>• 100 checks through <code>POST /verify</code> or the <code>verify_artifact</code> MCP tool<br>
• four layers per check: schema contract, emptiness, generation provenance, mandate authority<br>
• an Ed25519-signed verdict you can verify offline, without trusting this service</p>
<p class="muted">After 30 days the key simply stops working. If it is useful, $99/30 days
keeps it running — or $49/30 days for India pricing. If you run agents with wallets, the
paid product is different: an <strong>audit at $1,250</strong> (first three, then $2,500),
ten working days, one line of evidence per finding — <a href="/plans">pricing</a> ·
<a href="https://mrpkk.github.io/nidhipati/audit-sample.html">sample report</a> ·
<a href="/demo">demo</a> · <a href="/article">why positional scanning</a></p>
</div>
<script>
async function send(){
  const out = document.getElementById('out');
  const email = document.getElementById('email').value.trim();
  const note = document.getElementById('note').value.trim();
  if (!email && !note) {
    out.innerHTML = '<div class="err">Give an email or one line about what you verify.</div>';
    return;
  }
  out.innerHTML = '<div class="muted">sending…</div>';
  try {
    const r = await fetch('/start', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({email: email, note: note})});
    const d = await r.json();
    if (d.error) { out.innerHTML = '<div class="err">' + d.error + '</div>'; return; }
    var extra = d.key
      ? '<p class="muted">Your key (header <code>' + (d.header || 'X-ATTEST-ENTITLEMENT') +
        '</code>):</p><pre style="background:#141821;border:1px solid #232a33;border-radius:8px;padding:12px;overflow:auto;font:12px ui-monospace,monospace">' +
        String(d.key).replace(/</g, '&lt;') + '</pre>'
      : '';
    out.innerHTML = '<div class="ok">' + d.message + '</div>' + extra;
    document.getElementById('f').style.display = 'none';
  } catch (e) { out.innerHTML = '<div class="err">' + e.message + '</div>'; }
}
</script>
</body></html>"""

_REVIEW_HTML = """<!doctype html><html lang="en"><head><meta charset=utf-8>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>attest — free human review of one artifact</title>
<meta name="description" content="Send one agent artifact and get a free written human review: schema, emptiness, provenance, authority, and one fix.">
<link rel="canonical" href="https://attest.rta.lat/review">
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.65 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:44px 22px 80px}
 h1{font-size:28px;margin:0 0 6px} .s{color:#969eac;margin:0 0 24px}
 .box{background:#141821;border:1px solid #232a33;border-radius:12px;padding:18px;margin:18px 0}
 a{color:#7fd1b9} code{background:#171b21;padding:2px 6px;border-radius:4px}
 .cta{display:inline-block;background:#1c6b58;color:#eafff8;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:600;margin-top:10px}
 .muted{color:#8b939f;font-size:14px}
</style></head><body>
<h1>Free human review of one artifact</h1>
<p class="s">Not ready to pay? Send one artifact. We return a written review in two working days.</p>
<div class="box">
<p><strong>What to send:</strong> a public repo/URL, one JSON artifact, or the exact output of a scanner
that returned “no issues”. No keys, no customer data, no private prompts.</p>
<p><strong>What you get:</strong> the four layers checked separately — schema contract, emptiness,
generation provenance, mandate authority — plus the rule that fired and one concrete fix.</p>
<p><strong>What we do not do:</strong> no “100% safe”, no legal opinion, no recovery promise.
If the artifact is fine, the review says it is fine.</p>
<a class="cta" href="mailto:maxim.pkk@gmail.com?subject=attest%20review">Email one artifact</a>
</div>
<p class="muted">Prefer self-serve? <a href="/start">100 free checks for 30 days</a> ·
<a href="/demo">demo</a> · <a href="/plans">pricing</a>. The review is free because nobody has paid yet;
it is how we learn whether the product is useful.</p>
</body></html>"""

_PRIVACY_HTML = """<!doctype html><html lang="en"><head><meta charset=utf-8>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>attest — privacy</title>
<meta name="description" content="What attest stores, what it does not store, and how to have it deleted.">
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.65 system-ui,sans-serif;max-width:720px;margin:0 auto;padding:44px 22px 80px}
 h1{font-size:26px;margin:0 0 18px} h2{font-size:18px;margin:26px 0 8px}
 p,li{color:#c3cad4} code{background:#171b21;padding:2px 6px;border-radius:4px}
</style></head><body>
<h1>Privacy</h1>
<p>attest checks artifacts. It does not want to know anything about you, so it
stores as little as possible.</p>
<h2>What we store</h2>
<ul>
<li><strong>Call counters</strong> — how many checks a caller made, per day, so
the free tier can be enforced. No artifacts, no prompts, no results.</li>
<li><strong>Feedback you send us</strong> — a yes/no answer and, if you write
one, a comment. Stored with a short hash of the caller, not an IP address.</li>
<li><strong>Requests for early access</strong> — the email you typed, and
whatever you wrote about what you verify.</li>
</ul>
<h2>What we do not store</h2>
<ul>
<li>Artifacts you check, and the verdicts, beyond the counters above;</li>
<li>your prompts, model outputs, or anything you paste into the demo;</li>
<li>your IP address — the server sees the tunnel's address, not yours.</li>
</ul>
<h2>Payments</h2>
<p>Payments settle on-chain via x402 (USDC on Base). The receipt is signed by us
and verifiable offline. The wallet you pay from is visible on the public
blockchain, as any blockchain payment is — that is a property of the network,
not of this service.</p>
<h2>Deletion</h2>
<p>Write to the address in the footer of any page and we will delete the
feedback or request you name. Counter aggregates can be reset on request.</p>
</body></html>"""

LANDING = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>attest — artifact verification for agents</title>
<meta name="description" content="Four-layer verification for AI agent artifacts: schema, emptiness, generation provenance, mandate authority. Ed25519-signed and independently verifiable.">
<meta property="og:type" content="website">
<meta property="og:site_name" content="attest">
<meta property="og:title" content="attest — artifact verification for agents">
<meta property="og:description" content="Four-layer verification for AI agent artifacts: schema, emptiness, generation provenance, mandate authority. Ed25519-signed, verifiable offline. 20 free checks/day.">
<meta property="og:url" content="https://attest.rta.lat/">
<meta property="og:image" content="https://attest.rta.lat/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="attest — artifact verification for agents">
<meta name="twitter:description" content="Verify AI agent artifacts before you trust them: schema, prompt injection, emptiness, provenance. Ed25519-signed verdicts.">
<meta name="twitter:image" content="https://attest.rta.lat/og.png">
<link rel="canonical" href="https://attest.rta.lat/">
<link rel="alternate" hreflang="en" href="https://attest.rta.lat/">
<link rel="alternate" hreflang="hi" href="https://attest.rta.lat/hi">
<link rel="alternate" hreflang="x-default" href="https://attest.rta.lat/">
<style>
:root{--bg:#0d1117;--fg:#e6edf3;--dim:#8b949e;--line:#30363d;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--acc:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:26px;margin:0 0 6px}
.lead{color:var(--dim);margin:0 0 24px}
textarea{width:100%;min-height:190px;background:#010409;color:var(--fg);border:1px solid var(--line);
 border-radius:6px;padding:12px;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
textarea:focus{outline:none;border-color:var(--acc)}
.row{display:flex;gap:10px;margin:12px 0;flex-wrap:wrap;align-items:center}
button{background:var(--acc);color:#04121f;border:0;border-radius:6px;padding:9px 20px;
 font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
input[type=text]{background:#010409;color:var(--fg);border:1px solid var(--line);border-radius:6px;
 padding:8px 10px;font:13px ui-monospace,monospace;min-width:230px}
.hint{color:var(--dim);font-size:13px}
.card{border:1px solid var(--line);border-radius:8px;padding:16px;margin-top:18px;background:#010409}
.v{font-size:19px;font-weight:700;display:flex;align-items:center;gap:9px}
.v.accept{color:var(--ok)}.v.review{color:var(--warn)}.v.reject{color:var(--bad)}
.reason{color:var(--dim);margin:7px 0 0}
.bar{height:5px;background:var(--line);border-radius:3px;margin:14px 0 6px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--ok)}
.bar i.review{background:var(--warn)}.bar i.reject{background:var(--bad)}
table{border-collapse:collapse;width:100%;font-size:14px}
td,th{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left}
th{color:var(--dim);font-weight:500}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.tiers{display:grid;gap:10px;grid-template-columns:repeat(3,1fr);margin:14px 0}
.t{border:1px solid var(--line);border-radius:8px;padding:12px}
.t b{display:block;margin-bottom:4px}
.warn{border-left:3px solid var(--warn);padding:12px 16px;border-radius:6px;background:#010409;margin:18px 0}
</style>
</head>
<body><div class="wrap">
<h1>attest — artifact verification for agents</h1>
<p class="lead">An agent calls a tool or another agent and receives a foreign artifact that
goes straight into its context. Four checks, each answering only its own question.</p>

<label class="hint">Artifact JSON</label>
<textarea id="a">{"summary":"Analysis complete","findings":["first finding","second finding"]}</textarea>
<div class="row">
  <input type="text" id="s" value="demo" placeholder="source">
  <button id="go" onclick="run()">Verify</button>
  <a class="hint" href="/demo">four-layer demo →</a>
  <a class="hint" href="/start">100 free checks →</a>
  <a class="hint" href="/review">free human review →</a>
</div>

<div class="card" id="res" style="display:none">
  <div class="v" id="v"></div>
  <p class="reason" id="r"></p>
  <div class="bar"><i id="b"></i></div>
  <p class="hint" id="sc"></p>
</div>

<h2 style="font-size:17px;margin:30px 0 6px">Four layers, four questions</h2>
<table>
<tr><th>Layer</th><th>Question</th><th>Answers it</th></tr>
<tr><td>Form</td><td>does it match the schema?</td><td><code>/verify</code></td></tr>
<tr><td>Emptiness</td><td>is there anything inside it?</td><td><code>emptiness</code></td></tr>
<tr><td>Provenance</td><td>what conditions produced it?</td><td><code>generation</code></td></tr>
<tr><td>Authority</td><td>was the action permitted?</td><td><code>authority</code></td></tr>
</table>

<h2 style="font-size:17px;margin:26px 0 6px">In CI, on every commit</h2>
<p class="hint">A check that runs only when someone remembers does not protect a pipeline.
The same four layers run from a GitHub Action; a rejection fails the build.</p>
<pre style="background:#010409;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:13px">- uses: mrpkk/attest@v1
  with:
    paths: 'reports/*.json'
    fail-on: reject</pre>
<p class="hint"><a href="https://github.com/mrpkk/attest">Action and CLI</a> · a network error or
an exhausted quota is reported as an error, never as accepted.</p>

<h2 style="font-size:17px;margin:26px 0 6px">Pricing</h2>
<p class="hint">__FREE_LIMIT__ free checks per day.</p>
<div class="tiers">
 <div class="t"><b>Trial</b>0 USDC<br><span class="hint">__FREE_LIMIT__ checks per day, full check, no limit on artifact size</span></div>
 <div class="t"><b>Per call</b>0.005 USDC<br><span class="hint">beyond the free tier, paid over x402 on Base</span></div>
 <div class="t"><b>Subscription</b>99 USDC<br><span class="hint">removes the limit, suitable for CI pipelines</span></div>
 <div class="t"><b>India (PPP)</b>49 USDC<br><span class="hint">same 30 days, purchasing-power price. <a href="/pay?plan=ppp">Pay</a></span></div>
</div>

<h2 style="font-size:17px;margin:26px 0 6px">What 790 ₽ / 30 days includes</h2>
<ul class="hint" style="margin:6px 0 0 18px;padding:0">
<li>100 checks — five times the free daily tier.</li>
<li>Field-level verdict: which field is critical, which is data, and why.</li>
<li>Same MCP endpoint and the same <code>POST /verify</code> — nothing to reinstall.</li>
<li>Ed25519-signed verdict you can verify without trusting us.</li>
<li>No auto-renewal: the key simply stops working after 30 days.</li>
</ul>
<p class="hint" style="margin-top:10px"><b>Not included:</b> no guarantee that an artifact is safe,
no blocking, no human review. It is one more check before you ship — not a replacement for review.</p>

<h2 style="font-size:17px;margin:26px 0 6px">Buying a 30-day token</h2>
<p class="hint"><b>Pay from any wallet, no account:</b> send 99 USDC on Base (49 for India)
to the project address, paste the transaction hash — the transfer is verified on-chain and a
30-day token is issued in the same response. <a href="/pay">Pay with USDC →</a></p>
<p class="hint">x402 is a three-step flow: ask, sign, retry. No account, no card, no dashboard.</p>
<pre style="background:#141821;border:1px solid #1f242e;border-radius:8px;padding:12px;overflow:auto;font:12.5px/1.5 ui-monospace,monospace;color:#e8ecf4">curl -X POST https://attest.rta.lat/subscribe
# 402 + challenge: price, asset, network, payTo
# sign the EIP-3009 authorization with any x402 client, then:
curl -X POST https://attest.rta.lat/subscribe -H "PAYMENT-SIGNATURE: &lt;base64&gt;"
# 200 {"entitlement_token": "...", "valid_until": ...}</pre>
<div class="warn"><b>What this does not do.</b> A valid form is not meaningful content, and a
signed artifact is not a permitted action. Absence of signals means the coarse checks did not fire —
it does not prove the artifact is sound. The signature is Ed25519: the public key travels with
the attestation, so you can verify it yourself without trusting this service.</div>

<p class="hint">Source: <a href="https://github.com/mrpkk/attest">github.com/mrpkk/attest</a> ·
BusinessMCP: <a href="https://businessmcp.com/mcp-servers/attest">marketplace</a> ·
Set: <a href="https://indra.rta.lat">indra.rta.lat</a> · <a href="/hi">हिन्दी</a></p>
</div>
<script src="/feedback.js" defer></script>
<script>
async function run(){
  const b=document.getElementById("go"); b.disabled=true;
  try{
    const r=await fetch("/verify",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({artifact:JSON.parse(document.getElementById("a").value),
                           source:document.getElementById("s").value})});
    const d=await r.json();
    document.getElementById("res").style.display="block";
    const v=document.getElementById("v");
    v.className="v "+(d.verdict||"");
    v.textContent=(d.verdict||"").toUpperCase();
    document.getElementById("r").textContent=d.reason||"";
    const bar=document.getElementById("b");
    bar.className=d.verdict||""; bar.style.width=(d.trust_score||0)+"%";
    const e=d.emptiness;
    document.getElementById("sc").textContent=e
      ? ("emptiness: "+e.verdict+" (score "+e.score+")"+(e.signals&&e.signals[0]
          ? " — "+e.signals[0].detail:"")) : "";
  }catch(ex){ alert("Failed: "+ex.message); }
  finally{ b.disabled=false; }
}
</script>
</body></html>"""

# Хинди-версия витрины (правило владельца 20.10.2026: Индия — обязательное
# направление, хинди — первый класс). Тексты заменяются точными строками:
# если английская витрина изменится, тест на /hi упадёт — это и нужно.
_HI_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ('<html lang="en">', '<html lang="hi">'),
    ('<title>attest — artifact verification for agents</title>',
     '<title>attest — AI एजेंट आर्टिफैक्ट का सत्यापन</title>'),
    ('<meta name="description" content="Four-layer verification for AI agent artifacts: schema, emptiness, generation provenance, mandate authority. Ed25519-signed and independently verifiable.">',
     '<meta name="description" content="AI एजेंट आर्टिफैक्ट का चार-स्तरीय सत्यापन: स्कीमा, खालीपन, उत्पत्ति और अधिकार। Ed25519 हस्ताक्षरित, स्वतंत्र रूप से सत्यापन योग्य।">'),
    ('<meta property="og:title" content="attest — artifact verification for agents">',
     '<meta property="og:title" content="attest — AI एजेंट आर्टिफैक्ट का सत्यापन">'),
    ('<meta name="twitter:title" content="attest — artifact verification for agents">',
     '<meta name="twitter:title" content="attest — AI एजेंट आर्टिफैक्ट का सत्यापन">'),
    ('<link rel="canonical" href="https://attest.rta.lat/">',
     '<link rel="canonical" href="https://attest.rta.lat/hi">'),
    ('<h1>attest — artifact verification for agents</h1>',
     '<h1>attest — AI एजेंट आर्टिफैक्ट का सत्यापन</h1>'),
    ('<p class="lead">An agent calls a tool or another agent and receives a foreign artifact that\ngoes straight into its context. Four checks, each answering only its own question.</p>',
     '<p class="lead">एजेंट किसी टूल या दूसरे एजेंट को कॉल करता है और एक बाहरी आर्टिफैक्ट पाता है जो सीधे उसके कॉन्टेक्स्ट में चला जाता है। चार जाँचें, हर एक केवल अपने ही प्रश्न का उत्तर देती है।</p>'),
    ('<label class="hint">Artifact JSON</label>', '<label class="hint">आर्टिफैक्ट JSON</label>'),
    ('>Verify</button>', '>सत्यापित करें</button>'),
    ('four-layer demo →', 'चार-स्तरीय डेमो →'),
    ('<a class="hint" href="/start">100 free checks →</a>',
     '<a class="hint" href="/start">100 मुफ़्त जाँच →</a>'),
    ('<a class="hint" href="/review">free human review →</a>',
     '<a class="hint" href="/review">मुफ़्त मानव समीक्षा →</a>'),
    ('<h2 style="font-size:17px;margin:30px 0 6px">Four layers, four questions</h2>',
     '<h2 style="font-size:17px;margin:30px 0 6px">चार स्तर, चार प्रश्न</h2>'),
    ('<tr><th>Layer</th><th>Question</th><th>Answers it</th></tr>',
     '<tr><th>स्तर</th><th>प्रश्न</th><th>उत्तर देता है</th></tr>'),
    ('<tr><td>Form</td><td>does it match the schema?</td><td><code>/verify</code></td></tr>',
     '<tr><td>रूप</td><td>क्या यह स्कीमा से मेल खाता है?</td><td><code>/verify</code></td></tr>'),
    ('<tr><td>Emptiness</td><td>is there anything inside it?</td><td><code>emptiness</code></td></tr>',
     '<tr><td>खालीपन</td><td>क्या इसमें वास्तविक सामग्री है?</td><td><code>emptiness</code></td></tr>'),
    ('<tr><td>Provenance</td><td>what conditions produced it?</td><td><code>generation</code></td></tr>',
     '<tr><td>उत्पत्ति</td><td>यह किन परिस्थितियों में बना?</td><td><code>generation</code></td></tr>'),
    ('<tr><td>Authority</td><td>was the action permitted?</td><td><code>authority</code></td></tr>',
     '<tr><td>अधिकार</td><td>क्या यह क्रिया अनुमत थी?</td><td><code>authority</code></td></tr>'),
    ('<h2 style="font-size:17px;margin:26px 0 6px">Pricing</h2>',
     '<h2 style="font-size:17px;margin:26px 0 6px">मूल्य</h2>'),
    ('__FREE_LIMIT__ free checks per day.', '__FREE_LIMIT__ मुफ़्त जाँच प्रतिदिन।'),
    ('<div class="t"><b>Trial</b>0 USDC<br><span class="hint">__FREE_LIMIT__ checks per day, full check, no limit on artifact size</span></div>',
     '<div class="t"><b>नि:शुल्क</b>0 USDC<br><span class="hint">__FREE_LIMIT__ जाँच प्रतिदिन, पूरी जाँच, आर्टिफैक्ट के आकार की सीमा नहीं</span></div>'),
    ('<div class="t"><b>Per call</b>0.005 USDC<br><span class="hint">beyond the free tier, paid over x402 on Base</span></div>',
     '<div class="t"><b>प्रति कॉल</b>0.005 USDC<br><span class="hint">मुफ़्त सीमा के बाद, Base पर x402 से भुगतान</span></div>'),
    ('<div class="t"><b>Subscription</b>99 USDC<br><span class="hint">removes the limit, suitable for CI pipelines</span></div>',
     '<div class="t"><b>सदस्यता (30 दिन)</b>99 USDC<br><span class="hint">सीमा हटाती है, CI पाइपलाइन के लिए उपयुक्त</span></div>'),
    ('<div class="warn"><b>What this does not do.</b> A valid form is not meaningful content, and a\nsigned artifact is not a permitted action. Absence of signals means the coarse checks did not fire —\nit does not prove the artifact is sound. The signature is Ed25519: the public key travels with\nthe attestation, so you can verify it yourself without trusting this service.</div>',
     '<div class="warn"><b>यह क्या नहीं करता।</b> सही रूप का अर्थ वास्तविक सामग्री नहीं है, और हस्ताक्षरित आर्टिफैक्ट का अर्थ अनुमत क्रिया नहीं है। संकेतों का न होना केवल यह दिखाता है कि स्थूल जाँचें नहीं चलीं — यह सिद्ध नहीं करता कि आर्टिफैक्ट ठीक है। हस्ताक्षर Ed25519 है: सार्वजनिक कुंजी सत्यापन के साथ चलती है, इसलिए आप इस सेवा पर भरोसा किए बिना स्वयं जाँच सकते हैं।</div>'),
    (' <div class="t"><b>India (PPP)</b>49 USDC<br><span class="hint">same 30 days, purchasing-power price. <a href="/pay?plan=ppp">Pay</a></span></div>',
     ' <div class="t"><b>भारत (PPP)</b>4 USDC<br><span class="hint">वही 30 दिन, खरीद-क्षमता के अनुसार मूल्य। <a href="/pay?plan=ppp">भुगतान</a></span></div>'),
    ("""<h2 style="font-size:17px;margin:26px 0 6px">What 790 ₽ / 30 days includes</h2>
<ul class="hint" style="margin:6px 0 0 18px;padding:0">
<li>100 checks — five times the free daily tier.</li>
<li>Field-level verdict: which field is critical, which is data, and why.</li>
<li>Same MCP endpoint and the same <code>POST /verify</code> — nothing to reinstall.</li>
<li>Ed25519-signed verdict you can verify without trusting us.</li>
<li>No auto-renewal: the key simply stops working after 30 days.</li>
</ul>
<p class="hint" style="margin-top:10px"><b>Not included:</b> no guarantee that an artifact is safe,
no blocking, no human review. It is one more check before you ship — not a replacement for review.</p>

<h2 style="font-size:17px;margin:26px 0 6px">Buying a 30-day token</h2>""",
     """<h2 style="font-size:17px;margin:26px 0 6px">790 ₽ / 30 दिन में क्या शामिल है</h2>
<ul class="hint" style="margin:6px 0 0 18px;padding:0">
<li>100 जाँचें — मुफ़्त दैनिक सीमा से पाँच गुना।</li>
<li>हर फ़ील्ड पर निर्णय: कौन-सा फ़ील्ड गंभीर है, कौन-सा केवल डेटा है, और क्यों।</li>
<li>वही MCP एंडपॉइंट और वही <code>POST /verify</code> — कुछ दोबारा इंस्टॉल नहीं करना।</li>
<li>Ed25519 हस्ताक्षरित निर्णय — हम पर भरोसा किए बिना जाँच सकते हैं।</li>
<li>कोई ऑटो-नवीनीकरण नहीं: 30 दिन बाद कुंजी बस काम करना बंद कर देती है।</li>
</ul>
<p class="hint" style="margin-top:10px"><b>शामिल नहीं:</b> आर्टिफैक्ट सुरक्षित होने की गारंटी नहीं,
कुछ ब्लॉक नहीं होता, मानवीय समीक्षा नहीं। यह रिलीज़ से पहले एक और जाँच है — समीक्षा का विकल्प नहीं।</p>

<h2 style="font-size:17px;margin:26px 0 6px">30 दिन का टोकन कैसे खरीदें</h2>"""),
    ('<p class="hint"><b>Pay from any wallet, no account:</b> send 99 USDC on Base (49 for India)\nto the project address, paste the transaction hash — the transfer is verified on-chain and a\n30-day token is issued in the same response. <a href="/pay">Pay with USDC →</a></p>',
     '<p class="hint"><b>किसी भी वॉलेट से भुगतान करें, कोई खाता नहीं:</b> Base पर 99 USDC (भारत के लिए 4)\nभेजें, ट्रांज़ैक्शन हैश चिपकाएँ — ब्लॉकचेन पर जाँच के बाद उसी उत्तर में 30 दिन का टोकन मिलता है।\n<a href="/pay">USDC से भुगतान करें →</a></p>'),
    ('<p class="hint">x402 is a three-step flow: ask, sign, retry. No account, no card, no dashboard.</p>',
     '<p class="hint">x402 तीन कदमों का प्रवाह है: अनुरोध, हस्ताक्षर, पुनः प्रयास। कोई खाता नहीं, कोई कार्ड नहीं, कोई डैशबोर्ड नहीं।</p>'),
    ('# 402 + challenge: price, asset, network, payTo', '# 402 + चुनौती: कीमत, संपत्ति, नेटवर्क, payTo'),
    ('# sign the EIP-3009 authorization with any x402 client, then:',
     '# किसी भी x402 क्लाइंट से EIP-3009 प्राधिकरण पर हस्ताक्षर करें, फिर:'),
    ('<p class="hint">Source: <a href="https://github.com/mrpkk/attest">github.com/mrpkk/attest</a> ·\nBusinessMCP: <a href="https://businessmcp.com/mcp-servers/attest">marketplace</a> ·\nSet: <a href="https://indra.rta.lat">indra.rta.lat</a> · <a href="/hi">हिन्दी</a></p>',
     '<p class="hint">स्रोत: <a href="https://github.com/mrpkk/attest">github.com/mrpkk/attest</a> ·\nबिज़नेसMCP: <a href="https://businessmcp.com/mcp-servers/attest">मार्केटप्लेस</a> ·\nसेट: <a href="https://indra.rta.lat">indra.rta.lat</a> · <a href="/">English</a></p>'),
)


def landing_hi() -> str:
    """Хинди-версия витрины. Точные замены; недостающая строка — исключение."""
    page = LANDING
    for english, hindi in _HI_REPLACEMENTS:
        if english not in page:
            raise ValueError(f"hindi landing: строка не найдена: {english[:60]!r}")
        page = page.replace(english, hindi)
    return page



BAZAAR_SERVICE_NAME = "attest"
BAZAAR_TAGS = ["verification", "security", "mcp", "agent-safety"]

# Манифесты (Д6): агент находит продукт по стандартным путям, без README
# и без регистрации. Файлы лежат в корне репозитория, сервис отдаёт их же.
MANIFEST_FILES = ("llms.txt", "SKILL.md", "openapi.json")
MANIFEST_MIME = {
    "llms.txt": "text/plain; charset=utf-8",
    "SKILL.md": "text/markdown; charset=utf-8",
    "openapi.json": "application/json; charset=utf-8",
}
VERIFY_DESCRIPTION = "Deterministic verification of an agent artifact"


def resolve_manifest(name: str) -> Path | None:
    """Найти файл манифеста.

    Порядок: ATTEST_MANIFEST_DIR (тесты/деплой) → корень репозитория или
    каталога установленного пакета → файлы, положенные внутрь пакета.
    """
    if name not in MANIFEST_FILES:
        raise ValueError(f"unknown manifest: {name}")
    candidates: list[Path] = []
    env_dir = os.environ.get("ATTEST_MANIFEST_DIR")
    if env_dir:
        candidates.append(Path(env_dir) / name)
    here = Path(__file__).resolve().parent
    candidates.append(here.parent / name)
    candidates.append(here / name)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
BASE_NETWORK = "eip155:8453"
BASE_SEPOLIA_NETWORK = "eip155:84532"

# Контракт USDC по сети: нужен там, где актив не задан явно.
USDC_BY_NETWORK = {
    BASE_NETWORK: USDC_BASE,
    BASE_SEPOLIA_NETWORK: USDC_BASE_SEPOLIA,
}


class TokenDomainUnknown(ValueError):
    """Домен EIP-712 токена не подтверждён — подпись строить и проверять нельзя."""


@dataclass(frozen=True)
class EIP712Domain:
    """Домен подписи EIP-712: часть типизированных данных, не сама подпись."""

    name: str
    version: str
    verifying_contract: str
    chain_id: int


# Проверено 2026-09-30 вызовами eth_call к USDC в сети Base:
#   name() -> "USD Coin", version() -> "2", decimals() -> 6, chainId 8453.
# Тест сверяет эту таблицу с такой же в пакете agentpay, чтобы значения
# одинаковых протокольных констант не разъехались.
#
# Имя в домене EIP-712 различается между сетями, и это не опечатка:
# на Base mainnet токен называется "USD Coin", а на Base Sepolia — "USDC".
# Проверено 2026-10-03: name() на mainnet и Sepolia плюс проверка подписи
# настоящим фасилитатором (ошибка была "invalid signature", после
# исправления имени — "transfer amount exceeds balance", то есть подпись
# принята контрактом).
VERIFIED_DOMAINS: dict[tuple[str, str], EIP712Domain] = {
    (BASE_NETWORK, USDC_BASE.lower()): EIP712Domain(
        name="USD Coin", version="2", verifying_contract=USDC_BASE, chain_id=8453
    ),
    (BASE_SEPOLIA_NETWORK, USDC_BASE_SEPOLIA.lower()): EIP712Domain(
        name="USDC", version="2", verifying_contract=USDC_BASE_SEPOLIA, chain_id=84532
    ),
}


def eip712_domain(network: str, asset: str) -> EIP712Domain:
    """Домен подписи для сети и актива; отказ, если пара не проверена."""
    domain = VERIFIED_DOMAINS.get((network, asset.strip().lower()))
    if domain is None:
        raise TokenDomainUnknown(
            f"the EIP-712 domain for asset {asset} on network {network} is not verified; "
            f"the signature cannot be checked"
        )
    return domain

# Себестоимость расчёта на Base измерена 2026-10-02, а не взята из документации:
# gasPrice 0.006 Gwei, transferWithAuthorization ≈ 90 000 газа, ETH $2702.
# Это 0.00000054 ETH ≈ $0.00146 за вызов. Продавать дешевле — убыток на каждом
# вызове, поэтому цена проверяется функцией `check_price_covers_cost`.
SETTLEMENT_GAS = 90_000
REFERENCE_GAS_GWEI = 0.006
REFERENCE_ETH_USD = 2702.24
MIN_MARGIN_MULTIPLIER = 2.0


def settlement_cost_usd(
    gas_gwei: float = REFERENCE_GAS_GWEI,
    gas_used: int = SETTLEMENT_GAS,
    eth_usd: float = REFERENCE_ETH_USD,
) -> float:
    """Себестоимость одного расчёта в долларах.

    Считается от измеренной цены газа, а не от чужой оценки: единственный
    способ узнать реальную себестоимость — посмотреть на сеть.
    """
    return (gas_gwei * 1e-9 * gas_used) * eth_usd


def check_price_covers_cost(price_atoms: int, cost_usd: float | None = None) -> None:
    """Отказаться назначать цену ниже себестоимости с запасом.

    Молчаливый убыток на каждом вызове — самый дорогой вид ошибки в ценообразовании:
    счёт растёт, выручка тоже растёт, а денег нет. Проверка делает это
    невозможным незаметно.
    """
    cost = settlement_cost_usd() if cost_usd is None else cost_usd
    price_usd = price_atoms / 1_000_000
    needed = cost * MIN_MARGIN_MULTIPLIER
    if price_usd < needed:
        raise ValueError(
            f"price {price_usd:.6f} USDC is below the computed cost "
            f"{cost:.6f} USDC (needs >= {needed:.6f} with a "
            f"x{MIN_MARGIN_MULTIPLIER:g} margin); selling cheaper loses money per call"
        )


_ASCII_PRINTABLE = re.compile(r"^[\x20-\x7e]+$")


def validate_bazaar_metadata(
    service_name: str, tags: list[str], icon_url: str | None
) -> None:
    """Проверить метаданные листинга по правилам фасилитатора.

    Фассилитатор применяет «soft-drop»: невалидное поле молча выбрасывается,
    а остальное сохраняется. То есть опечатка не ломает листинг — она тихо
    убирает сервис из поиска. Поэтому проверяем сами, до отправки клиенту.
    """
    if not _ASCII_PRINTABLE.match(service_name) or len(service_name) > 32:
        raise ValueError("serviceName: только печатный ASCII, не длиннее 32")
    if len(tags) > 5:
        raise ValueError("tags: не больше 5")
    for tag in tags:
        if not _ASCII_PRINTABLE.match(tag) or len(tag) > 32:
            raise ValueError(f"tag {tag!r}: только печатный ASCII, не длиннее 32")
    if icon_url:
        if not icon_url.startswith(("http://", "https://")):
            raise ValueError("iconUrl должен быть абсолютным http(s)-адресом")
        if len(icon_url) > 2048:
            raise ValueError("iconUrl длиннее 2048")
        host = icon_url.split("//", 1)[1].split("/", 1)[0].lower()
        if host.startswith("127.") or host in ("localhost", "[::1]") or (
            host and host[0].isdigit() and host.replace(".", "").isdigit()
        ):
            raise ValueError("iconUrl не должен указывать на IP или localhost: защита от SSRF")


def build_discovery_info() -> dict[str, Any]:
    """Декларация bazaar: что принимает эндпоинт и что он возвращает.

    Агент читает её вместо догадок, поэтому схемы описаны явно, а не «посмотрите
    документацию». Отсутствие `input.type`/`output.type` — самая частая причина
    тихого выпадения из каталога.
    """
    return {
        "bazaar": {
            "info": {
                "input": {
                    "type": "http",
                    "method": "POST",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "artifact": {
                                "type": "object",
                                "description": "Artifact produced by an AI agent: JSON object, array, or string.",
                            },
                            "schema": {
                                "type": "object",
                                "description": "Optional JSON Schema the artifact must satisfy.",
                            },
                            "source": {
                                "type": "string",
                                "description": "Where the artifact came from, for the record.",
                            },
                        },
                        "required": ["artifact"],
                    },
                },
                "output": {
                    "type": "json",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "verdict": {"type": "string", "enum": ["accept", "review", "reject"]},
                            "trust_score": {"type": "number"},
                            "reason": {"type": "string"},
                            "violations": {"type": "array"},
                            "signals": {"type": "array"},
                            "attestation": {"type": "object"},
                        },
                    },
                    "example": {
                        "verdict": "reject",
                        "trust_score": 40.0,
                        "reason": "critical signal: injection_in_data_field",
                        "violations": [],
                        "signals": [{"kind": "injection_in_data_field", "where": "$.note"}],
                        "attestation": {"algorithm": "HMAC-SHA256", "signature": "..."},
                    },
                },
            }
        }
    }


def build_challenge(
    *,
    resource: str,
    pay_to: str,
    price_atoms: int,
    description: str = "Deterministic verification of an agent artifact",
    max_timeout_seconds: int = 300,
    service_name: str = BAZAAR_SERVICE_NAME,
    tags: list[str] | None = None,
    icon_url: str | None = None,
    discoverable: bool = True,
    network: str = BASE_NETWORK,
    asset: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Собрать настоящий челлендж x402 v2: (заголовок, тело-челлендж).

    Форма взята из живого ответа agentsvc.io (`tests/fixtures` в соседнем
    пакете agentpay), а не из документации: у v2 `resource` — объект, сумма
    приходит строкой, а домен токена лежит в `extra`.

    `discoverable=True` добавляет расширение bazaar: именно оно делает сервис
    видимым в каталоге после первой оплаты, без всякой регистрации.

    `network` и `asset` позволяют выставить счёт в другой сети — прежде
    всего в Base Sepolia (eip155:84532), чтобы платёжный путь можно было
    проверить бесплатно: публичный facilitator mainnet не держит. По
    умолчанию поведение прежнее — mainnet и настоящий USDC.

    `pay_to` обязан быть задан. Молча пропущенный адрес — это либо
    «все платежи уйдут неизвестно куда», и подпись это не спасёт.
    """
    if not pay_to or not re.fullmatch(r"0x[a-fA-F0-9]{40}", pay_to):
        raise ValueError("pay_to должен быть адресом 0x… из 40 шестнадцатеричных знаков")
    if price_atoms <= 0:
        raise ValueError("price_atoms должен быть положительным")
    if not resource.startswith(("http://", "https://")):
        raise ValueError("resource.url должен быть абсолютным: относительный отбрасывается")
    check_price_covers_cost(price_atoms)
    tags = BAZAAR_TAGS if tags is None else tags
    validate_bazaar_metadata(service_name, tags, icon_url)
    resource_info: dict[str, Any] = {
        "url": resource,
        "description": description,
        "mimeType": "application/json",
    }
    if discoverable:
        resource_info["serviceName"] = service_name
        resource_info["tags"] = tags
        if icon_url:
            resource_info["iconUrl"] = icon_url
    # Имя токена в домене EIP-712 зависит от сети («USD Coin» на mainnet,
    # «USDC» на Sepolia) — берём из VERIFIED_DOMAINS, чтобы челлендж и
    # проверка подписи не разъезжались. Найдено живым платежом 16.10.2026:
    # челлендж говорил «USD Coin» на Sepolia — клиент, доверяющий челленджу,
    # подписал бы неверный домен и фасилитор отклонил бы платёж.
    try:
        _tok_dom = eip712_domain(network, asset or USDC_BASE)
        _extra = {"name": _tok_dom.name, "version": _tok_dom.version}
    except TokenDomainUnknown:
        _extra = {"name": "USD Coin", "version": "2"}
    challenge: dict[str, Any] = {
        "x402Version": 2,
        "resource": resource_info,
        "accepts": [{
            "scheme": "exact",
            "network": network,
            "amount": str(price_atoms),
            "asset": asset or USDC_BASE,
            "payTo": pay_to,
            "maxTimeoutSeconds": int(max_timeout_seconds),
            "extra": _extra,
        }],
    }
    if discoverable:
        challenge["extensions"] = build_discovery_info()
    token = base64.b64encode(
        json.dumps(challenge, separators=(",", ":")).encode()
    ).decode()
    return token, challenge


@dataclass
class _Response:
    status: int
    body: Any
    content_type: str = "application/json; charset=utf-8"


# Префикс для размещения за общим доменом: rta.lat/attest/health работает так же,
# как отдельный поддомен attest.rta.lat. Нужен там, где DNS-запись создать
# нельзя — Cloudflare-токен привязан к чужому IP и не даёт добавить запись.
PATH_PREFIXES = ("/attest",)


# Ключ IndexNow. Публикуется открытым файлом /<ключ>.txt — это и есть
# доказательство владения хостом; секретом не является. Один ключ годится
# для Bing и Яндекса (оба принимают IndexNow), поэтому sitemap не единственный
# способ сообщить о страницах: 20.10.2026 выяснилось, что сайт не в индексе
# ни у одного из них.
_INDEXNOW_KEY = "79b5d8b3abc6edc97859cc7c3f6d85de"


def _glama_claim() -> dict:
    """Подтверждение владения доменом для каталога Glama.

    Glama показывает токен в интерфейсе, и его надо опубликовать по
    /.well-known/glama.json. Токен стабилен и привязан к аккаунту:
    один и тот же годится для всех доменов.

    Glama перепроверяет файл ежедневно и при пропаже даёт семь дней на
    восстановление — поэтому токен живёт в конфигурации, а не в коде.
    """
    import os
    token = os.environ.get("GLAMA_CLAIM_TOKEN", "").strip()
    if not token:
        return {}
    return {
        "$schema": "https://glama.ai/mcp/schemas/connector.json",
        "claim": token,
    }



def _server_card() -> dict:
    """Карта сервера для каталогов MCP (SEP-1649).

    Каталог Smithery сканирует сервер сам, но если сканирование не
    проходит — за авторизацией, из-за WAF или по таймауту — он читает
    эту карту вместо сканирования. Карта статична и не требует, чтобы
    сканер достучался до /mcp.

    Отдаём инструменты ровно те, что реально есть, из одного источника
    с самим сервером: расхождение между картой и /mcp читается как обман.
    """
    from .mcp import BRIDGE_TOOL, VERIFY_TOOL
    tools = []
    for tool in (VERIFY_TOOL, BRIDGE_TOOL):
        tools.append({
            "name": tool["name"],
            "description": tool["description"],
            "inputSchema": tool["inputSchema"],
        })
    return {
        "serverInfo": {"name": "attest", "version": "0.1.0"},
        "authentication": {"required": False, "schemes": []},
        "tools": tools,
        "resources": [],
        "prompts": [],
    }



# Методы MCP, не тратящие квоту: обнаружение, а не работа.
FREE_METHODS = frozenset({
    "initialize", "tools/list", "resources/list", "prompts/list",
    "ping", "notifications/initialized", "notifications/cancelled",
})


def _is_free_method(raw: bytes) -> bool:
    """Бесплатна ли операция. Не разобрали — считаем платной."""
    try:
        payload = json.loads(raw.decode("utf-8", "ignore") or "{}")
    except (ValueError, TypeError):
        return False
    if isinstance(payload, list):
        if not payload:
            return False
        return all(isinstance(x, dict) and x.get("method") in FREE_METHODS
                   for x in payload)
    return isinstance(payload, dict) and payload.get("method") in FREE_METHODS


def _base_url() -> str:
    """Публичный адрес: в sitemap обязаны быть абсолютные URL."""
    import os
    return os.environ.get("ATTEST_BASE_URL",
                          "https://attest.rta.lat").rstrip("/")


def _robots() -> str:
    """Краулеров пускаем: индексация витрины — это трафик.

    Закрыт только `/mcp`: это потоковый endpoint для машин, а не документ.
    """
    return ("User-agent: *\n"
            "Allow: /\n"
            "Disallow: /mcp\n"
            f"Sitemap: {_base_url()}/sitemap.xml\n")


def _sitemap() -> str:
    """Карта сайта: без неё краулер не знает, что обходить.

    `/subscribe` и `/verify` в карту не идут: это endpoints, а не
    документы. Их индексация бессмысленна.
    """
    base = _base_url()
    urls = "".join(
        f"<url><loc>{base}{page}</loc></url>"
        for page in ("", "/hi", "/demo", "/plans", "/article", "/catalogs",
                     "/start", "/privacy", "/health")
    )
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{urls}</urlset>")


def route_path(raw: str) -> str:
    """Снять префикс и хвостовой слеш — дальше сравнение идёт как раньше."""
    path = urlparse(raw).path
    for prefix in PATH_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            path = path[len(prefix):]
            break
    return path.rstrip("/") or "/"


class AttestHandler(BaseHTTPRequestHandler):
    """Обработчик запросов. Состояние живёт в атрибутах класса — один сервер."""

    server_version = "attest/" + __version__
    free_tier = FreeTier()
    # Расход пакета раннего доступа: subject → число использованных проверок.
    # В памяти процесса, как free_tier: пережить рестарт счётчик не может.
    # При рестарте пакет начнётся заново — это честнее, чем блокировка.
    ent_usage: dict[str, int] = defaultdict(int)
    pricing = PRICING
    x402_pay_to: str | None = os.environ.get("ATTEST_PAY_TO") or None
    x402_price_atoms: int = _env_int("ATTEST_PRICE_ATOMS", 5000)
    # Цена 30-дневной подписки для покупателей с низкой покупательной способностью
    # (Индия — обязательное направление, правило 20.10.2026). Поштучная цена
    # не снижается: ниже $0.002 рельс съедает больше половины выручки.
    ppp_price_usd: float = _env_float("ATTEST_PPP_PRICE_USD", 49.0)
    # Отзывы пользователей: append-only JSONL рядом с метриками.
    feedback_path: Path = STATE_PATH.with_name("feedback.jsonl")
    # Заявки на пакет раннего доступа. Append-only, как отзывы: IP не
    # храним — только почту, текст и время.
    leads_path: Path = STATE_PATH.with_name("leads.jsonl")
    # Сеть счёта. Раньше сеть была жёстко mainnet, а ATTEST_NETWORK в конфиге
    # службы не читался нигде: переменная совпадала с умолчанием и потому
    # молчала ровно тогда, когда её меняют на тестнет. Из-за этого платёжный
    # путь нельзя было проверить, не имея настоящих денег.
    x402_network: str = os.environ.get("ATTEST_NETWORK") or BASE_NETWORK
    x402_asset: str | None = os.environ.get("ATTEST_ASSET") or None
    # Адрес фасилитатора, который отправляет подписанную авторизацию в цепь.
    # Без него подпись проверяется и НЕ оплачивается: клиент получает услугу,
    # а деньги не двигаются. Раньше переменной не было вовсе, и сервис молча
    # отдавал платную работу бесплатно.
    x402_facilitator: str | None = os.environ.get("ATTEST_FACILITATOR") or None
    x402_rpc_url: str | None = os.environ.get("ATTEST_RPC_URL") or None
    # Секрет вызова от api.market. Вызовы с этим заголовком не тратят наш
    # бесплатный лимит и не требуют x402: покупатель платит маркетплейсу.
    gateway_key: str | None = os.environ.get("ATTEST_GATEWAY_KEY") or None
    confirm_timeout_seconds: float = 3.0
    # nonce'ы уже оплаченных платежей: повтор той же подписи оплатой не считается.
    # С 17.10.2026 лежат на диске (metrics.SpentNonces): раньше перезапуск
    # возвращал их к жизни, и оплаченный платёж принимался второй раз.
    _seen_nonces = staticmethod(spent_nonces)

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("ATTEST_QUIET"):
            return
        super().log_message(fmt, *args)

    def _transparency(self):
        """Журнал прозрачности: файл рядом со состоянием, ключ головы — свой.

        Свой ключ, а не ключ подписи вердиктов: голова дерева и квитанция —
        разные заявления, и один ключ на оба позволял бы подменить одно другим.
        """
        if getattr(self, "_tlog_cache", None) is None:
            from pathlib import Path as _Path
            path = _Path(STATE_PATH).with_name("transparency.log")
            log = _tlog.TransparencyLog(path)
            key_path = _Path(STATE_PATH).with_name("transparency.key")
            key_path.parent.mkdir(parents=True, exist_ok=True)
            if key_path.exists():
                raw = key_path.read_bytes()
            else:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                priv = Ed25519PrivateKey.generate()
                raw = priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                key_path.write_bytes(raw)
                key_path.chmod(0o600)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _K
            self._tlog_cache = (log, _K.from_private_bytes(raw))
        return self._tlog_cache

    def client_id(self) -> str:
        """Кто платит лимит.

        `X-Forwarded-For` важнее адреса сокета: сервис стоит за туннелем
        Cloudflare, поэтому адрес сокета у всех один (127.0.0.1), и лимит
        становился **общим на весь сервис** — 20 бесплатных проверок в сутки
        на всех, и боты съедали их целиком (21.10.2026: 27 отказов 402 в сутки
        на MCP, где оплата была невозможна в принципе).

        Доверяем только первому хопу: клиент может подделать заголовок, если
        достучится напрямую, — это поднимает потолок одного клиента, но не
        даёт ничего сверх бесплатного тарифа, который и так бесплатен.
        Тот же подход уже обкатан в drift (`ratelimit.client_key`).
        """
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return f"ip:{first}"
        return (f"ip:{self.client_address[0]}" if self.client_address
                else "unknown")

    def do_GET(self) -> None:  # noqa: N802
        path = route_path(self.path)
        # Показ страницы — верх воронки. Считаем ДО обработчиков: они
        # возвращают управление и до этой точки дело не доходит.
        if path in ("/", "/demo", "/pricing", "/article"):
            METRICS.view(channel_of(self.path, self.headers.get("Referer")),
                         agent=self.headers.get("User-Agent"))
            METRICS.save()
        if path == "/pay":
            self._send(200, self._pay_page().encode(), "text/html; charset=utf-8")
        elif path == "/":
            page = _with_schema(LANDING).replace("__FREE_LIMIT__", str(self.free_tier.daily_limit))
            self._send(200, page.encode(), "text/html; charset=utf-8")
        elif path == "/article":
            # Статья живёт на своём домене, а не в репозитории: ссылка на
            # неё идёт в HN и каталоги, и она же работает на SEO.
            from .article import ARTICLE_HTML
            self._send(200, ARTICLE_HTML.encode(), "text/html; charset=utf-8")
        elif path == "/health":
            self._send_json(200, {"status": "ok", "version": __version__})
        elif path == "/stats":
            client = self.client_id()
            self._send_json(200, {
                "free_limit": self.free_tier.daily_limit,
                "free_used": self.free_tier.used(client),
                "free_remaining": self.free_tier.remaining(client),
            })
        elif path == "/mcp":
            # A plain GET is a catalog health probe: answer 200. A client that
            # asks for text/event-stream is trying the legacy SSE transport;
            # 405 tells it to fall back to POST, which is our real transport.
            accept = self.headers.get("Accept") or ""
            if "text/event-stream" in accept:
                self._send_json(405, {
                    "error": "SSE is not supported; use POST /mcp for JSON-RPC",
                })
            else:
                self._send_json(200, {
                    "status": "ok",
                    "transport": "streamable-http",
                    "method": "POST",
                    "note": "This endpoint accepts JSON-RPC over POST. GET is a health probe.",
                })
        elif path == "/receipts":
            from .receipts_page import RECEIPTS_HTML
            self._send_html(RECEIPTS_HTML)
        elif path == "/checkpoints":
            from .checkpoints_page import CHECKPOINTS_HTML
            self._send_html(CHECKPOINTS_HTML)
        elif path == "/scitt":
            from .scitt_page import SCITT_HTML
            self._send_html(SCITT_HTML)
        elif path == "/docs":
            from .docs_page import DOCS_HTML
            self._send_html(DOCS_HTML)
        elif path == "/verify-offline":
            page_path = Path(__file__).with_name("web") / "offline.html"
            if page_path.exists():
                self._send_html(page_path.read_text(encoding="utf-8"))
            else:
                self._send_json(404, {"error": "offline page is not built"})
        elif path == "/privacy":
            self._send_html(_PRIVACY_HTML)
        elif path == "/catalogs":
            from .catalogs import CATALOGS_HTML
            self._send_html(CATALOGS_HTML)
        elif path == "/plans":
            self._send_html(_PLANS_HTML)
        elif path == "/.well-known/mcp/server-card.json":
            # Статическая карточка сервера: каталоги (Smithery и другие)
            # берут из неё список инструментов, если скан живого /mcp не
            # прошёл. Собирается из тех же описаний, что отдаёт /mcp.
            from .server_card import SERVER_CARD
            self._send(200, SERVER_CARD.encode("utf-8"), "application/json")
        elif path == "/review":
            self._send_html(_REVIEW_HTML)
        elif path == "/start":
            self._send_html(_START_HTML)
        elif path == "/demo":
            self._send_html(DEMO.replace("__FREE_LIMIT__",
                                         str(self.free_tier.daily_limit)))
        elif path == "/metrics":
            snapshot = METRICS.snapshot()
            snapshot["feedback"] = self._feedback_counts()
            self._send_json(200, snapshot)
        elif path == "/.well-known/glama.json":
            card = _glama_claim()
            if card:
                self._send_json(200, card)
            else:
                self._send_json(404, {"error": "claim token not configured"})
        elif path == "/.well-known/mcp/server-card.json":
            self._send_json(200, _server_card())
        elif path == "/hi":
            METRICS.view(channel_of(self.path, self.headers.get("Referer")),
                         agent=self.headers.get("User-Agent"))
            METRICS.save()
            page = _with_schema(landing_hi()).replace(
                "__FREE_LIMIT__", str(self.free_tier.daily_limit))
            self._send_html(page)
        elif path == "/feedback.js":
            self._send(200, _FEEDBACK_JS.encode("utf-8"),
                       "application/javascript; charset=utf-8")
        elif path == f"/{_INDEXNOW_KEY}.txt":
            # Доказательство владения хостом для IndexNow (Bing, Яндекс).
            self._send(200, _INDEXNOW_KEY.encode("utf-8"),
                       "text/plain; charset=utf-8")
        elif path in ("/.well-known/oauth-protected-resource",
                      "/.well-known/oauth-protected-resource/mcp"):
            # RFC 9728. Клиенты MCP спрашивают этот файл перед подключением
            # (88 запросов за неделю в логах). Отсутствие файла заставляет
            # клиента гадать про токен — отвечаем честно: токен не нужен.
            self._send_json(200, self._oauth_resource_metadata())
        elif path in ("/.well-known/oauth-authorization-server",
                      "/.well-known/oauth-authorization-server/mcp"):
            # Мы не authorization server: OAuth не требуется, оплата по x402.
            self._send_json(404, {
                "error": "not an authorization server",
                "note": "attest needs no OAuth token: 20 free checks per day, "
                        "then $0.005 per call over x402 (USDC, Base)",
                "payment": f"{self._base_url()}/.well-known/x402",
            })
        elif path == "/favicon.ico":
            self._send_file("favicon.ico", "image/x-icon")
        elif path == "/og.png":

            # Картинка для превью ссылок (Open Graph). Без неё шаринг в соцсетях
            # и каталогах даёт пустую карточку — проверено 20.10.2026.
            png = Path(__file__).resolve().parent.parent / "og.png"
            if png.is_file():
                self._send(200, png.read_bytes(), "image/png")
            else:
                self._send_json(404, {"error": "og.png not found"})
        elif path == "/robots.txt":
            self._send(200, _robots().encode("utf-8"),
                          "text/plain; charset=utf-8")
        elif path == "/sitemap.xml":
            self._send(200, _sitemap().encode("utf-8"),
                          "application/xml; charset=utf-8")
        elif path == "/subscribe":
            return self._handle_subscribe(describe_only=True)
        elif path == "/verify":
            # Раньше здесь был 404 на GET, и это выглядело как поломка.
            # На деле /verify принимает только POST, а открыть его в
            # браузере — значит отправить GET. Страница-заглушка объясняет
            # это и даёт ссылку на живой пример, вместо того чтобы
            # заставлять догадываться.
            self._send_html(_VERIFY_GET_HTML)
        elif path == "/pricing":
            self._send_json(200, {
                "free_limit": self.free_tier.daily_limit,
                "pricing": self._dict_pricing(),
                "x402": {
                    "enabled": bool(self.x402_pay_to),
                    "pay_to": self.x402_pay_to,
                    "price_atoms": self.x402_price_atoms,
                    "network": "eip155:8453",
                    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "note": None if self.x402_pay_to else "wallet is not configured (ATTEST_PAY_TO is empty)",
                },
            })
        elif path in ("/.well-known/x402", "/.well-known/x402.json"):
            self._send_json(200, self._x402_discovery_doc())
        elif path == "/.well-known/agent-card.json":
            self._send_json(200, agent_card(
                name=BAZAAR_SERVICE_NAME,
                description=VERIFY_DESCRIPTION,
                base_url=self._base_url(),
                services=self._catalog_services(),
                version=__version__,
            ))
        elif path == "/log/head":
            log, key = self._transparency()
            head = log.head(key)
            self._send_json(200, {"size": head.size, "root": head.root,
                                  "timestamp": head.timestamp, "signature": head.signature,
                                  "public_key": _tlog_public_key(key),
                                  "damaged_tail": log.damaged_tail})
        elif path.startswith("/log/proof/"):
            log, key = self._transparency()
            try:
                index = int(path.rsplit("/", 1)[-1])
                proof = log.inclusion(index)
            except (ValueError, IndexError):
                self._send_json(404, {"error": "no such leaf", "path": path})
                return
            proof["head"] = log.head(key).__dict__
            self._send_json(200, proof)
        elif path.startswith("/log/consistency/"):
            log, key = self._transparency()
            try:
                old_size = int(path.rsplit("/", 1)[-1])
                proof = log.consistency(old_size)
            except (ValueError, IndexError):
                self._send_json(400, {"error": "old_size must be within the tree"})
                return
            proof["head"] = log.head(key).__dict__
            self._send_json(200, proof)
        elif path.lstrip("/") in MANIFEST_FILES:
            self._serve_manifest(path.lstrip("/"))
        else:
            self._send_json(404, {"error": "no such path", "path": path})

    def _dict_pricing(self) -> dict[str, Any]:
        """Тарифы с настоящим лимитом: объявлять 20 при реальных 3 — враньё."""
        data = json.loads(json.dumps(self.pricing))
        data["free"]["limit_per_day"] = self.free_tier.daily_limit
        return data

    def do_HEAD(self) -> None:  # noqa: N802
        """HEAD для health-check площадок.

        Каталоги (BusinessMCP и подобные) проверяют доступность HEAD-запросом.
        Без этого метода BaseHTTPRequestHandler отвечает 501, и живой сервис
        выглядит мёртвым — 26.10.2026 так приостановили листинг attest.
        Тело для HEAD не отправляется по протоколу.
        """
        path = route_path(self.path)
        if path in ("/", "/health", "/mcp", "/pricing", "/demo", "/article", "/stats"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if path in ("/health", "/mcp", "/stats")
                             else "text/html; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        path = route_path(self.path)
        if path == "/log/register":
            payload = self._read_json()
            if payload is None:
                return
            statement = payload.get("statement")
            if not isinstance(statement, str) or not statement.strip():
                self._send_json(400, {"error": "statement must be a non-empty string"})
                return
            log, key = self._transparency()
            index = log.append(statement.encode())
            head = log.head(key)
            self._send_json(200, {
                "index": index,
                "leaf": log.leaves[index].hex(),
                "proof": [h.hex() for h in _tlog.inclusion_proof(log.leaves, index)],
                "head": head.__dict__,
                "public_key": _tlog_public_key(key),
                "note": "inclusion proves membership in this tree; non-equivocation needs a monitor",
            })
            return
        if path == "/start":
            payload = self._read_json()
            if payload is None:
                return
            email = str(payload.get("email") or "").strip()[:200]
            note = str(payload.get("note") or "").strip()[:400]
            # Почта не обязательна. Агент, который упёрся в лимит, почты не
            # имеет: требование превращало лид-магнит в тупик именно для тех,
            # кого мы хотели удержать. С почтой — 100 проверок и письмо с
            # ключом; без почты — 20 проверок, ключ сразу в ответе.
            if email and not EMAIL_RE.fullmatch(email):
                self._send_json(400, {"error": "a valid email is required"})
                return
            # Ключ выдаём сразу, а не «в течение дня»: заявка без ключа —
            # это человек, который ушёл ждать письмо, которого никто не
            # отправит. Токен пишется в заявку, поэтому даже при сбое SMTP
            # его можно отправить руками, не выдавая второй.
            subject = email or f"anon-{self.client_id()}"
            max_calls = 100 if email else 20
            grant = issue_entitlement(subject, days=30, max_calls=max_calls)
            record = {"ts": int(time.time()), "email": email, "note": note,
                      "token": grant["token"], "valid_until": grant["valid_until"],
                      "max_calls": max_calls}
            try:
                self.leads_path.parent.mkdir(parents=True, exist_ok=True)
                with self.leads_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError as exc:
                self._send_json(500, {"error": f"could not store the request: {exc}"})
                return
            METRICS.lead()
            if email:
                send_error = _send_key_email(email, grant["token"], grant["valid_until"])
                if send_error:
                    print(f"attest: ключ выдан, письмо не ушло ({email}): {send_error}")
                    message = ("Request received and the key is issued. Email delivery "
                               "failed on our side — we will send it by hand today.")
                else:
                    message = f"Key sent to {email}. Check the inbox (and spam)."
            else:
                message = ("Key issued — no email, so it is shorter: 20 checks. "
                           "Send us an email and we will send a 100-check key too.")
            body = {"ok": True, "message": message}
            if not email:
                # Без почты письмо не отправить — отдаём ключ сразу.
                body["key"] = grant["token"]
                body["max_calls"] = max_calls
                body["header"] = ENT_HEADER
            self._send_json(200, body)
            return
        if path == "/pay/claim":
            return self._handle_onchain_claim()
        if path == "/pay/enot":
            return self._handle_enot_create()
        if path == "/pay/enot/notify":
            return self._handle_enot_notify()
        if path == "/feedback":
            payload = self._read_json()
            if payload is None:
                return
            verdict = str(payload.get("verdict") or "")
            if verdict not in ("up", "down"):
                self._send_json(400, {"error": "verdict must be 'up' or 'down'"})
                return
            comment = str(payload.get("comment") or "").strip()[:500]
            page = str(payload.get("page") or "")[:120]
            self._feedback_append(verdict, comment, page)
            self._send_json(200, {"ok": True})
            return
        if path == "/mcp":
            self._handle_mcp()
            return
        if path == "/subscribe":
            return self._handle_subscribe()
        if path != "/verify":
            self._send_json(404, {"error": "no such path", "path": path})
            return
        client = self.client_id()
        try:
            payload = self._read_json()
        except ValueError as exc:
            self._send_json(400, {"error": f"bad request: {exc}"})
            return
        if payload is None:
            return
        if "artifact" not in payload:
            self._send_json(400, {"error": "field \"artifact\" is required"})
            return
        source = payload.get("source")
        source = source if isinstance(source, str) and source.strip() else "unknown"

        # v2 спецификация называет заголовок PAYMENT-SIGNATURE, v1 — X-PAYMENT.
        # Берём оба: клиент может прийти по любой из версий.
        # Предоплаченный доступ проверяется ДО списания бесплатного
        # счётчика: у подписчика лимита нет вовсе, а не «есть, но не
        # тратится».
        # Вызов от маркетплейса: покупатель уже платит api.market, и их
        # шлюз шлёт запрос с секретным заголовком. Наш бесплатный лимит и
        # x402 здесь не применяются — иначе покупатель, заплативший
        # платформе, упирается в наш 402 (их ревью поймало это 19.10).
        if self._gateway_call():
            METRICS.check(channel_of(self.path, self.headers.get("Referer")),
                          paid=False, client=self.client_id(),
                          agent=self.headers.get("User-Agent"))
            return self._handle_entitled(
                payload, source,
                "api.market gateway — billed by the marketplace")

        ent_token = self.headers.get(ENT_HEADER)
        ent_ok, ent_why = self._entitlement_access(ent_token)
        if ent_ok:
            return self._handle_entitled(payload, source, ent_why)
        # Токен предъявлен и не прошёл. Молча списать проверку по
        # бесплатному тарифу здесь хуже: покупатель решит, что оплатил,
        # и будет искать ошибку там, где её нет. Особенно это касается
        # пакета раннего доступа: исчерпанный пакет должен сказать
        # «исчерпан», а не тихо продолжить по 20 бесплатных в сутки.
        if ent_token:
            print(f"attest: entitlement отвергнут: {ent_why}")
            self._send_json(402, {
                "error": ent_why,
                "entitlement": {"accepted": False, "reason": ent_why},
                "hint": ("Buy 30 days of access: https://attest.rta.lat/subscribe"
                         if "exhausted" not in ent_why else
                         "Your early-access package is used up. Extend it: "
                         "https://attest.rta.lat/subscribe"),
            })
            return

        payment_header = self.headers.get("PAYMENT-SIGNATURE") or self.headers.get("X-PAYMENT")
        try:
            self.free_tier.spend(client)
            METRICS.check(channel_of(self.path, self.headers.get("Referer")),
                          paid=False, client=self.client_id(),
                          agent=self.headers.get("User-Agent"))
        except FreeTierExhausted as exc:
            if not payment_header:
                METRICS.paywall_hit()
                token = self._challenge_header()
                self._send_json(
                    402,
                    self._exhausted_body(exc, client),
                    extra_headers={"Payment-Required": token} if token else None,
                )
                return
            try:
                METRICS.pay_attempt()
                payment = self._verify_payment(payment_header)
                METRICS.payment(
                    channel_of(self.path, self.headers.get("Referer")),
                    int(getattr(payment, "amount_atoms", 0) or 0),
                    payer=getattr(payment, "payer", None))
            except PaymentError as exc:
                self._send_json(exc.status, {"error": exc.reason, "paid": False})
                return
            body = self._verify_result(payload, source, paid=payment)
            self._send_json(200, body)
            return

        body = self._verify_result(payload, source, paid=None)
        self._send_json(200, body)

    def _entitlement_access(self, token: str | None) -> tuple[bool, str]:
        """Проверить подписку и списать один вызов из её пакета.

        У обычной подписки (max_calls отсутствует) лимита нет. У пакета
        раннего доступа — 100 проверок: расход считается по subject, и
        когда пакет исчерпан, клиент получает честный отказ, а не
        молчаливый возврат к бесплатному тарифу.
        """
        ent, why = redeem_entitlement(token, trusted_key=public_key_b64())
        if ent is None:
            return False, why
        if ent.max_calls is not None:
            used = self.ent_usage.get(ent.subject, 0)
            if used >= ent.max_calls:
                return False, (f"package exhausted: {used}/{ent.max_calls} "
                               f"checks used")
            self.ent_usage[ent.subject] = used + 1
        return True, why

    def _mcp_charge(self) -> bool:
        """Списать квоту или принять оплату. True — можно работать.

        Три пути по порядку: подписка (entitlement) → оплата за вызов (x402) →
        бесплатная квота. Раньше MCP знал только бесплатную квоту: подписчик
        через MCP получал 402, и оплатить его было нечем (принимался только
        X-PAYMENT на HTTP). На практике это давало 27 отказов в сутки от
        живых клиентов, дошедших до платного действия (21.10.2026).
        """
        client = self.client_id()
        channel = channel_of(self.path, self.headers.get("Referer"))

        ent_token = self.headers.get(ENT_HEADER)
        ent_ok, ent_why = self._entitlement_access(ent_token)
        if ent_ok:
            METRICS.check(channel, paid=False, client=self.client_id())
            return True
        if ent_token:
            print(f"attest: entitlement отвергнут: {ent_why}")
            self._send_json(402, {
                "error": ent_why,
                "entitlement": {"accepted": False, "reason": ent_why},
                "hint": "Buy 30 days of access: https://attest.rta.lat/subscribe",
            })
            return False

        payment_header = (self.headers.get("PAYMENT-SIGNATURE")
                          or self.headers.get("X-PAYMENT"))
        if payment_header:
            try:
                METRICS.pay_attempt()
                payment = self._verify_payment(payment_header)
            except PaymentError as exc:
                self._send_json(exc.status, {"error": exc.reason, "paid": False})
                return False
            METRICS.payment(channel, int(payment.amount_atoms or 0),
                            payer=payment.payer)
            return True

        try:
            self.free_tier.spend(client)
        except FreeTierExhausted as exc:
            METRICS.paywall_hit()
            token = self._challenge_header(resource=f"{self._base_url()}/mcp")
            body = self._exhausted_body(exc, client)
            # Клиент по MCP должен знать, какой ресурс оплачивать и каким
            # заголовком: без этого 402 нечем оплатить.
            body["resource"] = f"{self._base_url()}/mcp"
            body["accepts"] = ["PAYMENT-SIGNATURE", "X-PAYMENT"]
            self._send_json(402, body,
                            extra_headers=({"Payment-Required": token}
                                            if token else None))
            return False
        METRICS.check(channel, paid=False, client=self.client_id())
        return True

    def _handle_mcp(self) -> None:
        """MCP-эндпоинт: тот же бесплатный тариф и те же правила проверки."""
        from . import mcp as mcp_module

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send_json(400, {"error": "Content-Length is not a number"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(400, {"error": f"body must be 1..{MAX_BODY_BYTES} bytes"})
            return
        raw = self.rfile.read(length)
        # Обнаружение не тарифицируется. initialize и tools/list —
        # рукопожатие и перечисление: каталог обязан иметь право
        # убедиться, что сервер жив, не платя квоты. Раньше квота
        # списывалась ДО разбора запроса, и при исчерпании каталог
        # получал 402 и помечал сервер нерабочим.
        #
        # Платной остаётся работа: tools/call. Не разобрали — работа.
        if not _is_free_method(raw):
            if not self._mcp_charge():
                return

        def verify(artifact, schema, source):
            return attest(artifact, schema, source=source)

        # 2026-07-28: версия приходит заголовком, сессии нет. Заголовок
        # передаём в разбор и возвращаем тем же значением: клиент должен
        # видеть, с какой версией он говорил.
        requested_version = self.headers.get("MCP-Protocol-Version")
        answer = mcp_module.respond(raw, verify, protocol_version=requested_version)
        if answer is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, body = answer
        self._send(status, body, "application/json; charset=utf-8",
                   extra_headers={"MCP-Protocol-Version": requested_version or mcp_module.PROTOCOL_VERSION})

    def _feedback_append(self, verdict: str, comment: str, page: str) -> None:
        """Записать отзыв. IP не храним — только короткий хеш (антиспам)."""
        path = self.feedback_path
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"ts": int(time.time()), "verdict": verdict, "comment": comment,
                  "page": page,
                  "client": hashlib.sha256(self.client_id().encode()).hexdigest()[:16]}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _feedback_counts(self) -> dict[str, int]:
        counts = {"up": 0, "down": 0, "comments": 0}
        path = self.feedback_path
        if not path.is_file():
            return counts
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                rec = json.loads(line)
                v = rec.get("verdict")
                if v in ("up", "down"):
                    counts[v] += 1
                if rec.get("comment"):
                    counts["comments"] += 1
        except Exception:  # noqa: BLE001 — битая строка не должна ронять метрики
            pass
        return counts

    def _gateway_call(self) -> bool:
        """Вызов от маркетплейса? Сравнение постоянного времени.

        Проверяем только если секрет задан: без ATTEST_GATEWAY_KEY
        заголовок не значит ничего — иначе забытая переменная открыла
        бы платный путь кому угодно, кто угадает имя заголовка.
        """
        key = self.gateway_key
        if not key:
            return False
        supplied = self.headers.get(GATEWAY_HEADER) or ""
        return hmac.compare_digest(supplied, key)

    def _handle_entitled(self, payload: dict, source: str,
                         detail: str = "") -> None:
        """Путь подписчика: лимита нет, ответ помечен действительным доступом."""
        schema = payload.get("schema")
        generation = payload.get("generation")
        result = attest(
            payload["artifact"],
            schema,
            source=source[:200],
            generation=generation if isinstance(generation, dict) else None,
            payload_mandate=payload.get("mandate"),
            payload_action=payload.get("action"),
            require_json=True,
        )
        body = result.as_dict()
        body["free_remaining"] = -1          # -1 = лимита нет
        body["paid"] = True
        body["entitlement"] = {"valid": True, "detail": detail}
        self._send_json(200, body)

    @staticmethod
    def _plan_is_ppp(path: str) -> bool:
        """Выбран ли тариф по паритету покупательной способности (?plan=ppp)."""
        query = urlparse(path).query or ""
        params = dict(pair.split("=", 1) for pair in query.split("&") if "=" in pair)
        return params.get("plan") == "ppp"

    def _subscription_price_usd(self) -> float:
        """Цена 30-дневного доступа: обычная или PPP (?plan=ppp).

        PPP-цена не публикуется в общем прайсе: она для покупателей с низкой
        покупательной способностью (Индия) и передаётся ссылкой. Иначе
        западный покупатель просто выберет $4 вместо $9.
        """
        if self._plan_is_ppp(self.path):
            return max(0.0, float(self.ppp_price_usd))
        return float(entitlement.PRICE_USD)

    # ── Оплата картой через ENOT ────────────────────────────────────────────
    # Клиент платит картой или СБП, деньги приходят нам в USDT. Наш код —
    # счёт и проверка уведомления; эквайринг и конвертация на стороне ENOT.
    # Контракт API и границы доверия — в attest/enot.py.

    def _onchain_orders_path(self) -> Path:
        return self.leads_path.with_name("onchain_orders.jsonl")

    def _pay_page(self) -> str:
        """Страница прямой оплаты: адрес, цена и поле для хеша транзакции."""
        pay_to = self.x402_pay_to or ""
        price = self._subscription_price_usd()
        ppp = self._plan_is_ppp(self.path)
        note = ("India price (purchasing power)" if ppp else "Standard price")
        return f"""<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Pay for attest with USDC</title>
<style>body{{font:16px/1.55 system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 18px;color:#111}}
code{{background:#f2f2f2;padding:2px 6px;border-radius:5px}}input{{width:100%;padding:10px;font:15px ui-monospace,monospace;border:1px solid #ccc;border-radius:8px}}
button{{margin-top:10px;padding:10px 16px;border-radius:8px;border:1px solid #111;background:#111;color:#fff;font:inherit;cursor:pointer}}
#out{{margin-top:16px;padding:12px;border-radius:8px;background:#f7f7f7;white-space:pre-wrap;font:14px ui-monospace,monospace}}</style>
<h1>Pay {price:g} USDC for 30 days</h1>
<p>{note}. Send USDC on <b>Base</b> to this address, then paste the transaction hash below.
No account, no card, no signup. Buying from India? <a href="/pay?plan=ppp">This page at the
purchasing-power price</a>.</p>
<p><code>{pay_to}</code></p>
<p>Any wallet works: MetaMask, Rabby, Coinbase Wallet, an exchange withdrawal to Base.
Send at least {price:g} USDC; a smaller amount is rejected rather than silently accepted.</p>
<input id=tx placeholder="0x… transaction hash">
<button id=go>Check payment</button>
<div id=out>Nothing checked yet.</div>
<script>
document.getElementById('go').onclick = async () => {{
  const out = document.getElementById('out');
  out.textContent = 'Checking the transaction on Base…';
  const r = await fetch('/pay/claim', {{method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{tx: document.getElementById('tx').value.trim()}})}});
  const j = await r.json();
  out.textContent = j.token
    ? 'Paid. Send this token in the ' + j.header + ' header:\n\n' + j.token
    : 'Not accepted: ' + (j.error || 'unknown reason');
}};
</script></html>"""

    def _handle_onchain_claim(self) -> None:
        """Принять оплату, проверенную в блокчейне, и выдать токен на 30 дней."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length).decode() or "{}")
        except ValueError:
            return self._send_json(400, {"error": "body must be JSON with a tx field"})
        tx = str((payload or {}).get("tx") or "").strip()
        if not self.x402_pay_to:
            return self._send_json(503, {"error": "payment is not configured: no wallet set"})
        orders = self._onchain_orders_path()
        used = onchain.load_used(orders)
        if tx.lower() in used:
            return self._send_json(409, {"error": "this transaction was already used"})
        price = self._subscription_price_usd()
        atoms = int(round(price * 1_000_000))
        try:
            transfer = onchain.confirm_transfer(
                tx, pay_to=self.x402_pay_to, min_atoms=atoms,
                # Актив и сеть — из конфигурации: на тестовой сети USDC другой,
                # и зашитый mainnet-адрес отверг бы настоящий перевод.
                asset=self.x402_asset or USDC_BY_NETWORK.get(self.x402_network, USDC_BASE),
                rpc_url=os.environ.get("ATTEST_RPC_URL", onchain.DEFAULT_RPC),
                confirmations=int(os.environ.get("ATTEST_RPC_CONFIRMATIONS", "2")))
        except onchain.TransferRejected as exc:
            return self._send_json(402, {"error": str(exc), "required_usdc": price})
        except Exception as exc:  # noqa: BLE001 — сеть важна как причина
            return self._send_json(503, {"error": f"could not check the chain: {type(exc).__name__}"})
        grant = entitlement.issue(subject=transfer.payer or transfer.tx_hash,
                                  days=30, max_calls=None)
        orders.parent.mkdir(parents=True, exist_ok=True)
        onchain.record(orders, transfer, plan=grant["plan"], subject=transfer.payer)
        METRICS.payment("onchain", transfer.amount_atoms, payer=transfer.payer)
        self._send_json(200, {
            "paid": True, "amount_usdc": transfer.amount_atoms / 1_000_000,
            "payer": transfer.payer, "block": transfer.block,
            "valid_until": grant["valid_until"], "header": grant["header"],
            "token": grant["token"],
        })

    def _enot_orders_path(self) -> Path:
        return self.leads_path.with_name("enot_orders.jsonl")

    def _enot_record(self, record: dict[str, Any]) -> None:
        path = self._enot_orders_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _enot_already_paid(self, order_id: str) -> bool:
        """Идемпотентность: провайдер вправе повторить уведомление.

        Второй токен за один платёж — это подарок, который мы не планировали,
        поэтому журнал заказов читается до выдачи.
        """
        try:
            lines = self._enot_orders_path().read_text(encoding="utf-8").splitlines()
        except OSError:
            return False
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("order_id") == order_id and record.get("status") == "paid":
                return True
        return False

    def _handle_enot_create(self) -> None:
        if not enot.enabled():
            self._send_json(503, {
                "error": "card payments are not enabled yet",
                "hint": "set ENOT_SHOP_ID and ENOT_API_KEY in ~/.env",
            })
            return
        # Тело необязательно: цена одна, поэтому клиенту достаточно нажать кнопку.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        order_id = _uuid.uuid4().hex
        data, error = enot.create_invoice(order_id)
        if error:
            self._send_json(502, {"error": f"payment provider: {error}"})
            return
        self._enot_record({"ts": int(time.time()), "order_id": order_id,
                           "invoice_id": data.get("id"),
                           "amount": data.get("amount"), "status": "created"})
        METRICS.pay_attempt()
        body: dict[str, Any] = {"ok": True, "url": data.get("url"),
                                "order_id": order_id,
                                "amount": data.get("amount")}
        warning = enot.wallet_warning()
        if warning:
            body["warning"] = warning
        self._send_json(200, body)

    def _handle_enot_notify(self) -> None:
        """Уведомление об оплате. Отвечаем 200 и не выдаём токен дважды."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send_json(400, {"error": "bad Content-Length"})
            return
        raw = self.rfile.read(min(length, 64 * 1024)) if length > 0 else b""
        form = {key: values[0] for key, values in
                parse_qs(raw.decode("utf-8", errors="replace")).items()}
        # order_id мы кладём в custom_fields: документация прямо говорит, что
        # эта строка возвращается в уведомлении. Если провайдер пришлёт её
        # отдельным полем — берём и его.
        order_id = ""
        custom = form.get("custom_field") or form.get("custom_fields") or ""
        if custom:
            try:
                parsed = json.loads(custom) if isinstance(custom, str) else custom
                if isinstance(parsed, dict):
                    order_id = str(parsed.get("order_id") or "")
            except json.JSONDecodeError:
                order_id = ""
        order_id = order_id or str(form.get("order_id") or "")

        ok, reason = enot.verify_notification(form)
        if not ok:
            self._enot_record({"ts": int(time.time()), "order_id": order_id,
                               "status": "rejected", "reason": reason,
                               "amount": form.get("amount")})
            self._send_json(400, {"error": reason})
            return
        if not order_id:
            self._enot_record({"ts": int(time.time()), "status": "rejected",
                               "reason": "no order id in notification"})
            self._send_json(400, {"error": "no order id"})
            return
        if self._enot_already_paid(order_id):
            self._send_json(200, {"ok": True, "duplicate": True})
            return

        amount = float(str(form.get("amount") or enot.PRICE_RUB).replace(",", "."))
        grant = issue_entitlement(f"enot:{order_id}", days=30, max_calls=100)
        self._enot_record({"ts": int(time.time()), "order_id": order_id,
                           "status": "paid", "amount": amount,
                           "currency": form.get("currency"),
                           "signature_seen": enot.signature_seen(form),
                           "signature": enot.signature_digest(form),
                           "valid_until": grant["valid_until"]})
        # Валюта разная: x402 считает в микро-USDC, карта — в копейках. Пишем
        # в тот же счётчик канала, чтобы «сколько заплатили» было видно, но
        # не складываем единицы измерения молча.
        METRICS.payment("enot", int(round(amount * 100)))
        email = str(form.get("email") or "").strip()
        body = {"ok": True, "order_id": order_id,
                "valid_until": grant["valid_until"]}
        if email:
            send_error = _send_key_email(email, grant["token"], grant["valid_until"])
            body["email_sent"] = not send_error
        self._send_json(200, body)

    def _handle_subscribe(self, describe_only: bool = False) -> None:
        """Купить 30 дней неограниченного доступа за один платёж.

        x402 умеет оплату за вызов и ничего больше: ни периодичности, ни
        автосписания. Поэтому тариф здесь — предоплата, а не подписка в
        обычном смысле, и `/pricing` говорит об этом прямо. Иначе мы бы
        обещали покупателю списание, которого не происходит.
        """
        if describe_only:
            return self._send_json(200, {"subscription":
                                         entitlement_describe()})
        if not self.x402_pay_to:
            return self._send_json(503, {
                "error": "payment is not configured: no wallet set "
                         "(ATTEST_PAY_TO is empty)"})
        head = (self.headers.get("PAYMENT-SIGNATURE")
                or self.headers.get("X-PAYMENT"))
        price_usd = self._subscription_price_usd()
        amount_atoms = int(price_usd * 1_000_000)
        if not head:
            challenge = self._challenge_header(
                amount_atoms=amount_atoms,
                resource=f"{self._base_url()}/subscribe")
            desc = entitlement_describe()
            # Цена в теле обязана совпадать с ценой в заголовке: иначе
            # покупатель из Индии видит 99 USDC там, где с него просят 4.
            desc["price"] = f"{price_usd:g}"
            if self._plan_is_ppp(self.path):
                desc["plan"] = "ppp-30d"
            return self._send_json(
                402,
                {"error": f"pay {price_usd:g} USDC for 30 days of unlimited access",
                 "subscription": desc,
                 "header": entitlement.HEADER,
                 # Без x402-клиента человек платит переводом: /pay проверяет
                 # транзакцию в блокчейне и выдаёт тот же токен.
                 "pay_human": {"url": f"{self._base_url()}/pay",
                               "price_usdc": price_usd}}, 
                extra_headers={"Payment-Required": challenge}
                if challenge else None)
        try:
            # Сверка идёт с ценой ЭТОГО плана, а не с ценой вызова. Баг до
            # 20.10.2026: _verify_payment всегда строил чек на 5000 атомов,
            # и платёж подписки (99 USDC) отвергался как «сумма не равна».
            payment = self._verify_payment(head, amount_atoms=amount_atoms)
        except PaymentError as exc:
            return self._send_json(exc.status, {"error": exc.reason})
        # Подписка — тоже деньги: без этой записи 99 USDC не попадали в
        # revenue_atoms, а первый платёж клиента — в repeat_usage_7d.
        METRICS.payment(
            channel_of(self.path, self.headers.get("Referer")),
            int(getattr(payment, "amount_atoms", 0) or 0),
            payer=getattr(payment, "payer", None))
        granted = issue_entitlement(self.client_id(),
                                    entitlement.DEFAULT_DAYS)
        self._send_json(200, {
            "subscription": entitlement_describe(),
            "entitlement_token": granted["token"],
            "valid_until": granted["valid_until"],
            "header": entitlement.HEADER,
            "how": ("send the token in the "
                    f"{entitlement.HEADER} header on every request"),
            "payment": {"payer": payment.payer,
                        "amount_atoms": payment.amount_atoms,
                        "pay_to": payment.pay_to},
        })

    def _settle(self, header_value: str, requirement, domain) -> dict:
        """Отправить подписанную авторизацию в цепь через фасилитатор.

        Локальная проверка подписи доказывает НАМЕРЕНИЕ заплатить. Деньги
        переходят только когда авторизацию отправит кто-то с газом — за это
        отвечает фасилитатор. Без этого шага сервис отдавал платную работу
        бесплатно: подпись сходилась, счётчик выручки рос, баланс клиента
        не менялся. Проверено на Base Sepolia 17.10.2026.
        """
        if not self.x402_facilitator:
            raise PaymentError(
                "расчёт не настроен: не задан ATTEST_FACILITATOR. "
                "Принимать оплату без него нельзя — деньги не перейдут.",
                status=503,
            )
        import base64 as _b64
        import json as _json
        import urllib.request
        try:
            body = _json.loads(_b64.b64decode(header_value))
        except Exception as exc:                      # noqa: BLE001
            raise PaymentError(f"платёж не разобран: {exc}") from exc

        payload = {
            "paymentPayload": body,
            "paymentRequirements": {
                "scheme": "exact",
                "network": requirement.network,
                # Только amount. maxAmountRequired — поле v1: при
                # x402Version 2 в payload фасилитатор PayAI отвечает
                # invalid_payment_requirements «got V1 ('maxAmountRequired')»
                # и платеж не проводится. Проверено вживую 17.10.2026
                # против facilitator.payai.network/settle.
                "amount": str(requirement.amount_atoms),
                "resource": requirement.resource,
                "description": "Deterministic verification of an agent artifact",
                "mimeType": "application/json",
                "payTo": requirement.pay_to,
                "maxTimeoutSeconds": 300,
                "asset": requirement.asset,
                # Имя и версия токена нужны фасилитатору для домена EIP-712.
                "extra": {"name": domain.name, "version": domain.version},
            },
        }
        url = self.x402_facilitator.rstrip("/") + "/settle"
        req = urllib.request.Request(
            url, data=_json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "User-Agent": "attest/1.0"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                result = _json.loads(r.read())
        except Exception as exc:                      # noqa: BLE001
            raise PaymentError(f"расчёт у фасилитатора не выполнен: {exc}") from exc

        if not result.get("success"):
            reason = result.get("errorReason") or result.get("errorMessage")                      or "без причины"
            raise PaymentError(f"фасилитатор не подтвердил расчёт: {reason}")

        tx = str(result.get("transaction") or "")
        if not tx:
            raise PaymentError(
                "фасилитатор ответил успехом без транзакции. "
                "Оплата не засчитана.")
        return {"transaction": tx,
                "payer": result.get("payer") or getattr(requirement, "payer", None),
                "confirmed_on_chain": bool(self.x402_rpc_url)}

    def _verify_payment(self, header_value: str, amount_atoms: int | None = None):
        """Проверить оплату по челленджу, который мы сами же и выставили."""
        from .payment import PaymentRequirement, verify_payment
        self._last_settlement = None

        if not self.x402_pay_to:
            raise PaymentError(
                "payment is not configured: no wallet set (ATTEST_PAY_TO is empty)",
                status=503,
            )
        token, challenge = build_challenge(
            resource=f"{self._base_url()}/verify",
            pay_to=self.x402_pay_to,
            price_atoms=(self.x402_price_atoms if amount_atoms is None
                         else int(amount_atoms)),
            network=self.x402_network,
            asset=self.x402_asset,
        )
        requirement = PaymentRequirement.from_challenge(challenge)
        domain = eip712_domain(requirement.network, requirement.asset)
        payment = verify_payment(
            requirement,
            header_value,
            domain,
            seen_nonces=self._seen_nonces(),
        )
        # Подпись сошлась — но это только разрешение. Пока авторизация не
        # отправлена в цепь, денег нет.
        self._last_settlement = self._settle(header_value, requirement, domain)
        return payment

    def _verify_result(self, payload: dict, source: str, paid) -> dict[str, Any]:
        schema = payload.get("schema")
        generation = payload.get("generation")
        result = attest(
            payload["artifact"],
            schema,
            source=source[:200],
            generation=generation if isinstance(generation, dict) else None,
            payload_mandate=payload.get("mandate"),
            payload_action=payload.get("action"),
            require_json=True,
        )
        body = result.as_dict()
        body["free_remaining"] = self.free_tier.remaining(self.client_id())
        body["paid"] = paid is not None
        # Проверка формы отвечает на вопрос «правильно ли оформлено».
        # Этот блок — на второй: «есть ли что оформлять».
        try:
            _art, _ = _coerce_json_field(payload["artifact"], "artifact")
            _sch, _ = _coerce_json_field(schema, "schema")
            hollow = scan_for_emptiness(
                _art,
                _sch if isinstance(_sch, dict) else None,
            )
            score = emptiness_score(hollow)
            body["emptiness"] = {
                "score": score,
                "verdict": emptiness_verdict(score, hollow),
                "signals": [s.as_dict() for s in hollow[:12]],
                "note": ("Absence of signals does not prove meaningfulness — "
                         "it only means the coarse checks did not fire."),
            }
        except Exception as exc:  # noqa: BLE001
            # Детектор пустоты не имеет права ломать проверку: если он
            # сломался, клиент должен получить свой результат, а не 500.
            body["emptiness"] = {"error": f"{type(exc).__name__}: {exc}"}

        auth = body.get("attestation", {}).get("record", {}).get("authority")
        if auth is not None:
            body["authority"] = auth
            body["authority_hash"] = body["attestation"]["record"].get(
                "authority_hash")
        else:
            # Мандат не предъявлен. Молчать об этом нельзя: иначе «нет
            # проверки разрешения» выглядит как «разрешение есть».
            body["authority"] = {
                "allowed": False, "rule": "no_mandate",
                "note": "no mandate supplied — authority was not checked",
            }

        gen = payload.get("generation")
        if isinstance(gen, dict):
            ctx = GenerationContext(
                **{k: v for k, v in gen.items() if k in _GEN_FIELDS})
            body["generation"] = {
                "context": ctx.as_dict(),
                "chain": verify_chain(
                    {"chain_hash": result.attestation.record.chain_hash,
                     "content_hash": _digest(payload["artifact"])},
                    ctx),
            }
        else:
            # Условия не переданы. Молчать об этом нельзя: иначе клиент
            # решит, что привязка есть и проверена.
            body["generation"] = {
                "chain": {"status": "NO_CHAIN", "bound": False,
                          "detail": "generation conditions were not supplied — "
                                    "there is no binding"},
                "hint": "supply generation: {model, model_version, prompt, "
                        "parameters, generated_at, generator}",
            }
        if paid is not None:
            settled = getattr(self, "_last_settlement", None) or {}
            body["payment"] = {
                "payer": paid.payer,
                "amount_atoms": paid.amount_atoms,
                "pay_to": paid.pay_to,
                "nonce": paid.nonce,
                # Квитанция о расчёте: без транзакции клиент не может
                # доказать, что заплатил, а мы — что получили. Раньше
                # этих полей не было вовсе, и «оплачено» означало только
                # «предъявлена подпись».
                "settled": bool(settled),
                "transaction": settled.get("transaction"),
                "confirmed_on_chain": settled.get("confirmed_on_chain"),
            }
        return body

    def _base_url(self) -> str:
        """Абсолютный базовый URL, по которому нас видит клиент.

        За прокси с HTTPS Host один, а схема — в X-Forwarded-Proto: собирать
        `http://` из Host вслепую значит выдать клиенту resource, по которому
        он подпишет платёж, а мы его при проверке не узнаем.
        """
        env = (os.environ.get("ATTEST_BASE_URL") or "").rstrip("/")
        if env:
            return env
        host = self.headers.get("Host") or "attest.local"
        proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
        if proto in ("http", "https"):
            scheme = proto
        else:
            scheme = "http" if host.startswith(("localhost", "127.", "[::1")) else "https"
        return f"{scheme}://{host}"

    def _catalog_services(self) -> list[dict[str, Any]]:
        """Список услуг для каталогов: path + description + цена в USD."""
        return [
            {
                "path": "/verify",
                "description": VERIFY_DESCRIPTION,
                "price_usd": atomic_to_usd(self.x402_price_atoms),
            }
        ]

    def _oauth_resource_metadata(self) -> dict[str, Any]:
        """RFC 9728: Protected Resource Metadata для MCP-эндпоинта."""
        base = self._base_url()
        return {
            "resource": f"{base}/mcp",
            "authorization_servers": [],
            "scopes_supported": ["mcp:tools"],
            "bearer_methods_supported": [],
            "resource_documentation": f"{base}/mcp",
            "resource_name": BAZAAR_SERVICE_NAME,
            "resource_policy_uri": f"{base}/pricing",
        }

    def _send_file(self, name: str, mime: str) -> None:
        """Отдать статический файл репозитория. Нет файла — честный 404."""
        path = Path(__file__).resolve().parent.parent / name
        if not path.is_file():
            self._send_json(404, {"error": f"{name} not found"})
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(body)

    def _serve_manifest(self, name: str) -> None:
        """Отдать файл манифеста. Нет файла — честный 404, а не пустой 200."""
        path = resolve_manifest(name)
        if path is None:
            self._send_json(404, {
                "error": f"manifest {name} not found",
                "hint": "the files are in the repository root; set ATTEST_MANIFEST_DIR",
            })
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", MANIFEST_MIME[name])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _x402_discovery_doc(self) -> dict[str, Any]:
        """`.well-known/x402` — каталог в формате живого agentsvc.io.

        accepts берём из того же build_challenge, что и заголовок
        Payment-Required: каталог и реальный челлендж не могут разойтись.
        """
        base = self._base_url()
        doc = discovery_document(base_url=base, services=self._catalog_services())
        doc["x402Version"] = 2
        doc["provider"] = BAZAAR_SERVICE_NAME
        doc["facilitator"] = "PayAI"
        doc["items"] = []
        doc["total"] = 0
        if self.x402_pay_to:
            try:
                _, challenge = build_challenge(
                    resource=f"{base}/verify",
                    pay_to=self.x402_pay_to,
                    price_atoms=self.x402_price_atoms,
                    network=self.x402_network,
                    asset=self.x402_asset,
                )
            except (ValueError, TypeError) as exc:
                doc["note"] = f"challenge could not be assembled: {exc}"
            else:
                doc["items"] = [{
                    "resource": f"{base}/verify",
                    "type": "http",
                    "x402Version": 2,
                    "method": "POST",
                    "accepts": challenge["accepts"],
                    "lastUpdated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "metadata": {
                        "name": "Verify artifact",
                        "description": VERIFY_DESCRIPTION,
                        "mimeType": "application/json",
                        "category": "security",
                        "tags": BAZAAR_TAGS,
                        "price_usd": atomic_to_usd(self.x402_price_atoms),
                    },
                }]
                doc["total"] = 1
        else:
            doc["note"] = (
                "wallet is not configured (ATTEST_PAY_TO is empty)",
                "the catalog does not return prices and addresses"
            )
        doc["docs"] = f"{base}/llms.txt"
        return doc

    def _challenge_header(self, amount_atoms: int | None = None,
                          resource: str | None = None) -> str | None:
        """Заголовок `Payment-Required` с челленджем x402.

        Сумму и ресурс можно задать: подписка на 30 дней — другой товар с
        другой ценой, и выставлять ей челлендж на стоимость одного вызова
        значило бы продавать её за 0,005 USDC.

        Ошибка конфигурации не должна ронять сервис: клиент всё равно получит
        402 и текстовое объяснение, просто без машиночитаемого челленджа.
        """
        if not self.x402_pay_to:
            return None
        try:
            token, _ = build_challenge(
                resource=resource or f"{self._base_url()}/verify",
                pay_to=self.x402_pay_to,
                price_atoms=(self.x402_price_atoms if amount_atoms is None
                             else amount_atoms),
                network=self.x402_network,
                asset=self.x402_asset,
            )
        except (ValueError, TypeError) as exc:
            print(f"attest: x402-челлендж не собран: {exc}")
            return None
        return token

    def _exhausted_body(self, exc: FreeTierExhausted, client: str) -> dict[str, Any]:
        hint = (
            f"Pay {self.x402_price_atoms / 1_000_000} USDC to address "
            f"{self.x402_pay_to} and retry with the X-PAYMENT header."
            if self.x402_pay_to
            else "Per-call payment is not configured yet: contact us and we will continue."
        )
        return {
            "error": f"free limit reached ({exc.used}/{exc.limit} per day)",
            "free_remaining": 0,
            "resets_at": "00:00 UTC",
            "x402": {
                "enabled": bool(self.x402_pay_to),
                # Сеть и актив — из конфигурации, а не константами: раньше
                # здесь были вписаны mainnet-значения, и на тестнете блок
                # врал о сети, в которой выставлен счёт.
                "network": self.x402_network,
                "asset": self.x402_asset or USDC_BY_NETWORK.get(
                    self.x402_network, USDC_BASE),
                "price_atoms": self.x402_price_atoms,
                "pay_to": self.x402_pay_to,
            },
            "hint": hint,
            # Ответ «всё, иди плати» — тупик для агента без кошелька.
            # 22.10.2026: 114 раз клиенты упёрлись в лимит и ни один не
            # прислал заголовок оплаты. Значит, барьер должен вести туда,
            # где можно получить больше без денег: в бесплатный пакет.
            "free_pack": {
                "description": ("100 проверок на 30 дней бесплатно, без карты "
                                "и без регистрации. Заявка по ссылке, ключ "
                                "приходит на почту."),
                "url": f"{self._base_url()}/start",
                "header": ENT_HEADER,
            },
            # Если человек не готов платить, у него должен быть путь
            # получить пользу и оставить след. Разбор одного артефакта
            # бесплатный: это не продажа, а первый настоящий контакт.
            "human_review": {
                "description": ("One artifact reviewed by a human, free. "
                                "Written reply in two working days."),
                "url": f"{self._base_url()}/review",
            },
            # Человеку без x402-клиента нужен способ заплатить. Страница /pay
            # проверяет перевод USDC в блокчейне и выдаёт тот же токен.
            "pay_human": {
                "description": ("Send USDC on Base from any wallet and paste the "
                                "transaction hash: the transfer is verified on-chain "
                                "and a 30-day token is issued in the same response."),
                "url": f"{self._base_url()}/pay",
                "price_usdc": self._subscription_price_usd(),
            },
        }

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send_json(400, {"error": "Content-Length is not a number"})
            return None
        if length <= 0:
            self._send_json(400, {"error": "empty body"})
            return None
        if length > MAX_BODY_BYTES:
            self._drain(length)
            self._send_json(413, {"error": f"body larger than {MAX_BODY_BYTES} bytes"})
            return None
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": f"JSON parse failed: {exc}"})
            return None
        if not isinstance(parsed, dict):
            self._send_json(400, {"error": "expected a JSON object"})
            return None
        return parsed

    def _drain(self, length: int) -> None:
        """Прочитать и выбросить тело, которое мы отказались обрабатывать.

        Без этого клиент, продолжающий слать 512 КБ, ловит разрыв соединения
        вместо внятного ответа 413: мы ответили, не дочитав запрос.
        Ограничиваем объём, чтобы отказ не превращался в бесплатный
        исходящий канал для всех подряд.
        """
        remaining = min(length, 8 * 1024 * 1024)
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    def _send_html(self, html: str) -> None:
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def _send_json(
        self, status: int, body: Any, extra_headers: dict[str, str] | None = None
    ) -> None:
        self._send(
            status,
            json.dumps(body, ensure_ascii=False).encode(),
            "application/json; charset=utf-8",
            extra_headers=extra_headers,
        )

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Поднять сервис. Блокирующий вызов — до Ctrl-C."""
    server = ThreadingHTTPServer((host, port), AttestHandler)
    free = AttestHandler.free_tier.daily_limit
    print(f"attest: http://{host}:{port}  {free} free checks per day")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
