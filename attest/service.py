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
import hmac
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__
from .core import attest
from .metrics import METRICS, channel_of, spent_nonces
from .signing import public_key_b64
from . import entitlement
from .entitlement import HEADER as ENT_HEADER, issue as issue_entitlement, redeem, describe as entitlement_describe
from .generation import GenerationContext, verify_chain
from .provenance import digest as _digest

_GEN_FIELDS = ("model", "model_version", "prompt", "parameters",
              "generated_at", "generator", "generator_version")
from .emptiness import (emptiness_score, emptiness_verdict,
                           scan_for_emptiness)
from .payment import PaymentError
from .x402 import atomic_to_usd, agent_card, discovery_document

DEFAULT_FREE_DAILY = 20

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
    # Раньше здесь стояло «9 USDC в месяц» без кода приёма: тариф был виден
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

DEMO = """<!doctype html><meta charset=utf-8><title>attest — artifact verification</title>
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
  <button onclick="run()">Check form and emptiness</button></div>
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
"""

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

<h2 style="font-size:17px;margin:26px 0 6px">Pricing</h2>
<p class="hint">__FREE_LIMIT__ free checks per day.</p>
<div class="tiers">
 <div class="t"><b>Trial</b>0 USDC<br><span class="hint">__FREE_LIMIT__ checks per day, full check, no limit on artifact size</span></div>
 <div class="t"><b>Per call</b>0.005 USDC<br><span class="hint">beyond the free tier, paid over x402 on Base</span></div>
 <div class="t"><b>Subscription</b>9 USDC<br><span class="hint">removes the limit, suitable for CI pipelines</span></div>
</div>

<div class="warn"><b>What this does not do.</b> A valid form is not meaningful content, and a
signed artifact is not a permitted action. Absence of signals means the coarse checks did not fire —
it does not prove the artifact is sound. The signature is Ed25519: the public key travels with
the attestation, so you can verify it yourself without trusting this service.</div>

<p class="hint">Source: <a href="https://github.com/mrpkk/attest">github.com/mrpkk/attest</a> ·
Set: <a href="https://indra.rta.lat">indra.rta.lat</a></p>
</div>
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
        for page in ("", "/demo", "/pricing", "/article", "/health")
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
    pricing = PRICING
    x402_pay_to: str | None = os.environ.get("ATTEST_PAY_TO") or None
    x402_price_atoms: int = _env_int("ATTEST_PRICE_ATOMS", 5000)
    # Цена 30-дневной подписки для покупателей с низкой покупательной способностью
    # (Индия — обязательное направление, правило 20.10.2026). Поштучная цена
    # не снижается: ниже $0.002 рельс съедает больше половины выручки.
    ppp_price_usd: float = _env_float("ATTEST_PPP_PRICE_USD", 3.0)
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

    def client_id(self) -> str:
        """Кто платит лимит. Заголовок вызывающего не берём: его можно подделать.

        За обратным прокси адресом — адрес прокси, и лимит станет общим на всех.
        Это осознанно: честный тариф важнее абсолютной точности учёта.
        """
        return self.client_address[0] if self.client_address else "unknown"

    def do_GET(self) -> None:  # noqa: N802
        path = route_path(self.path)
        # Показ страницы — верх воронки. Считаем ДО обработчиков: они
        # возвращают управление и до этой точки дело не доходит.
        if path in ("/", "/demo", "/pricing", "/article"):
            METRICS.view(channel_of(self.path, self.headers.get("Referer")))
            METRICS.save()
        if path == "/":
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
            self._send_json(405, {"error": "use POST /mcp"})
        elif path == "/demo":
            self._send_html(DEMO.replace("__FREE_LIMIT__",
                                         str(self.free_tier.daily_limit)))
        elif path == "/metrics":
            self._send_json(200, METRICS.snapshot())
        elif path == "/.well-known/glama.json":
            card = _glama_claim()
            if card:
                self._send_json(200, card)
            else:
                self._send_json(404, {"error": "claim token not configured"})
        elif path == "/.well-known/mcp/server-card.json":
            self._send_json(200, _server_card())
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
        elif path.lstrip("/") in MANIFEST_FILES:
            self._serve_manifest(path.lstrip("/"))
        else:
            self._send_json(404, {"error": "no such path", "path": path})

    def _dict_pricing(self) -> dict[str, Any]:
        """Тарифы с настоящим лимитом: объявлять 20 при реальных 3 — враньё."""
        data = json.loads(json.dumps(self.pricing))
        data["free"]["limit_per_day"] = self.free_tier.daily_limit
        return data

    def do_POST(self) -> None:  # noqa: N802
        path = route_path(self.path)
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
                          paid=False)
            return self._handle_entitled(
                payload, source,
                "api.market gateway — billed by the marketplace")

        ent_token = self.headers.get(entitlement.HEADER)
        ent_ok, ent_why = redeem(ent_token, trusted_key=public_key_b64())
        if ent_ok:
            return self._handle_entitled(payload, source, ent_why)
        # Токен предъявлен и не прошёл. Молча списать проверку по
        # бесплатному тарифу здесь хуже: покупатель решит, что оплатил,
        # и будет искать ошибку там, где её нет.
        if ent_token:
            print(f"attest: entitlement отвергнут: {ent_why}")

        payment_header = self.headers.get("PAYMENT-SIGNATURE") or self.headers.get("X-PAYMENT")
        try:
            self.free_tier.spend(client)
            METRICS.check(channel_of(self.path, self.headers.get("Referer")),
                          paid=False)
        except FreeTierExhausted as exc:
            if not payment_header:
                token = self._challenge_header()
                self._send_json(
                    402,
                    self._exhausted_body(exc, client),
                    extra_headers={"Payment-Required": token} if token else None,
                )
                return
            try:
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
            try:
                self.free_tier.spend(self.client_id())
            except FreeTierExhausted as exc:
                self._send_json(402, self._exhausted_body(exc, self.client_id()))
                return

        def verify(artifact, schema, source):
            return attest(artifact, schema, source=source)

        answer = mcp_module.respond(raw, verify)
        if answer is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, body = answer
        self._send(status, body, "application/json; charset=utf-8")

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
            schema if isinstance(schema, dict) else None,
            source=source[:200],
            generation=generation if isinstance(generation, dict) else None,
            payload_mandate=payload.get("mandate"),
            payload_action=payload.get("action"),
        )
        body = result.as_dict()
        body["free_remaining"] = -1          # -1 = лимита нет
        body["paid"] = True
        body["entitlement"] = {"valid": True, "detail": detail}
        self._send_json(200, body)

    def _subscription_price_usd(self) -> float:
        """Цена 30-дневного доступа: обычная или PPP (?plan=ppp).

        PPP-цена не публикуется в общем прайсе: она для покупателей с низкой
        покупательной способностью (Индия) и передаётся ссылкой. Иначе
        западный покупатель просто выберет $3 вместо $9.
        """
        query = urlparse(self.path).query or ""
        params = dict(pair.split("=", 1) for pair in query.split("&") if "=" in pair)
        if params.get("plan") == "ppp":
            return max(0.0, float(self.ppp_price_usd))
        return float(entitlement.PRICE_USD)

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
            return self._send_json(
                402,
                {"error": f"pay {price_usd:g} USDC for 30 days of unlimited access",
                 "subscription": entitlement_describe(),
                 "header": entitlement.HEADER},
                extra_headers={"Payment-Required": challenge}
                if challenge else None)
        try:
            # Сверка идёт с ценой ЭТОГО плана, а не с ценой вызова. Баг до
            # 20.10.2026: _verify_payment всегда строил чек на 5000 атомов,
            # и платёж подписки (9 USDC) отвергался как «сумма не равна».
            payment = self._verify_payment(head, amount_atoms=amount_atoms)
        except PaymentError as exc:
            return self._send_json(exc.status, {"error": exc.reason})
        # Подписка — тоже деньги: без этой записи 9 USDC не попадали в
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
            schema if isinstance(schema, dict) else None,
            source=source[:200],
            generation=generation if isinstance(generation, dict) else None,
            payload_mandate=payload.get("mandate"),
            payload_action=payload.get("action"),
        )
        body = result.as_dict()
        body["free_remaining"] = self.free_tier.remaining(self.client_id())
        body["paid"] = paid is not None
        # Проверка формы отвечает на вопрос «правильно ли оформлено».
        # Этот блок — на второй: «есть ли что оформлять».
        try:
            hollow = scan_for_emptiness(
                payload["artifact"],
                schema if isinstance(schema, dict) else None,
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
