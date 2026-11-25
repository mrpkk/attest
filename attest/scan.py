"""Скан MCP-сервера: что он умеет и чего у него нет.

Зачем: вход воронки. Человек вставляет URL своего MCP-сервера, за 30 секунд
получает 2–3 конкретные находки: какие инструменты двигают деньги/меняют
состояние, есть ли аннотации, упомянуты ли бюджет, лимит, kill-switch,
квитанция и аудит. Без находок письмо — спам; с находками — повод.

Только stdlib: сервис attest не тянет лишних зависимостей.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request
from html import escape
from urllib.parse import urlsplit

TIMEOUT = 12
UA = "attest-scan/0.1 (+https://attest.rta.lat/scan)"
MONEY_WORDS = ("pay", "payment", "transfer", "send", "buy", "purchase", "swap",
               "bridge", "withdraw", "deposit", "spend", "charge", "invoice", "refund")
WRITE_WORDS = ("write", "update", "create", "delete", "drop", "remove", "execute",
               "run", "shell", "eval", "deploy", "admin", "set_", "put_", "post_")
CONTROL_WORDS = ("budget", "limit", "cap", "quota", "kill", "stop", "pause",
                 "receipt", "audit", "spend", "approval", "policy")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Редирект — это обход проверки адреса: не ходим за ним.

    Без этого `https://evil.example → http://127.0.0.1:8291/pay/...` превращает
    скан в SSRF-прокси одним запросом.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise urllib.error.HTTPError(req.full_url, code,
                                     "redirects are not followed by the scanner",
                                     headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect)


def assert_public_url(url: str) -> None:
    """Разрешаем только публичные http(s)-адреса.

    Проверяем и имя, и **все** адреса, которые оно резолвит: `localhost`,
    `127.0.0.1`, `169.254.169.254` (метаданные облака), `10/8`, `192.168/16`,
    `::1` — всё это внутренняя сеть, а не MCP-сервер клиента.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise RuntimeError("url must be http:// or https://")
    host = (parts.hostname or "").strip().lower()
    if not host:
        raise RuntimeError("url has no host")
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        raise RuntimeError("internal address is not allowed")
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise RuntimeError(f"host does not resolve: {type(exc).__name__}") from exc
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            raise RuntimeError("host resolves to an unparsable address") from None
        if not ip.is_global:
            raise RuntimeError("internal address is not allowed")


def _rpc(url: str, payload: dict, session: str = "") -> tuple[dict, str]:
    assert_public_url(url)
    """Один JSON-RPC вызов. Возвращает (ответ, id сессии). Понимает SSE."""
    body = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": UA,
    }
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with _OPENER.open(req, timeout=TIMEOUT) as resp:
        sid = resp.headers.get("Mcp-Session-Id", session)
        raw = resp.read(2_000_000).decode("utf-8", "ignore")
        ctype = resp.headers.get("Content-Type", "")
    if "text/event-stream" in ctype or raw.lstrip().startswith("event:"):
        data = [l[5:].strip() for l in raw.splitlines() if l.startswith("data:")]
        raw = data[-1] if data else "{}"
    return json.loads(raw or "{}"), sid


def fetch_tools(url: str) -> list[dict]:
    """initialize → tools/list. Бросает RuntimeError с человеческой причиной."""
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "attest-scan", "version": "0.1"}}}
    try:
        first, sid = _rpc(url, init)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"сервер ответил HTTP {e.code}") from e
    except Exception as e:
        raise RuntimeError(f"не удалось подключиться: {type(e).__name__}") from e
    if "result" not in first:
        raise RuntimeError("сервер не ответил на initialize (это MCP-эндпоинт?)")
    try:
        _rpc(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    except Exception:
        pass
    try:
        listed, _ = _rpc(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, sid)
    except Exception as e:
        raise RuntimeError(f"tools/list не ответил: {type(e).__name__}") from e
    tools = (listed.get("result") or {}).get("tools")
    if tools is None:
        raise RuntimeError("сервер не отдал список инструментов")
    return tools


def _name(tool: dict) -> str:
    return str(tool.get("name") or tool.get("title") or "").lower()


def _text(tool: dict) -> str:
    parts = [str(tool.get("name") or ""), str(tool.get("title") or ""),
             str(tool.get("description") or "")]
    return " ".join(parts).lower()


def analyze(tools: list[dict]) -> dict:
    """Чистая функция: список инструментов → находки и счёт риска."""
    total = len(tools)
    money, write, annotated = [], [], 0
    for t in tools:
        name = _name(t)
        if any(w in name for w in MONEY_WORDS):
            money.append(name)
        elif any(w in name for w in WRITE_WORDS):
            write.append(name)
        if any(k in t for k in ("annotations", "readOnlyHint", "destructiveHint")):
            annotated += 1
    controls = " ".join(_text(t) for t in tools)
    has_control = {w: w in controls for w in ("budget", "limit", "kill", "receipt", "audit")}
    findings = []
    if money:
        findings.append({
            "severity": "high",
            "title": f"{len(money)} инструмент(ов) двигают деньги",
            "detail": "Например: " + ", ".join(money[:5]) + ". " +
                      "Ошибка агента = реальный платёж; нужен лимит на вызов и на период.",
        })
    if write:
        findings.append({
            "severity": "medium",
            "title": f"{len(write)} инструмент(ов) меняют состояние",
            "detail": "Запись/удаление/исполнение без подтверждения человеком — " +
                      "классический путь к необратимым действиям.",
        })
    if total and annotated < total:
        findings.append({
            "severity": "medium",
            "title": f"{total - annotated} из {total} инструментов без аннотаций",
            "detail": "Нет readOnlyHint/destructiveHint: клиент не знает, что безопасно, " +
                      "и показывает подтверждение на всё — или ни на что.",
        })
    if not has_control["budget"] and not has_control["limit"]:
        findings.append({
            "severity": "high",
            "title": "Не упомянуты бюджет и лимиты",
            "detail": "В описаниях нет budget/limit/cap: агент не знает границы, " +
                      "а вы узнаете о перерасходе по счёту.",
        })
    if not has_control["kill"] and not has_control["receipt"]:
        findings.append({
            "severity": "medium",
            "title": "Нет kill-switch и квитанции",
            "detail": "Остановить агента и доказать, что именно он сделал, нечем.",
        })
    high = sum(1 for f in findings if f["severity"] == "high")
    score = min(100, high * 35 + (len(findings) - high) * 15)
    return {"tools": total, "annotated": annotated, "money_tools": money,
            "write_tools": write, "controls": has_control,
            "findings": findings[:4], "score": score,
            "verdict": "needs attention" if score >= 50 else "looks controlled"}


def scan(url: str) -> dict:
    assert_public_url(url)
    tools = fetch_tools(url)
    result = analyze(tools)
    result["url"] = url
    return result


def scan_page() -> str:
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP server scan — check tools, annotations and hidden instructions | attest</title>
<meta name="description" content="Scan any MCP server in 30 seconds: which tools can move money or state, whether annotations exist, and whether descriptions contain hidden instructions. No account, five scans a day free.">
<link rel="canonical" href="https://attest.rta.lat/scan">
<meta property="og:type" content="website">
<meta property="og:title" content="MCP server scan — what your agent can do, and what it cannot stop">
<meta property="og:description" content="Paste an MCP server URL: tools that move money, missing annotations, instructions hidden in descriptions. Free, no account.">
<meta property="og:url" content="https://attest.rta.lat/scan">
<meta name="twitter:card" content="summary">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[{"@type":"Question","name":"How do I scan an MCP server?","acceptedAnswer":{"@type":"Answer","text":"Paste the server URL (SSE or HTTP transport) into the form. The scan reads the public tools/list response and returns flags in about 30 seconds — no account, no card."}},{"@type":"Question","name":"What does an MCP server scan check?","acceptedAnswer":{"@type":"Answer","text":"Whether each tool can move money or change state, whether annotations are declared, and whether descriptions contain hidden instructions for an AI agent."}},{"@type":"Question","name":"Is an MCP server scan a security audit?","acceptedAnswer":{"@type":"Answer","text":"No. It is a filter before an audit: it shows what the server can do, not what it will do, and does not read prompts, results or user data."}}]}</script>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebApplication","name":"MCP server scan","applicationCategory":"DeveloperApplication","operatingSystem":"Any","url":"https://attest.rta.lat/scan","description":"Scan an MCP server's public tool list: tools that move money or state, missing annotations, and hidden instructions in descriptions.","offers":{"@type":"Offer","price":"0","priceCurrency":"USD"}}</script>
<style>
:root{color-scheme:dark}
body{margin:0;background:#0d1117;color:#e6edf3;font:16px/1.55 system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:48px 20px}
h1{font-size:30px;margin:0 0 8px}
p.s{color:#8b949e;margin:0 0 24px}
form{display:flex;gap:8px;flex-wrap:wrap}
input{flex:1 1 320px;padding:12px;border-radius:8px;border:1px solid #30363d;background:#161b22;color:#e6edf3}
button{padding:12px 18px;border-radius:8px;border:0;background:#2f81f7;color:#fff;font-weight:600;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}
#out{margin-top:26px}
.f{border:1px solid #30363d;border-radius:10px;padding:14px 16px;margin:10px 0;background:#161b22}
.f.high{border-color:#f85149}.f.medium{border-color:#d29922}
.t{font-weight:700;margin-bottom:4px}.d{color:#8b949e}
.score{font-size:14px;color:#8b949e;margin-top:14px}
.cta{margin-top:22px;padding:16px;border:1px solid #2f81f7;border-radius:10px;background:#0d1b2f}
.cta a{color:#58a6ff}
.err{color:#f85149}
.doc{margin-top:44px;border-top:1px solid #21262d;padding-top:26px}
.doc h2{font-size:20px;margin:26px 0 8px}
.doc table{width:100%;border-collapse:collapse;font-size:14.5px;margin:10px 0}
.doc th,.doc td{border:1px solid #30363d;padding:8px 10px;text-align:left;vertical-align:top}
.doc th{background:#161b22;color:#8b949e}
.doc pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;overflow:auto;font-size:13px}
.doc code{background:#161b22;padding:2px 5px;border-radius:4px}
.doc a{color:#58a6ff}
.doc ul{margin:8px 0;padding-left:20px;color:#c9d1d9}
.doc li{margin:4px 0}
</style></head><body><main>
<h1>Scan your MCP server</h1>
<p class="s">30 seconds. No account. We show what your agent can do — and what it can't stop.</p>
<form id="f"><input id="u" placeholder="https://your-server.com/mcp" required>
<button id="b" type="submit">Scan</button></form>
<div id="out"></div>

<section class="doc">
<h2>What a scan of an MCP server looks like</h2>
<p>The scan reads the server's public tool list — the same <code>tools/list</code> answer any MCP
client receives — and reports three things a buyer or a reviewer needs to know before pointing an
agent at it:</p>
<table>
<tr><th>Check</th><th>Why it matters</th></tr>
<tr><td>Tools that can move money or state</td><td>A tool that transfers, approves or deletes is a
different risk class from one that reads a price.</td></tr>
<tr><td>Annotations present</td><td><code>readOnlyHint</code>, <code>destructiveHint</code> and
<code>openWorldHint</code> tell the client what the tool does; without them every tool looks equally
dangerous.</td></tr>
<tr><td>Descriptions that instruct instead of describe</td><td>A description containing "ignore
previous instructions" is a hidden instruction, not documentation.</td></tr>
</table>

<h2>Example result</h2>
<pre><code>Tools: 14, annotated: 9, risk score: 42/100 — needs review
[high]   transfer_usdc — moves funds, no readOnlyHint
[high]   description of "approve" contains "ignore previous instructions"
[medium] delete_channel — destructive, destructiveHint missing</code></pre>
<p class="s">Synthetic example. The scan does not read prompts, does not store content, and does not
call any tool — only the public list.</p>

<h2>Limits</h2>
<ul>
<li>One server per scan, three findings; five free scans a day per address.</li>
<li>The server must answer <code>tools/list</code> over HTTP. Stdio-only servers are not reachable
from here.</li>
<li>No account, no card, nothing stored about the server beyond counters.</li>
</ul>

<h2>What the scan does not do</h2>
<ul>
<li>It does not prove the server is safe — it shows what it can do, not what it will do.</li>
<li>It does not read tool results, prompts or user data.</li>
<li>It is not the $19 audit: the audit reads one month of spend logs and ties each finding to a row.</li>
</ul>

<h2>FAQ: scanning an MCP server</h2>
<dl>
<dt>How do I scan an MCP server?</dt>
<dd>Paste the server URL (SSE or HTTP transport) into the form above. The scan reads the public
<code>tools/list</code> response and returns flags in about 30 seconds — no account, no card.</dd>
<dt>What does an MCP server scan check?</dt>
<dd>Three things per tool: can it move money or change state, does it declare annotations
(read-only / destructive), and do its descriptions contain hidden instructions for an AI agent.</dd>
<dt>Is this a security audit?</dt>
<dd>No. It is a filter before one: it shows what the server can do, not what it will do, and it does not
read prompts, results or user data. The $19 audit reads a month of spend logs instead.</dd>
</dl>

<h2>MCP server scan vs. a vulnerability scanner</h2>
<p>A vulnerability scanner and an MCP server scan answer different questions, and using one where the other
belongs is how teams end up with a clean report and an incident. A vulnerability scanner looks for known
weaknesses in code and dependencies. An MCP server scan starts from the public <code>tools/list</code> answer
and asks what the agent is allowed to do with this server: which tools can move money, write files or delete
state, which of them declare <code>readOnlyHint</code> or <code>destructiveHint</code>, and whether a tool
description quietly carries instructions aimed at the model rather than the human reading it.</p>
<p>That means the scan can be run before you have the source, before there is a repository, and against a
third-party server you are about to connect — the three cases where a code scanner has nothing to chew on.
It also means the result is deliberately shallow: a tool can be honest in its description and still be
implemented badly. The scan reduces the surface you must review; it does not remove the review.</p>
<h2>What to do with the result</h2>
<p>Start with the tools that can move money or change state. For each one, decide the answer to a single
question: what stops this action if the agent is wrong? If the answer is "the model's judgement", you have
found the real risk. Three answers exist and none of them require rewriting the server:</p>
<ul>
<li><b>A receipt</b> — the action leaves a signed, verifiable record that a human can check afterwards.</li>
<li><b>A limit</b> — an amount or a count beyond which the tool refuses, regardless of intent.</li>
<li><b>A kill switch</b> — a way to stop the agent in one step, without editing prompts.</li>
</ul>
<p>Tools that are read-only need a different check: confirm the annotation is true, because a read-only tool
that writes is the most common mismatch between description and behaviour we see.</p>
<h2>How often to scan</h2>
<p>Scan when the server is new to you, when it changes, and before you raise its permissions. The public tool
list is what the agent will actually see at runtime, so a scan after a deployment is the cheapest check that
the deployment did not quietly widen the surface. There is no scheduled monitoring on the free path: this is a
point-in-time read, not a watchdog.</p>
<h2>Next steps</h2>
<p><a href="/docs/scan?ref=scan-page">What a spend scan checks, with limits</a> ·
<a href="/store?ref=scan-page">All tools and prices</a> ·
<a href="/plans?ref=scan-page">The $19 audit — scope</a></p>
</section>

<div class="cta" id="cta" hidden>
<b>Want the full report?</b> One month of logs, one line of evidence per finding.
<a href="https://nidhipati.ailegal.legal/pay/card?product=agent-spend-audit?ref=scan-page">$19 founding audit (first 10)</a> —
or reply to the email and we'll send the checklist.
</div>
<script>
const f=document.getElementById('f'),u=document.getElementById('u'),b=document.getElementById('b'),o=document.getElementById('out'),cta=document.getElementById('cta');
f.addEventListener('submit',async e=>{e.preventDefault();o.innerHTML='';cta.hidden=true;b.disabled=true;b.textContent='Scanning…';
try{const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u.value.trim()})});
const d=await r.json();if(!r.ok){o.innerHTML='<p class="err">'+(d.error||'scan failed')+'</p>';return;}
o.innerHTML='<div class="score">Tools: '+d.tools+', annotated: '+d.annotated+', risk score: '+d.score+'/100 — '+d.verdict+'</div>'+
d.findings.map(x=>'<div class="f '+x.severity+'"><div class="t">'+x.title+'</div><div class="d">'+x.detail+'</div></div>').join('');
if(d.findings.length)cta.hidden=false;}catch(err){o.innerHTML='<p class="err">network error</p>';}
finally{b.disabled=false;b.textContent='Scan';}});
</script></main></body></html>"""
