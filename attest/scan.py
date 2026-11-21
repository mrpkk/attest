"""Скан MCP-сервера: что он умеет и чего у него нет.

Зачем: вход воронки. Человек вставляет URL своего MCP-сервера, за 30 секунд
получает 2–3 конкретные находки: какие инструменты двигают деньги/меняют
состояние, есть ли аннотации, упомянуты ли бюджет, лимит, kill-switch,
квитанция и аудит. Без находок письмо — спам; с находками — повод.

Только stdlib: сервис attest не тянет лишних зависимостей.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from html import escape

TIMEOUT = 12
UA = "attest-scan/0.1 (+https://attest.rta.lat/scan)"
MONEY_WORDS = ("pay", "payment", "transfer", "send", "buy", "purchase", "swap",
               "bridge", "withdraw", "deposit", "spend", "charge", "invoice", "refund")
WRITE_WORDS = ("write", "update", "create", "delete", "drop", "remove", "execute",
               "run", "shell", "eval", "deploy", "admin", "set_", "put_", "post_")
CONTROL_WORDS = ("budget", "limit", "cap", "quota", "kill", "stop", "pause",
                 "receipt", "audit", "spend", "approval", "policy")


def _rpc(url: str, payload: dict, session: str = "") -> tuple[dict, str]:
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
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
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
    tools = fetch_tools(url)
    result = analyze(tools)
    result["url"] = url
    return result


def scan_page() -> str:
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scan your MCP server — attest</title>
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
</style></head><body><main>
<h1>Scan your MCP server</h1>
<p class="s">30 seconds. No account. We show what your agent can do — and what it can't stop.</p>
<form id="f"><input id="u" placeholder="https://your-server.com/mcp" required>
<button id="b" type="submit">Scan</button></form>
<div id="out"></div>
<div class="cta" id="cta" hidden>
<b>Want the full report?</b> One month of logs, one line of evidence per finding.
<a href="https://nidhipati.ailegal.legal/pay/card?product=agent-spend-audit">$19 founding audit (first 10)</a> —
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
