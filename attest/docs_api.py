"""`/docs/api` — API одной страницей: эндпоинты, лимиты, ошибки, curl.

Зачем. `/docs` объясняет, что доказывает квитанция, но не даёт ни одной команды
`curl`, ни лимитов, ни формата ошибок. Агент (и человек, который его настраивает)
упирается в догадки — а догадки стоят вызовов из бесплатной квоты.

Источник истины по адресам — `openapi.json`; тест сверяет, что каждый путь из
схемы есть на этой странице.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Что не попадает в openapi.json, но обязано быть в документации: JSON-RPC и
#: человеческие страницы оплаты.
EXTRA_ENDPOINTS = {
    "POST /mcp": "MCP 2026-07-28 (JSON-RPC): tools/list, tools/call — verify_artifact, verify_artifact_batch",
    "POST /api/free-scan": "free spend scan: email + CSV (≤200 KB), written reply in one business day",
    "GET /verify-receipt": "human page: paste a receipt, see whether it verifies",
    "GET /pay": "human page: pay 99 USDC from any wallet, token issued in the same response",
}

LIMITS = [
    ("Free checks", "5 per day per client, no signup"),
    ("Per call, paid", "$0.005 USDC over x402 (Base)"),
    ("30 days", "99 USDC (India: 49 USDC)"),
    ("Request body", "256 KB maximum for /verify"),
    ("Rate", "burst-limited per IP; 429 with Retry-After"),
]

ERRORS = [
    ("400", "`invalid JSON` / `artifact must be an object` — тело не разобрано; ничего не списано"),
    ("402", "free limit reached. Body carries `free_remaining: 0`, `resets_at`, and three ways forward: "
            "`free_pack` (100 checks/30 days), `human_review` (one artifact, free), `pay_human` (99 USDC)"),
    ("413", "body larger than the limit — уменьшите артефакт, квота не тронута"),
    ("429", "rate limited — `Retry-After` в секундах"),
    ("500", "internal — пришлите `X-Request-ID`, по нему находим запрос"),
]

CURL = [
    ("Verify an artifact", """curl -s -X POST https://attest.rta.lat/verify \\
  -H 'content-type: application/json' \\
  -d '{"artifact": {"findings": [{"id": "f1", "title": "checked the schema"}]}}'"""),
    ("List MCP tools", """curl -s -X POST https://attest.rta.lat/mcp \\
  -H 'content-type: application/json' \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'"""),
    ("Call a tool over MCP", """curl -s -X POST https://attest.rta.lat/mcp \\
  -H 'content-type: application/json' \\
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"verify_artifact","arguments":{"artifact":{"findings":[]}}}}'"""),
    ("Pay per call (x402)", """# 402 → pay 0.005 USDC on Base → retry with the header
curl -s -X POST https://attest.rta.lat/verify \\
  -H 'content-type: application/json' \\
  -H "X-PAYMENT: <payment payload>" \\
  -d '{"artifact": {...}}'"""),
]


def openapi_paths() -> list[str]:
    try:
        data = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for path, ops in (data.get("paths") or {}).items():
        for method in ops:
            out.append(f"{method.upper()} {path}")
    return sorted(out)


def page_html() -> str:
    schema_rows = "".join(
        f"<tr><td><code>{p}</code></td><td>см. <a href='/openapi.json'>openapi.json</a></td></tr>"
        for p in openapi_paths())
    extra_rows = "".join(
        f"<tr><td><code>{path}</code></td><td>{desc}</td></tr>"
        for path, desc in EXTRA_ENDPOINTS.items())
    limit_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in LIMITS)
    error_rows = "".join(f"<tr><td><code>{code}</code></td><td>{text}</td></tr>"
                         for code, text in ERRORS)
    curl_blocks = "".join(
        f"<h3>{title}</h3><pre><code>{body}</code></pre>" for title, body in CURL)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>attest API — endpoints, limits, errors, curl | attest</title>
<meta name="description" content="attest API in one page: verify artifacts, MCP tools over JSON-RPC, free limits, x402 pricing, error contract and copy-paste curl examples.">
<link rel="canonical" href="https://attest.rta.lat/docs/api">
<meta property="og:type" content="website">
<meta property="og:title" content="attest API — endpoints, limits, errors, curl">
<meta property="og:description" content="One page: verify, MCP tools, limits, x402 pricing and the error contract, with commands you can paste.">
<meta property="og:url" content="https://attest.rta.lat/docs/api">
<meta name="twitter:card" content="summary">
<style>
 body{{margin:0;background:#0b0d10;color:#e6e6e6;font:16px/1.65 ui-sans-serif,system-ui,sans-serif}}
 main{{max-width:760px;margin:0 auto;padding:40px 20px 80px}}
 h1{{font-size:30px;margin:0 0 6px}} h2{{font-size:20px;margin:32px 0 10px}}
 h3{{font-size:16px;margin:20px 0 6px;color:#a9b4c0}}
 a{{color:#7fd1b9}} code{{background:#171b21;padding:2px 5px;border-radius:4px;font-size:.92em}}
 pre{{background:#12161c;border:1px solid #232a33;border-radius:8px;padding:12px 14px;overflow:auto}}
 pre code{{background:none;padding:0;font-size:13px}}
 table{{border-collapse:collapse;width:100%;font-size:14.5px;margin:10px 0}}
 th,td{{border:1px solid #232a33;padding:8px 10px;text-align:left;vertical-align:top}}
 th{{background:#141920;color:#8b97a4}} .s{{color:#8b97a4}}
</style></head><body><main>
<h1>API in one page</h1>
<p class="s">Verify an artifact, call the MCP tools, know the limits and the error shape before you write code.</p>

<h2>Endpoints</h2>
<table><tr><th>Path</th><th>Notes</th></tr>{schema_rows}{extra_rows}</table>

<h2>Limits</h2>
<table><tr><th>What</th><th>Value</th></tr>{limit_rows}</table>
<p class="s">Free limit is per client, not per key: five checks a day cover integration, then either a paid
call or the free 100-check pack (<code>/start</code>). Money is never taken without a payment header.</p>

<h2>Errors</h2>
<table><tr><th>Status</th><th>What it means</th></tr>{error_rows}</table>
<p class="s">A <code>402</code> is not a dead end: the body names three ways forward, and one of them is free.</p>

<h2>Copy-paste examples</h2>
{curl_blocks}

<h2>Verify without trusting us</h2>
<p>Every paid verdict is Ed25519-signed. <a href="/verify-offline">/verify-offline</a> checks it in the
browser with no network calls; <code>conformance/receipt-vectors.json</code> (CC0) lets your own code
disagree with ours and be right about it.</p>
<p class="s">Machine-readable: <a href="/openapi.json">openapi.json</a> ·
<a href="/llms.txt">llms.txt</a> · <a href="/docs">what a receipt proves</a></p>
</main></body></html>"""
