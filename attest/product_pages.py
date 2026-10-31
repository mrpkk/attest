"""Посадочные страницы двух дорогих продуктов attest (31.10.2026).

Зачем отдельные страницы. В отчётах EU AI Act Evidence Pack ($1,500/$3,000) и
MCP Security Pass ($500/$1,500) значились «страницы готовы», а по адресам
`/eu-ai-act` и `/mcp-security` отдавался 404 — купить было нечего. Здесь обе
страницы по адресам, которые называют в письмах, и с рабочей оплатой: перевод
USDC на Base проверяется до выдачи результата, без оплаты — 402.

Правила текста: только EN, заголовок — польза (6–12 слов), цена и кнопка в
первом экране, три строки доверия, FAQ из трёх вопросов, честная граница
«чего это не делает». Ни одного слова «revolutionary», «AI-powered», ни одной
цифры без источника.
"""

from __future__ import annotations

BASE_CSS = """
 body{margin:0;background:#0b0d10;color:#e6e6e6;font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
 main{max-width:820px;margin:0 auto;padding:34px 20px 72px}
 h1{font-size:32px;line-height:1.18;margin:0 0 10px;letter-spacing:-.02em}
 h2{font-size:20px;margin:30px 0 10px}
 p{margin:0 0 14px} a{color:#7fd1b9}
 .lead{font-size:17.5px;color:#a9b4c0;margin-bottom:18px}
 code{background:#171b21;padding:2px 5px;border-radius:4px;font-size:.9em;font-family:ui-monospace,Menlo,monospace}
 table{border-collapse:collapse;width:100%;font-size:14.5px;margin:0 0 16px}
 th,td{border:1px solid #232a33;padding:8px 11px;text-align:left;vertical-align:top}
 th{background:#141920}
 .grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));margin:14px 0}
 .card{border:1px solid #232a33;border-radius:12px;padding:16px;background:#10141a}
 .card b{font-size:25px;color:#7fd1b9;display:block}
 .trust{display:flex;flex-wrap:wrap;gap:8px 18px;font-size:13.5px;color:#8b97a4;margin:12px 0 0;padding:0;list-style:none}
 .trust li::before{content:"✓ ";color:#7fd1b9}
 .btn{display:inline-block;margin-top:10px;padding:12px 20px;border-radius:9px;background:#7fd1b9;color:#062018;font-weight:700;text-decoration:none;border:0;font-size:16px;cursor:pointer}
 .pay{border:1px solid #232a33;border-radius:12px;padding:16px;background:#10141a;margin:18px 0}
 .addr{font:13.5px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;background:#0b0d10;border:1px solid #30363d;border-radius:8px;padding:10px}
 .meta{color:#8b97a4;font-size:13.5px}
 input[type=text],input[type=email]{width:100%;box-sizing:border-box;background:#0b0d10;border:1px solid #30363d;border-radius:8px;color:#e6e6e6;padding:11px;margin:6px 0;font-size:15px}
 details{border:1px solid #232a33;border-radius:10px;padding:12px 14px;margin:0 0 10px;background:#10141a}
 summary{cursor:pointer;font-weight:600}
 .out{margin-top:10px;font-size:14px;white-space:pre-line}
 @media(max-width:520px){h1{font-size:26px} main{padding:22px 15px 60px} .lead{font-size:16px}}
"""


def _shell(title: str, description: str, canonical: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<link rel="canonical" href="https://attest.rta.lat{canonical}">
<style>{BASE_CSS}</style></head><body><main>{body}</main></body></html>"""


def _pay_block(price_note: str, endpoint: str, pay_to: str, extra_fields: str = "") -> str:
    return f"""
<div class="pay">
 <div><b>Pay in USDC on Base</b> — send the exact amount, then paste the transaction hash.
 Payment is verified on-chain before anything is handed over.</div>
 <p class="addr">{pay_to}</p>
 <input id="tx" type="text" placeholder="0x… transaction hash" autocomplete="off">
 {extra_fields}
 <button class="btn" id="go" type="button">Verify payment — start intake</button>
 <div class="out" id="out"></div>
 <p class="meta">No account, no card. Network: Base only, asset: USDC. A different network or
 asset means the funds are lost. The same transaction cannot be used twice.</p>
</div>
<script>
document.getElementById('go').onclick = async () => {{
  const out = document.getElementById('out');
  const body = {{tx: document.getElementById('tx').value.trim()}};
  document.querySelectorAll('[data-field]').forEach(el => {{ body[el.dataset.field] = el.value.trim(); }});
  if (!body.tx) {{ out.textContent = 'Paste the transaction hash first.'; return; }}
  out.textContent = 'Checking the transaction on Base…';
  const r = await fetch('{endpoint}', {{method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify(body)}});
  const j = await r.json().catch(() => ({{}}));
  if (r.ok) {{
    out.textContent = 'Paid. Order ' + j.order_id + '\\n' + (j.next || '');
  }} else {{
    out.textContent = 'Not accepted: ' + (j.error || ('HTTP ' + r.status));
  }}
}};
</script>"""


EU_AI_ACT_BODY = """
<h1>EU AI Act evidence your reviewer accepts in one folder</h1>
<p class="lead">A buyer's security team asks how your AI system meets the Act. You need the mapping,
the risk register and the logs in one pack — not a slide with a checkbox.</p>

<div class="grid">
 <div class="card"><b>$1,500</b>Base pack · 5 business days
  <p class="meta">All listed artifacts for one system, one jurisdiction assumption, one revision round.</p></div>
 <div class="card"><b>$3,000</b>Extended · 72 hours
  <p class="meta">Same scope, priority queue, daily checkpoint, delivery within 72 hours of intake.</p></div>
</div>
<ul class="trust">
 <li>No account needed</li>
 <li>Payment checked on-chain before intake</li>
 <li>Every claim in the pack points to a file you can open</li>
</ul>
__PAY__

<h2>What the pack contains</h2>
<table>
<tr><th>Artifact</th><th>What it answers</th></tr>
<tr><td><strong>Article map</strong> (6, 9, 10, 11, 12, 13, 14, 15, 43, 72)</td>
    <td>For each article: what it requires, what your system does, which file shows it, what is missing</td></tr>
<tr><td><strong>Risk register</strong></td>
    <td>Intended use, misuse, affected people, severity, mitigation, residual risk, owner</td></tr>
<tr><td><strong>Technical documentation template</strong></td>
    <td>The structure of Annex IV, pre-filled with your answers where they exist and marked gaps where they do not</td></tr>
<tr><td><strong>Logging template</strong></td>
    <td>Which events to record, fields, retention, tamper evidence, and how a refusal is recorded</td></tr>
<tr><td><strong>Conformity checklist</strong></td>
    <td>Step-by-step self-assessment with the evidence each step needs; article 43 route named as a route, not as a certificate</td></tr>
</table>

<h2>What this is not</h2>
<ul>
<li>Not a legal opinion and not a substitute for your lawyer or a notary.</li>
<li>Not a certificate, not notified-body approval, not a guarantee that a regulator accepts the format.</li>
<li>Deadlines and penalties are not restated from memory: where the pack mentions a date or an amount,
  it links the official text; if the text is not available to us, the pack says “verify in the official text”
  instead of quoting a number.</li>
<li>If your logs cannot support a claim, the pack records the gap. It does not fill gaps with wording.</li>
</ul>

<h2>Sample</h2>
<p><a href="/eu-ai-act-evidence/sample.pdf">4-page sample (PDF)</a> — built from our own artifacts:
an article-map page, a risk-register row, a signed deny record and the offline verification command.</p>

<h2>Questions</h2>
<details><summary>How fast can we start?</summary>
 <p>Payment is verified on-chain, then you get the intake form the same day. Base pack is delivered in
 5 business days from intake; extended — within 72 hours.</p></details>
<details><summary>Do you need access to our systems?</summary>
 <p>No. You send logs, policy documents and model information. If something cannot be shown, it is
 marked as a gap rather than assumed.</p></details>
<details><summary>What if the pack is not delivered?</summary>
 <p>Undelivered work is refunded in USDC to the paying address. Delivered work is not refunded;
 the revision round exists so that the format, not the facts, can be corrected.</p></details>
<p class="meta"><a href="/">attest</a> · <a href="/mcp-security">MCP Security Pass</a> ·
<a href="/deny-evidence">deny evidence</a> · <a href="/docs">docs</a> ·
<a href="mailto:maxim.pkk@gmail.com?subject=EU%20AI%20Act%20evidence%20pack">maxim.pkk@gmail.com</a></p>
"""

MCP_SECURITY_BODY = """
<h1>Know what your MCP server exposes before a reviewer does</h1>
<p class="lead">One server, one written report: what it can do, who can call it, what happens when a call
is refused — with severity, reproduction steps and the patches to apply.</p>

<div class="grid">
 <div class="card"><b>$500</b>Audit · 5 business days
  <p class="meta">One MCP server: findings, severity, reproduction, fix order. One revision round.</p></div>
 <div class="card"><b>$1,500</b>Audit with fixes · 48 hours
  <p class="meta">Same scope plus the patches applied by us, then a re-check of the same checks.</p></div>
</div>
<ul class="trust">
 <li>No account needed</li>
 <li>Payment checked on-chain before intake</li>
 <li>Re-check included in the $1,500 tier: same checks, new report</li>
</ul>
__PAY__

<h2>What we check — OWASP MCP Top 10</h2>
<table>
<tr><th>Risk area</th><th>What the report says</th></tr>
<tr><td>Token and session handling</td><td>How credentials are issued, stored, scoped and revoked; what happens without them</td></tr>
<tr><td>Tool definitions and instructions</td><td>Which descriptions can steer a model, unsafe defaults, missing annotations</td></tr>
<tr><td>Authorization and scopes</td><td>Which tools read, write, spend or delete; whether scopes are enforced server-side</td></tr>
<tr><td>Input handling</td><td>Path traversal, injection through tool arguments, unsafe deserialization, SSRF</td></tr>
<tr><td>Deny mode and logging</td><td>Whether the server can refuse, what it records, whether a refusal can be verified later</td></tr>
<tr><td>Supply chain and updates</td><td>Dependencies, pinned versions, what an update can change without review</td></tr>
</table>
<p class="meta">Each finding: id, severity (critical/high/medium/low), what an attacker gains, exact steps
to reproduce, the patch, and the check that proves the patch worked.</p>

<h2>What this is not</h2>
<ul>
<li>Not a penetration test of your infrastructure and not a certification.</li>
<li>Not a guarantee that no vulnerability exists — it covers the listed checks on one server.</li>
<li>No invented findings: if a category is clean, the report says “clean” with the command used.</li>
</ul>

<h2>Example report</h2>
<p>Example on request: write to
<a href="mailto:maxim.pkk@gmail.com?subject=MCP%20Security%20Pass%20example">maxim.pkk@gmail.com</a>
and you get a redacted report for one of our own servers. We do not publish a fake sample.</p>

<h2>Questions</h2>
<details><summary>Do you need production access?</summary>
 <p>No. A staging instance or a local run is enough; the report is about the server's surface, not your data.</p></details>
<details><summary>How is the $1,500 tier different?</summary>
 <p>We apply the patches ourselves in your repository, then run the same checks again and ship both
 reports — before and after — so a reviewer can compare.</p></details>
<details><summary>What if you find nothing?</summary>
 <p>Then the report states which checks ran and what they returned. “Nothing found” is a result only
 when the checks are named; otherwise it is a guess.</p></details>
<p class="meta"><a href="/">attest</a> · <a href="/eu-ai-act">EU AI Act evidence pack</a> ·
<a href="/deny-evidence">deny evidence</a> · <a href="/docs">docs</a> ·
<a href="mailto:maxim.pkk@gmail.com?subject=MCP%20Security%20Pass">maxim.pkk@gmail.com</a></p>
"""


def eu_ai_act_page(pay_to: str) -> str:
    pay = _pay_block("$1,500 base / $3,000 extended", "/api/eu-ai-act/order", pay_to,
                     extra_fields=('<input id="email" type="email" data-field="email" '
                                   'placeholder="email for the intake form (optional)">'))
    return _shell("EU AI Act evidence pack — article map, risk register, logs",
                  "EU AI Act evidence pack: article map (6, 9–15, 43, 72), risk register, technical "
                  "documentation template, logging template, conformity checklist. $1,500 base, "
                  "$3,000 extended. USDC on Base, no account.",
                  "/eu-ai-act", EU_AI_ACT_BODY.replace("__PAY__", pay))


def mcp_security_page(pay_to: str) -> str:
    pay = _pay_block("$500 audit / $1,500 with fixes", "/api/mcp-security/order", pay_to,
                     extra_fields=('<input id="server" type="text" data-field="server_url" '
                                   'placeholder="MCP server URL or repository (optional)">'))
    return _shell("MCP Security Pass — OWASP MCP Top 10 audit for one server",
                  "MCP security audit for one server: OWASP MCP Top 10 checks, findings with severity, "
                  "concrete patches and a re-check. $500 audit, $1,500 with fixes. USDC on Base, no account.",
                  "/mcp-security", MCP_SECURITY_BODY.replace("__PAY__", pay))
