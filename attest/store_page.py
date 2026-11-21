"""Магазин: одна страница, один вход, ясная цена.

CRO-принципы: одно действие (скан), ценность за 5 секунд, возражения сняты
рядом с ценой (доверие/цена/усилие/время), доказательства — образец отчёта и
честная строка «платящих пока 0», гарантии возврата.
"""
import json


def _card(title, price, note, href, cta="Купить", old=""):
    old_html = f'<s>{old}</s> ' if old else ""
    return f"""<div class="card">
<div class="row"><h3>{title}</h3><div class="price">{old_html}{price}</div></div>
<p class="muted">{note}</p>
<a class="btn small" href="{href}">{cta}</a>
</div>"""


def store_page() -> str:
    products = [
        ("Free scan", "$0", "One MCP server, three findings. No account, no card.",
         "https://attest.rta.lat/scan", "Scan now"),
        ("Founding audit", "$19", "One month of agent logs, one line of evidence per finding. "
         "First 10 teams; then $199. Nothing found — no fee.",
         "https://nidhipati.ailegal.legal/pay/card?product=agent-spend-audit-founding", "Start audit", "$199"),
        ("KARTA receipt", "$19", "A written receipt for what your agent spent: per call, per payee, "
         "with the order to fix.",
         "https://nidhipati.ailegal.legal/pay/card?product=karta-report", "Buy report"),
        ("Drift mandate", "$79", "Hard limits, payee allowlist and a kill switch in front of your agent. "
         "Setup + runbook in 48 hours.",
         "https://nidhipati.ailegal.legal/pay/card?product=drift-kill-switch", "Add limits"),
        ("Site Guard", "$49/yr", "Uptime every 5 minutes, SSL and domain expiry, alerts to Telegram. One site, 12 months.",
         "https://nidhipati.ailegal.legal/pay/card?product=site-guard-year", "Guard my site"),
        ("Channel Vault", "$19", "Full export of a Telegram channel: posts, media, members. One channel, one ZIP.",
         "https://nidhipati.ailegal.legal/pay/card?product=channel-vault-export", "Back up"),
        ("Doc Answer Box", "$49", "Upload documents, get a link that answers with citations and refuses when unsure. One team, first month.",
         "https://nidhipati.ailegal.legal/pay/card?product=doc-answer-box", "Open the box"),
        ("Sheet Doctor", "$19", "Duplicates, whitespace, dates and broken rows: clean file plus a fix report. Up to 50k rows.",
         "https://nidhipati.ailegal.legal/pay/card?product=sheet-doctor", "Clean my file"),
    ]
    cards = "\n".join(_card(*p) for p in products)
    ld = {
        "@context": "https://schema.org",
        "@type": "ItemList",
        "name": "Agent tools by RTA",
        "itemListElement": [
            {"@type": "Product", "name": t, "description": n,
             "offers": {"@type": "Offer", "price": p.replace("$", "").split("/")[0],
                        "priceCurrency": "USD", "url": h}}
            for t, p, n, h, *_ in products
        ],
    }
    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent tools — prove what your agent bought | RTA</title>
<meta name="description" content="Scan any MCP server in 30 seconds. See what your agent can spend, write or delete — and whether anything stops it. Free scan, $19 founding audit, USDC or card.">
<meta property="og:title" content="Your agent moves money. Can you prove what it bought?">
<meta property="og:description" content="Free MCP scan, $19 founding audit, limits and receipts. USDC or card.">
<meta property="og:image" content="https://attest.rta.lat/og.png">
<link rel="canonical" href="https://attest.rta.lat/store">
<style>
:root{{color-scheme:dark;--bg:#0b0f14;--card:#121923;--line:#1f2a37;--txt:#e8eef5;--mut:#8fa1b3;--acc:#4c8dff;--ok:#3fb950}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--txt);font:16px/1.6 -apple-system,Segoe UI,Roboto,system-ui,sans-serif}}
main{{max-width:1060px;margin:0 auto;padding:0 20px 64px}}
a{{color:var(--acc);text-decoration:none}}
.top{{display:flex;justify-content:space-between;align-items:center;padding:18px 0;border-bottom:1px solid var(--line);font-size:14px}}
.brand{{font-weight:700;letter-spacing:.5px}}
.hero{{padding:58px 0 30px}}
.heroGrid{{display:grid;grid-template-columns:1.15fr .85fr;gap:28px;align-items:start}}
.demo{{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px}}
.dhead{{font-size:13px;color:var(--mut);margin-bottom:10px}}
.drow{{font-size:14px;margin:6px 0 12px}}
.finding{{border-radius:10px;padding:10px 12px;margin:8px 0;font-size:14px}}
.finding b{{display:block}}
.finding span{{color:var(--mut);font-size:13px}}
.finding.high{{border:1px solid #f85149;background:#1d1113}}
.finding.ok{{border:1px solid #2ea043;background:#0f1a12}}
@media(max-width:820px){{.heroGrid{{grid-template-columns:1fr}}}}
h1{{font-size:clamp(32px,5vw,52px);line-height:1.08;margin:0 0 16px;letter-spacing:-1px}}
.lead{{font-size:19px;color:var(--mut);margin:0 0 26px}}
.cta{{display:inline-block;background:var(--acc);color:#fff;padding:14px 22px;border-radius:10px;font-weight:700}}
.cta.ghost{{background:transparent;border:1px solid var(--line);color:var(--txt);margin-left:10px}}
.proof{{display:flex;gap:18px;flex-wrap:wrap;color:var(--mut);font-size:14px;margin-top:22px}}
.proof b{{color:var(--txt)}}
h2{{font-size:26px;margin:56px 0 8px}}
.sub{{color:var(--mut);margin:0 0 22px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}}
.card h3{{font-size:17px;margin:0}}
.row{{display:flex;justify-content:space-between;gap:10px;align-items:baseline}}
.price{{font-size:22px;font-weight:800;white-space:nowrap}}
.price s{{color:var(--mut);font-weight:500;font-size:15px;margin-right:4px}}
.muted{{color:var(--mut);font-size:14px;margin:8px 0 12px}}
.btn{{display:inline-block;background:var(--acc);color:#fff;padding:9px 14px;border-radius:9px;font-weight:600}}
.btn.small{{font-size:14px}}
.steps{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}
.step{{border-left:2px solid var(--acc);padding:4px 0 4px 14px}}
.trust{{margin-top:40px;padding:18px;border:1px solid var(--line);border-radius:14px;background:var(--card)}}
.trust p{{margin:6px 0}}
details{{border-bottom:1px solid var(--line);padding:12px 0}}
summary{{cursor:pointer;font-weight:600}}
footer{{margin-top:50px;border-top:1px solid var(--line);padding-top:20px;color:var(--mut);font-size:14px}}
</style></head><body><main>
<nav class="top"><span class="brand">RTA · agent tools</span><span><a href="/scan">Scan</a> · <a href="/plans">Pricing</a> · <a href="mailto:maxim.pkk@gmail.com">Contact</a></span></nav>

<section class="hero">
<div class="heroGrid">
<div>
<h1>Your agent moves money.<br>Can you prove what it bought?</h1>
<p class="lead">Scan any MCP server in 30 seconds. See the tools that can spend, write or delete —
and whether anything stops them. Then fix it with a receipt, a limit or a kill switch.</p>
<a class="cta" href="/scan">Scan free — no account</a>
<a class="cta ghost" href="https://mrpkk.github.io/nidhipati/audit-sample.html">See a sample audit</a>
<div class="proof"><span><b>Free</b> scan</span><span><b>$19</b> founding audit</span>
<span><b>USDC</b> or card</span><span><b>Nothing found</b> — no fee</span></div>
</div>
<div class="demo">
<div class="dhead">Scan result · drift.rta.lat/mcp</div>
<div class="drow"><b>3</b> tools &nbsp;·&nbsp; <b>3</b> annotated &nbsp;·&nbsp; <b>0.9s</b></div>
<div class="finding high"><b>No kill switch or receipt</b><span>Stop it and prove what it paid — nothing does.</span></div>
<div class="finding ok"><b>Budget and limits mentioned</b><span>Descriptions name a cap and a budget.</span></div>
<div class="drow muted">risk 15/100 · verdict: looks controlled</div>
<a class="btn small" href="/scan">Run on your server</a>
</div>
</div>
</section>

<h2>Three questions nobody can answer today</h2>
<p class="sub">Ask your team. The silence is the product.</p>
<div class="steps">
<div class="step"><b>1. What did the agent just receive?</b><br><span class="muted">Tool output goes straight into context. Nobody checks if it is poisoned or wrong.</span></div>
<div class="step"><b>2. What is it allowed to spend?</b><br><span class="muted">No hard limit per call, per period, per payee — until the invoice arrives.</span></div>
<div class="step"><b>3. Where is the receipt?</b><br><span class="muted">"It says it paid" is not evidence. A receipt is.</span></div>
</div>

<h2>Start with a scan. Fix with a receipt.</h2>
<p class="sub">One ladder: free scan → $19 audit → limits and receipts. Pay once, or once a year.</p>
<div class="grid">
{cards}
</div>

<h2>How it works</h2>
<div class="steps">
<div class="step"><b>1. Scan</b><br><span class="muted">Paste your MCP URL. We list tools and find what can move money or state.</span></div>
<div class="step"><b>2. See</b><br><span class="muted">Three findings with severity — no account, no content stored.</span></div>
<div class="step"><b>3. Fix</b><br><span class="muted">Audit, mandate or kill switch. We deliver files, tests and a runbook.</span></div>
</div>

<div class="trust">
<p><b>Straight answers to the awkward questions</b></p>
<p><b>Is my data safe?</b> Scan reads the public tool list only; we do not store prompts or content.</p>
<p><b>What if you find nothing?</b> The audit is free. You keep the report saying so.</p>
<p><b>What if I pay and get nothing?</b> Refund in USDC to the paying address, or card reversal.</p>
<p><b>Why so cheap?</b> Founding price for the first 10 teams. The price returns to $199 after that. <b>0 paying customers so far</b> — the report is how we earn the first one.</p>
<p><b>How fast?</b> Scan in 30 seconds; audit in 5 working days; mandate in 48 hours.</p>
</div>

<h2>Questions</h2>
<details><summary>What is an MCP server?</summary><p class="muted">A standard way for an AI agent to call tools: search, databases, payments. If an agent can act, it goes through MCP.</p></details>
<details><summary>Do I need an account?</summary><p class="muted">No. Scan is free and anonymous. Account is needed only for a paid audit, where we need your logs.</p></details>
<details><summary>Which payments do you accept?</summary><p class="muted">Card via Nidhipati, or USDC on Base. For annual products — one payment, no subscription.</p></details>
<details><summary>Can you work inside our infrastructure?</summary><p class="muted">Yes: private deployment, white-label receipts and a custom policy pack. Write to maxim.pkk@gmail.com.</p></details>
<details><summary>Is this only for crypto agents?</summary><p class="muted">No. Any agent that calls paid APIs, writes data or sends messages has the same three questions.</p></details>

<footer>
<p>RTA tools: <a href="https://attest.rta.lat">attest</a> · <a href="https://karta.rta.lat">KARTA</a> ·
<a href="https://drift.rta.lat">drift</a> · <a href="https://nidhipati.ailegal.legal">Nidhipati</a> ·
<a href="https://pramana.ailegal.legal">PRAMANA</a></p>
<p>Contact: <a href="mailto:maxim.pkk@gmail.com">maxim.pkk@gmail.com</a></p>
</footer>
</main>
<script type="application/ld+json">{json.dumps(ld, ensure_ascii=False)}</script>
</body></html>"""
