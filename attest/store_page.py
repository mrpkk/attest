"""Магазин v2: дизайн и функционал в лучших традициях 2026.

Что взято из референсов (без перегруза):
- Linear / Raycast — реальный продукт в первом экране: живой скан, а не картинка.
- Vercel — один смысл, один CTA, минимум веса.
- Stripe — ясность цены и доверие рядом с кнопкой.
- Framer — нативные View Transitions и мягкое появление секций.
- Apple — крупная типографика и воздух.
- Notion — карточки-модули, из которых собирается страница.
- Arc — градиентная глубина без «кислотности».
- Figma — продукт показан интерфейсом, не обещаниями.
Технологии: island-подход (один лёгкий JS-остров), container queries,
:has(), clamp(), view transitions, IntersectionObserver, View Transitions API,
никаких фреймворков и внешних шрифтов — страница весит десятки КБ.
"""
import json


def _card(group, title, price, note, href, cta, old="", badge=""):
    old_html = f"<s>{old}</s> " if old else ""
    badge_html = f'<span class="badge">{badge}</span>' if badge else ""
    return f"""<article class="card" data-group="{group}">
<div class="card-top"><h3>{title}</h3>{badge_html}</div>
<div class="price">{old_html}{price}</div>
<p>{note}</p>
<a class="btn small" href="{href}">{cta}</a>
</article>"""


def store_page() -> str:
    cards = "\n".join([
        _card("agent", "Free scan", "$0", "One MCP server, three findings. No account, no card.",
              "/scan", "Scan now", badge="Start here"),
        _card("agent", "Founding audit", "$19", "One month of agent logs, one line of evidence per finding. "
              "First 10 teams. Nothing found — no fee.",
              "https://nidhipati.ailegal.legal/pay/card?product=agent-spend-audit-founding",
              "Start audit", old="$199", badge="First 10"),
        _card("agent", "KARTA receipt", "$19", "A written receipt for what your agent spent: per call, per payee, with the fix order.",
              "https://nidhipati.ailegal.legal/pay/card?product=karta-report", "Buy report"),
        _card("agent", "Drift mandate", "$79", "Hard limits, payee allowlist and a kill switch in front of your agent. Setup in 48 hours.",
              "https://nidhipati.ailegal.legal/pay/card?product=drift-kill-switch", "Add limits"),
        _card("simple", "Site Guard", "$49/yr", "Uptime every 5 minutes, SSL and domain expiry, alerts to Telegram. One site, 12 months.",
              "https://nidhipati.ailegal.legal/pay/card?product=site-guard-year", "Guard my site"),
        _card("simple", "Doc Answer Box", "$49", "Upload documents, get a link that answers with citations and refuses when unsure. One team.",
              "https://nidhipati.ailegal.legal/pay/card?product=doc-answer-box", "Open the box"),
        _card("simple", "Sheet Doctor", "$19", "Duplicates, whitespace, dates and broken rows: clean file plus a fix report. Up to 50k rows.",
              "https://nidhipati.ailegal.legal/pay/card?product=sheet-doctor", "Clean my file"),
        _card("simple", "Channel Vault", "soon", "Full export of a Telegram channel: posts, media, members. The exporter is being finished.",
              "mailto:maxim.pkk@gmail.com?subject=Channel%20Vault%20waitlist", "Join waitlist"),
    ])
    ld = {
        "@context": "https://schema.org",
        "@type": "ItemList",
        "name": "Agent tools by RTA",
        "itemListElement": [
            {"@type": "Product", "name": t,
             "description": n,
             "offers": {"@type": "Offer", "price": p.replace("$", "").split("/")[0].replace("soon", "0"),
                        "priceCurrency": "USD", "url": h}}
            for t, p, n, h in [
                ("Free scan", "$0", "MCP server scan", "https://attest.rta.lat/scan"),
                ("Founding audit", "$19", "Agent spend audit", "https://nidhipati.ailegal.legal/pay/card?product=agent-spend-audit-founding"),
                ("KARTA receipt", "$19", "Agent spend receipt", "https://nidhipati.ailegal.legal/pay/card?product=karta-report"),
                ("Drift mandate", "$79", "Spend limits and kill switch", "https://nidhipati.ailegal.legal/pay/card?product=drift-kill-switch"),
                ("Site Guard", "$49", "Uptime, SSL and domain", "https://nidhipati.ailegal.legal/pay/card?product=site-guard-year"),
                ("Doc Answer Box", "$49", "RAG for a folder", "https://nidhipati.ailegal.legal/pay/card?product=doc-answer-box"),
                ("Sheet Doctor", "$19", "Excel and CSV cleanup", "https://nidhipati.ailegal.legal/pay/card?product=sheet-doctor"),
            ]
        ],
    }
    html = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent tools — prove what your agent bought | RTA</title>
<meta name="description" content="Scan any MCP server in 30 seconds. See what your agent can spend, write or delete — and whether anything stops it. Free scan, $19 founding audit, USDC or card.">
<meta property="og:title" content="Your agent moves money. Can you prove what it bought?">
<meta property="og:description" content="Free MCP scan, $19 founding audit, limits and receipts. USDC or card.">
<meta property="og:image" content="https://attest.rta.lat/og.png">
<link rel="canonical" href="https://attest.rta.lat/store">
<style>
:root{
  --bg:#070a0f; --bg2:#0b1018; --panel:#0f1621; --line:#1e2a3a; --txt:#edf3fb;
  --mut:#93a4b8; --acc:#5b8cff; --acc2:#7cf7c4; --ok:#3fd68f; --warn:#f5b83d; --bad:#ff6b6b;
  --radius:16px; --max:1080px;
  color-scheme:dark;
}
[data-theme="light"]{
  --bg:#f7f9fc; --bg2:#eef3fa; --panel:#ffffff; --line:#dbe4f0; --txt:#0c1522;
  --mut:#54657a; --acc:#2f6bff; --acc2:#0f9d76; --ok:#148b5a; --warn:#a86a00; --bad:#c02b2b;
  color-scheme:light;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--txt);
  font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:
   radial-gradient(60vw 40vw at 15% -10%, color-mix(in srgb, var(--acc) 22%, transparent), transparent 70%),
   radial-gradient(50vw 40vw at 90% 0%, color-mix(in srgb, var(--acc2) 14%, transparent), transparent 70%),
   var(--bg)}
a{color:var(--acc);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:var(--max);margin:0 auto;padding:0 20px}
.skip{position:absolute;left:-999px}
.skip:focus{left:12px;top:12px;background:var(--panel);padding:8px 12px;border-radius:8px;z-index:50}
header{position:sticky;top:0;z-index:30;backdrop-filter:blur(14px);
  background:color-mix(in srgb, var(--bg) 76%, transparent);border-bottom:1px solid var(--line)}
.nav{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 0}
.brand{font-weight:800;letter-spacing:.4px}
.brand span{color:var(--acc2)}
.nav-links{display:flex;gap:16px;align-items:center;font-size:14px}
.nav-links a{color:var(--txt)}
.icon{background:none;border:1px solid var(--line);color:var(--txt);border-radius:10px;
  width:38px;height:38px;cursor:pointer;font-size:16px}
.hero{padding:72px 0 36px}
.hero-grid{display:grid;grid-template-columns:1.15fr .85fr;gap:28px;align-items:start}
.eyebrow{display:inline-flex;align-items:center;gap:8px;font-size:13px;color:var(--mut);
  border:1px solid var(--line);border-radius:999px;padding:6px 12px;margin-bottom:18px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 12px var(--ok)}
h1{font-size:clamp(34px,5.4vw,58px);line-height:1.04;letter-spacing:-1.4px;margin:0 0 18px}
.lead{font-size:clamp(17px,1.7vw,20px);color:var(--mut);margin:0 0 26px;max-width:56ch}
.btn{display:inline-flex;align-items:center;gap:8px;background:var(--acc);color:#fff;
  padding:13px 20px;border-radius:12px;font-weight:700;border:0;cursor:pointer;font-size:15px}
.btn:hover{text-decoration:none;filter:brightness(1.08)}
.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
.btn.small{padding:9px 13px;font-size:14px;border-radius:10px}
.metrics{display:flex;gap:18px;flex-wrap:wrap;color:var(--mut);font-size:14px;margin-top:22px}
.metrics b{color:var(--txt)}
.panel{background:color-mix(in srgb, var(--panel) 92%, transparent);border:1px solid var(--line);
  border-radius:var(--radius);padding:16px;box-shadow:0 20px 60px rgba(0,0,0,.28)}
.scan-row{display:flex;gap:8px;flex-wrap:wrap}
input[type=url]{flex:1 1 220px;background:var(--bg2);border:1px solid var(--line);color:var(--txt);
  border-radius:10px;padding:12px;font:14px ui-monospace,monospace}
input:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--acc2);outline-offset:2px}
.result{margin-top:12px;font-size:14px}
.finding{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0}
.finding.high{border-color:var(--bad)}
.finding.medium{border-color:var(--warn)}
.muted{color:var(--mut)}
.stats{margin-top:12px;font-size:13px;color:var(--mut)}
section.block{padding:56px 0 8px}
h2{font-size:clamp(24px,3vw,34px);letter-spacing:-.6px;margin:0 0 8px}
.sub{color:var(--mut);margin:0 0 22px}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 18px}
.tab{background:transparent;border:1px solid var(--line);color:var(--mut);border-radius:999px;
  padding:8px 14px;font-size:14px;cursor:pointer}
.tab.active{background:var(--txt);color:var(--bg);border-color:var(--txt)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.card{background:color-mix(in srgb, var(--panel) 94%, transparent);border:1px solid var(--line);
  border-radius:var(--radius);padding:16px;transition:transform .18s ease,border-color .18s ease;
  display:flex;flex-direction:column;gap:6px}
.card:hover{transform:translateY(-2px);border-color:color-mix(in srgb, var(--acc) 55%, var(--line))}
.card h3{font-size:17px;margin:0}
.card-top{display:flex;justify-content:space-between;gap:8px;align-items:center}
.badge{font-size:11px;border:1px solid var(--line);border-radius:999px;padding:2px 8px;color:var(--mut)}
.price{font-size:22px;font-weight:800}
.price s{font-size:14px;color:var(--mut);font-weight:500;margin-right:4px}
.card p{color:var(--mut);font-size:14px;margin:0 0 8px;flex:1}
.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.step{border-left:2px solid var(--acc);padding:4px 0 4px 14px}
.trust{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-top:18px}
.trust div{border:1px solid var(--line);border-radius:12px;padding:14px;background:color-mix(in srgb,var(--panel) 70%,transparent)}
details{border-bottom:1px solid var(--line);padding:12px 0}
summary{cursor:pointer;font-weight:600}
footer{margin:56px 0 40px;border-top:1px solid var(--line);padding-top:20px;color:var(--mut);font-size:14px}
.reveal{opacity:0;transform:translateY(14px);transition:opacity .5s ease,transform .5s ease}
.reveal.in{opacity:1;transform:none}
@media (max-width:820px){.hero-grid{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){
  html{scroll-behavior:auto}
  .reveal{opacity:1;transform:none;transition:none}
  .card{transition:none}
}
::view-transition-old(root),::view-transition-new(root){animation-duration:.25s}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header><div class="wrap nav">
  <div class="brand">RTA <span>/ agent tools</span></div>
  <nav class="nav-links" aria-label="Main">
    <a href="#products">Products</a>
    <a href="#how">How it works</a>
    <a href="#faq">FAQ</a>
    <button class="icon" id="theme" aria-label="Toggle theme" title="Toggle theme">◐</button>
    <a class="btn small" href="/scan">Scan free</a>
  </nav>
</div></header>

<main id="main">
<div class="wrap hero">
  <div class="hero-grid">
    <div>
      <div class="eyebrow"><span class="dot"></span><span id="live">checking service…</span></div>
      <h1>Your agent moves money.<br>Can you prove what it bought?</h1>
      <p class="lead">Scan any MCP server in 30 seconds. See the tools that can spend, write or delete —
      and whether anything stops them. Then fix it with a receipt, a limit or a kill switch.</p>
      <a class="btn" href="/scan">Scan free — no account</a>
      <a class="btn ghost" href="/plans">Fix it — from $19</a>
      <a class="btn ghost" href="https://mrpkk.github.io/nidhipati/audit-sample.html">See a sample audit</a>
      <div class="metrics">
        <span><b>Free</b> scan</span><span><b>$19</b> founding audit</span>
        <span><b>USDC</b> or card</span><span><b>Nothing found</b> — no fee</span>
      </div>
    </div>
    <div class="panel" aria-label="Live scan">
      <form class="scan-row" id="scanForm">
        <input type="url" id="scanUrl" placeholder="https://your-server.com/mcp" aria-label="MCP server URL" required>
        <button class="btn small" type="submit" id="scanBtn">Scan</button>
      </form>
      <div class="result" id="scanOut"><span class="muted">Paste your MCP URL — we list tools and find what can move money or state.</span></div>
    </div>
  </div>
</div>

<section class="wrap block" id="products">
  <h2>Start with a scan. Fix with a receipt.</h2>
  <p class="sub">One ladder: free scan → $19 audit → limits and receipts. Pay once, or once a year.</p>
  <div class="tabs" role="tablist" aria-label="Product groups">
    <button class="tab active" data-tab="all" role="tab" aria-selected="true">All</button>
    <button class="tab" data-tab="agent" role="tab" aria-selected="false">Agent tools</button>
    <button class="tab" data-tab="simple" role="tab" aria-selected="false">Simple tools</button>
  </div>
  <div class="grid" id="cards">
__CARDS__
  </div>
</section>

<section class="wrap block" id="proof">
  <h2>Check it before you pay</h2>
  <p class="sub">Everything below is verifiable in a browser or a terminal — no screenshots needed.</p>
  <div class="trust">
    <div><b>Live counters</b><br><span class="muted">Views, scans and paywall hits: <a href="/api/funnel">/api/funnel</a>
    — the same numbers we see.</span></div>
    <div><b>Ten free checks a day</b><br><span class="muted">The scan endpoint is the same one agents call:
    <code>curl -s -X POST https://attest.rta.lat/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'</code></span></div>
    <div><b>Verdict you can verify offline</b><br><span class="muted">Every paid verdict is Ed25519-signed:
    <a href="/verify-receipt">/verify-receipt</a> checks it without trusting us.</span></div>
    <div><b>Nothing found — no fee</b><br><span class="muted">Written rule, not a promise by email:
    <a href="/docs/scan">/docs/scan</a> and the audit scope on <a href="/plans">/plans</a>.</span></div>
  </div>
</section>

<section class="wrap block" id="how">
  <h2>How it works</h2>
  <p class="sub">No account for the scan. No subscription for annual products.</p>
  <div class="steps">
    <div class="step reveal"><b>1. Scan</b><br><span class="muted">Paste your MCP URL. We list tools and find what can move money or state.</span></div>
    <div class="step reveal"><b>2. See</b><br><span class="muted">Three findings with severity — no content stored, no prompts read.</span></div>
    <div class="step reveal"><b>3. Fix</b><br><span class="muted">Audit, mandate or kill switch. Files, tests and a runbook.</span></div>
  </div>
  <div class="trust">
    <div><b>Is my data safe?</b><br><span class="muted">Scan reads the public tool list only; we do not store prompts or content.</span></div>
    <div><b>What if you find nothing?</b><br><span class="muted">The audit is free. You keep the report saying so.</span></div>
    <div><b>What if I pay and get nothing?</b><br><span class="muted">Refund in USDC to the paying address, or card reversal.</span></div>
    <div><b>Why so cheap?</b><br><span class="muted">Founding price for the first 10 teams. <b>0 paying customers so far</b> — the report earns the first one.</span></div>
  </div>
</section>

<section class="wrap block" id="faq">
  <h2>Questions</h2>
  <details><summary>What is an MCP server?</summary><p class="muted">A standard way for an AI agent to call tools: search, databases, payments. If an agent can act, it goes through MCP.</p></details>
  <details><summary>Do I need an account?</summary><p class="muted">No. Scan is free and anonymous. Account is needed only for a paid audit, where we need your logs.</p></details>
  <details><summary>Which payments do you accept?</summary><p class="muted">Card via Nidhipati, or USDC on Base. Annual products — one payment, no subscription.</p></details>
  <details><summary>Can you work inside our infrastructure?</summary><p class="muted">Yes: private deployment, white-label receipts and a custom policy pack. Write to maxim.pkk@gmail.com.</p></details>
  <details><summary>Is this only for crypto agents?</summary><p class="muted">No. Any agent that calls paid APIs, writes data or sends messages has the same three questions.</p></details>
</section>

<div class="wrap"><footer>
<p>RTA tools: <a href="https://attest.rta.lat">attest</a> · <a href="https://karta.rta.lat">KARTA</a> ·
<a href="https://drift.rta.lat">drift</a> · <a href="https://nidhipati.ailegal.legal">Nidhipati</a> ·
<a href="https://pramana.ailegal.legal">PRAMANA</a></p>
<p>Contact: <a href="mailto:maxim.pkk@gmail.com">maxim.pkk@gmail.com</a></p>
</footer></div>
</main>

<script>
(() => {
  const $ = (s, r=document) => r.querySelector(s);
  // theme
  const saved = localStorage.getItem('rta-theme');
  if (saved) document.documentElement.dataset.theme = saved;
  $('#theme').addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    const apply = () => { document.documentElement.dataset.theme = next; localStorage.setItem('rta-theme', next); };
    if (document.startViewTransition) document.startViewTransition(apply); else apply();
  });
  // tabs
  const cards = [...document.querySelectorAll('#cards .card')];
  document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => { x.classList.remove('active'); x.setAttribute('aria-selected','false'); });
    t.classList.add('active'); t.setAttribute('aria-selected','true');
    const g = t.dataset.tab;
    const apply = () => cards.forEach(c => { c.hidden = !(g === 'all' || c.dataset.group === g); });
    if (document.startViewTransition) document.startViewTransition(apply); else apply();
  }));
  // live status
  fetch('/health').then(r => r.ok ? r.json() : Promise.reject()).then(d => {
    $('#live').textContent = 'service live · v' + (d.version || 'ok');
  }).catch(() => { $('#live').textContent = 'service status unknown'; });
  // scan
  const out = $('#scanOut'), form = $('#scanForm'), btn = $('#scanBtn');
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const url = $('#scanUrl').value.trim();
    if (!url) return;
    btn.disabled = true; btn.textContent = 'Scanning…';
    out.innerHTML = '<span class="muted">Connecting…</span>';
    try {
      const r = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url})});
      const d = await r.json();
      if (!r.ok) { out.innerHTML = '<span style="color:var(--bad)">' + (d.error || 'scan failed') + '</span>'; return; }
      out.innerHTML = '<div class="stats">Tools: ' + d.tools + ' · annotated: ' + d.annotated + ' · risk ' + d.score + '/100 — ' + d.verdict + '</div>' +
        d.findings.map(f => '<div class="finding ' + f.severity + '"><b>' + f.title + '</b><div class="muted">' + f.detail + '</div></div>').join('');
    } catch (err) {
      out.innerHTML = '<span style="color:var(--bad)">network error</span>';
    } finally { btn.disabled = false; btn.textContent = 'Scan'; }
  });
  // reveal
  const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }), {threshold:.15});
  document.querySelectorAll('.reveal').forEach(el => io.observe(el));
})();
</script>
<script type="application/ld+json">__LD__</script>
</body></html>"""
    return html.replace("__CARDS__", cards).replace("__LD__", json.dumps(ld, ensure_ascii=False))
