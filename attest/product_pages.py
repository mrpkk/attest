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
 input[type=file]{width:100%;box-sizing:border-box;background:#0b0d10;border:1px solid #30363d;border-radius:8px;color:#e6e6e6;padding:9px;margin:6px 0;font-size:14px}
 textarea{width:100%;box-sizing:border-box;background:#0b0d10;border:1px solid #30363d;border-radius:8px;color:#e6e6e6;padding:11px;margin:6px 0;font-size:13px;font-family:ui-monospace,Menlo,monospace;min-height:110px;resize:vertical}
 label{display:block;font-size:13.5px;color:#a9b4c0;margin-top:8px}
 .row{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
 details{border:1px solid #232a33;border-radius:10px;padding:12px 14px;margin:0 0 10px;background:#10141a}
 summary{cursor:pointer;font-weight:600}
 .out{margin-top:10px;font-size:14px;white-space:pre-line}
 @media(max-width:520px){h1{font-size:26px} main{padding:22px 15px 60px} .lead{font-size:16px}}
"""


def _shell(title: str, description: str, canonical: str, body: str,
           jsonld: str = "") -> str:
    url = f"https://attest.rta.lat{canonical}"
    ld = f'\n<script type="application/ld+json">{jsonld}</script>' if jsonld else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<link rel="canonical" href="{url}">
<meta property="og:type" content="website">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{description}">
<meta property="og:url" content="{url}">
<meta name="twitter:card" content="summary">
<style>{BASE_CSS}</style>{ld}</head><body><main>{body}</main></body></html>"""


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


POP_INTAKE_FORM = """
<h2>Free self-serve build</h2>
<p>This free JSON build is separate from the $300 order above; use it to see what the report contains before paying.</p>
<p>Upload one ZIP, describe the site and the date. The builder unpacks it, reads EXIF, compares the
place and the time with your claim and signs the report. The download link expires after 24 hours; stored files are purged on the next intake.</p>
<form class="pay" id="pop-form">
 <label for="zip">Photos — one ZIP, up to 25 MB, 200 files, JPEG/PNG/HEIC</label>
 <input id="zip" type="file" accept=".zip,application/zip">
 <label for="ref">Object — site, parcel or building</label>
 <input id="ref" type="text" placeholder="Plot 14, Rotterdam port" autocomplete="off">
 <label for="what">What should the report confirm?</label>
 <input id="what" type="text" placeholder="40 ha solar farm, operational since May" autocomplete="off">
 <div class="row">
  <label for="lat">Latitude<input id="lat" type="text" placeholder="52.123456" autocomplete="off"></label>
  <label for="lon">Longitude<input id="lon" type="text" placeholder="4.654321" autocomplete="off"></label>
  <label for="when">Captured at, UTC<input id="when" type="text" placeholder="2026-11-02T11:20:00Z" autocomplete="off"></label>
 </div>
 <button class="btn" id="build" type="button">Build report</button>
 <div class="out" id="pop-out"></div>
 <p class="meta">The payment step is not connected yet, so this build is free while we finish it.
Nothing is stored about you: the ZIP is unpacked in a temporary folder and removed after the report is built.</p>
</form>
<script>
document.getElementById('build').onclick = async () => {
  const out = document.getElementById('pop-out');
  const file = document.getElementById('zip').files[0];
  if (!file) { out.textContent = 'Choose a ZIP with the photos first.'; return; }
  const claim = {
    subject: {type: 'site', ref: document.getElementById('ref').value.trim()},
    claim: document.getElementById('what').value.trim(),
    captured_at: document.getElementById('when').value.trim(),
  };
  const lat = document.getElementById('lat').value.trim();
  const lon = document.getElementById('lon').value.trim();
  if (lat || lon) claim.location = {lat: lat, lon: lon};
  const form = new FormData();
  form.append('zip', file);
  form.append('claim', JSON.stringify(claim));
  out.textContent = 'Building the report — this can take a few seconds.';
  const r = await fetch('/api/proof-of-place/build', {method: 'POST', body: form});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { out.textContent = 'Not built: ' + (j.error || ('HTTP ' + r.status)); return; }
  out.textContent = 'Verdict: ' + j.verdict + ' · ' + j.files + ' file(s) · report ' + j.report_id;
  const link = document.createElement('a');
  link.href = j.download_url;
  link.textContent = 'Download report.json';
  const line = document.createElement('div');
  line.append(link, ' — link expires in ' + j.expires_in_hours + ' hours; stored files are purged on the next intake.');
  out.append(line);
};
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

<p><a href="/scan?ref=mcp_security">Scan an MCP server first</a> — 30 seconds, no account. The scan lists tools that can move money or state and flags hidden instructions; the audit goes deeper on what it finds.</p>
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


PROOF_OF_PLACE_BODY = """
<h1>Prove where the work actually happened, not where the report says</h1>
<p class="lead">A photo, a place, a time. We check what can be checked, name what cannot, and hand you
an artifact a buyer or an insurer can open without trusting the sender.</p>

<div class="grid">
 <div class="card"><b>$300</b>Report on your photos
  <p class="meta">You send photos; we return an evidence report with the layers we could verify and the gaps we found.</p></div>
 <div class="card"><b>Not yet</b>Independent capture
  <p class="meta">We do not yet have a vetted operator network, so we do not sell this tier.
  The report says plainly what your own photos can and cannot prove.</p></div>
 <div class="card"><b>$99/mo</b>Stream
  <p class="meta">Continuous checks on one site: new photos, new dates, new gaps. Cancel by not paying.</p></div>
</div>
<ul class="trust">
 <li>No account needed</li>
 <li>Payment is separate from the free build below</li>
 <li>Every layer in the report says how it was checked</li>
</ul>
__PAY__
__INTAKE__

<h2>Proof layers, weakest to strongest</h2>
<table>
<tr><th>Layer</th><th>What we check</th><th>What it can still miss</th></tr>
<tr><td><strong>File integrity</strong></td><td>SHA-256 of each file; EXIF presence</td><td>A photo taken elsewhere and re-wrapped; edits and re-saves are not detected</td></tr>
<tr><td><strong>Time</strong></td><td>Capture time against the claim</td><td>Wrong device clock; frame sequence is not cross-checked</td></tr>
<tr><td><strong>Place, declared</strong></td><td>GPS and EXIF coordinates cross-checked against the described site</td><td><strong>GPS can be spoofed</strong> — this is not proof on its own</td></tr>
<tr><td><strong>Place, visual</strong></td><td><strong>Not yet</strong> — landmark, skyline and satellite checks are not implemented in this build</td><td>A convincing reconstruction; satellite imagery sees only the top</td></tr>
<tr><td><strong>Independent capture</strong></td><td>A local operator we hire takes the photos</td><td>Only as good as the operator's honesty — the highest tier we sell</td></tr>
</table>

<h2>What this is not</h2>
<ul>
<li><strong>Not proof of ownership.</strong> We confirm that a place matches a description; who owns it is a registry question, not a photo question.</li>
<li><strong>GPS coordinates are forgeable</strong> by design. We say so in every report and never sell metadata as proof.</li>
<li><strong>Satellites look from above</strong>: a roof, a yard, an empty field. Interiors, basements and what happens under a canopy are outside their view.</li>
<li>Not a legal opinion and not a valuator's appraisal. If a dispute reaches a court, the report is evidence to argue about, not a verdict.</li>
<li>If the layers disagree, the report states the disagreement. We do not average it into a score.</li>
</ul>

<h2>Questions</h2>
<details><summary>What do you need from me for the $300 report?</summary>
 <p>The original files (not screenshots), the address or site as you describe it, the date you claim, and
 what decision the report is for. Ten to thirty photos are enough for one site.</p></details>
<details><summary>Why does independent capture cost more?</summary>
 <p>It is not available yet: we have not vetted an operator network, and selling a capture we cannot
 deliver would be a promise without a product. When it opens, the price will be one number, not a range.</p></details>
<details><summary>What if the photos do not support the claim?</summary>
 <p>The report says so, with the reason per layer. That is the product: a report that can also come back
 negative is the only one worth paying for.</p></details>
__TRAILER__
"""

TRUST_DESK_BODY = """
<h1>Prove what your agent did, refused and was allowed to spend</h1>
<p class="lead">One pilot, three artifacts: an artifact verdict, a mandate with limits, and a deny journal.
A buyer's security team can check all three without trusting your dashboard.</p>

<div class="grid">
 <div class="card"><b>$1,500</b>Pilot · 10 business days
  <p class="meta">One agent workflow, three artifacts, one revision round. Then $299/month if you keep it running.</p></div>
 <div class="card"><b>$299/mo</b>After the pilot
  <p class="meta">Same three artifacts on live traffic, no long-term commitment, no auto-renewal.</p></div>
</div>
<ul class="trust">
 <li>No account needed</li>
 <li>Payment checked on-chain before intake</li>
 <li>Each artifact verifies offline with the key we publish</li>
</ul>
__PAY__

<h2>What the pilot contains</h2>
<table>
<tr><th>Artifact</th><th>What it answers</th></tr>
<tr><td><strong>Artifact verdict</strong></td><td>Four layers on a real artifact from your pipeline: schema, emptiness, provenance, authority. Verdict and reasons, not a score.</td></tr>
<tr><td><strong>Mandate and limits</strong></td><td>What the agent may do, to whom, up to what amount, until when — as a signed record that a refusal can be checked against.</td></tr>
<tr><td><strong>Deny journal</strong></td><td>Every refusal: who asked, which policy fired, why, with a hash chain and an offline verification command.</td></tr>
</table>
<p class="meta">Delivered as files (JSON + a one-page verdict) plus the verification commands.
Acceptance is not our word: you run them.</p>

<h2>What this is not</h2>
<ul>
<li>Not a penetration test of your infrastructure and not a certification.</li>
<li>Not legal advice; if a regulator asks for a legal position, a lawyer signs it.</li>
<li>It does not prove that no other log exists — only that the log you show was not altered after issue.</li>
<li>If your logs cannot support a claim, the artifact says so. We do not fill gaps with wording.</li>
</ul>

<h2>Questions</h2>
<details><summary>How do we start?</summary>
 <p>Pay in USDC on Base, paste the transaction hash here. You get the intake form the same day:
 one agent workflow, current logs, and the system prompt or policy you want covered.</p></details>
<details><summary>What do we need from you?</summary>
 <p>Read access to a sample of artifacts and logs from one workflow, and the policy that decides allow/deny.
 No production access and no customer data are required for the pilot.</p></details>
<details><summary>What if the artifacts are not delivered?</summary>
 <p>Undelivered work is refunded in USDC to the paying address. Delivered work is not refunded; one revision
 round exists so the format, not the facts, can be corrected.</p></details>
__TRAILER__
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


def proof_of_place_page(pay_to: str) -> str:
    pay = _pay_block("$300 report / independent capture not yet available / $99 per month", "/api/proof-of-place/order",
                     pay_to,
                     extra_fields=('<input id="email" type="email" data-field="email" '
                                   'placeholder="email for the intake form (optional)">'))
    body = PROOF_OF_PLACE_BODY.replace("__PAY__", pay).replace(
        "__INTAKE__", POP_INTAKE_FORM).replace(
        "__TRAILER__",
        '<p class="meta"><a href="/">attest</a> · <a href="/trust-desk">Agent Trust Desk</a> · '
        '<a href="/deny-evidence">deny evidence</a> · '
        '<a href="mailto:maxim.pkk@gmail.com?subject=Proof%20of%20Place">maxim.pkk@gmail.com</a></p>')
    return _shell("Proof of Place — where and when the work actually happened",
                  "Photo evidence report: file integrity, time, declared place, visual place, independent "
                  "capture. $300 report, independent capture not yet available, $99/month stream. USDC on Base.",
                  "/proof-of-place", body)


def trust_desk_page(pay_to: str) -> str:
    pay = _pay_block("$1,500 pilot / $299 per month after", "/api/trust-desk/order", pay_to,
                     extra_fields=('<input id="email" type="email" data-field="email" '
                                   'placeholder="email for the intake form (optional)">'))
    body = TRUST_DESK_BODY.replace("__PAY__", pay).replace(
        "__TRAILER__",
        '<p class="meta"><a href="/">attest</a> · <a href="/deny-evidence">deny evidence</a> · '
        '<a href="/mcp-security">MCP Security Pass</a> · <a href="/eu-ai-act">EU AI Act evidence pack</a> · '
        '<a href="mailto:maxim.pkk@gmail.com?subject=Agent%20Trust%20Desk">maxim.pkk@gmail.com</a></p>')
    return _shell("Agent Trust Desk — an agent you can put in front of a buyer",
                  "Pilot $1,500: artifact verification, mandate with limits, deny journal. Three artifacts "
                  "a buyer's security team can verify offline. $299/month after the pilot. USDC on Base.",
                  "/trust-desk", body)


def mcp_security_page(pay_to: str) -> str:
    pay = _pay_block("$500 audit / $1,500 with fixes", "/api/mcp-security/order", pay_to,
                     extra_fields=('<input id="server" type="text" data-field="server_url" '
                                   'placeholder="MCP server URL or repository (optional)">'))
    return _shell("MCP Security Pass — OWASP MCP Top 10 audit for one server",
                  "MCP security audit for one server: OWASP MCP Top 10 checks, findings with severity, "
                  "concrete patches and a re-check. $500 audit, $1,500 with fixes. USDC on Base, no account.",
                  "/mcp-security", MCP_SECURITY_BODY.replace("__PAY__", pay))


FREE_SCAN_SCHEMA = """<script type="application/ld+json">
{"@context":"https://schema.org","@type":"Service",
 "name":"Free agent spend scan",
 "description":"Send one CSV of an AI agent's spend log; a human replies within one business day with what the file shows and what it cannot.",
 "provider":{"@type":"Organization","name":"attest","url":"https://attest.rta.lat"},
 "areaServed":"Worldwide",
 "offers":{"@type":"Offer","price":"0","priceCurrency":"USD",
  "availability":"https://schema.org/InStock","url":"https://attest.rta.lat/free-scan"},
 "isRelatedTo":{"@type":"Service","name":"Agent spend audit",
  "offers":{"@type":"Offer","price":"199","priceCurrency":"USD",
            "url":"https://attest.rta.lat/plans#audit"}}}
</script>"""

FREE_SCAN_BODY = """
<h1>Send one CSV, see where your agent's money went</h1>
<p class="lead">A free scan of one spend log: a human reads the file and replies within one business day
with what it shows, what it cannot show, and whether a $199 audit would find anything more.
No GitHub, no account, no card.</p>

<!-- Воронка: после скана человек видит следующий шаг здесь же, а не ищет его сам.
     Нажатие отмечается маячком — без этого «free scan → аудит» измерить нечем. -->
<div class="box" id="after-scan">
<h3>After the scan</h3>
<p>If the file shows money that left without a reason, the next step is the audit: one month of logs,
five working days, a written report where every finding is tied to a row and a rule. $199 flat,
nothing found — no fee.</p>
<p><a id="audit-cta" class="btn" href="/plans#audit"
 onclick="try{navigator.sendBeacon('/api/audit-intent')}catch(e){}">See the $199 audit</a>
 <a class="btn" href="https://nidhipati.ailegal.legal/pay/card?product=agent-spend-audit"
 onclick="try{navigator.sendBeacon('/api/audit-intent')}catch(e){}">Pay by card — $199</a></p>
</div>

<h2>What file to send</h2>
<p>A CSV export of what your agent spent — from your billing dashboard, your wallet indexer,
or a table you keep by hand. One row per transaction.</p>
<table>
<tr><th>Column</th><th>What we read from it</th></tr>
<tr><td><code>date</code></td><td>When the spend happened (any common format)</td></tr>
<tr><td><code>amount</code></td><td>How much left the account</td></tr>
<tr><td><code>asset</code></td><td>USDC, ETH, a token, a card charge</td></tr>
<tr><td><code>payee</code></td><td>Who received it</td></tr>
<tr><td><code>tx_hash</code></td><td>The transaction, if there is one</td></tr>
</table>
<p class="meta">No file at hand? <a download="sample-spend.csv" href="data:text/csv;charset=utf-8,date%2Camount%2Casset%2Cpayee%2Ctx_hash%0A2026-11-01%2C0.42%2CUSDC%2Capi.vendor.example%2C0xaa11%0A2026-11-01%2C0.42%2CUSDC%2Capi.vendor.example%2C0xaa11%0A2026-11-02%2C1.10%2CUSDC%2Csearch.provider.example%2C0xbb22%0A2026-11-03%2C0.00%2CUSDC%2Cfailed.vendor.example%2Cfailed">Download a synthetic sample (4 rows, including one duplicate)</a> — it shows the format, nothing of ours.</p>
<p class="meta">These are the columns that make the scan cheap, not a requirement: a file without them
is still read, and the reply says what could not be checked. Up to 200 KB, header row included.
Nothing about your file is published; it is read for this scan and kept private.</p>

<form class="pay" id="scan-form">
 <label for="email">Email for the reply</label>
 <input id="email" type="email" placeholder="you@company.com" autocomplete="email">
 <label for="csvfile">Spend log — CSV, up to 200 KB</label>
 <input id="csvfile" type="file" accept=".csv,text/csv,text/plain">
 <label for="csv">…or paste the CSV here</label>
 <textarea id="csv" placeholder="date,amount,asset,payee,tx_hash&#10;2026-11-01,0.42,USDC,api.vendor.example,0x…"></textarea>
 <label for="note">What should the scan look for? (optional, one line)</label>
 <input id="note" type="text" placeholder="e.g. whether the agent pays the same vendor twice">
 <button class="btn" id="send" type="button">Request free scan</button>
 <div class="out" id="scan-out"></div>
 <p class="meta">The reply is written by a person, not generated per request, so it never claims to be
an automated report. If the file is too thin to say anything useful, the reply says that too.
<a href="/docs/scan?ref=scan-page">What exactly is checked, the limits, and what the scan does not do</a>.</p>
</form>
<script>
document.getElementById('csvfile').onchange = () => {
  const file = document.getElementById('csvfile').files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => { document.getElementById('csv').value = String(reader.result || ''); };
  reader.readAsText(file);
};
document.getElementById('send').onclick = async () => {
  const out = document.getElementById('scan-out');
  const body = {
    email: document.getElementById('email').value.trim(),
    csv: document.getElementById('csv').value,
    note: document.getElementById('note').value.trim(),
  };
  if (!body.email) { out.textContent = 'An email is needed for the reply.'; return; }
  if (!body.csv.trim()) { out.textContent = 'Attach the CSV or paste it first.'; return; }
  out.textContent = 'Sending…';
  const r = await fetch('/api/free-scan', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { out.textContent = 'Not accepted: ' + (j.error || ('HTTP ' + r.status)); return; }
  // Что уже прочитано — показываем сразу. Раньше страница отдавала только
  // «заявка принята», и человек уходил, не зная, что файл вообще разобрали.
  const cols = (j.columns || []).join(', ') || '—';
  const lines = [
    'Read: ' + (j.rows || 0) + ' rows · columns: ' + cols,
    (j.missing && j.missing.length) ? 'Not named in the header: ' + j.missing.join(', ') : 'Header looks complete.',
    j.message,
    'Request id: ' + j.request_id,
  ];
  out.textContent = lines.join('\\n');
  document.getElementById('scan-form').style.display = 'none';
};
</script>

<h2>What the free scan is not</h2>
<ul>
<li>Not a signed report and not the $199 audit: no per-finding evidence lines, no revision round.</li>
<li>Not an automated verdict. A person reads the file; that is why the reply takes up to a business day.</li>
<li>Not a place to send secrets. Strip API keys from the CSV — the scan needs amounts, not credentials.</li>
</ul>

<h2>After the scan</h2>
<p>If the file shows something worth a written report — duplicate payments, spend nobody approved,
a vendor the agent invented — the audit is the next step: one month of logs, five working days,
one line of evidence per finding, nothing found means no fee. <a href="/plans">Prices and scope</a>.</p>
<p><a href="/sample-audit">See a six-page synthetic sample of the audit</a>.</p>
"""


def free_scan_page() -> str:
    # Разметку кладём в начало тела: _shell отвечает за <head>, но JSON-LD
    # валиден и в теле, а поисковики читают его откуда угодно.
    return _shell("Free agent spend scan — send one CSV, no GitHub",
                  "Free scan of an AI agent's spend log: send a CSV by email, get a written reply "
                  "within one business day. No GitHub, no account, no card.",
                  "/free-scan", FREE_SCAN_SCHEMA + FREE_SCAN_BODY)



SAMPLE_AUDIT_BODY = """
<style>
 .audit{max-width:860px;margin:0 auto}
 .page{border:1px solid #232a33;border-radius:12px;padding:24px;margin:18px 0;background:#10141a}
 .kicker{letter-spacing:.14em;text-transform:uppercase;color:#7fd1b9;font-size:12px}
 .page h1{font-size:30px;margin:8px 0 10px} .page h2{font-size:22px;margin:0 0 10px}
 .page h3{font-size:17px;margin:18px 0 6px} .page p{color:#c3cad4}
 .page table{border-collapse:collapse;width:100%;font-size:13.5px;margin:10px 0}
 .page th,.page td{border:1px solid #2a3140;padding:7px 9px;text-align:left;vertical-align:top}
 .page th{background:#171c24;color:#e8ecf4}
 .note{color:#8b939f;font-size:13px} .ok{color:#9ff0cf} .warn{color:#ffd38a} .err{color:#ffb4b4}
 .grid2{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
 .box{border:1px solid #2a3140;border-radius:9px;padding:12px;background:#0d1117}
 @media print{.page{break-after:page;border:0;margin:0;padding:18mm 12mm}}
</style>
<div class="audit">
<section class="page">
 <div class="kicker">Synthetic sample · not a client · method real</div>
 <h1>Agent spend audit</h1>
 <p>This is a six-page sample of the written report. The export is a synthetic 44-row file with three agents; the findings are reproducible from the same CSV, but no client, company or real payment is shown.</p>
 <h2>Scope</h2>
 <table>
  <tr><th>Item</th><th>Value</th></tr>
  <tr><td>Period</td><td>one synthetic month</td></tr>
  <tr><td>Rows read</td><td>44</td></tr>
  <tr><td>Agents</td><td>agent-writer, agent-loop, agent-buyer</td></tr>
  <tr><td>Rail</td><td>USDC on Base (synthetic)</td></tr>
  <tr><td>What was checked</td><td>amount vs quote, duplicates, failed-but-billed, refunds, policy limits, asset/network/payee, loops</td></tr>
 </table>
 <p class="note">A real audit starts from your export and your own policy. This sample shows the shape and the level of evidence, not your numbers.</p>
</section>

<section class="page">
 <div class="kicker">Page 2 · summary</div>
 <h2>What the file shows</h2>
 <table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Rows read</td><td>44</td></tr>
  <tr><td>Settled</td><td>$0.661</td></tr>
  <tr><td>Spent without a recorded reason</td><td>$0.14</td></tr>
  <tr><td>Above the usual price</td><td>$0.36</td></tr>
  <tr><td>Over the policy limit</td><td>$0</td></tr>
  <tr><td>Errors / warnings</td><td>4 / 7</td></tr>
 </table>
 <p>The three amounts are deliberately separate. Adding them into one “saved” figure would double-count overlapping findings and make the report useless for finance.</p>
 <div class="box"><b>Verdict:</b> the file is <span class="warn">not clean</span>. Four findings need an answer before the next payment run; seven warnings are controls, not losses.</div>
</section>

<section class="page">
 <div class="kicker">Page 3 · errors</div>
 <h2>Findings that need an answer</h2>
 <table>
  <tr><th>Row</th><th>Code</th><th>Agent</th><th>$</th><th>Detail</th><th>Evidence</th></tr>
  <tr><td>5</td><td><code>duplicate_charge</code></td><td>agent-writer</td><td>0.02</td><td>same tx_hash as row 2</td><td>0xaaa1</td></tr>
  <tr><td>7</td><td><code>price_escalation</code></td><td>agent-writer</td><td>0.03</td><td>settled 0.05 above quote 0.02</td><td>0xaaa5</td></tr>
  <tr><td>8</td><td><code>failed_but_billed</code></td><td>agent-writer</td><td>0.03</td><td>status “failed” with 0.03 charged</td><td>0xaaa6</td></tr>
  <tr><td>9</td><td><code>missing_refund</code></td><td>agent-writer</td><td>0.06</td><td>charged 0.10 for actual 0.04; refund not recorded</td><td>0xaaa7</td></tr>
 </table>
 <p class="note">Each row is tied to a rule and a row number. The auditor can open the export and reproduce every line.</p>
</section>

<section class="page">
 <div class="kicker">Page 4 · warnings and controls</div>
 <h2>What is missing, not what is stolen</h2>
 <table>
  <tr><th>Row</th><th>Code</th><th>Agent</th><th>$</th><th>Detail</th></tr>
  <tr><td>0</td><td><code>budget_bypass</code></td><td>—</td><td>0</td><td>no policy file: any budget lives in a prompt, which the agent can argue with</td></tr>
  <tr><td>9</td><td><code>model_overpay</code></td><td>agent-writer</td><td>0.08</td><td>paid 0.10 against a median 0.02 for this tool and model</td></tr>
  <tr><td>10</td><td><code>unknown_asset</code></td><td>agent-writer</td><td>0.02</td><td>asset “MOON” is not recognised</td></tr>
  <tr><td>10</td><td><code>unknown_network</code></td><td>agent-writer</td><td>0.02</td><td>network “moonnet” is not recognised</td></tr>
  <tr><td>10</td><td><code>missing_payee</code></td><td>agent-writer</td><td>0.02</td><td>no payee recorded</td></tr>
  <tr><td>14</td><td><code>model_overpay</code></td><td>agent-writer</td><td>0.28</td><td>paid 0.30 against a median 0.02</td></tr>
  <tr><td>45</td><td><code>runaway_loop</code></td><td>agent-loop</td><td>0</td><td>31 calls in 60s (threshold 30)</td></tr>
 </table>
</section>

<section class="page">
 <div class="kicker">Page 5 · limits</div>
 <h2>What this report proves — and what it does not</h2>
 <div class="grid2">
  <div class="box"><h3 class="ok">Proves</h3><p>Each finding is tied to a row and a rule; the same input gives the same output; missing prices and unknown assets are reported, not guessed; the three amounts stay separate.</p></div>
  <div class="box"><h3 class="err">Does not prove</h3><p>It is not a statutory audit, not a legal claim and not a recovery. On-chain verification is not included. Missing rows cannot be found. Confirm every finding against the provider invoice before acting.</p></div>
 </div>
 <h3>Privacy</h3>
 <p>Send the minimum needed: amounts, dates, assets, payees and transaction hashes. Remove API keys, prompts, customer names and anything you would not put in a finance ticket.</p>
</section>

<section class="page">
 <div class="kicker">Page 6 · order</div>
 <h2>One month of logs. Five working days. $199.</h2>
 <p>Send a CSV export, one line about the agents and the policy you expected. You get a written PDF, a JSON file with the same findings, and a signed verdict you can check offline. If the file shows nothing, there is no fee.</p>
 <p><a class="btn" href="https://nidhipati.ailegal.legal/pay/card?product=agent-spend-audit">Pay by card — $199</a>
 <a class="btn" href="/free-scan">First, run the free scan</a>
 <a class="btn" href="/plans">Prices and scope</a></p>
 <p class="note">This sample is synthetic: it exists to show the report, not to claim a client result. The audit is not KYC, not a statutory audit and not a guarantee of recovery.</p>
</section>
</div>
"""


def sample_audit_page() -> str:
    return _shell("Agent spend audit — six-page synthetic sample",
                  "A six-page synthetic sample of an AI-agent spend audit: summary, findings, "
                  "limits and what the $199 report contains. Not a client result.",
                  "/sample-audit", SAMPLE_AUDIT_BODY)


SCAN_DOCS_BODY = """
<h1>How the free scan works</h1>
<p class="lead">One CSV of what your agent spent, read by a person, answered within one business day.
This page says exactly what is checked, what the limits are, and what the scan will not do — so you
can decide before you send anything.</p>

<h2>What is checked</h2>
<table>
<tr><th>Check</th><th>What it means</th></tr>
__CHECK_ROWS__
</table>
<p>Every item above is read by a person on your file. The tool parses rows and columns and counts them;
the checks themselves are not an automated verdict, and there is no score.</p>

<h2>Limits, exactly</h2>
<p><b>Free limit: __FREE_LIMIT__ scans per day per client.</b> Counted from the first call of the day (UTC).</p>
<ul>
<li>One file, up to <b>200 KB</b>, header row included.</li>
<li>One file per request; asks for more than that are read in turn, not in parallel.</li>
<li>Reply within <b>one business day</b> — a person reads it, so it does not arrive in seconds.</li>
<li>The reply says what could not be checked. Missing columns are named, not guessed.</li>
<li>No account, no GitHub access, no card. Nothing from your file is published.</li>
</ul>

<h2>Example of what a reply looks like</h2>
<pre><code>Read: 4 rows, columns: date,amount,asset,payee,tx_hash
Found: 1 duplicate (0.42 USDC to api.vendor.example, same day, two hashes present)
Cannot say: whether the second call was a retry — the log has no status column
Next: with a month of rows and statuses, the $199 audit can tie each finding to a row.</code></pre>
<p class="meta">This is a synthetic example, not a customer file. It shows the shape of an answer:
what was read, what was found, what is unknown, and what would make the answer better.</p>

<h2>What the scan does not do</h2>
<ul>
<li><b>Not an automated verdict.</b> There is no score, no pass/fail badge, no model deciding — a person reads the file.</li>
<li><b>Not the $199 audit.</b> No per-finding evidence lines, no revision round, no written report you can attach to a policy.</li>
<li><b>Not a security review.</b> Keys, permissions, contract logic and infrastructure are out of scope here.</li>
<li><b>Not financial or legal advice.</b> We say what the numbers show; what to do about it is your decision.</li>
<li><b>Not a place for secrets.</b> Strip API keys, tokens and personal data before sending. Amounts are what we need.</li>
</ul>

<h2>What happens after you send it</h2>
<table>
<tr><th>When</th><th>What you get</th></tr>
<tr><td>Same day</td><td>Confirmation that the file was read, with the row count and recognized columns.</td></tr>
<tr><td>Within one business day</td><td>Written reply: what was found, what could not be checked, and whether an audit would add anything.</td></tr>
<tr><td>If you want more</td><td>The $199 audit: one month of logs, five working days, one line of evidence per finding. Nothing found — no fee.</td></tr>
</table>

<div class="lang">
<h2>हिन्दी — सारांश</h2>
<p>यह मुफ़्त जाँच आपकी एजेंट की खर्च-लॉग फ़ाइल (CSV, <b>200 KB</b> तक) पढ़ती है और <b>6 जाँच</b> करती है:
डुप्लिकेट भुगतान, गलती के बाद भी कटा पैसा, कोटेशन बनाम भेजी गई रकम, न मिला रिफ़ंड, अनुमति-रहित
प्राप्तकर्ता, और लॉग में अंतराल। सीमा: प्रति दिन <b>__FREE_LIMIT__</b> जाँच, जवाब एक कार्यदिवस में।
यह ऑटोमैटिक फ़ैसला नहीं है — फ़ाइल इंसान पढ़ता है। भुगतान का सुरक्षा-ऑडिट या कानूनी सलाह नहीं।
गोपनीयता: API कुंजियाँ और निजी डेटा भेजने से पहले हटा दें।</p>
<h2>Русский — коротко</h2>
<p>Бесплатный скан читает файл расходов агента (CSV до <b>200 КБ</b>) и проверяет <b>6 пунктов</b>: дубли
оплат, списание при ошибке, обещанное против отправленного, невозвращённые возвраты, неутверждённые
получатели, провалы в логе. Лимит — <b>__FREE_LIMIT__</b> скана в сутки, ответ в течение рабочего дня.
Это не автоматический вердикт: файл читает человек. Это не аудит безопасности и не юридическая
консультация. Ключи и персональные данные перед отправкой удалите.</p>
</div>

<h2>How to send it</h2>
<p><a class="btn" href="/free-scan?ref=docs-scan">Open the free scan form</a>
 <a class="btn" href="/sample-audit?ref=docs-scan">See a six-page synthetic audit sample</a>
 <a class="btn" href="/plans?ref=docs-scan">The $199 audit — scope and price</a></p>
<p class="meta">Questions before sending a file: <a href="mailto:maxim.pkk@gmail.com?subject=attest%20free%20scan%20question">ask first</a>.
No file needed for that.</p>
"""


SCAN_FAQ = [
    ("What does the free scan actually check?",
     "Duplicates, failed-but-charged rows, quoted versus settled amounts, missing refunds, "
     "unapproved payees and gaps in the log. Each finding is described in words, not a score."),
    ("What are the limits?",
     "One CSV up to 200 KB, header row included. The reply arrives within one business day. "
     "Missing columns are named in the reply, not guessed."),
    ("Is the scan an automated verdict?",
     "No. A person reads the file and writes the reply. There is no score, no pass/fail badge "
     "and no model deciding."),
    ("Is this the $199 audit?",
     "No. The audit is one month of logs, five working days and a written report where every "
     "finding is tied to a row and a rule. The scan is the free first step."),
    ("What is out of scope?",
     "Keys, permissions, contract logic and infrastructure — that is a security review, "
     "not this scan. The scan also does not give financial or legal advice."),
]


def scan_faq_jsonld() -> str:
    import json as _json

    payload = {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [
            {"@type": "Question", "name": q,
             "acceptedAnswer": {"@type": "Answer", "text": a}}
            for q, a in SCAN_FAQ
        ],
    }
    return _json.dumps(payload, ensure_ascii=False)


def scan_docs_page(limit: int = 5) -> str:
    """Документация бесплатного скана: что проверяется, лимиты, чего не делает.

    Нужна потому, что «пришлите CSV» без описания границ — это просьба поверить
    на слово; здесь границы названы до отправки файла.
    """
    from .free_scan import CHECKS

    rows = "\n".join(f"<tr><td>{c['title']}</td><td>{c['means']}</td></tr>" for c in CHECKS)
    body = (SCAN_DOCS_BODY.replace("__FREE_LIMIT__", str(limit)).replace("__CHECK_ROWS__", rows))
    return _shell("Free scan — what is checked, limits, what it does not do",
                  "How the attest free spend scan works: checks, 200 KB and one business day limits, "
                  "a synthetic reply example, and what the scan explicitly does not do.",
                  "/docs/scan", body, jsonld=scan_faq_jsonld())
