"""Страница EU AI Act Evidence (29.10.2026). __PAY_TO__ подставляется сервисом."""

EU_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EU AI Act evidence pack — audit log, deny log, oversight, model card</title>
<meta name="description" content="Evidence pack for the EU AI Act: signed audit log, deny log, human oversight record, model card, risk assessment and data-flow map. From $1,500, express 72 hours.">
<link rel="canonical" href="https://attest.rta.lat/eu-ai-act-evidence">
<style>
 body{margin:0;background:#0b0d10;color:#e6e6e6;font:16px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
 main{max-width:820px;margin:0 auto;padding:42px 20px 80px}
 h1{font-size:34px;line-height:1.15;margin:0 0 12px;letter-spacing:-.02em}
 h2{font-size:21px;margin:34px 0 10px}
 p{margin:0 0 15px} a{color:#7fd1b9}
 .lead{font-size:18px;color:#a9b4c0}
 code{background:#171b21;padding:2px 5px;border-radius:4px;font-size:.9em;font-family:ui-monospace,Menlo,monospace}
 table{border-collapse:collapse;width:100%;font-size:14.5px;margin:0 0 18px}
 th,td{border:1px solid #232a33;padding:8px 11px;text-align:left;vertical-align:top}
 th{background:#141920}
 .grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));margin:18px 0}
 .card{border:1px solid #232a33;border-radius:12px;padding:18px;background:#10141a}
 .card b{font-size:26px;color:#7fd1b9;display:block}
 .btn{display:inline-block;margin-top:12px;padding:12px 20px;border-radius:9px;background:#7fd1b9;color:#062018;font-weight:700;text-decoration:none}
 .pay{border:1px solid #232a33;border-radius:12px;padding:18px;background:#10141a;margin:20px 0}
 .addr{font:14px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;background:#0b0d10;border:1px solid #30363d;border-radius:8px;padding:10px}
 .meta{color:#8b97a4;font-size:13.5px}
</style></head><body><main>
<h1>EU AI Act evidence pack</h1>
<p class="lead">Obligations become fully applicable on <strong>2 August 2026</strong>. When a buyer's
security team asks what your agent did, "we have a dashboard" is not an answer. This pack is the answer:
logs, refusals, oversight and data flow — in artifacts a third party verifies without trusting you.</p>

<h2>What the pack contains</h2>
<table>
<tr><th>Artifact</th><th>What it answers</th><th>Format</th></tr>
<tr><td><strong>Audit log</strong></td><td>Every decision, hash-chained, with the rule that fired</td><td>JSON + signed bundle</td></tr>
<tr><td><strong>Deny log (signed)</strong></td><td>What was refused, by which policy, why — the part auditors ask for</td><td>Ed25519 chain, offline-verifiable</td></tr>
<tr><td><strong>Human oversight record</strong></td><td>Where a human approved, reversed or stopped an action</td><td>Log export + policy</td></tr>
<tr><td><strong>Model card</strong></td><td>Which model, version, purpose, known limits, fallbacks</td><td>Markdown/PDF</td></tr>
<tr><td><strong>Risk assessment</strong></td><td>Intended use, misuse, blast radius, mitigations, residual risk</td><td>Markdown/PDF</td></tr>
<tr><td><strong>Data-flow map</strong></td><td>What leaves the system, to which subprocessor, for how long</td><td>Table + diagram</td></tr>
</table>

<p>Example of the deny artifact: <a href="/deny-evidence">attest.rta.lat/deny-evidence</a> —
“1,509 rows, zero denials” is the failure it prevents.</p>

<h2>Prices and deadlines</h2>
<div class="grid">
<div class="card"><b>$1,500</b>Base pack · 5 business days
<p class="meta">All six artifacts for one agent workflow, one jurisdiction assumption, one revision round.</p></div>
<div class="card"><b>$3,000</b>Express · 72 hours
<p class="meta">Same scope, priority queue, daily checkpoint calls, delivery within 72 hours of intake.</p></div>
</div>

<div class="pay">
<h2 style="margin-top:0">Pay in USDC (Base)</h2>
<p>Send the exact amount and email the transaction hash to
<a href="mailto:maxim.pkk@gmail.com?subject=EU%20AI%20Act%20evidence%20pack">maxim.pkk@gmail.com</a>
with the subject “EU AI Act evidence pack”. We reply within one business day with the intake form
(one agent, one workflow, current logs).</p>
<p class="addr">__PAY_TO__</p>
<p class="meta">Network: Base only · asset: USDC. No card, no account. Invoice available on request.
Not legal advice: the pack documents controls; a lawyer signs the legal position.</p>
</div>

<h2>What it does not claim</h2>
<ul>
<li>No certification, no notified-body approval, no legal opinion.</li>
<li>No guarantee that a regulator accepts the format.</li>
<li>If your logs cannot support a claim, the pack says so instead of inventing it.</li>
</ul>

<h2>Sample</h2>
<p><a href="/eu-ai-act-evidence/sample.pdf">Download the 4-page sample (PDF)</a> — built from our own
artifacts, with a signed deny record and an offline verification command.</p>

<p class="meta"><a href="/">attest</a> · <a href="/deny-evidence">deny evidence</a> ·
<a href="/docs">docs</a> · <a href="/pricing">pricing</a></p>
</main></body></html>"""
