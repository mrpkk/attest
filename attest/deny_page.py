"""Страница deny-evidence: продажа журнала отказов (29.10.2026)."""

DENY_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>1,509 rows, zero denials — Deny evidence for AI agents</title>
<meta name="description" content="A log where every row says allowed proves nothing. Deny evidence: a signed, append-only record of refusals — who asked, which policy, why. Ed25519, verifiable offline. $29/month.">
<link rel="canonical" href="https://attest.rta.lat/deny-evidence">
<style>
 body{margin:0;background:#0b0d10;color:#e6e6e6;font:16px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
 main{max-width:780px;margin:0 auto;padding:40px 20px 80px}
 h1{font-size:34px;line-height:1.15;margin:0 0 14px;letter-spacing:-.02em}
 h2{font-size:21px;margin:36px 0 10px}
 p{margin:0 0 15px} a{color:#7fd1b9}
 .lead{font-size:18px;color:#a9b4c0}
 code{background:#171b21;padding:2px 5px;border-radius:4px;font-size:.9em;font-family:ui-monospace,Menlo,monospace}
 pre{background:#12161c;border:1px solid #232a33;border-radius:8px;padding:13px 15px;overflow:auto}
 pre code{background:none;padding:0;font-size:13px;line-height:1.5}
 table{border-collapse:collapse;width:100%;font-size:14.5px;margin:0 0 18px}
 th,td{border:1px solid #232a33;padding:8px 11px;text-align:left;vertical-align:top}
 th{background:#141920}
 .price{border:1px solid #232a33;border-radius:12px;padding:20px;background:#10141a;margin:24px 0}
 .price b{font-size:30px;color:#7fd1b9}
 .btn{display:inline-block;margin-top:12px;padding:12px 20px;border-radius:9px;background:#7fd1b9;color:#062018;font-weight:700;text-decoration:none}
 .quote{border-left:3px solid #2b3440;padding:2px 0 2px 15px;color:#a9b4c0;margin:0 0 18px}
 .meta{color:#8b97a4;font-size:13.5px}
</style></head><body><main>
<h1>1,509 rows, zero denials</h1>
<p class="lead">That is the log one team showed their auditor. Every row said <em>allowed</em>.
The auditor asked the only question that matters: <strong>show me a refusal.</strong></p>

<p>A log without denials cannot prove that anything was ever stopped. It proves traffic, not control.
Deny evidence is the opposite artifact: every refusal, signed, chained, and readable by someone who
does not trust your dashboard.</p>

<blockquote class="quote">Illustration, not a customer case: a log where all 1,509 rows say <em>allowed</em>,
with no refusals, is the shape auditors distrust.<br>
<span class="meta">— constructed example, October 2026</span></blockquote>

<h2>What a deny record contains</h2>
<pre><code>{
  "v": 1,
  "prev": "&lt;sha256 of the previous record&gt;",
  "ts": "2026-10-29T09:14:02+00:00",
  "decision": "deny",
  "reason": "payee not in allowlist",
  "policy_id": "E03-allowlist",
  "task_id": "task_7f21",
  "artifact_hash": "sha256:9c1e…",
  "actor": "agent:research-1",
  "meta": {"requested_amount": "12.50", "allowed_max": "0.05"},
  "hash": "&lt;sha256 of this body&gt;",
  "signature": "&lt;Ed25519 signature&gt;",
  "public_key": "&lt;base64 key&gt;",
  "algorithm": "ed25519"
}</code></pre>

<h2>API in two calls</h2>
<pre><code># record a refusal
curl -X POST https://attest.rta.lat/deny \\
  -H 'content-type: application/json' \\
  -d '{"reason":"payee not in allowlist","policy_id":"E03-allowlist",
       "task_id":"task_7f21","artifact_hash":"sha256:9c1e","actor":"agent:research-1"}'

# read refusals since a moment
curl 'https://attest.rta.lat/deny?since=2026-10-29T00:00:00Z&limit=100'</code></pre>
<p class="meta">Full contract: <a href="https://attest.rta.lat/docs">attest.rta.lat/docs</a> · offline check:
<code>from attest.deny import read, verify_log; verify_log(read())</code></p>

<h2>What it proves — and what it does not</h2>
<table>
<tr><th>Proves</th><th>Does not prove</th></tr>
<tr><td>The record was not changed after issue</td><td>That no other chain was shown to someone else</td></tr>
<tr><td>The chain has no gaps (each <code>prev</code> matches)</td><td>That every refusal in your system reached this log</td></tr>
<tr><td>The signature verifies offline with the embedded key</td><td>That the policy behind the refusal was correct</td></tr>
</table>

<div class="price">
<b>$29</b> trial · 100 deny records · 7 days · signed export<br>
<b>$99</b> / month · unlimited records · 30-day retention
<p class="meta">Start with USDC on Base — no card, no account. Receipt is the transaction.</p>
<a class="btn" href="/pay">Start — $29 trial or $99/month</a>
<p class="meta">After payment the page issues an API key (X-API-Key) and a
<a href="/thanks">/thanks</a> page with the first call.</p>
<p class="meta">Included in the $99 attest plan. Free evaluation: 20 records/day.
Questions: <a href="mailto:maxim.pkk@gmail.com?subject=Deny%20evidence">maxim.pkk@gmail.com</a></p>
</div>

<p class="meta"><a href="/">attest</a> · <a href="/pricing">pricing</a> ·
<a href="/verify-offline">verify offline</a> · <a href="/docs">docs</a></p>
</main></body></html>"""
