"""Страница deny-evidence: пример, API, цена $29/мес (29.10.2026)."""

DENY_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deny evidence — a signed log of refusals, not just approvals</title>
<meta name="description" content="An append-only, Ed25519-signed log of every refusal: who asked, what, which policy, and why it was denied. Verifiable offline. $29/month.">
<link rel="canonical" href="https://attest.rta.lat/deny-evidence">
<style>
 body{margin:0;background:#0b0d10;color:#e6e6e6;font:16px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
 main{max-width:760px;margin:0 auto;padding:40px 20px 80px}
 h1{font-size:31px;line-height:1.2;margin:0 0 8px} h2{font-size:21px;margin:34px 0 10px}
 p{margin:0 0 15px} a{color:#7fd1b9}
 code{background:#171b21;padding:2px 5px;border-radius:4px;font-size:.9em;font-family:ui-monospace,Menlo,monospace}
 pre{background:#12161c;border:1px solid #232a33;border-radius:8px;padding:13px 15px;overflow:auto}
 pre code{background:none;padding:0;font-size:13px;line-height:1.5}
 table{border-collapse:collapse;width:100%;font-size:14.5px;margin:0 0 18px}
 th,td{border:1px solid #232a33;padding:8px 11px;text-align:left}
 th{background:#141920}
 .price{border:1px solid #232a33;border-radius:12px;padding:16px 18px;background:#10141a;margin:20px 0}
 .price b{font-size:26px;color:#7fd1b9}
 .meta{color:#8b97a4;font-size:13.5px}
</style></head><body><main>
<h1>Deny evidence</h1>
<p>A log where every action is <em>allowed</em> proves nothing about control. The useful artifact is the
opposite: a signed record of refusals — who asked, what for, which rule stopped it, and a signature
an auditor verifies without trusting us.</p>

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
  "signature": "&lt;Ed25519 over the canonical body&gt;",
  "public_key": "&lt;base64 public key&gt;",
  "algorithm": "ed25519"
}</code></pre>

<h2>API</h2>
<pre><code># record a refusal (your agent calls this when a rule says no)
curl -X POST https://attest.rta.lat/deny \\
  -H 'content-type: application/json' \\
  -d '{"reason":"payee not in allowlist","policy_id":"E03-allowlist",
       "task_id":"task_7f21","artifact_hash":"sha256:9c1e"<...>","actor":"agent:research-1"}'

# read what happened since a moment
curl 'https://attest.rta.lat/deny?since=2026-10-29T00:00:00Z&limit=100'</code></pre>

<h2>Offline verification</h2>
<pre><code>from attest.deny import read, verify_log
print(verify_log(read()))   # {"ok": true, "records": 128, "head": "..."}
# change one reason in a record → ok=false, broken_at points at it</code></pre>

<h2>What it proves — and what it does not</h2>
<table>
<tr><th>Proves</th><th>Does not prove</th></tr>
<tr><td>The record was not changed after issue</td><td>That no other chain was shown to someone else</td></tr>
<tr><td>The chain has no gaps (each <code>prev</code> matches)</td><td>That every denial in your system reached this log</td></tr>
<tr><td>The signature is ours and verifies offline</td><td>That the human decision behind the policy was right</td></tr>
</table>

<div class="price"><b>$29</b> / month · unlimited deny records, 30-day retention, signed export
· <a href="/subscribe">subscribe</a> · included in the $99 attest plan</div>

<p class="meta">No card required: USDC over x402, or <a href="/pay">pay from any wallet</a>.
Free for evaluation: 20 records per day.</p>
<p class="meta"><a href="/">attest</a> · <a href="/docs">docs</a> · <a href="/pricing">pricing</a></p>
</main></body></html>"""
