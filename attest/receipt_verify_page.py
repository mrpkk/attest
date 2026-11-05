"""Публичная страница проверки квитанции платежа.

Зачем страница, а не только API: человек, у которого спорят $30 тыс., ищет
не «attest», а «verify crypto payment proof». Ему нужен ответ целиком:
загрузить JSON, увидеть вердикт и понять, что именно проверено, а что нет.
"""

from __future__ import annotations

RECEIPT_VERIFY_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify a crypto payment receipt offline — receipt/1</title>
<meta name="description" content="Upload a payment receipt and check its Ed25519 signature in the browser. Verdict: ok, tampered, wrong_key or unsigned. The signed bytes are shown so anyone can reproduce the check without trusting the server.">
<link rel="canonical" href="https://attest.rta.lat/verify-receipt">
<meta property="og:title" content="Verify a crypto payment receipt">
<meta property="og:description" content="Offline Ed25519 check of a payment receipt: ok, tampered, wrong_key, unsigned. Canonical bytes shown for independent reproduction.">
<meta property="og:type" content="website">
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.65 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:40px 20px 80px}
 h1{font-size:28px;line-height:1.25;margin:0 0 10px} h2{font-size:19px;margin:32px 0 10px}
 p.s{color:#96a0ae;margin:0 0 18px} code{background:#171b21;padding:2px 6px;border-radius:4px;font-size:14px}
 pre{background:#10141a;border:1px solid #232a33;border-radius:8px;padding:12px;overflow:auto;font-size:13px;white-space:pre-wrap;word-break:break-all}
 a{color:#7fd1b9} textarea{width:100%;min-height:170px;background:#10141a;color:#e8ecf4;border:1px solid #232a33;border-radius:8px;padding:10px;font:13px/1.5 ui-monospace,monospace}
 button{background:#7fd1b9;color:#0b0d12;border:0;border-radius:6px;padding:9px 16px;font-weight:600;cursor:pointer;margin:10px 0}
 button:disabled{opacity:.5;cursor:default}
 .v{border-radius:8px;padding:14px 16px;margin:16px 0;border:1px solid #232a33;display:none}
 .v b{font-size:20px;display:block;margin-bottom:4px}
 .ok{border-color:#2f6b57;background:#0f1a16} .ok b{color:#7fd1b9}
 .bad{border-color:#6b3a34;background:#1a1210} .bad b{color:#ff9a8b}
 .warn{border-color:#6b5a34;background:#1a1710} .warn b{color:#e8c97f}
 table{border-collapse:collapse;width:100%;font-size:14.5px;margin:12px 0 18px}
 th,td{border:1px solid #232a33;padding:8px 10px;text-align:left;vertical-align:top}
 .muted{color:#96a0ae;font-size:14px}
</style></head><body>

<h1>Verify a crypto payment receipt</h1>
<p class="s">A <code>receipt/1</code> receipt records one on-chain transfer — tx hash, chain, amount,
sender, recipient, block, time — and signs it with Ed25519. This page checks the signature and the
canonical bytes. It does not ask the chain anything: the block is public, so the transfer is
re-checkable by anyone from the tx hash.</p>

<textarea id="in" placeholder='Paste the receipt JSON here, or choose the file below'></textarea>
<input type="file" id="file" accept=".json,application/json">
<div><button id="go">Verify</button> <span id="status" class="muted"></span></div>

<div class="v" id="out"><b id="verdict"></b><div id="detail" class="muted"></div>
 <div id="notes"></div></div>

<h2>What each verdict means</h2>
<table>
<tr><th>Verdict</th><th>Meaning</th></tr>
<tr><td><code>ok</code></td><td>The signature verifies against the public key in the receipt, and the signed fields are unchanged.</td></tr>
<tr><td><code>tampered</code></td><td>The signature does not verify: at least one signed field was changed after signing.</td></tr>
<tr><td><code>wrong_key</code></td><td>The receipt is internally consistent but signed by a key you did not name. Compare the fingerprint.</td></tr>
<tr><td><code>unsigned</code></td><td>There is no signature at all. Nothing was attested.</td></tr>
<tr><td><code>malformed</code></td><td>Not a <code>receipt/1</code> object, or a field has the wrong type. Nothing was checked.</td></tr>
</table>

<h2>Reproduce it without this page</h2>
<p class="s">The signed bytes are the canonical JSON (RFC 8785) of the receipt without
<code>signature</code> and <code>public_key</code>. Verify with the module itself — no network, no server:</p>
<pre>python3 -m attest.payment_receipt verify receipt.json --key &lt;issuer-public-key-b64&gt;</pre>

<h2>What a receipt proves, and what it does not</h2>
<table>
<tr><th>Proves</th><th>Does not prove</th></tr>
<tr><td>A transfer of that amount, asset and recipient existed in that block.</td><td>That goods or services were delivered.</td></tr>
<tr><td>The issuer signed those exact facts at issuance.</td><td>That the issuer is solvent, honest or still in business.</td></tr>
<tr><td>Any change to the facts breaks the signature.</td><td>That the transfer was for the stated subject: the subject is the requester's declaration, signed as a declaration.</td></tr>
<tr><td>The receipt records the facts the issuer read from the chain at issuance.</td><td>That the payer owned the funds lawfully.</td></tr>
</table>
<p class="s muted">A receipt costs $0.50. Issue one: <code>POST /api/receipt/issue</code> with
<code>{"tx_hash": "0x…", "chain": "base", "subject": "what was paid for"}</code>.</p>

<script>
const $ = id => document.getElementById(id);
$("file").addEventListener("change", async e => {
  const f = e.target.files[0];
  if (f) $("in").value = await f.text();
});
$("go").addEventListener("click", async () => {
  const text = $("in").value.trim();
  const out = $("out"), v = $("verdict"), d = $("detail"), n = $("notes");
  if (!text) { $("status").textContent = "paste a receipt first"; return; }
  $("go").disabled = true; $("status").textContent = "checking…";
  out.style.display = "none";
  try {
    const r = await fetch("/api/receipt/verify", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({receipt: text})
    });
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || ("HTTP " + r.status));
    const status = body.verdict;
    out.className = "v " + (status === "ok" ? "ok" : status === "wrong_key" ? "warn" : "bad");
    out.style.display = "block";
    v.textContent = status;
    d.textContent = body.detail || "";
    n.innerHTML = "";
    (body.notes || []).forEach(t => {
      const p = document.createElement("p"); p.className = "muted"; p.textContent = "• " + t; n.appendChild(p);
    });
    if (body.key_fingerprint) {
      const p = document.createElement("p"); p.className = "muted";
      p.textContent = "key fingerprint: " + body.key_fingerprint; n.appendChild(p);
    }
    if (body.signed) {
      const h = document.createElement("p"); h.className = "muted";
      h.textContent = "signed bytes (canonical JSON without signature and public_key):";
      n.appendChild(h);
      const pre = document.createElement("pre"); pre.textContent = body.signed; n.appendChild(pre);
    }
    $("status").textContent = "";
  } catch (err) {
    out.className = "v bad"; out.style.display = "block";
    v.textContent = "not checked"; d.textContent = String(err.message || err);
    $("status").textContent = "";
  } finally {
    $("go").disabled = false;
  }
});
</script>
</body></html>
"""
