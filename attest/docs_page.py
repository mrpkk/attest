"""Страница документации: три языка, без маркетинга.

Индия — первый класс (правило владельца), поэтому хинди идёт вторым, а не
«когда-нибудь». Русский — язык владельца и первых читателей.

Страница отвечает на четыре вопроса и молчит про остальное: что проверяется,
чего не проверяется, где это взять, как проверить самому.
"""

from __future__ import annotations

DOCS_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>attest — documentation</title>
<meta name="description" content="What an attest receipt verifies, what it does not, where the endpoints are, and how to check one offline in three steps.">
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.65 system-ui,sans-serif;max-width:820px;margin:0 auto;padding:38px 20px 80px}
 h1{font-size:28px;margin:0 0 6px} h2{font-size:20px;margin:36px 0 10px} h3{font-size:16px;margin:22px 0 6px}
 p.s{color:#96a0ae;margin:0 0 18px} code{background:#171b21;padding:2px 6px;border-radius:4px;font-size:14px}
 pre{background:#10141a;border:1px solid #232a33;border-radius:8px;padding:12px;overflow:auto;font-size:13px}
 a{color:#7fd1b9} li{margin:0 0 6px} .lang{border-top:1px solid #232a33;margin-top:48px;padding-top:8px}
 table{border-collapse:collapse;width:100%;font-size:14.5px;margin:10px 0 18px}
 th,td{border:1px solid #232a33;padding:8px 10px;text-align:left;vertical-align:top}
</style></head><body>

<h1>attest — documentation</h1>
<p class="s">A receipt is one signed record of what an agent was recorded as doing at the boundary
that governed it. This page says what that proves, what it does not, and how to check one yourself.</p>

<h2>What a receipt proves</h2>
<table>
 <tr><th>Proved</th><th>How</th></tr>
 <tr><td>The record was issued by that key</td><td>Ed25519 signature over a domain-separated digest</td></tr>
 <tr><td>It has not changed since</td><td><code>chain.hash</code> recomputed from the bytes; a mismatch is a rejection</td></tr>
 <tr><td>It was not re-encoded in transit</td><td>canonical form checked against the bytes received</td></tr>
 <tr><td>It sits where it claims in its chain</td><td>six chain conditions, all reported separately</td></tr>
 <tr><td>A third party saw it exist at a moment</td><td>inclusion proof in a transparency log, verifiable offline</td></tr>
</table>

<h2>What it does not prove</h2>
<ul>
 <li>That the agent was right, safe, or wise.</li>
 <li>That a named person approved the action: the approval field is an opaque label.</li>
 <li>That the action took effect in the world. A dispatch is not an outcome.</li>
 <li>That nothing happened outside the instrumented boundary.</li>
</ul>
<p class="s">These are non-claims, not disclaimers. A record that promises more than it holds is worse
than no record, because the reader cannot tell where the support ends.</p>

<h2>Endpoints</h2>
<table>
 <tr><th>Path</th><th>What it does</th></tr>
 <tr><td><code>POST /verify</code></td><td>verify an artifact: schema, emptiness, provenance, mandate</td></tr>
 <tr><td><code>POST /log/register</code></td><td>register a statement in the log, get an inclusion proof</td></tr>
 <tr><td><code>GET /log/head</code></td><td>signed tree head: size, root, signature, public key</td></tr>
 <tr><td><code>GET /log/proof/&lt;i&gt;</code></td><td>inclusion proof for leaf <code>i</code></td></tr>
 <tr><td><code>GET /log/consistency/&lt;n&gt;</code></td><td>proof that the tree of size <code>n</code> is contained in the current one</td></tr>
 <tr><td><code>POST /mcp</code></td><td>MCP 2026-07-28, stateless; tools <code>verify_artifact</code> and <code>verify_artifact_batch</code></td></tr>
 <tr><td><code>GET /verify-offline</code></td><td>the same verifier, inlined, no network calls</td></tr>
</table>

<h2>Check a receipt offline in three steps</h2>
<pre>1. open https://attest.rta.lat/verify-offline and save the page
2. paste the receipt text exactly as you received it, and the issuer public key
3. read the verdict — VALID means signature, canonical form and hash agree</pre>
<p class="s">The same corpus is published: <code>conformance/receipt-vectors.json</code>, CC0.
If your implementation disagrees with ours on those bytes, that disagreement is the useful result.</p>

<div class="lang">
<h2>हिन्दी — सारांश</h2>
<p class="s">रसीद एक हस्ताक्षरित रिकॉर्ड है: एजेंट ने नियंत्रण-सीमा पर क्या किया, यही दर्ज है।</p>
<ul>
 <li><strong>सिद्ध होता है:</strong> रिकॉर्ड उसी कुंजी से जारी हुआ, बाद में बदला नहीं, क्रम में अपनी जगह पर है, और लॉग में उसका अस्तित्व किसी तीसरे पक्ष ने देखा।</li>
 <li><strong>सिद्ध नहीं होता:</strong> एजेंट सही या सुरक्षित था; किसी व्यक्ति ने मंज़ूरी दी; कार्रवाई का असर दुनिया में हुआ।</li>
 <li><strong>जाँच:</strong> <code>/verify-offline</code> पृष्ठ सहेजें, इंटरनेट बंद करें, रसीद और सार्वजनिक कुंजी चिपकाएँ — फिर भी जाँच चलेगी।</li>
 <li><strong>लाइसेंस:</strong> वेक्टर CC0; कोड Apache-2.0.</li>
</ul>
</div>

<div class="lang">
<h2>Русский — коротко</h2>
<p class="s">Квитанция — одна подписанная запись о том, что агент сделал на границе, которая им управляла.</p>
<ul>
 <li><strong>Доказывает:</strong> запись выпущена этим ключом, не менялась после, стоит на своём месте в цепи, и третья сторона видела её существование.</li>
 <li><strong>Не доказывает:</strong> что агент был прав; что человек одобрил; что действие возымело эффект в мире.</li>
 <li><strong>Как проверить:</strong> сохранить страницу <code>/verify-offline</code>, выключить сеть, вставить квитанцию и публичный ключ — проверка работает.</li>
 <li><strong>Лицензия:</strong> векторы CC0, код Apache-2.0.</li>
</ul>
</div>

</body></html>
"""
