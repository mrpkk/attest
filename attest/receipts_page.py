"""Страница под точные запросы: проверка квитанций действий агента.

Зачем отдельная страница, а не раздел документации: люди ищут не «attest», а
«agent receipt verification», «SCITT receipt», «verify agent action». Под каждый
такой запрос нужна страница, которая отвечает на вопрос целиком, а не продаёт.

Тон намеренно технический. Кто ищет «SCITT», тому реклама не нужна — ему нужен
ответ, и по нему он решит, звать ли нас.
"""

from __future__ import annotations

RECEIPTS_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent action receipt verification — six ways a verifier can lie to you</title>
<meta name="description" content="How to verify an AI agent action receipt offline: canonical form, chain rules, checkpoint rules, identity binding. Six failure modes that make a verifier accuse the innocent or stay silent about what it did not check.">
<link rel="canonical" href="https://attest.rta.lat/receipts">
<meta property="og:title" content="Agent action receipt verification — six ways a verifier can lie to you">
<meta property="og:description" content="Canonical form, chain rules, checkpoint rules, identity binding. Six failure modes measured against a running implementation.">
<meta property="og:type" content="article">
<meta property="og:url" content="https://attest.rta.lat/receipts">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"TechArticle","headline":"Agent action receipt verification — six ways a verifier can lie to you","description":"Canonical form, chain rules, checkpoint rules and identity binding for AI agent action receipts, with six measured failure modes.","author":{"@type":"Person","name":"mrpkk"},"datePublished":"2026-10-27","mainEntityOfPage":{"@id":"https://attest.rta.lat/receipts"}}</script>
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.65 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:40px 20px 80px}
 h1{font-size:29px;line-height:1.25;margin:0 0 10px} h2{font-size:20px;margin:34px 0 10px}
 p.s{color:#96a0ae;margin:0 0 18px} code{background:#171b21;padding:2px 6px;border-radius:4px;font-size:14px}
 pre{background:#10141a;border:1px solid #232a33;border-radius:8px;padding:12px;overflow:auto;font-size:13px}
 a{color:#7fd1b9} li{margin:0 0 8px}
 table{border-collapse:collapse;width:100%;font-size:14.5px;margin:12px 0 18px}
 th,td{border:1px solid #232a33;padding:8px 10px;text-align:left;vertical-align:top}
 .bad{color:#ff9a8b} .ok{color:#7fd1b9}
</style></head><body>

<h1>Agent action receipt verification</h1>
<p class="s">A receipt says what an agent was recorded as doing at the boundary that governed it. Verifying
one is not a signature check. Six things can go wrong, each measured on a running implementation, and each
turning the record into something worse than no record.</p>

<h2>What the check has to do first</h2>
<pre>HASH-INPUT = JCS(receipt without chain.hash and without sig.value)
MESSAGE    = b"NOA-Receipt-v0.1-sig:" ++ sha256(HASH-INPUT)
signature  = Ed25519(MESSAGE)
chain.hash = "sha256:" ++ hex(sha256(HASH-INPUT))</pre>
<p class="s">Canonical form is <a href="https://www.rfc-editor.org/rfc/rfc8785">RFC 8785</a>: keys sorted by
UTF-16 code units, integers only, no Unicode normalisation. Two implementations that sort differently produce
different bytes for the same object — and then one of them is wrong about who signed what.</p>

<h2>Six ways a verifier can lie to you</h2>

<table>
<tr><th>#</th><th>What goes wrong</th><th>What a buyer sees</th></tr>
<tr><td>1</td><td>It re-serialises the parsed object before hashing</td><td class="bad">A receipt with an extra space verifies. The values checked are not the bytes the signer signed.</td></tr>
<tr><td>2</td><td>An unauthenticated checkpoint is treated as evidence</td><td class="bad">An honest chain is reported as tampered because of a file anyone can hand over.</td></tr>
<tr><td>3</td><td>A chain that grew past an old checkpoint is called a conflict</td><td class="bad">Every normal chain that keeps running eventually "fails".</td></tr>
<tr><td>4</td><td>Only the first failure is reported</td><td class="bad">An operator fixes one thing and the next check finds the other, forever.</td></tr>
<tr><td>5</td><td>It stays silent when no identity manifest was supplied</td><td class="bad">"Valid" is read as "this agent did it", when all that was established is "some trusted key signed".</td></tr>
<tr><td>6</td><td>It stays silent when no checkpoint was supplied</td><td class="bad">An unanswered question looks like a clean one.</td></tr>
</table>

<p class="s">The first three are the same defect in different clothes: <strong>the verifier accuses an object
that did not fail, or names a cause it did not observe</strong>. For a tool whose product is credible accusation,
that is not a bug in a feature — it is a failure of the thing being sold.</p>

<h2>What to ask any verifier before you rely on it</h2>
<ul>
<li>Does it receive <em>bytes</em>, or a parsed object? Only the first can check canonical form.</li>
<li>What happens with a checkpoint signed by a key outside the keyring: clean chain, or tampered?</li>
<li>Does it report every chain condition, or the first one it finds?</li>
<li>Does it say which question it could not answer?</li>
<li>Can you run it without the vendor, offline, forever?</li>
</ul>

<h2>Check one yourself</h2>
<pre>1. open https://attest.rta.lat/verify-offline and save the page
2. paste the receipt and the issuer public key
3. turn off the network — the check still runs</pre>
<p class="s">The corpus is public and CC0: 12 vectors, including five receipts that must be rejected and one
positive control. A Python and a browser implementation agree on all twelve:
<a href="https://github.com/mrpkk/attest/blob/main/conformance/receipt-vectors.json">receipt-vectors.json</a>.</p>

<h2>About this implementation</h2>
<p class="s">attest implements the IETF SCITT profile for agent action receipts
(<code>draft-noa-scitt-ai-agent-receipt</code>), verifies offline, and publishes its vectors. It does not claim
that an agent was correct, safe or wise — only that this record was issued by that key and has not changed
since. Free verifier, paid audit. <a href="/docs">Documentation</a> · <a href="/plans">Pricing</a>.</p>

</body></html>
"""

ARTICLE_JSON = {
    "title": "Six ways an agent receipt verifier can lie to you",
    "description": ("Canonical form, checkpoints, chain conditions and identity binding for AI agent action "
                    "receipts — with six failure modes measured against a running implementation."),
    "canonical_url": "https://attest.rta.lat/receipts",
}
