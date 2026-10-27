"""Вторая страница кластера: SCITT для действий агента.

Запрос «SCITT» ищут инженеры, которым нужен стандарт, а не продукт. Страница
отвечает на их вопрос и заканчивается тем, что можно проверить, — а не тем,
что можно купить.
"""

from __future__ import annotations

SCITT_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SCITT for AI agents: signed statements, transparency, and what a receipt proves</title>
<meta name="description" content="How the IETF SCITT architecture (RFC 9943) applies to AI agent actions: signed statements, hash chains, transparency logs, inclusion proofs — and the three claims a receipt cannot make.">
<link rel="canonical" href="https://attest.rta.lat/scitt">
<meta property="og:title" content="SCITT for AI agents: signed statements, transparency, and what a receipt proves">
<meta property="og:type" content="article">
<meta property="og:url" content="https://attest.rta.lat/scitt">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"TechArticle","headline":"SCITT for AI agents","description":"How RFC 9943 applies to AI agent actions, and the three claims a receipt cannot make.","author":{"@type":"Person","name":"mrpkk"},"datePublished":"2026-10-27","mainEntityOfPage":{"@id":"https://attest.rta.lat/scitt"}}</script>
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.65 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:40px 20px 80px}
 h1{font-size:28px;line-height:1.25;margin:0 0 10px} h2{font-size:20px;margin:34px 0 10px}
 p.s{color:#96a0ae;margin:0 0 18px} code{background:#171b21;padding:2px 6px;border-radius:4px;font-size:14px}
 pre{background:#10141a;border:1px solid #232a33;border-radius:8px;padding:12px;overflow:auto;font-size:13px}
 a{color:#7fd1b9} li{margin:0 0 8px}
</style></head><body>

<h1>SCITT for AI agents</h1>
<p class="s">SCITT — Supply Chain Integrity, Transparency and Trust — is the IETF architecture for statements
a third party can register and later prove existed. Published as
<a href="https://www.rfc-editor.org/rfc/rfc9943.html">RFC 9943</a> in June 2026. It was written for supply
chains; the same machinery answers the question an agent leaves behind: what did it do, and who can prove it?</p>

<h2>The three objects</h2>
<ul>
<li><strong>Signed Statement</strong> — the record itself, typically a COSE_Sign1 with the issuer and subject
in protected CWT claims. One action, one statement.</li>
<li><strong>Transparency Service</strong> — an append-only log that registers statements and returns a proof
of registration.</li>
<li><strong>Transparency Receipt</strong> — the log's signed proof that a statement is inside it. Not the same
object as the action receipt, and produced by a different party.</li>
</ul>

<h2>Why a self-signed chain is not enough</h2>
<p class="s">A hash chain proves that a record has not changed since the previous one. It does not prove the
issuer showed the same chain to everyone: an issuer can sign two divergent histories and show each to a
different counterparty. That is equivocation, and the only defence is a third party who publishes a head that
anyone can compare against.</p>
<p class="s">Registration gives you membership in the view the log served. It does not, by itself, give
non-equivocation — that needs consistency proofs between log states and a party who watches them. A deployment
that registers and never monitors has an auditable record and no equivocation defence. Saying so is part of
implementing it.</p>

<h2>What an agent receipt can and cannot claim</h2>
<p class="s">Three claims look like one and fail independently:</p>
<ul>
<li><strong>Pre-execution authorization</strong> — a named principal approved this exact action before it ran.</li>
<li><strong>Controller-reported outcome</strong> — a downstream system reported a terminal status, under its own
semantics.</li>
<li><strong>Physical completion</strong> — a witness observed the intended effect, against a criterion fixed
before execution.</li>
</ul>
<p class="s">A receipt carries the first only as a recorded name, and neither of the others. A record that
promises more than it holds is worse than no record, because the reader cannot tell where the support ends.</p>

<h2>What to check in a SCITT-based receipt</h2>
<pre>canonical form   JCS(parse(bytes)) == bytes, or the check is about a value nobody signed
signature        Ed25519 over a domain-separated digest, alg pinned to -19
chain            six conditions, each reported separately
checkpoint       answered / unanswered / unusable — and never a verdict about the chain
identity         the manifest is checked against the signature inside the record
absence          a question not answered is named, not omitted</pre>

<h2>Run it</h2>
<p class="s">A reference implementation of the agent action receipt profile, with public CC0 vectors and a
browser verifier: <a href="/receipts">six failure modes</a> ·
<a href="/verify-offline">check a receipt offline</a> ·
<a href="https://github.com/mrpkk/attest/blob/main/conformance/receipt-vectors.json">vectors</a>.</p>

</body></html>
"""
