"""Третья страница кластера: контрольная точка прозрачности.

Запрос «transparency log checkpoint», «append-only log consistency proof» ищут
те, кто строит журналы. Материала по теме мало, и почти весь он — для
сертификатов, а не для действий агента.
"""

from __future__ import annotations

CHECKPOINTS_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Transparency log checkpoints: extension, conflict, and the unverified case</title>
<meta name="description" content="How to compare a signed checkpoint against a hash chain: answered, unanswered and unusable, why a legitimate extension is not a conflict, and why an unauthenticated checkpoint must never become a finding about the chain.">
<link rel="canonical" href="https://attest.rta.lat/checkpoints">
<meta property="og:title" content="Transparency log checkpoints: extension, conflict, and the unverified case">
<meta property="og:type" content="article">
<meta property="og:url" content="https://attest.rta.lat/checkpoints">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"TechArticle","headline":"Transparency log checkpoints","description":"Answered, unanswered and unusable; extension versus conflict; and why an unauthenticated checkpoint must not accuse a chain.","author":{"@type":"Person","name":"mrpkk"},"datePublished":"2026-10-28","mainEntityOfPage":{"@id":"https://attest.rta.lat/checkpoints"}}</script>
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.65 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:40px 20px 80px}
 h1{font-size:28px;line-height:1.25;margin:0 0 10px} h2{font-size:20px;margin:34px 0 10px}
 p.s{color:#96a0ae;margin:0 0 18px} code{background:#171b21;padding:2px 6px;border-radius:4px;font-size:14px}
 pre{background:#10141a;border:1px solid #232a33;border-radius:8px;padding:12px;overflow:auto;font-size:13px}
 a{color:#7fd1b9} li{margin:0 0 8px}
 table{border-collapse:collapse;width:100%;font-size:14.5px;margin:12px 0 18px}
 th,td{border:1px solid #232a33;padding:8px 10px;text-align:left;vertical-align:top}
</style></head><body>

<h1>Transparency log checkpoints</h1>
<p class="s">A checkpoint is a signed assertion that a log's head was at a given position at a given moment.
It answers one question: <em>has the tail been cut?</em> Everything about comparing it follows from that
sentence, and most implementations get one of the three cases wrong.</p>

<h2>Three states, not two</h2>
<table>
<tr><th>State</th><th>When</th><th>What the verifier may say</th></tr>
<tr><td><code>answered</code></td><td>checkpoint supplied, well-formed, names this log, and the signature
checks against a key in the keyring</td><td>consistent, or <code>checkpoint-head-conflict</code></td></tr>
<tr><td><code>unanswered</code></td><td>no checkpoint supplied</td><td>the tail question was not asked — and
that is not the same as "no truncation"</td></tr>
<tr><td><code>unusable</code></td><td>supplied but malformed, for another log, or not authenticated</td>
<td>which of the three, and the tail stays unanswered</td></tr>
</table>

<h2>Why the unusable case is the one that matters</h2>
<p class="s">A checkpoint arrives as a file, often from the same party whose chain is in question. If an
unauthenticated one could establish anything, anyone able to hand you a file could manufacture a forensic
conclusion about someone else's history. That is not a bug in a corner case — it is the failure mode the whole
check is supposed to prevent.</p>
<p class="s">So: an unauthenticated checkpoint yields <code>checkpoint-unverified</code>, which is a finding
about the checkpoint. The chain stays whatever it was. A defective checkpoint subtracts an answer; it does not
create a failure.</p>

<h2>Extension is not conflict</h2>
<p class="s">A checkpoint asserts a head at the moment it was minted. A log that has grown since then legitimately
shows a later head. The comparison therefore has to distinguish two mismatches:</p>
<pre>checkpoint.headHash appears in the presented chain at exactly checkpoint.highestSeq
and the presented head is at a HIGHER seq        -> consistent extension, not a conflict

anything else                                     -> checkpoint-head-conflict</pre>
<p class="s">The second case is reported without a cause. Deleted tail, a fork, a checkpoint over a different
lineage, a signer error — four explanations, and the comparison separates none of them. Naming one is
manufacturing an accusation from a comparison that did not observe it.</p>

<h2>What a checkpoint does not give you</h2>
<ul>
<li><strong>Freshness.</strong> The timestamp is signer-chosen; an authentic checkpoint stays authentic forever.</li>
<li><strong>Non-equivocation.</strong> That needs consistency proofs between log states and a party watching them.
A deployment that registers and never monitors has an audit trail and no equivocation defence.</li>
<li><strong>Scope across agents.</strong> On a chain carrying several agent identities, a checkpoint authorised
for the opener certifies the opener's view, not a co-agent's tail.</li>
</ul>

<h2>In code</h2>
<pre>verify_chain(receipts, keyring, checkpoint=cp, manifest=manifest)
  -> conditions: six chain conditions, all reported
  -> checkpoint: {state: answered|unanswered|unusable, result: consistent|checkpoint-head-conflict}</pre>
<p class="s">Reference implementation and public vectors:
<a href="https://github.com/mrpkk/attest">github.com/mrpkk/attest</a> ·
<a href="/receipts">six ways a verifier can lie</a> ·
<a href="/scitt">SCITT for agents</a></p>

</body></html>
"""
