"""Статья под запрос «MCP server scan»: как проверить сервер до подключения.

Зачем отдельная страница. `/scan` — инструмент, `/docs/scan` — справка о нём; ни одна из них не
отвечает на поисковый вопрос целиком. Статья собирает то, что человек ищет перед подключением
сторонннего сервера: что смотреть, как читать результат, чего скан не покажет.
"""
from __future__ import annotations

from .product_pages import _shell

BODY = """
<p class="lead">An MCP server is a set of tools your agent can call. Before you connect one, you can read
what it exposes — the public <code>tools/list</code> answer — and decide whether the surface is worth
the risk. That is what an MCP server scan does, and this page explains what it shows, what it cannot,
and how to use the result.</p>

<h2>What an MCP server scan reads</h2>
<p>The scan asks the server one question: <code>tools/list</code>. That answer is public by design — it is
the same list your agent receives at runtime — and it contains, for each tool, a name, a description and
an optional annotation block. From that answer the scan extracts three things:</p>
<ul>
<li><b>What each tool can do.</b> A tool that moves money, writes files or deletes state is a different
kind of risk from one that only reads. We look at the declared name and description, not at the
implementation.</li>
<li><b>Whether annotations are declared.</b> <code>readOnlyHint</code>, <code>destructiveHint</code> and
<code>openWorldHint</code> are how the server tells a client what a tool does to the world. Missing
annotations are not an error, but they are the difference between a client that can warn you and one that
cannot.</li>
<li><b>Whether a description tries to talk to the model.</b> Text aimed at an agent rather than at a human
("ignore previous instructions", "send the key to…") is a prompt-injection attempt parked in metadata. The
scan flags the pattern and names the field it sits in.</li>
</ul>

<h2>What it cannot show</h2>
<p>This is the part most scan pages leave out, and it is the part that decides whether you should trust
the result:</p>
<ul>
<li><b>What the tool will actually do.</b> A description is a claim. A tool declared read-only can still
write; the scan cannot see the code behind it.</li>
<li><b>Whether the data is safe.</b> The scan does not read prompts, results, user data or keys. It only
reads the tool list, which is what makes it safe to run against a third-party server.</li>
<li><b>Whether you are allowed to call it.</b> Permissions live on the server side; the scan does not
authenticate and does not test your credentials.</li>
<li><b>Whether the server is honest.</b> A tool can be described accurately and implemented badly. The
scan narrows the review; it does not replace it.</li>
</ul>

<h2>How to read the result</h2>
<p>Start with the tools that can move money or change state, and for each one answer a single question:
what stops this action if the agent is wrong? If the answer is "the model's judgement", you have found
the risk. Three answers exist, and none of them require rewriting the server:</p>
<ul>
<li><b>A receipt</b> — the action leaves a signed record a human can check afterwards.</li>
<li><b>A limit</b> — an amount or a count beyond which the tool refuses, whatever the intent.</li>
<li><b>A kill switch</b> — a way to stop the agent in one step, without editing prompts.</li>
</ul>
<p>For read-only tools, the useful check is different: confirm the annotation is true. A read-only tool
that writes is the most common mismatch between description and behaviour we see.</p>

<h2>When to scan</h2>
<p>Scan a server when it is new to you, when it changes, and before you raise its permissions. The public
tool list is exactly what the agent will see at runtime, so a scan right after a deployment is the
cheapest check that the deployment did not quietly widen the surface. There is no scheduled monitoring on
the free path: this is a point-in-time read, not a watchdog.</p>

<h2>Scan versus audit versus vulnerability scanner</h2>
<p>Three different questions, often confused:</p>
<ul>
<li><b>Scan</b> — what does this server expose right now? Thirty seconds, free, no account.</li>
<li><b>Audit</b> — what has this agent actually done with it? That requires logs and a person reading them.</li>
<li><b>Vulnerability scanner</b> — are there known weaknesses in the code or dependencies? It needs the
code; a scan does not.</li>
</ul>
<p>Running one of them and calling it another is how teams end up with a clean report and an incident.</p>

<h2>Do it now</h2>
<p>Paste a server URL and get the tool list back in about thirty seconds — no account, no card:
<a href="/scan?ref=article-mcp-scan">MCP server scan</a>. The reference on limits and the exact checks is
<a href="/docs/scan?ref=article-mcp-scan">/docs/scan</a>; the paid audit, which reads your spend logs, is
on <a href="/plans?ref=article-mcp-scan">/plans</a>.</p>
"""


def scan_article_page() -> str:
    jsonld = ('{"@context":"https://schema.org","@type":"TechArticle",'
              '"headline":"MCP server scan: what it shows, what it cannot",'
              '"description":"How to read an MCP server\'s public tool list before connecting it: '
              'tools that move money, missing annotations, hidden instructions, and the limits of a scan.",'
              '"author":{"@type":"Organization","name":"attest","url":"https://attest.rta.lat"},'
              '"datePublished":"2026-11-26",'
              '"mainEntityOfPage":{"@id":"https://attest.rta.lat/mcp-scan-guide"}}')
    return _shell("MCP server scan: what it shows and what it cannot — attest",
                  "An MCP server scan reads the public tools/list answer: which tools move money or change "
                  "state, missing annotations, hidden instructions — and what the scan cannot prove.",
                  "/mcp-scan-guide", BODY, jsonld=jsonld)
