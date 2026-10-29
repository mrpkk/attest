"""MCP Security Pass и 5 SEO-страниц под MCP-боли (29.10.2026).

Аудитория: 47 879 серверов в реестре MCP; большинство не проходило security-обзор.
Тон: только проверяемые утверждения, без «мы лучшие». Цена и CTA ведут на /pay
или на письмо; пример доказательства — /deny-evidence.
"""

BASE_CSS = """
 body{margin:0;background:#0b0d10;color:#e6e6e6;font:16px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
 main{max-width:800px;margin:0 auto;padding:42px 20px 80px}
 h1{font-size:33px;line-height:1.18;margin:0 0 12px;letter-spacing:-.02em}
 h2{font-size:21px;margin:34px 0 10px}
 p,li{color:#c9d1d9} a{color:#7fd1b9}
 code{background:#171b21;padding:2px 5px;border-radius:4px;font-size:.9em;font-family:ui-monospace,Menlo,monospace}
 pre{background:#12161c;border:1px solid #232a33;border-radius:8px;padding:13px 15px;overflow:auto}
 pre code{background:none;padding:0;font-size:13px}
 table{border-collapse:collapse;width:100%;font-size:14.5px;margin:0 0 18px}
 th,td{border:1px solid #232a33;padding:8px 11px;text-align:left;vertical-align:top}
 th{background:#141920}
 .grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));margin:18px 0}
 .card{border:1px solid #232a33;border-radius:12px;padding:18px;background:#10141a}
 .card b{font-size:26px;color:#7fd1b9;display:block}
 .btn{display:inline-block;margin-top:12px;padding:12px 20px;border-radius:9px;background:#7fd1b9;color:#062018;font-weight:700;text-decoration:none}
 .pay{border:1px solid #232a33;border-radius:12px;padding:18px;background:#10141a;margin:18px 0}
 .addr{font:14px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;background:#0b0d10;border:1px solid #30363d;border-radius:8px;padding:10px}
 .meta{color:#8b97a4;font-size:13.5px}
 .lead{font-size:18px;color:#a9b4c0}
"""


def _shell(title: str, description: str, canonical: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<link rel="canonical" href="https://attest.rta.lat{canonical}">
<style>{BASE_CSS}</style></head><body><main>{body}</main></body></html>"""


MCP_PASS_BODY = """
<h1>MCP Security Pass</h1>
<p class="lead">A reviewer will ask what your MCP server can do, who can call it, and what happens
when a call is refused. We produce the evidence for those three questions — for one server,
in five business days.</p>

<h2>What the pass covers</h2>
<table>
<tr><th>Area</th><th>What we check</th></tr>
<tr><td>Authentication</td><td>Token or OAuth flow, transport security, key handling, what happens without credentials</td></tr>
<tr><td>Scopes</td><td>Which tools can read, write, spend or delete; whether scopes are enforced server-side</td></tr>
<tr><td>Tool descriptions</td><td>Instruction surface: descriptions that can steer a model, unsafe defaults, missing annotations</td></tr>
<tr><td>Deny mode</td><td>Whether the server can refuse, what it records, whether the refusal is verifiable</td></tr>
<tr><td>Logs</td><td>What is logged, retention, tamper evidence, hash chain where possible</td></tr>
<tr><td>Report</td><td>Findings with severity, reproduction steps, fix order, and an evidence pack</td></tr>
</table>

<div class="grid">
<div class="card"><b>$500</b>Standard pass · 5 business days
<p class="meta">One server, one revision round, written report with severity and fix order.</p></div>
<div class="card"><b>$1,500</b>Pass + deny evidence + re-test
<p class="meta">Everything in Standard, plus a signed deny log wired to <code>POST /deny</code>, offline verification, and one re-test after fixes (72 hours).</p></div>
</div>

<div class="pay">
<h2 style="margin-top:0">Pay in USDC (Base)</h2>
<p>Send the exact amount, then email the transaction hash to
<a href="mailto:maxim.pkk@gmail.com?subject=MCP%20Security%20Pass">maxim.pkk@gmail.com</a>
with the subject “MCP Security Pass”. Intake form follows within one business day.</p>
<p class="addr">__PAY_TO__</p>
<a class="btn" href="#pay">Pay $500 — email the hash</a>
<p class="meta">Network Base only · asset USDC · no card, no account. Invoice on request.
The deny log example is public: <a href="/deny-evidence">attest.rta.lat/deny-evidence</a>.</p>
</div>

<h2>What it does not claim</h2>
<ul>
<li>Not a certification, not a penetration test, not a legal opinion.</li>
<li>No guarantee that a directory or a buyer will accept the report.</li>
<li>If a control is missing, the report says so with the reproduction step.</li>
</ul>
<p class="meta"><a href="/deny-evidence">Deny evidence</a> ·
<a href="/eu-ai-act-evidence">EU AI Act pack</a> · <a href="/docs">docs</a></p>
"""

SEO_PAGES = {
    "mcp-security-audit": {
        "title": "MCP security audit: what to check before you ship",
        "h1": "MCP security audit: the list a reviewer actually uses",
        "lead": "We scanned 2,500 public MCP servers. 72 touch money. None documented a spend limit. "
                "This page is the checklist we use when a team asks for a security pass.",
        "sections": [
            ("1. Authentication is not the same as authorisation",
             "A token in the URL, a shared key in a README, or an OAuth flow that returns a token the tool "
             "never checks — all three look like authentication. Ask one question: what happens when the "
             "credential is wrong? If the answer is a normal tool result, the server has no gate."),
            ("2. Scopes must be enforced on the server",
             "A scope written in the tool description is a suggestion. A scope checked before the handler "
             "runs is a control. List every tool that writes, spends or deletes, and show the check that "
             "runs before it."),
            ("3. Tool descriptions are an instruction surface",
             "Descriptions are read by a model as part of its own configuration. A description that says "
             "“always call this first” is an instruction, not documentation. Review descriptions the way "
             "you review prompts."),
            ("4. Refusals need a record",
             "A log where every row says allowed proves traffic, not control. An auditor asks for the "
             "refusal: which policy, which task, why. That record is what "
             "<a href=\"/deny-evidence\">deny evidence</a> is for."),
            ("5. Logs without tamper evidence are claims",
             "Hash-chained records and a signature let a third party verify the log offline. Without them, "
             "the log is your word — which is fine until the day it is not."),
        ],
        "cta": "The full pass checks these five areas on one server and returns a report with severity and fix order.",
    },
    "mcp-server-authentication": {
        "title": "MCP server authentication: tokens, scopes and the gap between them",
        "h1": "MCP server authentication: what “we have a token” hides",
        "lead": "Most MCP servers can show a token. Far fewer can show what happens when it is missing, "
                "wrong, or belongs to someone else.",
        "sections": [
            ("Missing credential",
             "Call every tool without a token. Any tool that answers normally is public, whatever the "
             "README says."),
            ("Wrong credential",
             "Send a syntactically valid token that belongs to nobody. The server must reject before the "
             "handler runs, not after it has done the work."),
            ("Scope per tool",
             "List tools by effect: read, write, spend, delete. For each, show the check. A single global "
             "token with full access is an audit finding, not a design choice."),
            ("Key handling",
             "Credentials in query strings end up in proxy logs. Tokens in tool output end up in model "
             "context. Both are leaks even when the call succeeds."),
        ],
        "cta": "The MCP Security Pass includes an authentication and scope review with reproduction steps.",
    },
    "mcp-tool-descriptions-security": {
        "title": "MCP tool descriptions are an instruction surface — treat them like prompts",
        "h1": "Tool descriptions are read as instructions",
        "lead": "A description is not documentation for humans only: the model reads it as part of its own "
                "configuration. That makes every description a place where a payload can land.",
        "sections": [
            ("Where the payload sits matters",
             "The same sentence in a result field and in a description field has a different blast radius. "
             "Our scanner escalates injections found in instruction fields and leaves the same text at base "
             "severity inside result fields."),
            ("Unsafe defaults",
             "“If the user does not specify, use the production key” is a description that changes behaviour. "
             "Defaults belong in code with a check, not in prose with a hope."),
            ("Missing annotations",
             "Without readOnly/destructive hints, an agent cannot tell a lookup from a delete. Directories "
             "render those hints; buyers use them."),
            ("Detection has limits",
             "Signature scanners lose to paraphrases. Positional escalation moderates severity; it does not "
             "recognise a phrase you never listed. Publish the limit instead of implying coverage."),
        ],
        "cta": "The pass reviews descriptions against the tools they describe, not as standalone text.",
    },
    "mcp-deny-log": {
        "title": "MCP deny log: proving what your agent refused",
        "h1": "A log with zero denials proves nothing",
        "lead": "“1,509 rows, zero denials” is the report one team gave an auditor. The auditor asked for the "
                "opposite: show me what was refused.",
        "sections": [
            ("What a deny record contains",
             "Reason, policy id, task id, artifact hash, actor and timestamp — signed, chained to the "
             "previous record, verifiable offline. Example and schema: "
             "<a href=\"/deny-evidence\">deny-evidence</a>."),
            ("Why the chain matters",
             "Anyone can write JSON. A hash chain plus an Ed25519 signature lets a third party prove the "
             "record was not edited after issue, without trusting your dashboard."),
            ("What it does not prove",
             "It does not prove that every refusal reached the log, and it does not prove the policy was "
             "right. Say that out loud in the report; auditors trust the limits more than the claims."),
            ("How to start",
             "Two calls: <code>POST /deny</code> to record, <code>GET /deny?since=</code> to read. "
             "Trial keys from 0.01 USDC on <a href=\"/pay\">/pay</a>."),
        ],
        "cta": "$29/month for unlimited deny records and signed export, or included in the MCP Security Pass.",
    },
    "mcp-server-monetization": {
        "title": "MCP server monetization without subscriptions",
        "h1": "MCP server monetization: per-call beats per-month",
        "lead": "An agent does not know in advance whether it needs five calls or fifty thousand. "
                "A monthly plan is the wrong shape for that buyer.",
        "sections": [
            ("Why subscriptions fail for agents",
             "Agents have no procurement process and no card. x402 makes the payment the authentication: "
             "a 402 response, a signed USDC transfer, a retried request."),
            ("What to charge for",
             "Charge for work that has a verifiable output: a check, a report, a signed record. Do not "
             "charge for “access” — an agent cannot value it."),
            ("The missing half",
             "Payment rails move money; they do not decide whether the spend should happen. A per-call "
             "server still needs a limit, and a log of refusals."),
            ("Our numbers",
             "The deny log is $29/month; the MCP Security Pass is $500–1,500; per-call x402 starts at "
             "$0.005. Each is priced by the job, not by seats."),
        ],
        "cta": "If your server takes money, the pass checks the gate before the payment, not only after it.",
    },
}


def seo_page(slug: str) -> str:
    page = SEO_PAGES[slug]
    body = [f"<h1>{page['h1']}</h1>", f"<p class='lead'>{page['lead']}</p>"]
    for title, text in page["sections"]:
        body.append(f"<h2>{title}</h2><p>{text}</p>")
    body.append(f"<div class='pay'><p>{page['cta']}</p>"
                "<a class='btn' href='/mcp-security-pass'>MCP Security Pass — $500</a> "
                "<p class='meta'>or <a href='/deny-evidence'>deny evidence</a> · "
                "<a href='/pay'>pay in USDC</a></p></div>")
    body.append("<p class='meta'><a href='/'>attest</a> · <a href='/docs'>docs</a> · "
                "<a href='/eu-ai-act-evidence'>EU AI Act pack</a></p>")
    return _shell(page["title"], page["lead"][:180], f"/mcp/{slug}", "\n".join(body))


def mcp_pass_page(pay_to: str) -> str:
    return _shell(
        "MCP Security Pass — auth, scopes, deny log, report",
        "Security review for one MCP server: authentication, scopes, tool descriptions, deny mode, logs and a report. $500, express $1,500.",
        "/mcp-security-pass",
        MCP_PASS_BODY.replace("__PAY_TO__", pay_to),
    )
