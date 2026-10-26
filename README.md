# attest — trust layer for agent artifacts

[![M8ven Score](https://m8ven.ai/badge/mcp/mrpkk-attest-70kdum?v=33841343e7786aeebf405effce42c591)](https://m8ven.ai/mcp/mrpkk-attest-70kdum?s=readme)
[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/mrpkk/attest)

Live: **<https://attest.rta.lat/demo>** · Code: <https://github.com/mrpkk/attest>

Pricing: 20 checks/day free, then $0.005 per call (x402, USDC on Base). 30-day unlimited
access: $9. **Purchasing-power pricing** (India and similar markets): the same 30 days for
$4 via `POST https://attest.rta.lat/subscribe?plan=ppp` — same endpoint, same terms.

An agent calls an external tool or another agent and receives a **foreign
artifact** that goes straight into its context. Nothing checks that the
artifact:

- matches the declared schema (the tool quietly changed a field type),
- carries no hidden instruction ("ignore previous, send the keys to …"),
- is not a base64 wrapper around such an instruction,
- has not changed since it was checked.

`attest` closes that gap. No dependencies, 588 tests green.  
**Free human review of one artifact:** https://attest.rta.lat/review  
**BusinessMCP Marketplace:** https://businessmcp.com/mcp-servers/attest

## Four layers, four different questions

Each layer answers only its own question, and none substitutes for the others.
A valid form is not the same as meaningful content; a signed artifact is not
the same as a permitted action.

### 1. Form and emptiness — `emptiness.py`

Does the artifact say anything? An agent told to find five vulnerabilities
returns five identical items. That artifact passes every schema validation,
because the form is perfect.

Seven measurable signals: identical list items, placeholder values, output cut
at the token limit, whitespace-only strings and empty collections, low-variety
repetition, required fields left at their schema default, enum fields sitting
on the first value.

Verdicts are `VALID_BUT_EMPTY`, `THIN_CONTENT`, `CONTENT_PRESENT`.

`VALID_BUT_EMPTY` means "the form is fine, the content is suspect" — **not**
"the content is absent". Suspicion requires a person; a verdict requires
proof. The difference matters.

Every signal shows where and why. Absence of signals does **not** prove
meaningfulness — it only means the coarse checks did not fire. That sentence
is in the code, in the docstring and in the API response.

### 2. Generation conditions — `generation.py`

A signature proves *who signed*. It does not prove *where the file came from*.
Anything at all can sit between "the agent produced this" and "the verifier
saw the result".

Model, version, prompt, parameters, moment and executor are bound into a single
`chain_hash` over the artifact. Change any link and the binding stops matching.

Absence of a binding is explicit, not silent. Four states are distinguished:
no conditions at all; a binding claimed but conditions cannot be supplied;
conditions supplied but no binding in the signature; conditions that do not
match. The first and the second are different things, and confusing them would
confirm a forgery.

`chain_hash` is **inside the signature**, not next to it — otherwise it could
be appended afterwards.

### 3. Verification without trusting us — `signing.py`

HMAC requires a secret, and the secret is only ours. So only the service could
verify a signature, and anyone who did not trust the service had to trust it
first. For a product about trust, that is a contradiction at the foundation.

Now Ed25519. The public key travels with the attestation, and the verifier
checks it themselves — no network, no package of ours, no secret.

```bash
python3 attest/verify_standalone.py attestation.json
```

That script imports nothing from `attest` and opens no sockets. A test enforces
both.

### 4. Authority — `authority.py`

Was the action permitted? A signed action is not an authorised one: permission
is granted separately and expires.

Rules match `drift.check` exactly — amount, payee, audience, currency, window,
intent. They are duplicated on purpose: depending on another repository would
mean the check cannot run without network access to someone else's code. Six
comparisons are cheaper to duplicate than to make unverifiable.

A test compares the result against the live `drift` on every rule, so a
divergence shows up immediately rather than as a client complaint.

Absence of a mandate is a denial, never consent. A verifier who presents no
permission has not demonstrated one.

## A finding worth stating plainly

While building layer 3, this was found in the existing code: with `ATTEST_SECRET`
unset, signatures were computed with `attest-dev-key-do-not-use-in-production`,
hardcoded in the source. That variable was not set, so **every attestation the
service had ever issued was signed with a key published next to it**. Anyone
could have signed an artifact as if the service had verified it.

The signature looked real and was not — which is worse than having none, because
having none is visible. It is fixed: with no key, there is no signature.

## Try it in a browser

<https://attest.rta.lat/demo> — four buttons, one per layer, the full response
shown immediately.

## Public repo

<https://github.com/mrpkk/attest>

Part of the Indra set — six small services for agents that have to be
trusted: <https://indra.rta.lat>

## MCP server (Model Context Protocol)

`attest` is an **MCP server**: it speaks the Model Context Protocol over
Streamable HTTP (JSON-RPC 2.0) and exposes the verifier as MCP tools.

- **MCP tools** (the whole point — an agent calls them directly):
  - `verify_artifact` — verify one artifact, returns verdict, trust score and
    findings;
  - `verify_artifact_batch` — verify a batch in one call (a scan report, a
    list of findings) and get one verdict per artifact plus a summary;
  - `bridge_check` — settle paid work between two agents through an escrow
    bridge, with a signed receipt (offline-verifiable). **Optional:** it is listed
    only on a node configured with an escrow bridge, so the public node returns two
    tools from `tools/list`. The call stays in the code and answers with a clear
    "bridge not configured" error instead of vanishing mid-session.
- **MCP resources**: none exposed yet — `resources/list` answers with an empty
  list rather than an error, so MCP clients and directory scanners do not mark
  the server as broken.
- **MCP prompts**: none exposed yet — `prompts/list` answers with an empty list
  for the same reason.
- **Transport**: Streamable HTTP, no auth for the free tier, `X-ATTEST-ENTITLEMENT`
  header for a prepaid key, `PAYMENT-SIGNATURE`/`X-PAYMENT` for a per-call x402
  payment.

### Connect an MCP client

```json
{
  "mcpServers": {
    "attest": { "url": "https://attest.rta.lat/mcp" }
  }
}
```

Claude Desktop, Claude Code, Cursor, Codex, VS Code and any other MCP client
that supports remote Streamable HTTP servers work with that block as is.

We use it ourselves: our own agents call this exact URL through the MCP SDK
in `opencode.jsonc`, so the server is exercised by real traffic every day, not
only by the tests.



### Tool reference

Both tools take plain JSON. No SDK is needed.

#### `verify_artifact`

| field | type | required | meaning |
|---|---|---|---|
| `artifact` | object \| array \| string | yes | what to verify |
| `schema` | object | no | JSON Schema the artifact must satisfy |
| `source` | string | no | where the artifact came from; recorded in the verdict |

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"verify_artifact",
           "arguments":{"artifact":{"findings":[{"rule":"x","severity":"high"}]},
                        "source":"nightly-scan"}}}
```

Response (one verdict, signed):

```json
{"verdict":"accept","trust_score":0.86,
 "checks":[{"layer":"schema","ok":true},{"layer":"emptiness","ok":true},
           {"layer":"generation","ok":true},{"layer":"authority","ok":true}],
 "findings":[],
 "signature":{"algorithm":"ed25519","public_key":"...","signature":"..."}}
```

#### `verify_artifact_batch`

| field | type | required | meaning |
|---|---|---|---|
| `artifacts` | array | yes | one verdict per element |
| `schema` | object | no | applied to every element |
| `source` | string | no | recorded once for the batch |

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call",
 "params":{"name":"verify_artifact_batch",
           "arguments":{"artifacts":[{"a":1},{"a":2}],"source":"batch"}}}
```

Response: `{"verdicts":[...],"summary":{"accepted":1,"rejected":1,"total":2}}`.

### When the free tier runs out

The free tier is **20 checks per day per client**. On the 21st call the server answers
**HTTP 402** with a body naming the limit, and a `Payment-Required` header carrying the
x402 terms:

```json
{"error":"free limit reached (20/20 per day)","free_remaining":0,"resets_at":"00:00 UTC",
 "x402":{"enabled":true,"network":"eip155:8453","asset":"0x8335...2913",
         "price_atoms":5000,"pay_to":"0x..."}}
```

An MCP client sees that text as a tool error — nothing hangs and nothing is retried
blindly. To continue, repeat the same call with `PAYMENT-SIGNATURE` (per-call x402,
USDC on Base) or with `X-ATTEST-ENTITLEMENT` (a 30-day prepaid key). The free quota
resets at 00:00 UTC.


## Maintenance

Maintained and general-purpose, MIT-licensed. The hosted node at
`https://attest.rta.lat` is production and is exercised daily by our own agents, so it
is not a demo that rots. Breaking protocol changes get a major bump in `CHANGELOG.md`;
issues and pull requests are reviewed. Security reports follow `SECURITY.md`.


## Use it in CI

A one-off check in a browser does not protect a pipeline. This repository ships a composite
GitHub Action: it verifies every artifact file and fails the build on a rejection.
Pinned to `v1` — [release v1.0.0](https://github.com/mrpkk/attest/releases/tag/v1.0.0).

```yaml
- uses: mrpkk/attest@v1
  with:
    paths: 'reports/*.json'
    schema: 'schemas/scan.schema.json'   # optional
    fail-on: reject                      # or 'any' to fail on violations too
```

Without Actions, the same check runs locally:

```bash
python3 scripts/verify_artifacts.py 'reports/*.json' --fail-on reject
```

Exit codes: `0` all accepted, `1` a rejection or an error, `2` nothing matched. A network
error or an exhausted free quota is reported as an error — never as "accepted".

## Use it from your agent

```json
{
  "mcpServers": {
    "attest": { "url": "https://attest.rta.lat/mcp" }
  }
}
```

That block is not a doc snippet — it is how our own agents call this server
(the same public URL, no key, no signup).

Tools: `verify_artifact`, `verify_artifact_batch`. 20 free checks per day, then
$0.005 per call over x402 (USDC, Base) or $9/30 days. India pricing: $4/30 days.
