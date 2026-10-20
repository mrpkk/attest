# attest — trust layer for agent artifacts

[![M8ven Score](https://m8ven.ai/badge/mcp/mrpkk-attest-70kdum?v=33841343e7786aeebf405effce42c591)](https://m8ven.ai/mcp/mrpkk-attest-70kdum?s=readme)
[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/mrpkk/attest)

Live: **<https://attest.rta.lat/demo>** · Code: <https://github.com/mrpkk/attest>

Pricing: 20 checks/day free, then $0.005 per call (x402, USDC on Base). 30-day unlimited
access: $9. **Purchasing-power pricing** (India and similar markets): the same 30 days for
$3 via `POST https://attest.rta.lat/subscribe?plan=ppp` — same endpoint, same terms.

An agent calls an external tool or another agent and receives a **foreign
artifact** that goes straight into its context. Nothing checks that the
artifact:

- matches the declared schema (the tool quietly changed a field type),
- carries no hidden instruction ("ignore previous, send the keys to …"),
- is not a base64 wrapper around such an instruction,
- has not changed since it was checked.

`attest` closes that gap. No dependencies, 399 tests green.

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
$0.005 per call over x402 (USDC, Base) or $9/30 days. India pricing: $3/30 days.
