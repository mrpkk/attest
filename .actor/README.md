# attest — trust layer for agent artifacts

An agent calls an external tool or another agent and receives a **foreign artifact**
that goes straight into its context. Nothing checks that the artifact matches the
declared schema, carries no hidden instruction, is not a base64 wrapper around one, and
has not changed since it was checked. `attest` closes that gap.

Four layers, four different questions:

1. **Form and emptiness** — a perfect form with empty content (ten identical findings)
   is `VALID_BUT_EMPTY`, not a pass.
2. **Poison** — hidden instructions, base64-wrapped payloads, prompt-injection shapes.
3. **Provenance** — Ed25519 signature over the artifact, verifiable without trust in
   the server.
4. **Entitlement** — who is allowed to use the result, checked before release.

Deny-by-default: anything unclassified is rejected.

## This Actor (standby mode)

The Actor runs `attest` as a ready HTTP server. Requests go to the standby URL:

| endpoint | what it does |
|---|---|
| `POST /verify` | check an artifact; returns verdict, violations, signals, provenance |
| `GET /health` | liveness |
| `POST /mcp` | MCP endpoint (`tools/call` → `verify`) for MCP-capable agents |
| `GET /demo` | browser form to try a check by hand |

Example:

```bash
curl -X POST "$ACTOR_STANDBY_URL/verify" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $APIFY_TOKEN" \
  -d '{"artifact": {"findings": ["a", "a", "a"]}, "source": "example"}'
```

Response: verdict (`accept` / `review` / `reject`), trust score, the exact rule that
fired, and an Ed25519 attestation of the result.

## Pricing

- Free tier: 5 checks/day per client.
- Above the free tier the hosted service settles on Base mainnet via x402 (USDC,
  no signup, ETH not required — the facilitator pays gas). Pricing and details:
  <https://attest.rta.lat/pricing>.
- Requests through the Apify platform are authenticated with your Apify token;
  platform-side pay-per-event pricing is configured on this Actor's Pricing tab.

## Source

Apache-2.0, Python standard library only: <https://github.com/mrpkk/attest> ·
399 tests green. The same code serves this Actor and the hosted endpoint.
