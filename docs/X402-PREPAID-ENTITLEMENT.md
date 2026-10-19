# x402 has no subscriptions — here's what we built instead

We sell an API call for $0.005 over [x402](https://x402.org): you send an artifact, we verify it, you get a signed verdict. It has been live for a few weeks. The first question we got from real users was not about the checks. It was:

> "Can I just pay monthly?"

Fair question. Every SaaS tool has a monthly plan. So we went looking for the subscription primitive in x402 — and found that there isn't one. Not "not yet". Not "coming in v3". There is no notion of recurrence in the protocol at all.

Here is what we learned, and the pattern we shipped instead: a **prepaid entitlement token**. One payment buys 30 days; after that the token is dead and buying again is an explicit act.

## What x402 actually is

x402 is a payment layer for HTTP. The server answers a request with `402 Payment Required` and a machine-readable challenge; the client signs a stablecoin authorization and retries with it; the server (or a facilitator) verifies and settles. No account, no API key, no card.

Our live challenge (trimmed) looks like this:

```json
{
  "x402Version": 2,
  "resource": {
    "url": "https://attest.rta.lat/verify",
    "description": "Verify an agent artifact",
    "mimeType": "application/json"
  },
  "accepts": [{
    "scheme": "exact",
    "network": "eip155:8453",
    "amount": "5000",
    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "payTo": "0xefCD6886f73064ea9EcbaA4741Ef1309A0885C59",
    "maxTimeoutSeconds": 300,
    "extra": { "name": "USD Coin", "version": "2" }
  }]
}
```

`amount` is in atomic units: 5000 = $0.005 of USDC on Base. The client signs an EIP-3009 `transferWithAuthorization` — a one-shot permission to move that exact amount, to that exact address, before `maxTimeoutSeconds` runs out. The facilitator submits it, pays the gas, and returns a receipt. The user never needs ETH.

That design is deliberately narrow. It is also why a subscription cannot be expressed in it.

## Why subscriptions do not fit

Three hard reasons — not opinions, properties of the protocol:

**1. Every payment is a fresh signature.** EIP-3009 authorizes one amount, one payee, one nonce, one deadline. There is nothing to "charge again next month" — next month's charge would need a new signature, at that moment, for that amount. A recurring debit would require a standing authorization, and x402 has no such object.

**2. The protocol stores nothing.** No customer record, no payment method, no mandate to debit later. The server gets a signed authorization and a settlement receipt. If you want a subscription, the subscription state is *yours* to keep — the protocol will not hold it for you.

**3. A 402 challenge is one-shot by construction.** The nonce must be accepted exactly once. If your server forgets its accepted nonces on restart, you have either a replay window (paid signatures accepted twice) or honest clients rejected with "nonce was never issued". We hit both failure modes in a sibling service before moving nonce state to disk. None of this is normative for subscriptions — it is just the mechanics of making one-shot payments safe.

So when a user asks for "monthly", what they actually want is not a debit mandate. They want: *pay once, stop thinking about per-call payments for a while.*

## The pattern: prepaid entitlement

We ship exactly that, with no protocol surgery:

1. The client pays **9 USDC once** over x402.
2. The server issues a **signed token**: `{subject, plan, issued_at, valid_until}` signed with Ed25519 — the same key that signs our verdicts.
3. The client presents it in `X-ATTEST-ENTITLEMENT` on each call.
4. The server verifies **the signature and the expiry**, not a database row. Expired means expired: the free tier simply resumes.

Relevant part of the implementation (simplified from [the repo](https://github.com/mrpkk/attest)):

```python
def issue(subject: str, days: int = 30) -> dict:
    now = int(time.time())
    payload = {"subject": subject, "plan": "unlimited-30d",
               "issued_at": now, "valid_until": now + days * 86400}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signed = sign(body)  # Ed25519
    return {"token": json.dumps({"payload": payload,
                                 "signature": signed.signature,
                                 "public_key": signed.public_key,
                                 "algorithm": "ed25519"}),
            "valid_until": payload["valid_until"],
            "auto_renews": False}
```

Two details that matter more than they look:

**The verifier refuses to trust the key carried inside the token.** This is the classic JWT `alg: none` mistake in another costume. A token must be checked against a key the verifier obtained out of band — for us, the service's published Ed25519 fingerprint. Otherwise anyone who reads the source (it is open) mints their own "unlimited" token in a minute.

**No auto-renewal is a feature, not a gap.** When the token expires, nothing is charged, nothing is silently renewed, and the free tier comes back. Renewal is an explicit purchase. That is why the `issue` response literally contains `"auto_renews": False` — the client should never have to wonder.

## What this buys each side

For the buyer:

- One payment, no card on file, no renewal trap.
- The token can be verified **offline**: the same Ed25519 key that signs verdicts signs entitlements, so an agent can check expiry and authenticity without calling us.
- Expiry is honest. The API says "valid for another 12 days", not "we'll figure out billing".

For us:

- No refunds pipeline for accidental renewals — there are no renewals.
- No stored payment methods, so no PCI surface and nothing to leak.
- Revenue is realized up front, which is what a small API actually needs to survive its own settlement costs.

## Honest limits

This pattern is not a subscription, and pretending otherwise would be the same lie we avoid in our verdicts:

- **It is a bearer token.** Whoever holds it can use it. The `subject` field names the payer, but possession is the check — same as an API key.
- **No revocation, only expiry.** We cannot un-issue a token; if it leaks, the blast radius is its remaining days. If you need revocation, you need server-side state and a lookup on every call — a different trade.
- **No refunds after issue**, and price changes apply to the next purchase, never retroactively.
- **No proration.** A 30-day token starts when it starts.

## The numbers, because they set the shape

- $0.005 per call, 20 free checks per day on the free tier.
- Measured settlement cost on Base: about **$0.00146** per transfer (≈90k gas at ETH $2,702 at the time we measured). At $0.005 that is a ~29% rail — our code refuses to configure a price below 2× cost.
- 9 USDC for 30 days: at the per-call price that is 1,800 calls. If you make fewer, pay per call; if you make more, the token is the cheaper path. No "contact sales".

This is also why the free tier exists and is server-side: a per-IP allowance of 20 calls/day costs us a fraction of a cent and lets a developer decide with real data instead of a trial funnel.

## Try it

- Live endpoint: `https://attest.rta.lat` — `POST /verify`, free tier 20/day, then $0.005 over x402.
- Machine-readable: [`/llms.txt`](https://attest.rta.lat/llms.txt), [`/openapi.json`](https://attest.rta.lat/openapi.json).
- Source: [github.com/mrpkk/attest](https://github.com/mrpkk/attest) (Apache-2.0, no dependencies).

If you are building an x402 seller, the takeaway is one line: **the protocol stops at one payment on purpose — sell time with a signed prepaid token, and say "no auto-renew" out loud.**

That is a smaller promise than "subscription". It is also one the protocol can actually keep.
