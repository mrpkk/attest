# The test suite was green while the payment path was broken

We sell a 30-day access token for 9 USDC over x402. The per-call price is 0.005 USDC. Both numbers are in the same service, and until today the second one was quietly used to validate the first.

The bug, in one line: the payment verifier rebuilt the x402 challenge from the **per-call** price, then compared the client's authorization amount against it **exactly**. A subscription payment of 9,000,000 atomic units was checked against a requirement of 5,000 atomic units, and rejected:

```
amount 9000000 atoms is not equal to the quoted 5000
```

(The service's own message is in Russian; that is the translation.)

Every subscription purchase would have failed. Nobody noticed, because the tests were green.

## Why the tests were green

Here is the shape of an x402 payment flow:

1. The client asks for the resource. The server answers `402` with a challenge: amount, asset, network, payee.
2. The client signs an EIP-3009 authorization **for that exact amount** and retries.
3. The server verifies the authorization against the challenge it issued, then hands it to a facilitator for settlement.

The tests covered step 1 well. One of them decoded the challenge for `/subscribe` and asserted `amount = 9_000_000` — correct. Another exercised the free-tier exhaustion path. The settlement call had its own test with a stubbed transport.

What no test covered was **step 3 for the subscription endpoint**: which amount the verifier compares against. The verifier had no parameter for it, so the answer was always "the per-call price" — and the test double never complained, because the fake transport doesn't care about numbers.

Green tests, broken money path. The same failure mode we had hit before: **when the transport is stubbed, a test proves the wiring on one side of the seam and says nothing about the other side**.

## How we noticed

Not by testing. By changing the price.

We were adding a purchasing-power tier: the same 30 days for $3 instead of $9 for buyers in markets where $9 is a week of groceries. That forced the question "which amount does the verifier compare against?" into the open. The answer was: neither of them. It compared against the *third* number, the per-call price.

A price change exposed a bug that a test suite could not.

## The fix

The expected amount became a parameter:

```python
def _verify_payment(self, header_value: str, amount_atoms: int | None = None):
    token, challenge = build_challenge(
        resource=f"{self._base_url()}/verify",
        pay_to=self.x402_pay_to,
        price_atoms=(self.x402_price_atoms if amount_atoms is None
                     else int(amount_atoms)),
        ...
    )
```

`/verify` keeps using the per-call price. `/subscribe` passes the price of the plan it just quoted — $9 or $3 — so the challenge and the verification can never disagree again.

Three tests came with it:

1. the standard plan's challenge is 9,000,000 atoms;
2. the PPP plan's challenge is 3,000,000 atoms;
3. **the verifier is called with the plan's amount, not the per-call price** — the test monkeypatches `verify_payment` to record `requirement.amount_atoms` and asserts `[9_000_000, 3_000_000]`.

The third test is the one that would have caught the original bug. It does not need real signatures or a chain: it tests the seam, not the cryptography.

## Three lessons that transfer to any x402 seller

**1. A challenge amount is not a payment check.** If your code builds the 402 body and the verification separately, they are two places that must agree. Test the agreement, not just the body.

**2. Stubbed transports hide asymmetries.** Every test double makes some class of bug invisible. The honest move is to name what the double hides, and cover that seam separately — cheaply, with a recorder instead of a real signature.

**3. Price experiments are also correctness tests.** The moment a price becomes a variable, every hardcoded copy of it is a bug waiting for a plan. We found this one by adding a second price; a coupon or a discount would have found it the same way.

## The postscript: no subscription primitive, again

The reason the amount was hardcoded in the first place is that x402 has **no subscription object**. There is no recurring charge to validate — every payment is a one-shot EIP-3009 authorization for a specific amount. So "subscription" is really a prepaid entitlement: one payment, one signed token, thirty days. That design is what made the price a parameter in the challenge builder and, eventually, a parameter everywhere.

If you are building an x402 service with more than one price, look at every place the price appears. Ours had three; the third one was the one that mattered.

---

We run the checker described here: [attest](https://attest.rta.lat) verifies AI agent artifacts before you trust them, and the source (Apache-2.0, stdlib only) is at [github.com/mrpkk/attest](https://github.com/mrpkk/attest). The subscription code lives in `attest/service.py`; the bug is in the git history, because that is where bugs belong.
