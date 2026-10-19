# Cloudflare error 1010 blocked our own API client — and the 530 that followed

Two failures hit the same API within one day, and they looked almost identical from the outside:

- a Python client got `403` with the body `error code: 1010` — while the exact same URL returned `200` in a browser;
- a few hours later, every hostname behind the same tunnel returned `530` with `error code: 1033`.

Neither error came from our service. Both were Cloudflare, and they have completely different causes. Here is what each one means, how to tell them apart in a minute, and what we changed so a machine client never hits them again.

## Error 1010: "The owner of this website has banned your access based on your browser's signature"

`1010` is **Browser Integrity Check** (BIC). It is part of the WAF that looks at the shape of the request — TLS fingerprint, headers, User-Agent — not at your API key. Anything that doesn't look like a normal browser gets a small HTML/plain-text page with `error code: 1010`, status `403`.

That is exactly what happened. Our MCP endpoint answered a browser fine, and a Python client using the default `Python-urllib/3.x` user agent got the BIC page. The body was not JSON, so the client reported a parse error — the real cause was invisible unless you looked at the raw response.

Why this matters for API products: **your API can be green in a browser and broken for every agent, SDK and script**. The failure is not 4xx from your app, it is closer to "your customer's client was classified as a bot".

### The 60-second diagnosis

1. Request the same URL four ways: browser, `curl`, `python -c "import urllib.request; ..."`, and your real client.
2. If some pass and some fail, print the raw body of the failing one. `error code: 1010` (or `1015`, `1020`) means Cloudflare, not your code.
3. Check the User-Agent. `python-requests` and `python-urllib` are the usual suspects; so are empty UAs.

### The fixes, in order of preference

**1. Exclude your API paths from BIC.** A WAF custom rule with "Skip → Browser Integrity Check" for `/api/*` (or your exact routes) keeps the bot protection on HTML and lets machine clients through. This is the fix we should have had from day one.

**2. Give machine clients a documented UA and headers.** If you publish an API, tell people what to send. A client sending `User-Agent: <product>/<version> (+https://docs)` and `Accept: application/json` is both polite and much less likely to be misclassified.

**3. Separate the hostnames.** `www.example.com` for humans with full bot protection, `api.example.com` for machines with BIC off. This also makes your caching and logging sane.

We did 1 and 2. The lesson we wrote into our checklist: **never test an API only in a browser**.

## Error 1033 / 530: the tunnel is gone, not the API

A few hours later the same hosts returned `530` with `error code: 1033`. That page says: "Argo Tunnel error — could not connect to the origin." In plain words: Cloudflare's edge had no healthy connector for our tunnel.

This one is not about your app at all. The service was running and answering on `127.0.0.1` the whole time — we checked, `200 OK` locally. The tunnel process had lost its connection to the edge and exited.

Two things we learned:

**`Restart=always` is not optional.** Our tunnel runs as a systemd user unit. When the process exits, systemd brings it back within seconds. A manually started `nohup cloudflared ...` dies silently and stays dead.

**Monitor the public URL, not localhost.** Our uptime check asked the local port, which was healthy the entire outage. If your health check never leaves the machine, it cannot see a tunnel failure. The check has to hit `https://your-domain/health`.

### The part that took longer: a stale VPN path

The second time the tunnel dropped, restarting it did not help. The logs said:

```
TLS handshake with edge error: read tcp 198.18.0.1:... -> 198.41.192.57:7844: i/o timeout
```

`198.18.0.1` is not a normal source address — it is the fake-IP gateway of a TUN interface from a VPN client. That machine routes Cloudflare's edge ranges (`198.41.192.0/24`, `198.41.200.0/24`) through the tunnel, because those ranges are blocked by the local ISP. The VPN session had gone stale, so every connector attempt timed out.

The fix was: restart the VPN client first, verify TCP to an edge IP, then restart the tunnel service. Restarting the tunnel first, as we did, only wastes a minute of reconnect backoff.

A short checklist we now run, in order:

```bash
systemctl --user status rta-tunnel        # is the connector process alive?
journalctl --user -u rta-tunnel -n 40     # what does the edge say?
curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health   # app alive?
curl -s -o /dev/null -w '%{http_code}' https://your.domain/health     # edge alive?
# if the edge handshakes time out and the source IP looks like a TUN gateway:
systemctl restart <vpn-client>
timeout 8 bash -c 'cat < /dev/null > /dev/tcp/198.41.192.57/7844'     # TCP to edge?
systemctl --user restart rta-tunnel
```

## The meta-lesson

Cloudflare is in front of your API. Its errors are not your API's errors, but your customers cannot tell the difference — a 1010 looks like "your service is broken", and a 530 looks like "your service is down". The only way to keep that from happening is to (a) keep bot protection off the machine paths, (b) let your tunnel be restarted automatically, and (c) check the public URL, not the local port.

Both bugs are boring once you know them. The expensive part was the hour we spent looking for a bug in our own code that was never there.

---

We build verification for AI agents: [attest](https://attest.rta.lat) checks a foreign artifact (schema, emptiness, provenance, authority) before an agent acts on it, and [drift](https://drift.rta.lat) enforces signed spending mandates before an agent pays. Both run behind exactly this kind of tunnel — which is why we now monitor them from the outside.
