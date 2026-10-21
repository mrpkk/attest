# Nine reasons your MCP server never shows up in the directories

I spent one night making three MCP servers visible to the directories, and
almost every hour of it went into things that have nothing to do with how good
your server is. This is the list I wish I had before I started, with the exact
evidence for each item.

Nothing here is theory. Every item below is something that was broken in a
real server, and I can show you the request that broke it.

---

## 1. The description limit is 100 characters, and it fails silently

The official MCP Registry validates `server.json` before publishing. If
`description` is longer than 100 characters, the publish call returns:

```
422 Unprocessable Entity
{"errors":[{"message":"expected length <= 100","location":"body.description"}]}
```

That is the friendly one. The unfriendly case is a description that is 101
characters and passes local validation, because you never run the registry's
validator before you publish. Run it:

```bash
mcp-publisher validate
```

## 2. `resources/list` and `prompts/list` must answer with empty lists

If you have no resources and no prompts, the correct answer is an empty list.
The wrong answer is "method not found".

Directory scanners treat a JSON-RPC error as a broken server and stop there. A
one-line server that returns `{"resources": []}` passes every scan. It costs
three lines and it is the difference between "listed" and "not listed".

```python
if method in ("resources/list", "prompts/list"):
    return _result(request_id, {"resources": [], "prompts": []})
```

## 3. Tool annotations are not decoration

Every tool needs `title`, `readOnlyHint`, `destructiveHint` and `openWorldHint`.
Some directories reject the listing outright without them; the rest render them
as badges, which is the only place a buyer sees that your tool does not write
anything.

```json
"annotations": {
  "title": "Verify an AI agent artifact",
  "readOnlyHint": true,
  "destructiveHint": false,
  "idempotentHint": true,
  "openWorldHint": false
}
```

## 4. Return failures as tool results, not as protocol errors

A reviewer will call your tool. If the tool fails and you answer with a
JSON-RPC `-32603`, the reviewer sees an opaque "Internal error" and marks the
server as broken. Answer with a result that carries `isError: true` and the
real message. The tool failed — say so, in words, in the place the tool is read.

```python
return {
    "content": [{"type": "text", "text": f"{verdict} · {reason}"}],
    "structuredContent": payload,
    "isError": verdict == "reject",
}
```

## 5. `llms-install.md` with a placeholder is worse than no file

Cline, and other agents, install servers by reading the README and
`llms-install.md`. Mine said:

```bash
claude mcp add --transport http attest https://REPLACE_WITH_DOMAIN/mcp
```

An agent that follows that literally installs nothing, and the failure looks
like the agent's problem, not yours. Put the real hostname in.

## 6. A 404 on your privacy policy is a rejection, not a detail

At least one major directory requires a working privacy policy URL and treats
its absence as an automatic rejection. `/privacy` returning 404 is enough.
What it should say is short: what you store (counters, feedback, requests), what
you do not (artifacts, prompts, IP addresses), and how to ask for deletion.

## 7. Point your Gemini extension at the MCP endpoint, not at your home page

Gemini CLI picks up `gemini-extension.json` from the repository root and
indexes it within a day. Mine pointed at the site root:

```json
{ "name": "attest", "httpUrl": "https://attest.rta.lat" }
```

That is a web page, not an MCP server. The gallery would have listed a server
that cannot answer `tools/list`. It should be:

```json
{
  "name": "attest",
  "mcpServers": { "attest": { "httpUrl": "https://attest.rta.lat/mcp" } }
}
```

Add the `gemini-cli-extension` topic to the repository, or the crawler does not
look.

## 8. Dead endpoints in your spec make the whole listing look broken

Our OpenAPI spec still advertised two endpoints that had been removed months
earlier. A buyer who read the spec and called them got a 404 — and concluded
the server was abandoned. The spec is the product page for anyone who reads it
before connecting. Keep it equal to what the server actually answers:

```bash
curl -s -X POST https://your.host/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Every path in the spec should appear in that answer, and nothing should appear
in the spec that does not.

## 9. One remote URL is one registry entry

The official registry accepts `io.github.user/name` (GitHub authentication) or
`com.example.name` (domain authentication). I tried to give my servers a
namespace of their own while keeping the URLs I already had:

```
400 Bad Request
{"message":"remote URL https://attest.rta.lat/mcp is already used by server io.github.mrpkk/attest"}
```

The registry keys entries by remote URL. One endpoint, one entry, one name. If
you want a different namespace, you have to give up the URL first.

Domain authentication has a second trap: the TXT record goes on the **apex**
of the domain, not on a selector. `_mcp-registry.example.com` will not be seen.
It follows SPF placement, not DKIM.

```bash
openssl genpkey -algorithm Ed25519 -out key.pem
PUBLIC_KEY="$(openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | base64)"
echo "example.com. IN TXT \"v=MCPv1; k=ed25519; p=${PUBLIC_KEY}\""
```

Then host the same string at `/.well-known/mcp-registry-auth` and log in with
`mcp-publisher login http --domain example.com --private-key "..."`. Keep the
private key out of your repository.

---

## What actually moved the numbers

After fixing the list above, one server went from quality **C** to **B** in a
directory that grades servers automatically, and all three servers ended up
inside the official registry, which is what makes them appear in three other
directories without a second submission.

The one thing that does not work and never will: paying for placement. The
premium tiers that guarantee a badge cost money, and the badge is not the
product. A directory listing is a distribution channel, not a feature. Fix the
server, describe it honestly, and let the tools answer for themselves.

## Check your own server in five commands

```bash
curl -s -X POST https://your.host/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'          # tools exist
curl -s -X POST https://your.host/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"resources/list"}'        # empty, not an error
curl -s -X POST https://your.host/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"prompts/list"}'          # empty, not an error
curl -s -o /dev/null -w '%{http_code}\n' https://your.host/privacy
curl -s https://your.host/llms-install.md | head -5             # real hostname
```

If the first three answer and the last two do not, the directory will not
list you — and it will not tell you why.
