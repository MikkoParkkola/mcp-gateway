# EVENTS.8: the operator's ChatGPT run

**Criterion (MIK-7630.EVENTS.8, `docs/requirements/RELEASE-4.0.0-scope-update.md`):**
"An end-to-end test drives a signed inbound webhook to a filtered subscription and a receiver that verifies every signature, and one ChatGPT run over a tunnel completes subscribe, verification, delivery and unsubscribe (MIK-7630 AC 7)."

The automated half is the CI test `end_to_end_with_a_signature_checking_receiver`
(`tests/mik_7630_events_delivery.rs`); its inbound POST is unsigned (the
fixture sets `require_signature: false`). This run is also the signed inbound
leg: the gateway here requires `X-Hub-Signature-256`, and `fire` records a
receipt (`fire.json`). The runbook grades nothing; the grader reads the
evidence it produces.

## What is automated, and what is not

Checked on release-line tip `bf42be6e2`, by a dry run on Spark that played
ChatGPT with a script over two real tunnels (the gateway under test, a
signature-checking receiver). Every row below passed; only the ChatGPT UI
clicks and ChatGPT's own reply are left to you.

| Prerequisite | State |
|---|---|
| Config: events on, a signed webhook route, API-key auth, audit log | `events8_run.py up` writes it (`events.enabled`, capability `github` with an HMAC `secret`, `webhooks.require_signature: true`) |
| Endpoint | a separate gateway on 127.0.0.1:39561; the live gateway (PID 53431) is never touched |
| Event source | `webhook.github.push.received`, filters `repo` and `ref`, fired by a signed `X-Hub-Signature-256` POST |
| OAuth | **gap, bridged**: the gateway is only a resource server (no authorization-server metadata, empty `authorization_servers`), and `events/subscribe` needs an authenticated principal, so ChatGPT cannot connect to it directly. `scripts/dev/mcp_events_oauth_shim.py` (test only, auto-approving) fronts it with RFC 9728 and RFC 8414 metadata, dynamic client registration and a PKCE token step |
| Tunnel | `cloudflared` quick tunnel to the shim, started by `up` with an explicit empty config (a default `config.yml` would answer 404) |
| ChatGPT side | a Work chat with plugin or developer-mode connectors enabled (MCP Events works in Work chats on ChatGPT web, or the desktop app with Work and Cloud selected) |

The shim approves every authorization request, so run it only for this
session and stop it afterwards: the tunnel URL is the only secret.

## The run

Run from a checkout of the release-line tip. Needs `cloudflared` and `python3`.

**1. Start the instance (terminal A).**

```
cargo build --release --bin mcp-gateway
python3 scripts/dev/events8_run.py up --gateway target/release/mcp-gateway
```

You should see `CONNECTOR URL (ChatGPT, OAuth, no client id needed):
https://<random>.trycloudflare.com/mcp`. Leave it running. (If the lead started
it on Spark, take the URL from them and skip this step; steps 4 and 5 then run
on Spark over SSH, in the same account, because `fire` and `evidence` read the
run directory and talk to the gateway on 127.0.0.1.) Terminal B must be on the
same machine and use the same `--dir` as terminal A. Evidence lands in
`~/events8-run/`.

**2. Connect ChatGPT.** In ChatGPT, create a plugin (or developer-mode
connector) with that MCP server URL and OAuth. Click through the sign-in; it
approves itself. The plugin page should list `webhook.github.push.received`
next to the gateway's tools. (If ChatGPT insists on an OAuth client ID or
refuses the server, stop: that is the result, send back what it says.)

**3. Subscribe (a Work chat).** Send: "Subscribe to
webhook.github.push.received with repo demo/repo. When one arrives, tell me
its ref."

**4. Fire the event (terminal B, same checkout).**

```
python3 scripts/dev/events8_run.py fire
```

It refuses until ChatGPT's subscribe was accepted. Then it prints
`inbound signed webhook answered 200` and `ChatGPT should now report this
ref: refs/heads/events8-<hex>` (a fresh ref per run). Within seconds
ChatGPT's chat should state that ref. Copy the reply.

**5. Unsubscribe, then capture.** Send: "Stop monitoring that." Then, in
terminal B:

```
python3 scripts/dev/events8_run.py evidence
```

It prints eight PASS lines and `AUTOMATED CHECKS: PASS`; a stale or
out-of-order log, an error answer, or a delivery for another subscription
fails. Press Ctrl-C in
terminal A to close the tunnel. Send back: `~/events8-run/evidence.json`,
`fire.json`, `shim.jsonl`, `audit.jsonl` from the same directory, and
ChatGPT's reply from step 4.

## Reading the result

The criterion needs one ChatGPT run that completes subscribe, verification,
delivery and unsubscribe. The grader reads, in order:

| Check | Source |
|---|---|
| OAuth token issued; `server/discover`; `events/list` | `shim.jsonl` (method names and statuses only) |
| `events/subscribe` answered with an `id` | `shim.jsonl` |
| Verification handshake passed (`events.verification`, `detail: verified`) | `audit.jsonl` |
| Signed inbound webhook accepted (status 200, body hash, delivery id, ref) | `fire.json` |
| Signed delivery accepted 2xx for that subscription (`events.delivery_outcome`, `delivered: true`) | `audit.jsonl` |
| `events/unsubscribe` answered | `shim.jsonl` |
| ChatGPT told you the ref in `fire.json` | your pasted reply |

The files hold no tokens, signing secrets, callback paths or bodies (the audit
log carries hashes and a callback host). A failed check names what to rerun:
no `events/list` means ChatGPT never saw events (rescan the plugin); a missing
`events.verification` means the subscribe was refused before the handshake
(see the `events/subscribe` row of `shim.jsonl`, `error_code`).
The run does not grade EVENTS.8; whoever grades it cites these files.
