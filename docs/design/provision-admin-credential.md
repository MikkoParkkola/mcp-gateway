# Design: an admin credential without a setup step

Status: draft for review, 2026-08-26. Tracked as MIK-7243. Blocks the release
carrying the CWE-346 fix, by decision: both ship together so no user meets a
default install with no admin path.

## SCOPE

FOR: after the ordinary install, an operator has admin without hand-editing
YAML, and the credential never lands anywhere it can leak.

OUT: authentication on by default for tool invocation.

That exclusion is load-bearing and the first draft broke it. Enabling
`auth.enabled` gates EVERY path, so a starter config that turns it on without
exempting the MCP endpoint breaks the client the operator already configured —
a worse regression than the missing dashboard it set out to fix. The generated
config therefore lists `/health` and `/mcp` under `auth.public_paths`: tools stay
open, management does not. A reviewer caught this as HIGH/CERTAIN.

## Why now

Removing admin from the anonymous identity left a default install with **no**
admin path: the six management tools are unavailable and `/dashboard` serves an
explanation. The remedy the docs give — `auth.enabled = true` with a bearer
token — requires editing YAML and, per MIK-7249, does not even apply without a
restart.

Authentication also closes two adversaries nothing else does: a second OS user
on the machine, and any network caller. Loopback isolates machines, not users.

## What already exists

`mcp-gateway setup wizard --configure-client` writes MCP configuration into
eight clients (`src/commands/config_export/mod.rs:18-27`). It carries no
credentials: `build_gateway_entry` emits one uniform shape for every client,
`{"url": "http://host:port/mcp"}` in proxy mode and a subprocess spawn in stdio
mode (`:100-122`).

There is **no documented way for an MCP client to use proxy mode with
authentication**. The only `Authorization` example in the docs is a curl
command. That is likely why authentication went unused, and why anonymous-admin
became the de facto mode.

## Unknowns, closed before this froze

| Question | How | Answer | What it changed |
|---|---|---|---|
| Can the eight client formats carry a credential? | Searched the clients' own documentation | The standard shape is supported — Cursor documents static bearer headers for remote servers, and `claude mcp add --transport http --header "Authorization: Bearer …"` exists | Kept proxy mode viable rather than abandoning it |
| Does every client actually honour it? | Same search | **No, and this is the load-bearing find.** There is a report that Claude Code does not attach configured `headers` for a `type: http` server. One source, possibly stale | Made stdio the reliable authenticated path and proxy the one that must be verified per client |
| Does stdio mode need a credential at all? | Read `build_gateway_entry` | No. The client spawns the gateway as a subprocess. No port, no header, nothing to leak | Made stdio the recommended shape for a single authenticated user |
| Is `bearer_token: "auto"` the mechanism? | Read `config/features/auth.rs:111-121` | No. It mints a fresh token on every call and never persists or prints it | Required real storage rather than reuse |

**Deferred unknown**: whether the Claude Code header report is current.
Owner: this ticket. Resolution: configure a gateway with auth on, point Claude
Code at it in proxy mode, and observe whether the header arrives. When: before
the proxy-mode path is documented as supported. If it resolves badly: proxy
mode with authentication is documented as unsupported for that client and stdio
is the only recommended shape for it. **Nothing that depends on this answer is
implemented until it is run.**

## Decision A — stdio carries no admin, and the design said otherwise

An earlier draft called stdio "the recommended authenticated shape" because it
needs no credential. All three reviewers refuted it independently, and they are
right: the stdio dispatcher supplies `MetaMcpCallerContext::default()`, whose
`is_admin` is false, and the admin tools are gated on the HTTP path. So stdio
users get tools and **no admin at all** — the very problem this design exists to
close.

Stdio remains the shape that needs no credential and exposes no port, which is
worth saying. It is not an admin path, and the earlier claim is withdrawn rather
than quietly dropped. Admin runs over the local HTTP surface, through the link
`serve` prints.

## Superseded — the original Decision A

`resolve_mode` prefers proxy when a daemon is reachable. With authentication on
and no verified header path, that preference points at the shape most likely to
fail. It flips: when authentication is enabled and the client is one whose
header support is unverified, the wizard writes stdio.

Costs the shared daemon — warm backends and one process for several clients.
Stated, not hidden. An operator who wants the daemon sets proxy mode explicitly.

## Decision B — the token is generated and written to the config, not the keychain

The keychain was the first choice and is wrong. `src/secrets.rs` reads; it does
not write. `auth.bearer_token` accepts a literal, `env:VAR`, or `auto` — no
keychain reference exists. And secret-service is absent on Windows and on plenty
of Linux installs, so provisioning would fail exactly where a fresh install
needs it most. Reviewers found all three.

The token is generated at `init` and written into `gateway.yaml`, which is
created readable only by the owner (MIK-7245, which is why that ticket came
first). The generated comment says not to commit it.

## Superseded — the original Decision B

Generated on first `setup wizard`, stored via the existing keychain integration
(`src/secrets.rs`), and referenced from `gateway.yaml` as `env:` or a keychain
reference — **never written literally**. Three of the eight client config files
are project-relative (`.cursor/mcp.json`, `.vscode/mcp.json`,
`.cline/mcp_servers.json`) and get committed.

Config files are already written `0600` (MIK-7245), which is a precondition for
this and is why that ticket came first.

## Decision C — the dashboard gets a one-time bootstrap, not a token in a URL

`serve` prints a link that carries a single-use bootstrap value, which the page
exchanges for a session and then removes from the address bar. A token in a
query string lands in shell history, in this gateway's own request logs
(`TraceLayer` is on the stack), and in the `Referer` of any outbound link.

## Accepted residual

An operator upgrading an existing install does not get a credential, because
`init` writes the starter config and an existing config is never rewritten.
`serve` names the command in that case, which is a message rather than a
mechanism. Raised by a reviewer as HIGH/CERTAIN and accepted for this change:
rewriting a config the operator owns is the kind of surprise that starts the
next report. Tracked separately.

Stdio users have no admin path. See Decision A.
