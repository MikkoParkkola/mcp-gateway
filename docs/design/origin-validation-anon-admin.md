# Design: close unauthenticated admin at /mcp

Status: draft for review, 2026-08-25. Prompted by an external report (Pluto
Security, CWE-346) confirmed at source.

## SCOPE

FOR: a caller with no credential must not be able to (a) reach `/mcp` from a
web page, or (b) hold admin.

OUT, filed not fixed: auth on by default; the destructive-confirmation gate's
fail-open path; rate limiting for the anonymous identity; the six capabilities
that take a caller-supplied URL.

## Problem, measured against main @634d23dc

1. `src/gateway/router/mod.rs:155-186` — no Host or Origin check, no CORS layer
   on any route. Zero hits repo-wide for `CorsLayer` / `allow_origin`.
2. `src/gateway/auth.rs:419-427` — auth disabled yields `admin: true`,
   `backends: ["*"]`, `rate_limit: 0`.
3. `src/config/features/auth.rs:19` — `enabled` defaults to false.
4. `src/gateway/router/handlers.rs:373-387` — the body is read raw. No
   Content-Type check, no session requirement (`get_or_create_session` creates
   one when the header is absent), no initialize handshake before `tools/call`.

Three delivery paths follow, in increasing order of what survives mitigation:

- DNS rebinding, as reported. Needs to read replies. Chrome 141/142 now gate
  public-to-loopback behind a permission prompt, so this prompts on current
  Chromium and works silently elsewhere.
- Blind cross-origin POST. Point 4 means `Content-Type: text/plain` is a CORS
  simple request: no preflight, no rebinding. The reply is unreadable, so this
  is write-only, and every side-effecting tool is a write.
- A local process running as the user. No browser involved. No mitigation in
  the list above touches it.

## Threat model — the adversaries, named

Missing from `SECURITY.md`, which lists defenses without stating what they
defend against. That omission is why this class stayed invisible: a gap in a
list of answers is not visible when the questions are unwritten.

| # | Adversary | Reaches the port | Stopped by |
|---|-----------|------------------|------------|
| 1 | Remote network attacker | No on a loopback bind. **Yes** in Docker, whose container default is `127.0.0.1`, so users must set `0.0.0.0` to reach it at all | Authentication only. Out of scope here |
| 2 | A web page the user visits | Yes | Decision 1 |
| 3 | Local process running as the user | Yes | Nothing. It reads the config, reads whatever the gateway reads, and forges any header. Not solvable at this layer |
| 4 | Another OS user on the same machine | **Yes — loopback isolates machines, not users** | Decision 2 downgrades it from admin to tool access. Authentication would close it. Out of scope here |
| 5 | A malicious backend MCP server | n/a | The six existing defenses |

This change addresses adversary 2 and half of adversary 4. It does not address
1 or 3, and says so rather than implying coverage.

## Decision 1 — validate the request's claimed target, ahead of auth

Four checks, in one middleware layer that runs **outside** authentication so a
cross-site request is refused before any identity, including the anonymous one,
is minted.

| Check | Rule | Why this rule |
|-------|------|---------------|
| `Origin` | Absent passes. Present must be allowlisted | A browser always attaches it to a scripted request; a non-browser MCP client never sends one. That asymmetry is the whole gate |
| `Sec-Fetch-Site` | Absent passes. `same-origin` and `none` pass. Anything else is refused | The Fetch standard omits `Origin` from a no-CORS GET, so the absent-Origin allowance would otherwise admit a hostile page opening SSE sessions. Browsers attach Fetch Metadata to every request, that GET included |
| `Host` / HTTP/2 `:authority` | Absent passes. Present must name this gateway | Refuses a rebound name. HTTP/2 carries no `Host` header, so reading only `Host` would leave the gate inert on the protocol browsers prefer |
| exempt paths | `/health` only | A monitoring probe carries no authority. `/metrics`, `/.well-known/*` and the key-server routes are merged outside this layer already |

The allow list is the loopback spellings of the bind at the bind port, the
configured bind address itself, and the `server.public_url` origin.

**`public_url` is re-read from the live config on every request.** It is
hot-reloadable and the RFC 9728 metadata handler already reads it live
(`src/config_reload/mod.rs:343-349`); a snapshot would refuse the very origin
the gateway advertises the moment an operator reloads a changed value. Bind
host and port are snapshotted instead, because those are restart-required, so a
snapshot cannot drift from the listener.

**When the bind is not loopback and no `public_url` is set, `Host` is checked
for being numeric rather than for naming a known host.** Such a gateway answers
at an address this process cannot predict, so the name cannot be checked. The
form can be, and that is sufficient: DNS rebinding requires a hostname to
rebind, while a client reaching a bare gateway over the network dials an
address. Names are therefore refused and numeric hosts admitted. A `public_url`
set later restores full gating, because it supplies a name we can judge.

An earlier revision skipped the check entirely here, on the claim that
"rebinding needs a loopback bind to be worth mounting". That claim is false:
rebinding reaches any address the victim's browser can, a LAN address included.
After a rebind the page is same-origin with the gateway, so a no-CORS GET sends
no `Origin`, reports `Sec-Fetch-Site: same-origin`, and would have passed an
unchecked `Host`. The numeric rule closes that without refusing legitimate
callers. Caught in design review, before it shipped.

### Rejected: an operator allow-list of extra browser origins

Built as `server.allowed_origins`, then removed. It could never work: a
cross-origin browser client also needs CORS preflight responses, which this
gate does not serve, so the setting would name origins that still could not
call the gateway. **Measured, not reasoned** — a request from an allowlisted
origin returned 403, because the unconditional `Sec-Fetch-Site` check refused
it after the Origin check passed it. Three independent reviewers found the same
defect. Shipping a setting that cannot do what its name says is worse than not
having one. Serve the page from the gateway's own origin, or use a non-browser
client.

### Rejected: a CORS layer

`tower-http`'s `cors` feature is already compiled in (`Cargo.toml:61`) and was
never used. It would not have helped: DNS rebinding makes the request
same-origin, so CORS never fires. This is why the check is hand-rolled.

### What Decision 1 does not do

It stops browsers. It does nothing about a process running as the same user,
which can omit or forge every header it reads. Anything claiming otherwise
would be false comfort.

## Decision 2 — anonymous is not admin

Auth disabled yields `admin: false`. Admin requires a credential.

`backends` stays `["*"]`. Note `can_access_backend` returns true for an EMPTY
list, so emptying the vector grants everything rather than nothing; a fix that
"clears backends" is a no-op wearing a fix's clothes.

Rejected alternative: a new `allow_anonymous_admin` config flag. The durable
reason is that the escape hatch already exists and is one line: `auth.enabled =
true` with a bearer token already yields admin, so a second mechanism would be
a duplicate route to the same grant. The weaker argument, that anyone who sets
the flag reintroduces the hole, does not survive contact with the fact that an
operator can already choose an insecure posture deliberately. Duplication is
the reason; danger is not.

Accepted cost, stated plainly: an operator running with no config loses the six
admin meta-tools and the admin dashboard view. That is a breaking change in the
default local case. The startup warning must name the fix.

## Why both

Decision 1 alone leaves the local-process path fully open. Decision 2 alone
leaves browser-driven reads of every non-admin tool. Neither is sufficient.

## Accepted residual risk

Stated so a reader can disagree with it, rather than discovering it later.

| Residual | Why accepted here |
|----------|-------------------|
| A local process running as the user has full tool access and forges any header | Not solvable at this layer. Needs OS-level isolation. Recorded in the threat model above as adversary 3; deliberately not ticketed, because there is no fix to schedule |
| A second OS user on the machine reaches every tool with the gateway's credentials, though no longer as admin | Needs authentication on by default. MIK-7243 |
| Docker deployments bind `0.0.0.0` with auth off and are exposed to the container network | Pre-existing, worse than the reported bug, outside this scope. Warns loudly at startup today. MIK-7244 |
| Admin is unreachable in a default local install until the operator enables auth | Deliberate. MIK-7243 provisions the credential through the existing setup wizard so nobody meets this |
| Config files are not written `0600`, so a token stored in one is readable by other local users | Pre-existing. MIK-7245, and blocking for MIK-7243 |
| The destructive-confirmation gate proceeds when a client omits the elicitation capability | Reduced by Decision 2, since the one covered tool now needs admin. MIK-7246 |
| Six capabilities take a caller-supplied URL, which is an out-of-band channel for a caller who cannot read responses | Narrow today, and nothing stops the count growing. MIK-7247 |

## Decision history

Kept because the reasoning matters more than the outcome, and two of these were
reversals.

| Round | Change | Cause |
|-------|--------|-------|
| 1 | Origin + Host validation, anonymous loses admin | The report, confirmed at source |
| 2 | Added `Sec-Fetch-Site` | A reviewer noted the Fetch standard omits `Origin` from a no-CORS GET, so the absent-Origin allowance admitted one |
| 2 | Host gating skipped for a non-loopback bind with no `public_url` | The first guard made a `0.0.0.0` bind refuse every request. Self-inflicted, caught by review |
| 3 | `server.allowed_origins` deleted | Measured non-functional. Three reviewers, one probe |
| 3 | HTTP/2 `:authority` read when `Host` is absent | The gate was inert over HTTP/2 |
| 3 | `public_url` re-read live | It is hot-reloadable; the snapshot would refuse a reloaded value |
| 3 | One constructor, not two | The two-constructor form silently dropped `public_url`, which is how the next defect gets written |

## Unknowns, resolved before this froze

- Does `tools/call` require a session or an initialize handshake first? Read
  `handlers.rs:414-470`. No, `get_or_create_session` creates on demand and the
  method dispatches directly. Changed the finding from read-only to write-capable.
- Does any capability take a caller-supplied URL, making exfiltration possible?
  `rg -l 'name: url' capabilities/`. Six of 125+. `linear_create_webhook` is the
  worst. Kept OUT of scope, and the count is why: narrow enough to defer.
- Does `/ui/api/config` leak secret values? Read `ui/mod.rs:593-618`. Names,
  transport and running state only. Changed severity: keys are usable, not readable.

## Test plan

One row per acceptance criterion. Every row below names a case that exists and
passes; an empty evidence cell would be the finding.

| AC | Criterion | Case | Level | Type |
|----|-----------|------|-------|------|
| AC1 | Cross-site Origin refused | `mcp_rejects_foreign_origin` | integration | negative |
| AC2 | Absent Origin passes, so CLI clients keep working | `mcp_allows_absent_origin` | integration | positive |
| AC3 | Bind-address Origin passes | `mcp_allows_bind_origin` | integration | positive |
| AC4 | Forged Host refused | `mcp_rejects_foreign_host` | integration | negative |
| AC5 | Loopback Host spellings pass | `allows_loopback_host_spellings` | unit | boundary |
| AC6 | Health stays reachable | `health_ignores_origin_gate` | integration | positive |
| AC7 | Auth disabled yields `admin: false` | `anonymous_is_not_admin` | unit | negative |
| AC8 | Anonymous still reaches non-admin tools | `anonymous_retains_backend_access` | unit | positive |
| AC9 | Admin meta-tools refuse anonymous | `anonymous_denied_admin_meta_tools` | unit | negative |
| AC10 | A bearer-token client is still admin | `bearer_client_remains_admin` | unit | regression |
| AC11 | No-CORS GET refused via Fetch Metadata | `mcp_rejects_no_cors_get_from_a_page` | integration | negative |
| AC12 | Opaque `Origin: null` refused | `mcp_rejects_opaque_origin` | integration | negative |
| AC13 | Same-origin browser request passes | `mcp_allows_same_origin_browser_request` | integration | positive |
| AC14 | HTTP/2 `:authority` refused when foreign | `mcp_rejects_foreign_authority_without_host_header` | integration | negative |
| AC15 | Wildcard bind stays reachable at a numeric host | `non_loopback_bind_stays_reachable` | unit | boundary |
| AC20 | Wildcard bind refuses a named host | `non_loopback_bind_refuses_a_named_host` | unit | negative |
| AC21 | The middleware applies the wildcard rule on the real route | `wildcard_bind_refuses_a_rebound_name_through_the_middleware`, `wildcard_bind_admits_a_numeric_host_through_the_middleware` | integration | negative, positive |
| AC16 | Wildcard bind with `public_url` gates Host again | `non_loopback_bind_with_public_url_gates_host` | unit | boundary |
| AC17 | A reloaded `public_url` takes effect without a restart | `public_url_change_is_picked_up_without_a_restart` | unit | regression |
| AC18 | The configured bind address is an allowed origin | `bind_address_origin_is_always_allowed` | unit | boundary |
| AC19 | The management API refuses anonymous | `anonymous_is_refused_admin_endpoints` | integration | negative |

Three failure modes a coverage count cannot see, so they are named:

- AC8 exists because `can_access_backend` returns true for an EMPTY backends
  list. A case asserting "anonymous has no backends" by emptying the vector
  would pass while granting everything. It asserts reachability, not the field.
- Every Origin case sends a valid JSON-RPC body, so a refusal is the gate and
  never a parse error. A 400 would prove nothing.
- AC14 asserts the `Host` header is absent before it asserts the refusal. Without
  that, the case would pass through the `Host` path and never exercise
  `:authority` at all.

### Order, stated honestly

Written before the implementation and failing first: AC1-AC10, AC14-AC18.
Retrofitted after the code existed: AC11, AC12, AC13, AC19. AC11 carries a
falsification probe — removing the Fetch Metadata check made it fail on its own
assertion, and restoring it made it pass. AC12 and AC13 would have passed
against the round-1 code; they are coverage, not regression guards, and are not
claimed as more.
