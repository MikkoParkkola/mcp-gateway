<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# What identifies a caller once sessions are gone

**FOR:** choosing the identity that replaces the protocol session in two places that
lost it — the transparency log's correlation key (`MIK-7215.CONTROL.3a`) and the
lifecycle reaper's tracking key and clock (`MIK-7215.CONTROL.4`).

**OUT:**

- the continuation envelope and its wiring (cluster A). Both rows below hold whether or
  not a caller sends `_meta`; nothing here depends on A landing.
- `MIK-7215.CONTROL.5`, which governs whether a partially-correlated log may ship. This
  design removes the case that made 3a partial; it does not rule on 5.
- any change to `principal_of` or to how a credential is validated.
- the transparency log's format, retention or signing.

No code below.

## The problem

MCP 2026-07-28 removed protocol sessions. `src/gateway/session_lifecycle.rs:26` states
the consequence against itself: `on_disconnect` has nothing left to fire on, because
there is no session to DELETE and the stream whose close drove the other trigger is
replaced by `subscriptions/listen`. Two mechanisms were built on the session and now
rest on nothing:

1. The transparency log's correlation key. `src/gateway/meta_mcp/invoke.rs:1812-1816`
   reads a W3C trace id out of `_meta`, falls back to `session_id`, then to a literal
   placeholder string. After this release the middle rung is always absent, so any
   caller that does not send `_meta` is logged under the placeholder and correlates
   with nothing.
2. The lifecycle reaper. `SessionLifecycle::{register,track,reap}`
   (`src/gateway/session_lifecycle.rs:48`, `:107`, `:124`) replaced the disconnect
   trigger with a deadline. `rg SessionLifecycle` outside that module returns doc
   comments in `src/security/firewall/**` and nothing else: no construction, no holder,
   no caller of `track` or `reap` in production.

They are one design because they are blocked on the same unmade choice. The module's own
doc comment (`src/gateway/session_lifecycle.rs:100-102`) says the key is "whatever the
caller is identified by — a principal after the migration, a session before it" and
leaves the migration half unspecified. The log's fallback chain has the same hole.

## Measured constraints

| constraint | evidence |
|---|---|
| a per-invocation id already exists and the log ignores it | `trace::generate()` at `src/gateway/meta_mcp/invoke.rs:767`, threaded through the call as `trace_id` and recorded on the span at `:1012`; the correlation chain at `:1812-1816` does not consult it |
| a stable per-caller identity already exists | `principal_of` (`src/gateway/auth.rs:38-43`) is the first 12 hex of a SHA-256 over the validated secret, set from the bearer token at `:209`, the API key at `:224`, the OIDC client identity at `src/key_server/mod.rs:154` |
| a principal is not always present | the log's caller field already falls back for an unauthenticated call (`src/gateway/meta_mcp/invoke.rs:1806`) |
| ownership is not a blocker | `register` takes `impl Fn(&str) + Send + Sync + 'static`, so registration happens at startup and the firewall is only *called* from inside the closure — established at `docs/design/2026-09-01-residue-four-rows.md:82-85` |
| the repo has a settled shape for a periodic task | `tokio::spawn` + `tokio::time::interval` + `tokio::select!` on a shutdown receiver, twice: cost persistence at `src/gateway/server/mod.rs:1372-1382` (300s) and the health probe at `:1937-1942` (config-driven) |
| the module names its own residual | a key re-tracked between `reap`'s removal and `fire_cleanup` still has its handlers fired (`src/gateway/session_lifecycle.rs:76-77`) |

## The decision

**The correlation key is per-invocation; the lifecycle key is per-principal. They are
different keys, and that is the point.**

`CONTROL.3a` asks that a correlation key survive. A correlation key answers "which
request was this", so it must be unique per request — and one already is minted per
invocation. The fallback chain gains the minted `trace_id` as its final rung, and the
placeholder is reachable only when no id was minted, which is not a state the invoke
path can be in.

`CONTROL.4` asks that cleanup happen without a disconnect. Cleanup is per *caller*, not
per request — the state being freed belongs to whoever authenticated — so the tracking
key is the principal, and the deadline is refreshed on each invocation by that caller.
A caller with no principal registers no deadline and holds no per-caller state to free.

The reaper runs as its own interval task spawned at gateway startup, following the
shape the repo already uses twice, and subscribing to the same shutdown broadcast.

### Options considered, and why the others were rejected

**For the correlation key:**

| option | rejected because |
|---|---|
| use the principal as the fallback | a principal is not per-request. Two concurrent calls from one caller collapse to one key, which is worse than a placeholder because the collision is invisible. An anonymous caller has none |
| refuse a request that carries no `_meta` trace id | turns a logging gap into an availability regression, and punishes every legacy client for a criterion about the log |
| leave the placeholder and widen `CONTROL.3a` | the criterion says the key must survive; widening it to match what shipped is the drift the ledger exists to catch |

**For the reaper's clock:**

| option | rejected because |
|---|---|
| reuse the cost-persistence timer (`src/gateway/server/mod.rs:1372`) | couples caller-state retention to a 300s cost-snapshot cadence that exists for another reason and may be retuned for that reason |
| reap lazily on the next invocation | a caller that never returns is exactly the caller whose state must be freed; the trigger is absent precisely when it is needed. This is the disconnect defect one indirection along |
| keep `on_disconnect` and fire it from stream close | `subscriptions/listen` replaced the stream whose close drove it (`src/gateway/session_lifecycle.rs:26`); a modern caller may never open one |

**For the module's named residual** (`:76-77`, a key re-tracked mid-reap has its handlers
fired): out of scope to *remove*, in scope to *not widen*. A per-principal key refreshed
on invocation makes the window reachable by an ordinary caller, where a per-session key
made it rare. Scheduled below rather than accepted silently.

## Unknowns

| question | how it was settled | what came back | what it changed |
|---|---|---|---|
| does a per-invocation id already exist on the invoke path, or must one be minted? | read `src/gateway/meta_mcp/invoke.rs:767`, `:1012`, `:1812-1816` | `trace::generate()` mints one per call and the correlation chain does not read it | removed the option of minting a second id, and made 3a a three-line rung rather than a mechanism |
| is the reaper blocked on another module's ownership? | `rg SessionLifecycle` across `src/`, plus `register`'s signature at `src/gateway/session_lifecycle.rs:48` | zero production references; `register` takes a closure, so the firewall is called, not edited | removed "who owns it" as a design question; the remaining question is the clock |
| does the repo have an established periodic-task shape, or is one being invented? | read `src/gateway/server/mod.rs:1372-1382` and `:1937-1942` | two live examples of spawn + interval + shutdown-select | chose a purpose-built task over reusing a timer, and fixed its shape |
| is a principal always available to key on? | read the log's own caller fallback at `src/gateway/meta_mcp/invoke.rs:1806` | no — an unauthenticated call already falls back there | made "no principal, no deadline" an explicit case rather than an assumed one |

### Deferred

| field | value |
|---|---|
| question | does the re-track window at `src/gateway/session_lifecycle.rs:76-77` need closing before this ships? |
| owner | `MIK-7215`, the increment that wires the reaper |
| what would resolve it | a test that re-tracks a key between `reap`'s removal and `fire_cleanup` and asserts the handlers ran once, driven through the production registration path |
| when | with the wiring, not after it — a leak reintroduced by the fix for a leak is the shape this row is about |
| what if it resolves badly | if the window is reachable and cannot be closed without an ownership model the module lacks, the reaper ships holding a lock across `fire_cleanup` and the handler contract narrows to "cheap and non-blocking", which is a smaller change than the ownership model and is recorded as the fallback |

## Open for the operator

**How long is a departed caller's per-principal state retained?**

The reaper needs a TTL, and a TTL is an operator-visible retention number, not an
implementation detail: it decides how long the gateway holds state belonging to a caller
that has stopped calling. Wiring a value chosen while typing would make the criterion
read as met while the number nobody agreed to is the one that ships.

Recommendation: **15 minutes, configurable**. The reason is that it must exceed the
longest gap a live caller can leave between invocations without being treated as gone —
otherwise the reaper frees state under an active caller — and it must stay far below the
cost-persistence cadence's order of magnitude so that a departed caller's state is not
held for hours. Fifteen minutes clears an idle interactive client's think-time with a
wide margin and bounds retention to something an operator can state in a privacy notice.
A shorter value is safe to choose and only risks extra re-registration; a longer one
trades memory and retention exposure for nothing this design needs.
