# MIK-7272.SUB.4 — idempotency on all three routes

> Extends `docs/design/2026-08-31-sub-4-idempotency-wiring.md` with the two
> routes that document left open, and names one design event.

## §P0 SCOPE

**FOR:** a side-effecting call re-issued after a broken stream, with a new request
id, is refused-or-replayed on **every** route a client can reach — generic
`tools/call` over HTTP, `tools/call` over stdio, and the direct
`POST /mcp/{name}` bypass.

**OUT:**
- a config field for idempotency (team-lead ruling 2026-09-08: enabled
  unconditionally, no switch)
- TTL as a config field — it stays the module constant it already is
- ADR-008 rung 2 (client-native OAuth passthrough). Checked end to end at
  `docs/design/2026-08-31-sub-4-idempotency-wiring.md:543`; INV-3 is what binds
  the direct route, and it is already the reason that route re-enforces guards
  locally rather than being re-routed through `invoke_tool_traced`.
- re-routing the direct path through `invoke_tool_traced`. INV-2 states the
  bypass exists; this change re-enforces the guard **at** the bypass, the same
  shape `enforce_oauth_isolation` already uses there (`backend_handlers.rs:749`).
- the response cache (`ResponseCache`), a separate contract with its own TTL
- route 1, which is already live and needs no edit

## Measured starting state (verified at source, 2026-09-09)

| route | key reaches the guard? | evidence |
|---|---|---|
| 1 — HTTP `tools/call` | yes | `RetryFields::from_params` at `router/handlers.rs:1222`; guard at `meta_mcp/invoke.rs:1338-1400` |
| 2 — stdio `tools/call` | wiring present, uncommitted | `server/mod.rs:1883` builds `RetryFields::from_params`; `stdio_caller_context` at `:2195` takes `retry: &RetryFields` and passes it through at `:2222` |
| 3 — direct `POST /mcp/{name}` | no | `backend_handlers.rs` never calls `idempotency_key_for`; its sole call site is `meta_mcp/invoke.rs:1338` |

`MetaMcp::enable_idempotency` is wired unconditionally at `server/mod.rs:743-747`,
so `idempotency_cache` is `Some` on every boot for all three routes. The cache was
never the gap; **supplying it a key** is.

### Route 2 is ADOPTED, not authored

The stdio wiring above was already in the working tree when this change started,
along with the un-`#[ignore]`ing of the regression test at `server/mod.rs:3691`.
It is adopted as found. This change does not rewrite it; it adds the one thing it
still lacks — the malformed refusal, below — and the acceptance tests that pin it.

## §P3 DESIGN EVENT — the malformed-retry refusal is client-visible

`RetryFields::from_params` records unusable `inputResponses`, `requestState` and
`_meta` idempotency-key fields in `malformed`. Today exactly one site reads it:
`router/handlers.rs:1223` refuses with `-32602`. Stdio and the direct route do not.

This change extends that refusal to both. That is a behaviour change visible to
clients on **both** transports: a request that previously ran — as a fresh call,
unprotected — now gets `-32602`.

It stays in. Silently ignoring a malformed idempotency key means the caller
believes it has replay protection and does not: a fail-open on the exact guarantee
this criterion asserts, and for a destructive tool the fail-open is the duplicate
side effect the client asked to be spared. Named here per §P3, flagged to the
operator, and carried as its own acceptance criterion (SUB.4.MALFORMED.1) so the
behaviour change is reviewed as a decision rather than inherited as a side effect.

## Axis 3 — the direct route's guard placement

`invoke_tool_traced` is not reachable from `backend_handlers`, and
`MetaMcp::idempotency_cache` is `pub(super)`. Two ways to close that:

1. widen the field's visibility — REJECTED. A `pub(crate)` field is an unrequested
   design event (VISIBILITY-IS-DESIGN) and lets any future caller reach past the
   namespacing `idempotency_key_for` performs.
2. a `pub(crate)` method on `MetaMcp` — ADOPTED. This is the precedent the file
   already sets: `enforce_oauth_isolation` (`meta_mcp/mod.rs:882`) is `pub(crate)`
   and is called from `backend_handlers.rs:749` for exactly this reason — the
   bypass re-enforces a guard it cannot reach through the funnel.

`MetaMcp::direct_route_idempotency(client_key, server, method, identity_suffix,
params) -> Result<Option<GuardOutcome>>`. Returns `None` when the cache is absent
or the client supplied no key. `enforce`, `GuardOutcome` and
`IdempotencyReservation` are already `pub` in `src/idempotency.rs`; nothing new is
exported.

`identity_suffix` is a parameter, not derived inside: without it one caller's key
replays another caller's result. Route 1 binds identity through
`retry_identity_suffix` (`src/gateway/meta_mcp/support.rs:80`), which takes TWO
inputs — the propagation `cache_binding` first, the verified subject otherwise.
The direct route holds both by the time it would call this: `verified_identity`
is lifted out of the request extensions before the body is consumed
(`backend_handlers.rs:449`), and `identity_key` is set by the propagation
resolution a few lines further down (`backend_handlers.rs:625` and `:638`). It binds
with the same two, in the same order. It does NOT bind on `api_key_name`: that
names the API KEY, not the end user, so two people sharing one gateway key would
share one cache entry — the exact disclosure `SUB.4.DIRECT.2` exists to deny.

The malformed refusal is reachable on this route for a plain reason: the handler
already parses the frame into `(id, method, params)` at
`backend_handlers.rs:509`, so `RetryFields::from_params(params.as_ref())` has its
argument in hand, before anything dispatches upstream.

## Open questions — scheduled, per §P1

| question | form | answer | what it changed |
|---|---|---|---|
| is the cache `Some` on every boot, or config-gated? | checkable — `rg -n 'enable_idempotency' src/` | wired unconditionally at `server/mod.rs:743`, no config predicate | removed the config axis from scope |
| does anything already read `RetryFields::malformed`? | checkable — `rg -n '\.malformed' src/gateway src/transport` | one site, `router/handlers.rs:1230` | confirmed the refusal is a real extension, not a duplicate |
| does ADR-008 rung 2 have to change? | askable — asked of the team lead, recorded in-tree | no: rung 2 is OAuth passthrough; INV-3 binds, the bypass keeps its local-guard shape | axis 3 became a placement decision, not an ADR amendment |
| should the malformed refusal ship? | askable — asked of the operator via the team lead | ruled IN, 2026-09-09 | it gets its own AC and is named as a §P3 design event |

**Deferred:** none.

## Assumption, stated

TTL is `crate::idempotency::CLEANUP_INTERVAL`, the module constant already in use
at the sole wiring site. This change introduces no second TTL and does not promote
it to config. Recorded per the surviving half of the 2026-09-07 ruling.

## §P2 TEST PLAN — one row per acceptance criterion

| AC | criterion | case | level | type | file |
|---|---|---|---|---|---|
| SUB.4.STDIO.1 | stdio `tools/call` carrying an `_meta` idempotency key reaches the guard with that key | `stdio_caller_context_carries_the_clients_idempotency_key` — ADOPTED, already live at `server/mod.rs:3692` | component | source-shape | `src/gateway/server/mod.rs` |
| SUB.4.DIRECT.1 | a second `POST /mcp/{name}` with the same key, same args, a NEW request id returns the FIRST result and does not re-invoke the backend | replay case | integration | behavioural | `tests/mik_7272_sub4_three_routes.rs` |
| SUB.4.DIRECT.2 | the same key from a DIFFERENT caller identity does not replay the first caller's result | identity-binding case | integration | behavioural | same |
| SUB.4.DIRECT.3 | no key supplied → the call proceeds unguarded, exactly as today | no-regression case | integration | behavioural | same |
| SUB.4.MALFORMED.1 | a malformed retry field is REFUSED with `-32602` on stdio and on the direct route (§P3 design event — client-visible on BOTH transports) | two refusal cases | integration | behavioural | same |

Q2 — can each case FAIL? DIRECT.1 fails today because `backend_handlers.rs` never calls
`idempotency_key_for`: a second POST re-invokes. DIRECT.2 fails against a naive
implementation that omits `identity_suffix` — it is the case that catches the
cross-caller replay, and it cannot pass by accident. DIRECT.3 fails if the guard
refuses or caches when no key was given. MALFORMED.1 fails today on both transports
because only `router/handlers.rs:1223` reads `is_malformed()`. STDIO.1's helper scans
for the literal `retry: &crate::protocol::mrtr::NO_RETRY` and fails if the hardcode
returns.
