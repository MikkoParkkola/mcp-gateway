# NFR.OBS.1 — a legacy stdio request must record the revision its session negotiated

Status: design accepted, not implemented. Dual-reviewed 2026-09-05 (gpt SHIP-WITH-FIXES, kimi SHIP-WITH-FIXES); both sets of findings are folded in below.

## Scope

FOR: making a legacy stdio request *after* `initialize` record the revision the session
negotiated, instead of `absent`/`none`.

OUT: `NFR.OBS.2` (the `tools/list` surface record); the modern stdio path, which already
sources its revision from `_meta`; HTTP, which reads the mandatory post-handshake header;
any change to `classify_request`; the retry and continuation work in cluster A.

## The defect

`classify_and_observe` (`src/protocol/meta.rs:466`) resolves a `RequestShape::Legacy`
revision as `header_version.or(params["protocolVersion"])`, falling to `("absent", "none")`
when neither is present (`:494-501`).

The stdio dispatcher passes `None` for `header_version` (`src/gateway/server/mod.rs:1680`),
correctly — stdio has no headers. Only `initialize` carries `protocolVersion` in the body,
and nothing on the stdio path remembers what was negotiated there. So every legacy stdio
request after the handshake records `protocol_revision=absent, revision_source=none` while
the session knows the answer. The criterion says *per request*, and `absent` is not a
missing answer, it is a wrong one.

This is why the criterion was recorded MET on 2026-09-05 and reopened the same day: the
record *site* is on both transports, which is what `d306c7e8` fixed. The record *content*
is still short on one of them.

## Design

1. `MetaMcp` gains a single `stdio_revision: Arc<RwLock<Option<String>>>` — one slot, not a
   map. `run_stdio` serves exactly one session for the life of the process, so a key buys
   nothing and costs an eviction policy the tree cannot currently honour: `session_promoted`
   is the pattern a map would copy, and its `clear_session_promoted`
   (`src/gateway/meta_mcp/mod.rs:1039`) has no production caller. A per-session map here
   would grow for the life of an HTTP process to serve a transport that never reads it.
2. The stdio dispatcher writes the slot when it handles `initialize`, and reads it on every
   later request.
3. `classify_and_observe` gains a fourth parameter, `session_version: Option<&str>`,
   consulted only by the `Legacy` arm. HTTP passes `None`; its header is mandatory after the
   handshake, so the slot would never be the answer there.
4. Precedence in the `Legacy` arm is `header_version -> params["protocolVersion"] ->
   session_version`. **The body outranks the store.** A client that re-handshakes mid-session
   sends a new `protocolVersion`, and a stored value ordered ahead of it would answer with
   the superseded revision — a stale record that looks authoritative.
5. A revision read from the slot is labelled `session`, not `handshake`. `handshake` means
   the request itself carried it; `session` means it did not and the gateway remembered.
   Both name the handshake as the origin, and only the second admits the request was silent.
   Collapsing them would make the record unable to answer the question it exists for.

`Modern` and `Malformed` are untouched. In particular the stdio session value is deliberately
not routed through `header_version`, because the `Malformed` arm labels a `header_version`
hit as source `header` — true on HTTP, false on stdio. A fix that mints a new wrong record
is not a fix.

## Rejected

| option | why not |
|---|---|
| reuse `header_version` for the stdio session value | the `Malformed` arm would label a stdio value `header` |
| thread the state through `dispatch_single` | nine call sites, and a fourth session store beside three that exist |
| reuse `session_state`, the FSM workflow store | different lifetime and semantics; couples protocol telemetry to workflow state |
| a `DashMap` keyed by session id | unbounded for the life of an HTTP process, with no eviction path to join |

## Unknowns, resolved

- Does anything evict `session_promoted` on disconnect, so a new per-session map could join
  it? — No. `clear_session_promoted` (`src/gateway/meta_mcp/mod.rs:1039`) is called only from
  `src/gateway/meta_mcp/spec_preview.rs:508`, a test. This is what moved the design from a
  map to a single slot. *(That unwired cleanup is a separate observation, not this change's
  work, and not a ticket.)*
- Can the HTTP path reach the `Legacy` arm with no header, making the slot load-bearing
  there? — Not for a conformant client: `MCP-Protocol-Version` is mandatory on every request
  after `initialize` in 2025-06-18. HTTP passes `None`. A non-conformant HTTP client still
  records `absent`/`none`, which is the truthful answer for a request that declared nothing
  anywhere.

## Test plan

| clause | case | level | can it fail today |
|---|---|---|---|
| legacy stdio, post-handshake, records the revision | dispatch `initialize` at `2025-06-18`, then `ping` on the same session; assert `2025-06-18`/`session` on the second record | integration, real dispatcher under a scoped subscriber | yes — records `absent`/`none` |
| the handshake request itself | dispatch `initialize` alone; assert `2025-06-18`/`handshake` from the body | integration | yes, if the new ordering breaks the existing fallback |
| a re-handshake supersedes the slot | `initialize` at `2025-06-18`, then `initialize` at `2025-03-26`; assert the second records `2025-03-26`/`handshake` | integration | yes — this is the stale-precedence defect the review caught |
| modern stdio unaffected | `ac_obs_1_stdio_records_the_revision_and_that_meta_carried_it` still asserts `_meta` | integration | yes |
| nothing declared anywhere | `ping` with no prior `initialize`; assert `absent`/`none` | unit | yes — a fix that invents a revision goes green wrongly |

Every case runs through `records_for` (`src/gateway/server/mod.rs:3108`), which pins the
process-wide callsite interest that made this criterion's evidence unreadable before
`b6836a02`. The two-request cases need a variant of that helper that keeps one `MetaMcp`
across both dispatches; a helper that rebuilds it would pass while the slot did nothing.
