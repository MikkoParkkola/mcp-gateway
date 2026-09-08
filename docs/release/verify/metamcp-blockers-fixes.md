# PR #473 meta-mcp blockers — fix log

Source report: `docs/release/verify/pr473-metamcp.md`, `## Blocking a 4.0.0 release`
(BLOCK-1..BLOCK-5). Working sequentially, one commit per finding. This file is
appended to after each finding so partial progress survives a kill.

Method per finding: re-verify at source -> failing test first -> smallest fix
at root cause -> re-run test -> clippy/fmt clean -> commit paths named
explicitly.

## Status

| finding | verdict | commit |
|---|---|---|
| BLOCK-1 | pending | |
| BLOCK-2 | pending | |
| BLOCK-3 | fixed, uncommittable (shared file) | |
| BLOCK-4 | fixed | pending commit |
| BLOCK-5 | pending | |

---
## BLOCK-3 — `_meta` injected into direct-route backend payloads

Root cause: `MetaMcp::exposes_meta_tool` delegated straight to
`MetaToolExposure::is_exposed`, which returns `true` for every ungoverned name
by design (`src/gateway/meta_mcp_tool_defs.rs:867-872`). The router feeds that
predicate to `merge_client_meta` as `is_meta_tool`
(`src/gateway/router/handlers.rs:1186`), so a surfaced backend tool answered
`true` and the client's `_meta` was merged into arguments the backend never
asked for.

Fix: a roster predicate, `is_governed_meta_tool`, ANDed into
`exposes_meta_tool` (`src/gateway/meta_mcp/mod.rs:607-609`). Exposure and
ownership are now separate questions, which is what the two call sites needed.

Test: `block3_a_surfaced_backend_tool_does_not_take_the_clients_meta`
(`src/gateway/router/tests.rs`).

**Not yet committable.** The one-line behaviour change lives in
`src/gateway/meta_mcp/mod.rs`, which currently also carries a concurrent
session's edits, including a `promote_interim_envelope` stub whose body is
`let _ = (tool_name, content, response);` — a no-op standing where BLOCK-1's
repair would go. Committing the file would publish that stub as if BLOCK-1 were
addressed. Splitting the commit is also not available: `is_governed_meta_tool`
has no other consumer, so `mod.rs`-less staging fails `-D warnings` on
`dead_code`. Operator decision required on how the shared file is divided.

## BLOCK-4 — a released reservation stored a result bound to no request

Root cause: `IdempotencyReservation::complete` routed through
`IdempotencyCache::mark_completed`, which recovers the admitting request's
fingerprint by looking the entry up. After a `release` — or an
`IN_FLIGHT_TIMEOUT` sweep — the entry is gone, the lookup yields the empty
string, and an empty fingerprint matches every later request, so the stored
result answered any call reusing the key for the whole TTL.

Fix: the reservation carries the fingerprint it was admitted for and passes it
to a new `mark_completed_bound` (`src/idempotency.rs:368`). The lookup path
remains for callers that hold no reservation.

Test: `released_then_completed_entry_stays_bound_to_its_own_request`
(`src/idempotency.rs`), asserting the fingerprint-mismatch refusal by message
rather than by `is_err` — the in-flight and at-capacity refusals are errors too
and neither would prove the binding held.
