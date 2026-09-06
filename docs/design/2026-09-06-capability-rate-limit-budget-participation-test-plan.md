# GH475.RL.10 — test plan (PREVENTION half)

Status: **draft, not yet reviewed as a plan** (§P2 requires its own dual-vendor pass).
Design: `docs/design/2026-09-06-capability-rate-limit-budget-participation.md`, option **O1**.
Companion to the DETECTION half, already landed (`src/capability/executor_tests.rs:1002`, `:1194`, `:1239`).

## What the criterion says, split into clauses

RL.10 — *"a typed rate-limit outcome needs no text."* Recorded today as
MET (behaviour) / ABSENT (property) at `docs/requirements/RELEASE-4.0.0-criteria-status.md:400`.
The property is absent because the exclusion is a substring match on a formatted
message. Each clause below is one thing that must be true before the property row
can read MET.

| # | criterion clause | case that proves it | V-model level | type | can it fail? |
|---|---|---|---|---|---|
| C1 | A capability 429 leaves the executor as an error carrying a **typed** HTTP status, not prose | drive `handle_response` with a 429 (REST); assert the returned `Error::Http`'s `status()` is `Some(429)` | unit | positive | yes — today the site returns `Error::Protocol`, so the match arm does not exist and the case cannot compile-and-pass until O1 lands. Free failure, no probe needed |
| C2 | Same, at the JSON-RPC format site | drive `jsonrpc.rs` execute path with a 429; same assertion | unit | positive | yes, same reason |
| C3 | Same, at the GraphQL format site | drive `graphql.rs` execute path with a 429; same assertion | unit | positive | yes, same reason |
| C4 | Classification reads the **type**, not the text | build the `Error::Http` for a 429 whose body and reason phrase contain **no** rate-limit token at all (body `{"detail":"x"}`, and assert `is_rate_limited(&err.to_string())` is `false` for that same string); assert `BudgetOutcome::of(&Err(err))` is still `IgnoredRateLimit` | unit | **discriminating** — this is the one case that distinguishes O1 from the status quo | yes: under today's code the outcome is `Failure`. This is the case whose failure IS the criterion |
| C5 | A non-429 HTTP failure is still counted as a failure | 500 through the same path; assert `BudgetOutcome::of` is `Failure` | unit | negative | yes — a match arm that returned `IgnoredRateLimit` for any `Http` would pass C4 and fail here. C4 without C5 is passable by a stub |
| C6 | The exclusion **effect** survives: a 429 does not trip the capability breaker | the three DETECTION tests, re-run unchanged against the new error type | unit | regression | yes — they assert on the effect via the shared predicate; if O1 changes the string the predicate sees, they break, which is the point of leaving them untouched |
| C7 | The truncated response body is not lost, only relocated (DESIGN EVENT 1) | capture `tracing` output for a 429 and assert the body fragment appears in the `warn!` record; assert the returned `Display` carries status and URL and **not** the body | unit | positive + negative pair | yes — an implementation that simply drops the body passes every other row here |
| C8 | A capability 429 maps to JSON-RPC code **-32000** (DESIGN EVENT 2) | `to_rpc_code(Error::Http(429-err))` | unit | positive | yes — today `Http` falls through to `_ => -32603`, so the case fails before the guarded arm exists |
| C9 | A non-429 `Http` error keeps `-32603` | `to_rpc_code(Error::Http(500-err))` | unit | negative | yes — guards the DESIGN EVENT 2 arm against being widened to all `Http` |
| C10 | `classify_dispatch_error` gains an `Error::Http` arm in the **same** commit (DESIGN EVENT 3) | assert the dispatch classification of a 429 `Error::Http`; the case lands with the format-site rewrite, never as a follow-up | unit | positive | yes |
| C11 | `is_rate_limited`'s predicate text is unchanged and still load-bearing for the MCP path | existing `recovery.rs` predicate tests, re-run; plus the OUT-of-scope statement asserted by their continued presence | unit | regression | yes — a "cleanup" that deletes the predicate breaks the MCP path and these rows |

## Rows with no case, and why

None. Every clause above has a case. If the plan review finds a clause the
criterion asserts and this table does not list, that empty cell is the finding —
per §P2 that is the whole point of reviewing a plan rather than the tests.

## The two questions a plan review must answer

1. **Does every criterion clause have a case, or a stated reason it has none?**
   Eleven clauses, eleven cases, zero stated exemptions. Answer above.
2. **Can each named case actually fail?** Answered per row, last column. The
   shape to distrust is C4: it is the only row whose failure *is* the criterion,
   and a fixture that hands `BudgetOutcome::of` an error it built itself would
   make it true by construction. C4's fixture must come from a real HTTP
   response through the real format site, exactly as the DETECTION tests do —
   and C4 additionally asserts that the **text** predicate says `false` on the
   same string, so a passing C4 cannot be explained by the substring path.

## Out of scope for this plan

Unchanged from the design's §P0: the MCP-backend recording path
(`src/backend/ops.rs`, `src/failsafe/`), RL.9 and RL.11, retry policy for a 429,
the predicate text of `is_rate_limited`, the `cap_test` CLI path
(`src/commands/cap.rs`), and external consumers of the `pub`
`CapabilityBackend` / `CapabilityExecutor`.
