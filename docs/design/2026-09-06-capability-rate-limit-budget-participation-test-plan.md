# GH475.RL.10 — test plan (PREVENTION half)

Status: **draft, not yet reviewed as a plan** (revised 2026-09-06 to follow the design's 429-only narrowing) (§P2 requires its own dual-vendor pass).
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
| C4 | Classification reads the **type**, not the text | drive a real 429 through a real format site; assert `BudgetOutcome::of(&Err(err))` is `IgnoredRateLimit`. Discrimination comes from a **mandatory mutation probe**, not from the assertion: flip the guard `e.status() == Some(429)` to `Some(430)` and the case must go red | unit + mutation probe | **discriminating** — the probe is what distinguishes O1 from the status quo | yes, but ONLY via the probe. See the note below: the assertion alone cannot fail once O1 lands |
| C5 | A non-429 HTTP failure is still counted as a failure | 500 through the same path; assert `BudgetOutcome::of` is `Failure` | unit | negative | yes — a match arm that returned `IgnoredRateLimit` for any `Http` would pass C4 and fail here. C4 without C5 is passable by a stub |
| C5b | A non-429 status is **not** re-carriered at all: it stays `Error::Protocol` with today's text | drive 500, 504 and 403 through each format site; assert the returned error matches `Error::Protocol(_)` and its string still contains the status and the body fragment | unit | **discriminating** — this is the row that pins the review's one substantive revision | yes: an implementation that gates on `error_for_status_ref()`'s `Err` rather than on `status == 429` returns `Error::Http` here and fails immediately. That implementation is the obvious one to write, which is why this row exists |
| C5c | The agent-facing classification of a non-429 failure is byte-for-byte unchanged | assert `classify_dispatch_error` yields `Timeout` for the 504 error and `BackendError` for the 500, exactly as it does before O1 | unit | regression | yes — under the wide gate a 504 becomes `BackendError`, which is the degradation both review legs raised. This row goes red on it |
| C6 | The exclusion **effect** survives: a 429 does not trip the capability breaker | the three DETECTION tests, re-run unchanged against the new error type | unit | regression | yes — they assert on the effect via the shared predicate; if O1 changes the string the predicate sees, they break, which is the point of leaving them untouched |
| C7 | The truncated response body is not lost, only relocated (DESIGN EVENT 1) | capture `tracing` output for a 429 and assert the body fragment appears in the `warn!` record; assert the returned `Display` does **not** carry the body | unit | positive + negative pair | yes — an implementation that simply drops the body passes every other row here |
| C7b | The backend URL never reaches the agent-facing error (DESIGN EVENT 1, the review's other blocking finding) | drive a 429 whose request URL carries a distinctive query parameter (`?api_key=CANARY`); assert `err.to_string()` contains neither the host, the path, nor `CANARY`; assert `err.url()` is `None` | unit | **negative, security** | yes: omitting `.without_url()` — the single easiest thing to forget, since `Error::Http(err)` compiles fine without it — puts the whole URL in `Display` and this row goes red on the canary |
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
   Fourteen clauses, fourteen cases, zero stated exemptions. Answer above.
2. **Can each named case actually fail?** Answered per row, last column. The
   shape to distrust is C4: it is the only row whose failure *is* the criterion,
   and a fixture that hands `BudgetOutcome::of` an error it built itself would
   make it true by construction. C4's fixture must come from a real HTTP
   response through the real format site, exactly as the DETECTION tests do.

   **C4's original mechanism was unsatisfiable and has been replaced.** It
   asked for a 429 whose error string carries no rate-limit token, and asserted
   `is_rate_limited` says `false` on it. No such string exists: `is_rate_limited`
   (`gateway/recovery.rs:286-307`) matches the bare token `429` after splitting
   on non-alphanumerics, and reqwest's `Display` for a status error always
   carries the numeric status — `.without_url()` removes the URL, not the code.
   So under O1 the text predicate and the typed predicate agree on every real
   429, and no assertion over a single run can tell them apart. That is the
   §P2 question-2 failure mode — a case whose staging removes the condition it
   observes — caught in this plan's own table.

   What separates them is a second run against mutated code. Flipping the
   guard to `Some(430)` breaks the typed path and leaves the text path intact:
   a C4 that still passes is reading the string. The probe is therefore not an
   optional strengthening of C4, it IS C4's discriminating power, and a C4
   landed without it proves nothing the DETECTION half did not already prove.
   Raised by the Grok leg as an improvement; promoted here because at source it
   is the difference between a case that can fail and one that cannot.

## Out of scope for this plan

Unchanged from the design's §P0: the MCP-backend recording path
(`src/backend/ops.rs`, `src/failsafe/`), RL.9 and RL.11, retry policy for a 429,
the predicate text of `is_rate_limited`, the `cap_test` CLI path
(`src/commands/cap.rs`), and external consumers of the `pub`
`CapabilityBackend` / `CapabilityExecutor`.
