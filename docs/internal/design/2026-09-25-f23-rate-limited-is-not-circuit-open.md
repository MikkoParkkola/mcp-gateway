# F23: a gateway rate-limit refusal is not an open breaker, and is not a backend failure

Status: design for review. Gating for 4.0. UPGRADING item 53.

## Problem (verified at source, base `docs/ranking-1-release-line`)

- `Failsafe::can_proceed` is `circuit_breaker.can_proceed() && rate_limiter.try_acquire()`
  (`src/failsafe/mod.rs:49`). Both callers turn a `false` into `Error::CircuitOpen`
  (`src/backend/ops.rs:298-306` request path, `:531-538` notification path), so the
  gateway's own per-backend rate limiter (default 100 rps, burst 50) refuses with
  "Circuit breaker open for backend 'x'" and sets `mcp_backend_circuit_state` to 0,
  although the breaker is closed.
- `BudgetOutcome::of` (`src/gateway/meta_mcp/invoke.rs:4000-4028`) samples every `Err` whose
  text is not rate-limit prose as `Failure`. "Circuit breaker open" is not, so each refusal
  lands in the backend and per-capability error budgets (defaults: capability 0.8 over at
  least 5 samples, backend 0.8 over at least 10).
- Result: one caller's burst past the limiter auto-disables the capability (and can kill
  the backend) for every caller. Observed in F22: "auto-disabling fixture:needs_input,
  error_rate=1.0" with zero `CircuitBreaker::record_failure` calls.

## Design

1. New `Error::RateLimited(String)` (backend name), message
   `Rate limit exceeded for backend '{0}'`. Added to the -32000 arm of `to_rpc_code`
   (same code as today, so no client sees a new one). `is_pre_dispatch()` includes it: the call was never sent,
   so idempotency reservations are released exactly as for `CircuitOpen`. Not retryable
   (`failsafe/retry.rs:96` unchanged). `classify_dispatch_error` maps it to
   `ErrorCategory::RateLimited`, so the recovery hint says "back off", not "breaker open".
2. `Failsafe::can_proceed() -> bool` is replaced by `Failsafe::admit(&self, backend: &str) -> Result<()>`:
   breaker first (`Err(CircuitOpen)`), then limiter (`Err(RateLimited)`). Breaker first keeps
   today's short-circuit: an open breaker does not spend a limiter token.
3. `ops.rs` request and notification paths both call `admit`, which also sets the circuit
   gauge from the breaker's decision only, so the paths cannot drift and a rate-limit
   refusal no longer reports an open circuit. Each path logs the refusal's own message.
4. `IgnoredRateLimit`'s doc now covers the gateway's own pre-dispatch refusal too.
   `BudgetOutcome::of` gets an explicit first arm `Err(Error::RateLimited(_)) => IgnoredRateLimit`.
   The message would also match `is_rate_limited`, but the variant arm is the contract and is
   what the mutant flips. `IgnoredRateLimit` records no sample in either budget (GH475.RL.1).
5. A genuinely open breaker is unchanged: `CircuitOpen`, same message, still sampled as `Failure`.

### Every `can_proceed` site

| Site | Today | After |
|---|---|---|
| `failsafe/mod.rs:49` `Failsafe::can_proceed` | breaker && limiter as one bool | removed; `admit` returns which one refused |
| `backend/ops.rs:298` request path | `CircuitOpen` for both | `admit`: `CircuitOpen` or `RateLimited` |
| `backend/ops.rs:531` notification path | `CircuitOpen` for both | same as above |
| `failsafe/mod.rs:130` unit test | asserts `!can_proceed()` after a trip | asserts `admit` is `Err(CircuitOpen)` |
| `failsafe/circuit_breaker.rs` `CircuitBreaker::can_proceed` | breaker only | unchanged |
| `gateway/auth.rs:337` per-client breaker | client's own breaker | unchanged (not the backend failsafe) |

Out of scope: the per-client breaker (`router/backend_handlers.rs:626,947,1020`,
`router/handlers.rs:1938`) still records any `Err` against the calling client; it is that
client's own circuit. Per-tenant limiter fairness (A's burst also starves B's tokens) is MIK-7547.

## Tests (red first)

In `src/gateway/meta_mcp/invoke/error_budget_tests.rs`, a real `Backend` (rate limit 1 rps,
burst 2; breaker default) behind an always-OK transport, driven through `MetaMcp::invoke_tool`:

- T1 `one_callers_burst_does_not_disable_the_capability_for_another`: caller A sends 12 calls;
  some are refused. Then, after one token refills, caller B calls the same tool. Assert: B is
  served; `is_capability_disabled` is false; both budget windows hold only successes; A's
  refusals are `RateLimited`, never "Circuit breaker open". Red at base: A's 10 refusals are
  sampled as failures, the capability is disabled, and B is refused.
- T2 `an_open_breaker_still_reports_circuit_open_and_counts`: trip the breaker; the next call is
  `CircuitOpen` and adds a `Failure` sample.
- T4 unit (`failsafe/mod.rs`): limiter exhausted, breaker closed: `admit` is
  `Err(RateLimited)` and the breaker state stays `Closed`.
- T5 (`router/probe_tests.rs`, metrics feature): rate limit burst 1, retry off; after a
  rate-limit refusal `mcp_backend_circuit_state` still reads 1. Red at base: it reads 0.
- T3 unit: `BudgetOutcome::of(&Err(RateLimited))` is `IgnoredRateLimit`;
  `of(&Err(CircuitOpen))` is `Failure`.

Mutant (CI throwaway, Tests-only ci.yml): the `RateLimited` arm in `BudgetOutcome::of`
returns `Failure`. T1 and T3 must redden.

T1 asserts the cross-tenant outcome first (B served, capability enabled, backend not
killed, no failure sample) and the message last. Red at base (Spark, `f23red-target`):
T1 fails; the refusal arrives as `isError` "Circuit breaker open for backend 'srv'" with a
`CIRCUIT_OPEN` recovery hint telling the caller to wait for the breaker. T2 passes at base.

## Review dispositions (kimi SHIP-WITH-FIXES, grok SHIP-WITH-FIXES)

- kimi: `to_rpc_code` arm not named. Accepted (item 1).
- kimi: T1 waits on a real 1 s refill. Kept: 12 in-process calls finish far inside one
  refill, and the wait is only for B's token. `governor` takes no injectable clock here.
- kimi: `IgnoredRateLimit` doc. Accepted (item 4).
- grok: no test reads the gauge. Accepted in part: the gauge is set inside `admit` (item 3),
  so both paths set it identically. T5 adds the rate-limit gauge row; the existing
  open-breaker row still covers the 0 case.
- grok: idempotency release row. Declined: `is_pre_dispatch` is the existing allowlist, and
  `RateLimited` joins `CircuitOpen` in it; the release behaviour is already pinned for that set.
- grok: Failsafe unit row. Accepted (T4). Notification path: covered by the shared helper.
- kimi/grok: a `rate_limited` counter. Deferred as an improvement; not needed for the defect.

## Compatibility

Behaviour change, UPGRADING item 53: a gateway-side rate-limit refusal now reads
"Rate limit exceeded for backend 'x'" (code still -32000), is not counted by the error
budgets, and no longer drops `mcp_backend_circuit_state` to 0. Clients or alerts that
matched "Circuit breaker open" to detect throttling must match the new text.
