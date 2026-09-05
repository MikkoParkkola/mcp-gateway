# Test plan — GH #475 error budgets

Written before the tests, reviewed as a plan. One row per acceptance criterion;
an empty evidence cell is the finding. Each row carries its red-run result
(the failure message it produced before the implementation existed) in the
tracking comment; a row with no recorded red run has not been shown to fail.
Design:
`docs/design/2026-09-05-error-budget-config.md`.

## Acceptance criteria → cases

| AC | criterion | case | level | type | home |
|---|---|---|---|---|---|
| GH475.RL.1 | a rate-limited response records nothing in the backend budget | drive the recorder with `IgnoredRateLimit`; assert sample count unchanged | unit | behaviour | `src/kill_switch/tests.rs` |
| GH475.RL.2 | …nor in the capability budget | same, capability recorder | unit | behaviour | `src/kill_switch/tests.rs` |
| GH475.RL.3 | …nor as a circuit-breaker failure | rate-limited dispatch `Err`; assert `circuit_breaker_stats()` failure count unchanged and state `Closed` | unit | behaviour | `src/backend/ops.rs` tests |
| GH475.RL.4 | a digit run inside a larger token is not a rate limit | `500` body quoting request id `4291a` → counts as failure | unit | boundary | `src/gateway/meta_mcp/invoke.rs` tests |
| GH475.RL.5 | the `throttl` stem does not exempt | `"throttling disabled"` → counts as failure | unit | boundary | same |
| GH475.RL.6 | the four accepted phrases do exempt | standalone `429`, `too many requests`, `rate limit`/`rate-limit`/`ratelimit`, `RESOURCE_EXHAUSTED` | unit | boundary | same |
| GH475.RL.7 | an ordinary failure is unaffected | plain `500` → failure in both budgets and the breaker | unit | regression | `src/kill_switch/tests.rs` |
| GH475.RL.8 | a success is still a success | `BudgetOutcome::Success` → success sample | unit | regression | same |
| GH475.RL.9 | a backend returning only `429`s neither opens its circuit nor exhausts a budget | end-to-end invoke against a stub backend emitting `429` past both thresholds | integration | behaviour | `tests/` |
| GH475.CFG.1 | the documented YAML parses | full `error_budget:` block → expected struct | unit | round-trip | `src/config/tests.rs` |
| GH475.CFG.2 | a partial section merges field-by-field | `error_budget: {threshold: 0.5}` → threshold 0.5, other four at today's defaults | unit | boundary | same |
| GH475.CFG.3 | a partial `capability:` merges the same way | `capability: {min_samples: 2}` → other four unchanged | unit | boundary | same |
| GH475.CFG.4 | absent section = today's behaviour (D4) | empty config → both `Default` impls, value for value | unit | regression | same |
| GH475.CFG.5 | **a configured backend threshold reaches the running budget** | config → setter → invoke; assert the breaker trips at the configured rate, not 0.8 | integration | wiring | `tests/` |
| GH475.CFG.5b | **a configured capability threshold reaches the running capability budget** | same path through the capability setter; a green CFG.5 says nothing about it, because the two setters are separate and separately callerless | integration | wiring | `tests/` |
| GH475.CFG.6 | a reload reports the section as restart-required | edit `error_budget`, reload → `pending_restart_fields` contains `error_budget` | unit | behaviour | `src/config_reload/` tests |
| GH475.VAL.1 | out-of-range threshold rejected, field named | `1.5`, `0.0`, `-1.0` → error naming `threshold` | unit | negative | `src/config/tests.rs` |
| GH475.VAL.2 | `.nan` rejected | YAML `.nan` → rejected, not accepted-and-inert | unit | negative | same |
| GH475.VAL.3 | sub-1 sizes rejected | `window_size: 0`, `min_samples: 0` | unit | negative | same |
| GH475.VAL.4 | `min_samples > window_size` rejected | `window_size: 10, min_samples: 11` | unit | negative | same |
| GH475.VAL.5 | zero duration rejected | `window_duration: 0s` | unit | negative | same |
| GH475.OBS.1 | each exclusion is observable | N rate-limited responses → suppression counter reads N | unit | behaviour | `src/kill_switch/tests.rs` |
| GH475.RL.10 | a typed rate-limit outcome needs no text | a capability `429` observed at `jsonrpc.rs` is excluded with the error text scrubbed to an unrelated string | integration | behaviour | `src/capability/executor/` tests |
| GH475.RL.11 | both recorders route through one predicate | the shared predicate is the only definition; a test asserts `ops.rs` and `invoke.rs` agree on the same input set, so the two cannot drift | unit | wiring | `src/error.rs` tests |
| GH475.RL.12 | a `429` records transport-health reachability | a throttled backend records a health success and no budget sample | unit | behaviour | `src/failsafe/` tests |
| GH475.VAL.6 | `window_size` above the upper bound is rejected | `window_size: 100001` → refused with the field named | unit | negative | same |
| GH475.MIG.1 | the 4.0.0 notice fires below 4.0.0 and writes nothing | stamp `3.9.0` → notice emitted, config file byte-identical | unit | behaviour | `src/commands/upgrade.rs` tests |
| GH475.MIG.2 | it is idempotent | second run at stamp `4.0.0` → silent | unit | behaviour | same |
| GH475.MIG.3 | the comparison direction is pinned | stamp `4.1.0` → silent; an inverted comparison makes this row fire | unit | negative | same |

No criterion is without a case. No case is without a criterion.

## Can each case actually fail?

Two rows carry the free failure that proves the rest are honest, because both
name behaviour that does not exist yet:

- **GH475.CFG.5 fails today for the reason #475 was filed.** Both setters have
  no callers (`src/gateway/meta_mcp/mod.rs:961`, `:967`), so no configured value
  can reach a running budget. A green CFG.5 before the wiring exists means the
  test is asserting against its own fixture, not the gateway.
- **GH475.RL.3 fails today**: `src/backend/ops.rs:255` records every dispatch
  `Err` unconditionally.

The remaining rows fail for ordinary reasons — the config key does not parse,
the validation does not exist, the outcome enum does not exist. Each is checked
by running it before the implementation, not by assertion.

Two shapes explicitly refused in this plan:

- **A fixture that reimplements the recorder.** RL.1–RL.3 and OBS.1 assert
  against the production budget and the production failsafe. A hand-rolled
  counter would pass whatever the gateway does.
- **A wiring test that constructs the budget directly.** CFG.5 must travel the
  config path. Building an `ErrorBudgetConfig` in the test and handing it to the
  budget proves the budget honours its own struct, which was never in doubt.

## Out of scope

Retry/backoff behaviour, per-backend overrides, and the other two dead setters —
per the design's own out-of-scope list.
