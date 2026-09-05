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
| GH475.RL.3 | …nor as a circuit-breaker failure | dispatch returns a rate-limited `Err`; assert `circuit_breaker_stats()` failure count unchanged and state `Closed` | unit | behaviour | `src/backend/ops.rs` tests |
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
| GH475.CFG.5 | **a configured backend threshold reaches the running budget** | boot the gateway from a YAML file carrying a non-default threshold; **the test may not call either setter** — it drives invoke and asserts the backend auto-kill fires at the configured rate, not 0.8 | integration | wiring | `tests/` |
| GH475.CFG.5b | **a configured capability threshold reaches the running capability budget** | same YAML-boot path, asserting capability disable at the configured rate; a green CFG.5 says nothing about it, because the two setters are separate and separately callerless | integration | wiring | `tests/` |
| GH475.CFG.6 | a reload reports the section as restart-required | edit `error_budget`, reload → `pending_restart_fields` contains `error_budget` | unit | behaviour | `src/config_reload/` tests |
| GH475.VAL.1 | out-of-range threshold rejected, field named | `1.5`, `0.0`, `-1.0` → error naming `threshold` | unit | negative | `src/config/tests.rs` |
| GH475.VAL.2 | `.nan` rejected | YAML `.nan` → rejected, not accepted-and-inert | unit | negative | same |
| GH475.VAL.3 | sub-1 sizes rejected | `window_size: 0`, `min_samples: 0` | unit | negative | same |
| GH475.VAL.4 | `min_samples > window_size` rejected | `window_size: 10, min_samples: 11` | unit | negative | same |
| GH475.VAL.5 | zero duration rejected | `window_duration: 0s` | unit | negative | same |
| GH475.OBS.1 | each exclusion is observable | N throttled responses through the gateway **plus a success control and an ordinary-failure control**; assert the suppression counter rose by exactly N and neither control moved it | integration | behaviour | `tests/` |
| GH475.RL.10 | a typed rate-limit outcome needs no text | a capability `429` observed at `jsonrpc.rs` is excluded with the error text scrubbed to an unrelated string | integration | behaviour | `src/capability/executor/` tests |
| GH475.RL.11 | both recorders route through one predicate | one signal table (the RL.4–RL.6 inputs) driven through **both real call paths** — backend dispatch and `MetaMCP` invoke — asserting an identical exempt/count verdict per input | unit | wiring | both call-site test modules |
| GH475.RL.13 | a `429` records transport-health reachability | drive a `429` through **backend dispatch**, not a hand-built `Failsafe`; assert the production failsafe gains one health success, no circuit-breaker failure, and no budget sample | integration | behaviour | `src/backend/ops.rs` tests |
| GH475.VAL.6 | `window_size` above the upper bound is rejected | `window_size: 100001` → refused with the field named | unit | negative | same |
| GH475.VAL.7 | every VAL row repeats under `capability:` | the same rejected values nested one level down are refused, naming the nested field | unit | negative | same |
| GH475.VAL.8 | the accepted side of each boundary is accepted | `threshold: 1.0`, `window_size: 1`, `min_samples: 1`, `min_samples == window_size`, `window_duration: 1s`, `window_size: 100000` all parse | unit | boundary | same |
| GH475.OBS.2 | the suppression debug event is emitted | one throttled response → one debug event naming the backend and the excluded outcome | unit | behaviour | `src/kill_switch/tests.rs` |
| GH475.CFG.7 | the shipped example config parses | the `error_budget:` block shipped in the example file, uncommented, loads and validates | unit | round-trip | `src/config/tests.rs` |
| GH475.MIG.4 | the notice says what the four changes are | the emitted text names all four items, the re-authentication and the startup-refusal consequences | unit | behaviour | `src/commands/upgrade.rs` tests |
| GH475.MIG.1 | the 4.0.0 notice fires below 4.0.0 and writes nothing | stamp `3.9.0` → notice emitted, config file byte-identical | unit | behaviour | `src/commands/upgrade.rs` tests |
| GH475.MIG.2 | it is idempotent, and the first run advances the stamp | start at stamp `3.9.0`, run the upgrade **twice**; assert exactly one notice total and stamp `4.0.0` after the first run | unit | behaviour | same |
| GH475.MIG.3 | the comparison direction is pinned | stamp `4.1.0` → silent; an inverted comparison makes this row fire | unit | negative | same |
| GH475.RL.14 | a backend reporting a `429` the MCP way is exempt | a rate-limit envelope arriving as `isError: true` inside a successful JSON-RPC result is excluded, while a non-rate-limit `isError: true` still counts | unit | boundary | `src/gateway/meta_mcp/invoke.rs` tests |
| GH475.NOTICE.1 | a quiet upgrade still delivers the breaking-change notices | the built binary is run with `--quiet` over a 2.x data directory; the notices appear on stderr and the progress chatter does not appear on stdout | integration | wiring | `tests/gh475_quiet_upgrade_still_warns.rs` |

Every criterion carries either a case or a recorded reason it has none, and the
reasons are in **Rows without a case** below. The `GH475.*` identifiers are
published in the tracking comment on GH #475, so closure evidence cites the same
strings the reporter can read (DoR B4).

## Rows without a case

Six rows were planned and are not implemented. Each names behaviour this change
does not add, so a case for it would assert against a fixture rather than the
gateway — which is the failure mode this plan exists to prevent. They are
recorded here rather than deleted, because deleting them would make the plan
read as complete.

| row | why there is no case | disposal |
|---|---|---|
| GH475.RL.9 | an end-to-end `429`-only backend needs a stub MCP backend harness that does not exist; RL.3, RL.7 and RL.13 cover the same predicate at the dispatch call site | ticket |
| GH475.RL.10 | the capability executor does not classify rate limits at all — `src/capability/executor/` has no call to the shared predicate. The criterion presupposes an exclusion that was never built | ticket |
| GH475.RL.11 | the property is structural rather than tested: `src/gateway/recovery.rs:281` is the single predicate and both call sites (`backend/ops.rs:254`, `meta_mcp/invoke.rs:2976`) reach it. No test drives one signal table through both | ticket |
| GH475.OBS.1 | there is no suppression counter to assert against; no metric is emitted when an outcome is excluded | ticket |
| GH475.OBS.2 | same cause — no debug event is emitted on exclusion | ticket |
| GH475.MIG.3 | the notice guard compares against `4.0.0` and no case pins the direction, so an inverted comparison would not be caught | ticket |


## Can each case actually fail?

Two rows carry the free failure that proves the rest are honest, because both
name behaviour that does not exist yet:

- **GH475.CFG.5 fails today for the reason #475 was filed.** Both setters have
  no callers (`src/gateway/meta_mcp/mod.rs:961`, `:967`), so no configured value
  can reach a running budget. A green CFG.5 before the wiring exists means the
  test is asserting against its own fixture, not the gateway.
- **GH475.RL.3 fails today**: `src/backend/ops.rs:255` records every dispatch
  `Err` unconditionally.

Most remaining rows fail for ordinary reasons — the config key does not parse,
the validation does not exist, the outcome enum does not exist. Each is checked
by running it before the implementation, not by assertion.

Four rows are **regressions and are green before the implementation**, so a red
run is not available and claiming one would be false. Each names the mutant that
must turn it red instead, run once against a deliberately broken build:

| row | falsifier |
|---|---|
| GH475.RL.7 | make the predicate return `true` unconditionally — a plain `500` must then fail this row |
| GH475.RL.8 | route `Success` into the failure arm |
| GH475.MIG.2 | remove the stamp write — the second run must then emit a second notice |

One review fix was refused, and the refusal is recorded so it is not re-raised:
a case requiring the backend rows to carry a rate-limit **status** rather than
rate-limit text. `src/error.rs:120-126` refuses status-only classification with
its own reason — this protocol overloads `404` and `400` to mean "session
expired, reinitialise" — and `backend/ops.rs` has only the `Error`, the status
having been discarded upstream. Text is the signal that path has. The capability
executor is different: `jsonrpc.rs:198` still holds the status, so a status-based
exclusion is possible there. It is not built, and GH475.RL.10 above records that.

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
