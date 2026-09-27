# Test plan: direct route runs the controls meta dispatch runs (#1452, MIK-7597)

Design: `docs/design/2026-09-27-direct-route-guards.md` (revision 4, eaf8cafc3). This plan fixes
where each test lives, its fixture, and what the red commit contains. Test evidence comes from CI
only (throwaway PRs for red and mutants).

## Files

| File | Holds |
|---|---|
| `src/gateway/router/direct_guards_tests.rs` (new, declared `#[cfg(test)]` from `router/mod.rs`) | T1, T1b, T2, T3, T3b, T4, T5, T6, T6b, T7, T7b, T9, T11 |
| `src/gateway/router/dispatch_parity_tests.rs` (new) | T8: the three parity tables and the structural source check |
| `src/gateway/meta_mcp/invoke/dispatch_guards_tests.rs` (new) | adapter unit table (§2.1a of the design), one row per input arm: ok result, `isError: true`, rate limit as `isError: true`, rate limit as JSON-RPC error, rate limit as transport error, other JSON-RPC error, other transport error; T3c source assertion |
| `src/gateway/meta_mcp/input_bridge` existing bridge tests | T3c behavioural half (bridged round then direct call) |

T10 (task-worker path) is added by whichever of this change and LIFECYCLE.1 lands second, per the
agreed chain; it is listed here so it is not lost.

## Shared fixture

One router fixture, modelled on `direct_tasks_owner_tests.rs` / `direct_audit_tests.rs`:
- `test_router_app_state_with_auth` with two API keys (`k-std`, non-admin, `backends: ["*"]`; a
  second key for budget cells), one backend `alpha` whose transport is a counting stub
  (`Arc<AtomicUsize>` of `tools/call` requests; answers configurable: ok result, `isError: true`,
  JSON-RPC error, rate-limit error, transport error).
- `MetaMcp` replaced in `AppState` as the audit tests do, then armed per cell with existing setters:
  kill switch `meta.kill_switch().kill("alpha")`; capability disable through
  `KillSwitch::record_capability_failure` to the configured limit; budget
  `with_cost_governance(BudgetEnforcer::new(cfg, registry))` with `cost_for(tool)=1.0` and a daily
  limit; profile `with_profile_registry` plus `gateway_set_profile` on the session; signing
  `enable_message_signing(secret, window, require_nonce)`; contract `set_response_contract`;
  inspection `response_inspection_action_mode = true`; context integrity preset `team_shared`.
- Meta-route twin: the same arming, called through `POST /mcp` `tools/call gateway_invoke`
  (server `alpha`), used by the parity tables.
- Every cell asserts the counter. The allowed baseline asserts exactly 1.

## Red commit

Tests plus signature-only stubs: `dispatch_guards.rs` with the four stage methods returning `Ok`
/ doing nothing, `DISPATCH_CONTROLS` as the six names, `DirectOutcome::from_response` returning a
fixed Success, `direct_guards.rs` with `run`/`before_dispatch`/`after_dispatch` that pass through.
No production call site changes, so every red cell fails on its assertion, not on compilation.

Expected red (stated reason) versus guards (green at red, pinned for later):

| Test | Red today because |
|---|---|
| T1, T2 | counter is 1 (backend called) |
| T1b | cached result returned instead of -32000 |
| T3 | call N+1 dispatches; no `_cost_warnings` |
| T3c | direct call after the bridged round dispatches; source assertion finds `admit_spend(` at :937 |
| T4 | refused-profile call dispatches |
| T5 | `require_nonce` row dispatches; cached-result row returns the cached value |
| T6 | `is_killed` stays false after N direct failures |
| T7 | fail-closed contract result delivered (HTTP 200 with result, not error) |
| T7b | HIGH-finding result delivered; team_shared result not withheld |
| T8 | G1-G6 rows differ between routes; structural check finds `kill_switch.is_killed` etc. in `invoke_tool_traced` |
| T9 | reservation hook counter is 1 |
| adapter table | stub classifies every case as Success |
| Guards (green at red): T3b, T6b, T11, T8 already-shared table, T5 signing-off and nonce-optional rows, T4 absent/empty header rows, allowed baselines | — |

## Mutants (one throwaway PR each, on the fix head)

M1 drop kill switch from `admit_target` (T1, T1b, T8). M2 skip `before_dispatch` on direct (T3, T8).
M3 drop spend recording from `account_dispatch` (T3). M4 drop the profile step (T4). M5 call
`run` after the idempotency reservation (T9, T1b). M6 drop the G7 refusal (T5). M7 skip
`account_dispatch` on direct (T6, T3). M8 skip `gate_payload` on direct (T7, T7b, T8). M9 re-add an
inline `admit_spend(` call in `invoke_tool_traced` (T8 structural). M10 route an S4 refusal to the
dispatch-`Err` arm (T7 status 500).

## Gates before push

fmt, `clippy --all-targets` (compile-only, on Spark, own target dir), file-size ratchet (`invoke.rs`
and `backend_handlers.rs` must not grow; new modules under 800 lines), orphan-module check, commit
hygiene.
