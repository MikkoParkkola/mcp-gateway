# Test plan: direct route runs the controls meta dispatch runs (#1452, MIK-7597)

Design: `docs/design/2026-09-27-direct-route-guards.md` (revision 4, eaf8cafc3). This plan fixes
where each test lives, its fixture, and what the red commit contains. Test evidence comes from CI
only (throwaway PRs for red and mutants).

## Files

| File | Holds |
|---|---|
| `src/gateway/router/direct_guards_tests.rs` (new, declared `#[cfg(test)]` from `router/mod.rs`) | T1, T1b, T2, T3, T3b, T3c (HTTP, via the test-only seam), T3d, T4, T5, T6, T6b, T7, T7b-i, T7b-ii, T9, T11, T11b |
| `src/gateway/router/dispatch_parity_tests.rs` (new) | T8: the parity tables, the structural source check, and T3c's source assertion (the bridged round calls `admit_spend_for`) |
| `src/gateway/meta_mcp/invoke/dispatch_guards_tests.rs` (new) | adapter unit table (§2.1a of the design), one row per input arm: ok result, `isError: true`, rate limit as `isError: true`, rate limit as JSON-RPC error, rate limit as transport error, other JSON-RPC error, other transport error |

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
- Backend mode axis: every direct-route control cell (T1-T7b, T11) and the allowed baseline run twice,
  once against a normal backend and once against a `passthrough: true` backend, because the route
  forwards passthrough params unsanitised and the guards must sit on both arms of
  `backend_handler_inner`.
- Idempotency: cells that exercise replay (T1b, T5 cached row, T11, T11b, T3d) carry the key in
  `params._meta["io.mcp-gateway/idempotency-key"]` (`IDEMPOTENCY_KEY_META`, `src/protocol/mrtr.rs:33`),
  as `tests/mik_7272_sub4_three_routes.rs` does; this route reads no HTTP header. The replaced
  `MetaMcp` has idempotency enabled (`enable_idempotency`), which the base fixture leaves off.
- Budget figures (T3, T3b, T3d): tool cost 1.0, key daily limit 5.0. The enforcer blocks when
  projected spend reaches the limit and notifies at 80 %, so calls 1-4 are admitted, call 4 carries
  `_cost_warnings` (projected 4.0 = 80 %), and call 5 is refused -32003 (projected 5.0 >= 5.0).
  T3b uses the same enforcer and changes only the backend answer. T3c uses limit 2.5, all in `direct_guards_tests.rs` on one `AppState` and one API key: the
  opening call and one bridged round are driven through `state.meta_mcp` with that key's caller
  context (projected 1.0, 2.0) and both dispatch; then the direct HTTP call with the same key is
  refused (3.0).
- Profiles (T4): the default profile admits `alpha:*`; a named profile `no-alpha-read` excludes
  `alpha:read`, set only through `gateway_set_profile` on a real `mcp-session-id`.
- T9 hook: a `#[cfg(test)]` counter incremented on entry to `MetaMcp::direct_route_idempotency`
  (`src/gateway/meta_mcp/direct_route.rs`), so `backend_handlers.rs` does not grow past its size
  baseline. It counts every reservation attempt, whatever the outcome.

## Red commit

Tests plus signature-only stubs: `dispatch_guards.rs` with the four stage methods returning `Ok`
/ doing nothing, `DISPATCH_CONTROLS` as the six names, `DirectOutcome::from_response` returning a
a sentinel outcome that matches no row of the adapter table, `direct_guards.rs` with
`run`/`before_dispatch`/`after_dispatch` that pass through, and the module declarations. Test
instrumentation in the red commit: the T9 counter hook and the fixture helpers, both `#[cfg(test)]`.
No production call site changes, so every red cell fails on its assertion, not on compilation.
CI runs these under the default feature set with `cost-governance` (the budget cells need it); the
red run must show exactly the red cells below failing and every guard passing.

Expected red (stated reason) versus guards (green at red, pinned for later):

| Test | Red today because |
|---|---|
| T1, T2 | counter is 1 (backend called) |
| T1b | cached result returned instead of -32000 |
| T3 | call N+1 dispatches; no `_cost_warnings` |
| T3c | limit 2.5: an opening call and one bridged round both dispatch and spend 2.0, then a direct call dispatches (should be -32003); the source assertion finds `admit_spend(` in `BridgeDispatcher::invoke` |
| T4 | refused-profile call dispatches |
| T5 | the signing-on rows (nonce optional and `require_nonce`) dispatch; the cached-result rows (run under both signing-on configs) return the cached value. At green each refusal is -32001 with the message `message signing is enabled; use gateway_invoke`, with zero backend calls and zero reservation attempts (T9 hook) |
| T6 | `is_killed` stays false after N direct failures |
| T7 | fail-closed contract result delivered (HTTP 200 with result, not error) |
| T7b-i | response inspection `action_mode`, a result carrying a HIGH finding: delivered (should be refused) |
| T7b-ii | inspection off, context integrity `team_shared`, a result carrying a tool-poisoning payload: delivered (should be withheld) |
| T11 | using T7's fail-closed contract: the first call's payload-gate refusal is a delivered result today (should be a JSON-RPC error settled into the idempotency entry; the retry must replay it with count still 1) |
| T8 | G1-G6 rows differ between routes; structural check finds `kill_switch.is_killed` etc. in `invoke_tool_traced` |
| T9 | reservation hook counter is 1 |
| adapter table | the sentinel stub matches no row, so every classification assertion fails |
| DIRECT.7 | T5 signing-on rows: both dispatch today (should be -32001, count 0) |
| DIRECT.9 | the OWASP self-assessment still carries the meta-layer-only qualifiers (`docs/OWASP_AGENTIC_AI_COMPLIANCE.md` ASI08 cost budgets, ASI09 kill switch, ASI10 kill switch and budgets) and the #1452 backlog line; CI's citation check stays green, and the fix commit removes both (document diff reviewed in the final review) |
| Guards (green at red): T3b, T6b, T11b (a preseeded cached error replays without dispatch), T3d (a successful cached result replays after the budget is exhausted, no dispatch, no spend), T8 already-shared table, T5 signing-off row and the signed `gateway_invoke` rows, T4 absent/empty header rows, allowed baselines | — |

## Mutants (one throwaway PR each, on the fix head)

M1 drop kill switch from `admit_target` (T1, T1b, T8). M2 skip `before_dispatch` on direct (T3, T8).
M3 drop spend recording from `account_dispatch` (T3). M4 drop the profile step (T4). M5 call
`run` after the idempotency reservation (T9, T1b). M6 drop the G7 refusal (T5). M6b restore the `&& require_nonce` condition (T5 nonce-optional row). M7 skip
`account_dispatch` on direct (T6, T3). M8 skip `gate_payload` on direct (T7, T7b, T8). M9 re-add an
inline `admit_spend(` call in `invoke_tool_traced` (T8 structural). M10 route an S4 refusal to the
dispatch-`Err` arm (T7 status 500). M11 wire the guards only on the sanitised arm, not the
passthrough arm (every passthrough-mode cell). M12 move `before_dispatch` above the idempotency
short-circuit (T3d spends or refuses a replay). M13 keep the old profile check inside
`check_invocation_policy` (T8 structural).

## Structural check scope (T8)

The source check reads `invoke_tool_traced`, `check_invocation_policy`, `accounted_dispatch`,
`backend_handler_inner` and `direct_guards.rs`, so a primitive left behind in the old profile or
accounting site is caught as well as a new inline one (M9, M13).

## Gates before push

fmt, `clippy --all-targets` (compile-only, on Spark, own target dir), file-size ratchet (`invoke.rs`
and `backend_handlers.rs` must not grow; new modules under 800 lines), orphan-module check, commit
hygiene.

## Amendment 1 (red commit)

Five differences between the red commit and revision 3, each with its reason:

1. T3c runs on the router fixture with one test-only seam (maintainer decision): a
   `#[cfg(test)] pub(crate)` wrapper `MetaMcp::invoke_tool_for_test` over `invoke_tool`, which is
   `pub(super)`. The fixture backend asks once (`Answer::AskOnce`), a test channel accepts, and the
   opening call plus one bridged round are driven on the same `MetaMcp` the router serves (limit
   2.5, cost 1.0, spend 2.0). The per-backend HTTP call with the same key must then be refused
   -32003 with no further dispatch. Production visibility is unchanged.
2. Already-shared table populated with live rows that pin the expected outcome on both routes,
   not only their agreement: tool-name validation and the authorizer (a key denied `read`) are
   refused with zero dispatches; the per-key rate limit (limit 1) dispatches the first call and
   refuses the second; with the production firewall installed on router and Meta-MCP
   (`fixture_firewalled`), a shell-injection argument is refused with zero dispatches and a
   GitHub-token-shaped result is delivered with the token redacted and the benign text kept, the
   same shape on both routes: a tool result is inspected under `PreserveInputRequired` on the meta
   route, which blocks only when `inputRequests` or `requestState` change (`Immutable`, which
   blocks any change, applies to bridge challenges only).
   Attestation, the invocation audit record and undeclared-key refusal are already pinned on both
   routes by `router/tests/attestation_routes.rs`, `router/direct_audit_tests.rs` and
   `router/r2_identity_keys_tests.rs`; the table cites them rather than duplicate them.
3. T4 stages the session profile with `session_profiles().set_profile` instead of calling
   `gateway_set_profile`. Equivalent: the tool writes that same store, and the control under test
   is the read through `active_profile`, which both paths share.
4. T5 keeps its cached row: an idempotency cache shared between an unsigned gateway (which seeds a
   result under the key) and a signing gateway built afterwards, so the entry exists before signing
   is on; the signing gateway must refuse -32001. The repeated-key row also asserts zero
   reservation attempts on the keyed requests.
5. The signed-`gateway_invoke` guard covers both signing configurations: nonce optional, and
   `require_nonce` with the nonce in the `gateway_invoke` arguments. Both must be signed.

## Amendment 2 (G8, DIRECT.10)

- T12 (DIRECT.10, red), in `dispatch_parity_tests.rs`, replacing the former T8 response-redaction
  guard (deleted): with the production firewall on both layers, a result carrying a credential is
  answered on both routes with HTTP 200, `-32600` "Response blocked by security firewall", the
  delivery-refusal projection (`excludes_client_accounting`), and one dispatch; run on the normal and
  passthrough backends. At red the per-backend route delivers the redacted result (CI run
  36344395634 recorded the meta refusal).
- T12b (DIRECT.10, red): a keyed per-backend call whose result is blocked replays on retry as the same
  delivery refusal (status 200, same body, `excludes_client_accounting`) without dispatching again;
  both backend modes.
- T12c (guards): with an explicit Warn rule, a credential-bearing result is delivered redacted on both
  routes; with a clean result (Allow) it is delivered unchanged; both backend modes.
- T8 `session_profile` parity row: `initialize` on `/mcp`, capture the returned `mcp-session-id`,
  bind `no-read` on that id with `session_profiles().set_profile`, then send that id on both routes.
- Expected-red table: T12 and T12b are red cells; T12c and the remaining already-shared rows are
  guards.
- Mutant M14: `after_dispatch` ignores a Block verdict (T12, T12b red).
