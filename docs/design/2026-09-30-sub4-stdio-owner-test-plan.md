# Test plan — I1: MIK-7272.OWNER.3 and MIK-7272.OWNER.5

Design: `docs/design/2026-09-30-sub4-stdio-owner.md` rev 3.1 (D1 with the `StdioNonce` amendment,
D4). This plan covers increment I1 only. Plans for I2 to I5 are appended here, each reviewed
before its failing tests are written.

## Rows under test (verbatim, `RELEASE-4.0.0-scope-update.md:143,145`)

- **MIK-7272.OWNER.3**: An injected principal tag or HTTP credential string equal to the stdio
  serialized spelling cannot select or alias the stdio local operator; only the transport creates
  the typed tag; same-key owner-specific outputs stay separate and the real stdio owner works.
- **MIK-7272.OWNER.5**: The real stdio-created context carries its execution principal but no
  verified identity, personal account or delegated grant; account-dependent calls are refused and
  an ordinary local mutation works.

## Where the harm is observable today

`CallerProvenance::LocalTransport` and `::Credential` currently lead to the same decision
(`establishes_the_operator`, `identity_propagation/caller_proof.rs:92`). So a string `"stdio"`
selecting `LocalTransport` changes no decision today; the classification change in D1 is
hardening, and its tests are pins. The harm a string spelling can do today is in the two
retained-output stores, which both namespace stdio by the string:

- the admission ledger (`ExecutionAdmission`, reached through `MetaMcp::admit_meta_sync`), which
  replays a secured result for the same owner and key;
- the response/idempotency cache (`IdempotencyCache`, reached inside `invoke_tool_traced`),
  namespaced by `caller_cache_principal` (`meta_mcp/support.rs:163`), stdio → `cred:5:stdio`.

The red tests therefore observe aliasing in those two stores, not the classification.

## Red-proof mechanics (CI is the only compiler)

The failing-tests commit must fail on assertions, never on compilation. Every test below uses only
items that exist before and after the fix:

- the tagged context: `super::super::stdio_caller_context(&authorizer, era)` (`server/mod.rs:3649`,
  `cfg(test)`, sets `stdio_nonce: Some(StdioNonce::process())`), and the production dispatcher
  `Gateway::dispatch_single_with_sink` with a `StdioClient`;
- the untagged "stdio" spelling: struct update on that context,
  `MetaMcpCallerContext { stdio_nonce: None, ..tagged }`. The field `stdio_nonce` exists today
  (`meta_mcp/mod.rs:186`), so this compiles before and after. A second spelling imitates an HTTP
  API-key caller: the same, plus `credential_kind: CredentialKind::ApiKey` and
  `authentication: Authenticated`;
- `MetaMcp::admit_meta_sync` (`pub(crate)`), `SyncLease::complete_secured` (`pub(crate)`), and the
  `EchoBackend::tools_call_count()` fixture (`server/tests/signing_nonce_allocations_support.rs:152`).

The tests live in a new file, `src/gateway/server/tests/owner3_stdio_tag.rs`, with their own
helpers, so the fix commit does not edit them.

## Tests

### OWNER.3

| # | Test | Setup and action | Assertion | Today | After fix |
|---|---|---|---|---|---|
| T3.1 | `stdio_results_are_keyed_by_transport_not_by_name` | One `MetaMcp`. The tagged context admits a keyed mutating `gateway_invoke` (key K) → `Owned`, completed with a secured response carrying a marker. Then, for each non-transport context in a table (the struct-update copy without the nonce; the same imitating an API-key credential kind), a fresh admission of the same K and arguments. | Every table row is `Owned`, not `Replay`, and none carries the marker. | Replay → RED | Owned |
| T3.2 | `a_named_context_does_not_seed_the_stdio_operators_results` | Reverse order: the untagged context first (completed with marker B), the tagged context second. | The tagged admission is `Owned`, not a replay of marker B. | RED | GREEN |
| T3.4 | `stdio_idempotency_entries_are_keyed_by_transport` | `Fixture::start_mutating`. A real stdio dispatch of a keyed call (key K in `_meta`) → count 1; the invoke path stores the result in `IdempotencyCache` under the operator's cache principal (`invoke.rs:1805-1845`). Then the same `gateway_invoke` arguments go through `MetaMcp::handle_tools_call` (the `pub` entry HTTP calls after its admission) with the untagged context, whose `retry` carries K. | Backend `tools_call_count() == 2`: the untagged caller reaches the backend, not the operator's entry. (No response-body comparison: the fixture backend may answer two calls identically.) | 1 → RED | 2 |
| T3.5 | `batched_stdio_calls_are_keyed_by_transport` | Real stdio **batch** of one keyed mutating call (K) through `dispatch_batch_with_sink`, then the untagged context admits K. | `Owned`: the batch item was stored under the operator namespace, not the string's. | RED | GREEN (fails again if batch items ever lose the tag) |
| T3.6 | `the_stdio_operator_replays_its_own_keyed_write` | Real stdio dispatch, keyed mutating call K, sent twice with the same JSON-RPC id. | `tools_call_count() == 1`; the second response's `result` member equals the first's (the id is rewritten on replay, so the comparison is on `result`, not the whole frame). | GREEN (positive control) | GREEN |
| T3.7 | `a_chain_step_keeps_the_stdio_tag` | `stdio_caller_context(..).with_retry(&retry)`. | `stdio_nonce.is_some()`. | GREEN (pin) | GREEN |

Pins added in the **fix** commit (they need the new `classify` signature and cannot exist before
it; they are extra, not the red proof):
- `classify` with principal `"stdio"` and no nonce → `Credential`; with a nonce → `LocalTransport`;
  anonymous with a nonce → still `LocalTransport` only when the principal is the stdio constant
  (exact rule written with the fix, reviewed in final review).
- each of the five stdio catalogue methods passes the nonce (via `stdio_catalogue::dispatch`) and
  the HTTP router passes `None`.

### OWNER.5

| # | Test | Setup and action | Assertion | Today |
|---|---|---|---|---|
| T5.1 | `real_stdio_context_carries_principal_and_no_personal_identity` | The context `build_stdio_caller_context` builds (the production builder, `server/mod.rs:3124`, called from the test module), not the `stdio_caller_context` fixture. | `credential_principal == Some("stdio")`; `stdio_nonce.is_some()`; `verified_identity`, `grant_subject`, `api_key_name` are `None`. | GREEN (pin) |
| T5.2 | `stdio_refuses_an_account_dependent_call_and_serves_a_local_mutation` | One `MetaMcp` with two backends, built by the account fixture (`meta_mcp/account_resolver_gateway.rs` `gateway_in`, `ServeMode::Stdio`): one bound to per-user identity propagation (`Bind::Propagation(external_cfg())`), one plain. Both called through `dispatch_single_with_sink` with a `StdioClient`. | Propagation backend: error contains "no verified end-user identity" and 0 dispatches to it. Plain mutating call in the same session: succeeds, 1 dispatch. | GREEN (pin) |
| T5.3 | (existing) `stdio_run_path_serves_its_operator_the_managed_account` (`server/tests/stdio_sole_operator.rs:365`) | — | The sole-operator deployment account stays served: "no personal account" means no per-user account, not that the deployment's account is withheld (D4). | GREEN, cited |

OWNER.5 is expected green on arrival: it pins current behaviour. Its "fails when the property is
removed" proof is the mutant batch (below), not a manufactured red.

## Mutant batch (CI mutants workflow, branch `throwaway/mutants-<digits>`)

Each mutant must turn at least one named test red; a surviving mutant fails the increment.

| M | Mutation (applied to the fix) | Must kill |
|---|---|---|
| M1 | admission namespace ignores the nonce (back to the principal string) | T3.1, T3.2, T3.5 |
| M2 | cache principal ignores the nonce | T3.4 |
| M3 | `build_stdio_caller_context` sets `stdio_nonce: None` | T3.5, T5.1 (not T3.6: both of its calls lose the tag alike and still replay) |
| M4 | batch path passes a non-stdio client (untagged) | T3.5 |
| M5 | `with_retry` drops `stdio_nonce` | T3.7 |
| M6 | stdio context sets `verified_identity`/`grant_subject` to a fixture value | T5.1 |
| M7 | the identity gate accepts a caller without verified identity for propagation backends | T5.2 |

## Out of this increment

OWNER.1/OWNER.4 (I2), LIFE.1 (I3), OWNER.2 (I4), STDIO.1 (I5).

## Review log

- Test-plan review, one seat (`kimi-review`, content inline, SHIP-WITH-FIXES). Taken:
  - M3's killers corrected to T3.5 and T5.1;
  - T3.4 asserts the dispatch count only, and T3.6 compares `result` members;
  - T3.1 and T3.3 merged into one table-driven test.

  Test names are made neutral, per the lead's handling rule.

---

# Test plan — I2: MIK-7272.OWNER.1 and MIK-7272.OWNER.4

Design: D2 and D3 (rev 4). Written 2026-09-30 in parallel with I1. The red commit waits for I1
to land.

## Rows under test (verbatim, `RELEASE-4.0.0-scope-update.md:141,144`)

- **MIK-7272.OWNER.1**: On modern stdio, keyed writes execute once and replay without another
  effect; a keyless write executes (no refusal); legacy unkeyed repeats execute twice; all six
  management branches are tested (MIK-7272 SUB4.STDIO.OWNER.1, amended by operator ruling
  2026-09-30).
- **MIK-7272.OWNER.4**: A ToolPolicy denial refuses a local-operator mutation before
  retained-output delivery with zero dispatch to the denied target, while a permitted
  neighbouring target works (MIK-7272 SUB4.STDIO.OWNER.4).

## Already covered at the production stdio dispatcher (cited, not duplicated)

| Clause | Existing test |
|---|---|
| keyed write executes once | `dispatcher_admission_arms.rs::a_keyed_mutation_dispatches_exactly_once` |
| keyed write replays without another effect | `dispatcher_admission_arms.rs::a_replayed_key_returns_the_stored_result_without_re_running_it` |
| keyless modern write executes | `unkeyed_admission.rs::t1_unkeyed_modern_mutation_is_admitted_by_default` |
| keyless modern repeat executes twice | `unkeyed_admission.rs::t7_unkeyed_reissue_executes_twice_by_default` |

`unkeyed_admission.rs` is compiled only with the `metrics` feature. CI runs `--all-features`,
but a default-feature build skips it. So T1.1 below re-asserts the keyless clause without that
feature gate.

## Facts the management rows rest on

- `mark_management_dispatch` (`meta_mcp/admission.rs:492-535`) has five arms for six tools:
  - kill/revive (`server` required);
  - `gateway_set_state` (`state`, session required);
  - `gateway_set_profile` (`profile`, session, known profile);
  - `gateway_reload_config` (a reload context must be installed);
  - `gateway_reload_capabilities` (a capability backend must be installed).

  A call that passes its arm marks the lease dispatched, and its secured result is retained for
  the key. A call that fails its arm is refused before dispatch, so the lease is abandoned and
  the key stays reusable.
- `gateway_kill_server` is the destructive floor (`destructive_confirmation.rs:213`). Stdio's
  confirmation channel is `Unavailable` (`server/mod.rs`, `stdio_caller_context`), so over stdio
  it is refused by the confirmation gate before admission marks anything.
- The reload context and the capability backend are installed only by the stdio serve loop
  (`server/mod.rs:2316,2384`), not by `build_meta_mcp`. Their "installed" rows therefore run
  through `run_stdio_on` with a config file (the `stdio_initialize_order.rs` harness shape). The
  dispatcher-level rows cover the "not installed" arm.

## Tests (new file `src/gateway/server/tests/owner1_stdio_management.rs`, own helpers)

| # | Test | Action over stdio | Assertion | Expected today |
|---|---|---|---|---|
| T1.1 | `keyless_modern_write_executes` | Unkeyed modern `gateway_invoke` to the mutating target, twice. | 2 dispatches, no refusal. | green |
| T1.2 | `legacy_unkeyed_repeat_executes_twice` | Legacy-shaped (no `_meta`) `gateway_invoke`, same arguments, twice. | 2 dispatches. | green |
| T1.3 | `kill_server_is_refused_before_admission_on_stdio` | Keyed modern `gateway_kill_server`, twice. | Both refused by the confirmation gate; the backend stays alive; the key is not retained (a third call gets the same refusal, not a replay). | green |
| T1.4 | `revive_server_replays_its_first_result` | Keyed modern `gateway_revive_server` for the fixture backend, twice. | Second response `result` equals the first; one revive effect (backend state transitions once). | green |
| T1.5 | `set_state_replays_without_a_second_transition` | Legacy `gateway_set_state` keyed `triage`, twice. | Second response replays the first (`previous: default`), not a second transition. | green |
| T1.6 | `set_profile_unknown_is_refused_and_the_key_stays_reusable` | Keyed `gateway_set_profile` for an unknown profile, then the same key for a known one. | First refused "Unknown routing profile"; second executes, because the abandoned lease freed the key. | green |
| T1.7 | `reload_config_without_a_reload_context_is_refused` | Dispatcher-level keyed `gateway_reload_config`. | Refused -32603 "Config reload is not enabled". | green |
| T1.8 | `reload_config_over_the_serve_loop_replays` | `run_stdio_on` with a config file; keyed `gateway_reload_config`, twice. | Second response replays the first; the reload ran once (reload generation or log counter advances by 1). | green |
| T1.9 | `reload_capabilities_without_a_backend_is_refused` | Dispatcher-level keyed `gateway_reload_capabilities`. | Refused -32603 "Capability backend is not enabled". | green |
| T1.10 | `reload_capabilities_over_the_serve_loop_replays` | `run_stdio_on`, capabilities enabled with an empty directory; keyed call, twice. | Second response replays the first; one reload. | green |

### OWNER.4 (new file `src/gateway/server/tests/owner4_stdio_policy.rs`)

Every step runs against one `MetaMcp`, calling `dispatch_single_with_sink` with the `ToolPolicy`
passed in per request. P1 is the default policy; P2 is `ToolPolicy::from_config` with
`deny: ["<TOOL>"]`. The neighbour U is a second tool on the same fixture backend.

| # | Test | Action | Assertion | Expected today |
|---|---|---|---|---|
| T4.1 | `a_denied_target_is_refused_before_its_retained_result` | Keyed T under P1 → executes (count 1). Same key and arguments under P2. | Refused with the policy error; the response carries no retained `result`; T count still 1. | green (D3: policy precedes admission replay on stdio) |
| T4.2 | `a_permitted_neighbour_still_works_under_the_denial` | Under P2, keyed call to U. | Executes; U count 1. | green |
| T4.3 | `a_denied_target_never_dispatches` | P2 from the start, keyed T. | Refused; T count 0. | green |
| T4.4 | `signing_does_not_skip_the_current_policy` | As T4.1, with message signing on (the `Fixture` already signs). Replay under P2. | Refused; T count 1. This pins that `prepared_for` reuses a check made in the same request (design D3). | green |

## Red proof

All I2 rows are expected green on arrival: D2 and D3 plan no product change. The red commit is
therefore "tests only, CI green", and the "fails when the property is removed" proof is the
mutant batch:

| M | Mutation | Must kill |
|---|---|---|
| N1 | `admit_meta_sync` checks policy after the admission replay instead of before (move `check_invocation_policy` below the ledger lookup) | T4.1, T4.4 |
| N2 | skip `check_invocation_policy` when `caller.signing` is `Some` regardless of `prepared_for` | T4.4 |
| N3 | `mark_management_dispatch` returns before `mark_dispatched()` for `gateway_set_state` | T1.5 |
| N4 | the `gateway_set_profile` arm skips the known-profile check | T1.6 |
| N5 | the confirmation gate treats `Unavailable` as confirmed | T1.3 |
| N6 | `admit_operation` treats a legacy unkeyed call as keyed under a fixed key | T1.2 |

If any I2 row is red on arrival, the design reopens (D2/D3 say "a red test reopens design"), and
the lead hears about it before a fix is written.
