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
| T1.3 | `kill_server_is_refused_on_stdio` | Keyed modern `gateway_kill_server`, twice. | Both refused by the confirmation gate (the destructive-confirmation refusal text); the fixture backend is still reachable afterwards (a `gateway_invoke` to it succeeds). No claim about key retention: a replayed refusal and a fresh refusal are indistinguishable from outside. | green |
| T1.4 | `revive_server_replays_its_first_result` | Keyed modern `gateway_revive_server` for the fixture backend, twice. | Second response `result` equals the first, and its text reports the same prior state. The distinguishing observable is the backend's revive count or state field, whichever the result reports; fixed at test-writing time and named in the test. | green |
| T1.5 | `set_state_replays_without_a_second_transition` | **Legacy shape** (idempotency key in `_meta`, no protocol fields): `gateway_set_state` to `triage`, twice with one key, then an unkeyed `gateway_set_state` to `complete`. | Second response has `previous: default` (a replay; a re-execution would say `previous: triage`). The third says `previous: triage`, so exactly one transition happened. | green |
| T1.6 | `set_profile_refusal_frees_the_key_and_success_replays` | **Legacy shape**, as T1.5 (a modern call is refused `NO_SESSION_FOR_PROFILE` before the arm runs, `admission.rs:368-378`). Keyed `gateway_set_profile` for an unknown profile; the same key for a known profile; that call again. | First refused, containing "Unknown routing profile". Second executes, because the abandoned lease freed the key. Third replays the second: equal `result`, and the session's profile was set once. | green |
| T1.7 | `reload_config_without_a_reload_context_is_refused` | Dispatcher-level keyed `gateway_reload_config`. | Refused -32603; message contains the full literal "Config reload is not enabled on this gateway" (substring match on the message). | green |
| T1.8 | `reload_config_over_the_serve_loop_replays` | `run_stdio_on` with a config file; keyed `gateway_reload_config`, twice. | Second response replays the first; the reload ran once (reload generation or log counter advances by 1). | green |
| T1.9 | `reload_capabilities_without_a_backend_is_refused` | Dispatcher-level keyed `gateway_reload_capabilities`. | Refused -32603; message contains the full literal "Capability backend is not enabled on this gateway" (substring match). | green |
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
| T4.4 | `signing_does_not_skip_the_current_policy` | As T4.1, with message signing on (the `Fixture` already signs). Replay under P2. Precondition: each stdio request builds a fresh signing context and prepares it under that request's policy (`server/mod.rs:2887-2891,3024-3026`), so for the replay either signing preparation or `check_invocation_policy` runs under P2. The test goes through `dispatch_single_with_sink`, which includes signing preparation. | Refused; T count 1. | green |

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

### I2 review log

- Test-plan review, one seat (`kimi-review`, content inline, SHIP-WITH-FIXES). All taken:
  - HIGH: T1.6 now uses the legacy shape, so it reaches the profile arm and kills N4.
  - T1.3 drops its unobservable key-retention claim.
  - T1.6 gains the replay call, so set_profile's replay clause is asserted.
  - T1.7 and T1.9 quote the full literals, matched as substrings.
  - T1.4 and T1.5 name their distinguishing observable.
  - T4.4 states its precondition.

---

# Test plan — I3: MIK-7272.LIFE.1

Design: D5 (rev 4). Written 2026-09-30, in parallel with I1's gates. Red commit after I2 lands.

## Row under test (verbatim, `RELEASE-4.0.0-scope-update.md:146`)

- **MIK-7272.LIFE.1**: A held legacy RPC can be cancelled and joined: cancelling it releases the
  held exchange and its waiter gets a terminal answer, with nothing left pending (MIK-7272
  SUB4.BRIDGE.LIFE.1).

Vocabulary (D5): the held exchange is the `StdioClientChannel.pending` entry for the outbound
`elicitation/create`. The waiter is the dispatch's `send_request` future, which is dropped; its
terminal answer is the joined task's `Cancelled` outcome. "Nothing left pending" means no
`pending` entry, no task in the `JoinSet`, and the slot and permit released.

## Harness

`Gateway::run_stdio_on` over `tokio::io::duplex`, with an HTTP fixture backend whose tool answers
`input_required` with one `elicitation/create` (the `stdio_initialize_order.rs` backend shape).
The fixture counts `tools/call` rounds. The client side is driven line by line:
1. `initialize` declaring `elicitation`;
2. a legacy `tools/call` to the asking tool (id `"held-1"`);
3. read frames until the outbound `elicitation/create` arrives (its id is `E`). The call is now
   held.

`pending` and the `JoinSet` are not visible from outside the loop, so "nothing left pending" is
observed through behaviour that differs only when an entry or task survives:
- a late answer to `E` resolves nothing, so no round 2 reaches the backend;
- no frame for `"held-1"` appears, even after stdin closes;
- `run_stdio_on` returns promptly at EOF, meaning every task was joined.

A bounded read helper collects frames for a fixed window (`ARRIVAL`, 5 s); every wait is bounded.

## Tests (new file `src/gateway/server/tests/life1_stdio_cancel.rs`)

| # | Test | Action | Assertion | Today |
|---|---|---|---|---|
| L1 | `cancel_releases_the_held_exchange` | Hold `"held-1"`. Send `notifications/cancelled {requestId: "held-1"}`. Then send the client's answer to `E`. | No second `tools/call` round reaches the backend (round count stays 1), and no frame with id `"held-1"` arrives within the window. | RED: the answer resolves `pending[E]`, the bridge retries, and a result frame for `"held-1"` is written |
| L2 | `a_cancelled_call_is_joined_before_eof_returns` | Hold, cancel, then close stdin. | `run_stdio_on` returns within 5 s, and no frame with id `"held-1"` was written at any point. | RED: `close()` fails the held prompt and an error frame for `"held-1"` is written |
| L3 | `an_unknown_cancel_is_ignored` | Send `notifications/cancelled` for an id never sent; then a normal `gateway_list_servers` call. | The normal call is answered; no error frame for the unknown id. | green (pin) |
| L4 | `initialize_is_not_cancelled` | Send `initialize` and a cancel naming its id in the same write. | The `initialize` response arrives. | green (pin; spec 2025-06-18 rule 2) |
| L5 | `cancelling_a_finished_call_changes_nothing` | A plain call that completes; then a cancel naming it; then another call. | Both calls answered once each; nothing else written. | green (pin; spec rule 4) |
| L6 | `a_cancelled_keyed_call_is_not_re_executed` | As L1 with the call keyed (legacy key in `_meta`); after the cancel, re-issue the same key and arguments, retrying within `ARRIVAL` until the settled refusal appears (the aborted task settles its lease asynchronously, so a first re-issue may still see the in-flight refusal). | Refused 409 "Secured execution result is unavailable" (settled as outcome-unknown, `admission.rs:333-336`); backend rounds stay 1 (settlement matrix, "held at the input bridge" row). | RED: the lease is still held, so the re-issue gets 409 "Execution is already in progress" (`:330-332`) |
| L7 | `a_batched_call_cannot_hold` | A batch holding one call to the asking tool. | The item's response is the bridge refusal (no session), and no outbound `elicitation/create` is written. | green (pin; D5 batch rule) |
| L8 | `eof_is_bounded_when_the_client_stops_reading` | Output is a `tokio::io::duplex(64)` whose read side the test never reads after the handshake. One held call suffices: its outbound `elicitation/create` frame is larger than 64 bytes, so the writer blocks on it. Then stdin closes. | `run_stdio_on` returns within `STDIO_DRAIN_TIMEOUT` (30 s) plus 10 s: the drain and the writer join share one deadline (D5 rev 4.1). | RED: `writer_task.await` is unbounded (`server/mod.rs:2718`) |

L8 costs about 30 s of wall time (the drain bound). It stays one test, and it is the only slow
row.

## Settlement matrix coverage

| Matrix row | Covered by |
|---|---|
| queued before dispatch | Not driven end to end: it needs 64 running dispatches to hold the permit. It is covered by the lease drop semantics already pinned in `idempotency/admission.rs` tests (`Lease::drop` abandons an undispatched lease). Named here so the gap is visible. |
| held at the input bridge | L6 |
| backend call in flight | L9 `a_cancel_during_the_backend_call_settles_unknown`: a fixture tool that sleeps 3 s; cancel mid-call; re-issue the same key, retrying within `ARRIVAL` as L6 does → 409 "Secured execution result is unavailable"; backend rounds 1. RED for the same reason as L6 (today: "Execution is already in progress"). |
| result secured, waiting to be queued | Not forcible without a hook between securing and queueing; the replay-on-reissue behaviour for completed keys is `dispatcher_admission_arms.rs::a_replayed_key_returns...`. Named gap. |

## Mutant batch

| M | Mutation | Must kill |
|---|---|---|
| P1 | the cancel handler ignores every id | L1, L2, L6, L9 |
| P2 | abort without recording the cancelled id | not killable at this level: the cancel line is always processed before EOF, so no frame can race it in a scripted test. The cancelled-id set is covered by design and review, not claimed as mutant-proven. |
| P3 | the completion arm never removes map entries | L5 (a later cancel for a reused id aborts the wrong task; the test reuses the finished id) |
| P4 | writer join unbounded again | L8 |
| P5 | the cancel handler does not skip `initialize` (a cancel naming the in-progress `initialize` id is acted on) | L4 |

### I3 review log

- Test-plan review, one seat (`kimi-review`, content inline, SHIP-WITH-FIXES). Taken:
  - the L6/L9 settlement race is handled with a bounded retry;
  - P2 is recorded as not killable at this level;
  - L8 gets one shared drain deadline (design D5), and its fill method is stated;
  - P5 is restated.

  Recorded here so it is not reopened: "its waiter gets a terminal answer" (the joined
  `Cancelled` outcome) is not observable from outside the loop. It is covered through L1 (a late
  answer resolves nothing) and L2 (the call is joined, and no frame appears).

# Test plan — I4: MIK-7272.OWNER.2

Design: D6 rev 5 (the task host, the carried mark, the typed owner) on top of D6 items 4–5.
Written 2026-10-01 at `bf5c901e3`. The red commit comes after rev 5's review.

## Row under test (verbatim, `RELEASE-4.0.0-scope-update.md:142`)

- **MIK-7272.OWNER.2**: The same protected task store reopens or relocates and its typed local
  operator retrieves the task; another store and a same-store HTTP owner cannot retrieve or alias
  it; exercised through store integration and the independent functional gate, with no global
  lookup and no new instance UUID (MIK-7272 SUB4.STDIO.OWNER.2).

## Harness

- **Binary over stdio.** A new integration file, `tests/mik_7272_owner2_stdio_tasks.rs`, spawns
  `CARGO_BIN_EXE_mcp-gateway serve --stdio` with an explicit `--config`. Its own helper is a small
  variant of `tests/common/stdio_session.rs`'s spawn that passes the config path; the shared
  helper is left as it is.
- **Config.**
  - `server.modern_protocol: true`;
  - `tasks.store_dir` = `<root>/tasks`. Stdio derives `<root>/tasks/stdio` (D6 rev 5 item 7);
  - one HTTP fixture backend that counts `tools/call` rounds. Its `slow` tool answers after 3 s,
    so a kill can land mid-call.
- **HTTP side.** I-OWN rows start an HTTP gateway on the same config from a second process, once
  the stdio child has exited. They reuse the start pattern in
  `tests/task_upstream_recovery/helper.rs:424-440`, copied into the new file's helper module and
  not shared.
- **Client sequence.**
  - `initialize` at the modern revision, declaring the Tasks extension.
  - A task-augmented `tools/call`: a `task` member, plus an idempotency key in `_meta`.
  - Then `tasks/get` until the task is terminal.

  Every wait is bounded (10 s, matching `READ_TIMEOUT`).

Red proof: every integration row drives only seams that exist before the fix (the binary, its
config, and JSON-RPC over pipes), so the red commit compiles and fails on assertions. The
in-crate rows (U1–U3) name new items (`TaskHost`, `TaskOwnerText`), so they land with the fix.
They are green on arrival, and the mutant batch is their proof.

## Integration rows (`tests/mik_7272_owner2_stdio_tasks.rs`)

| # | Test | Action | Assertion | Today |
|---|---|---|---|---|
| T1 | `stdio_serves_tasks_get_and_says_no_such_task` | After `initialize`, `tasks/get` for a random id. | -32602 "no such task", the HTTP text (`router/handlers.rs:112-114`). | RED: -32601 "Method not found" |
| T2 | `the_local_operator_creates_and_retrieves_a_task` | A task-augmented `tools/call` of the fixture tool with key K, then `tasks/get` until terminal. | The first answer is a create-task result carrying a `taskId`. The terminal task carries the fixture's result. Backend rounds = 1. | RED: answered synchronously, with no `taskId` |
| T3 | `the_task_survives_a_reopen` | T2, then close stdin, wait for exit, and respawn on the same config. `tasks/get` the id. | The same terminal result. Backend rounds still 1. | RED (no task) |
| T4 | `the_task_survives_a_relocation` | T2, then exit. Rename the base directory `<root>/tasks` to a new path, rewrite `tasks.store_dir` in the config, and respawn. `tasks/get` the id. | The same terminal result. No file in the store names a gateway instance id (the store files' names and fields are compared before and after: unchanged apart from the path). | RED |
| T5 | `another_store_does_not_have_it` | T2, then exit. Respawn with `tasks.store_dir` pointing at a fresh empty directory. `tasks/get` the id. | -32602 "no such task". | RED: -32601 |
| T6 | `i_own_a_same_store_http_owner_cannot_reach_it` (invariant I-OWN) | T2, then exit. Start HTTP with `tasks.store_dir` set explicitly to stdio's directory `<root>/tasks/stdio`, with auth off (owner `local:auth-disabled:tasks:v1`) and run `tasks/get`, `tasks/cancel` and `tasks/update` for the id. Repeat with auth on and an API-key client (owner `credential:…`). Stop HTTP, respawn stdio, and run `tasks/get`. | Every HTTP call answers -32602 "no such task". The stdio read afterwards still returns the result, so the cancel did not land. | RED (no task to protect) |
| T7 | `a_held_store_degrades_stdio_and_stops_advertising_tasks` | Spawn stdio A and keep it running. Spawn stdio B on the same config. | B serves `gateway_list_servers`. `tasks/get` answers -32601. Neither the modern `initialize` answer nor `server/discover` contains the Tasks extension. | RED: both advertise Tasks today |
| T8 | `discover_declares_tasks_when_stdio_serves_them` | Stdio with its store open: `server/discover`, then `tasks/get` for a random id. | Tasks is declared, and the `tasks/get` answer is -32602, not -32601 (D6 item 5: every declared extension is served). | RED: -32601 |
| T9 | `an_interrupted_stdio_task_is_settled_not_rerun` | A task on the `slow` tool. Kill the child (SIGKILL) about 1 s after the create answer, then respawn. `tasks/get` the id. | Terminal and an error, with the restart result `unknown` / `gateway_restart_after_dispatch` (`recovery.rs:123-137`). Backend rounds = 1 after 5 s. | RED (no task) |
| T10 | `an_http_restart_settles_a_stdio_task_but_cannot_read_it` | As T9, but after the kill HTTP is started with `tasks.store_dir` set explicitly to `<root>/tasks/stdio`. Then stop HTTP and respawn stdio. | HTTP `tasks/get` answers -32602. Stdio afterwards reads the settled restart result. Backend rounds = 1. | RED (no task) |
| T11 | `stdio_task_creation_ignores_the_http_auth_gate` | Config with `auth.enabled: true` and one API key. Stdio creates a task as in T2. | The task is created and completes (D6 rev 5 item 5). | RED (no task) |
| T12 | `http_and_stdio_share_a_config_without_contention` | With stdio A running on the default config, start HTTP on the same config. Run a task over each. | HTTP starts. Both create and read their own tasks. `<root>/tasks/stdio` exists and holds only stdio's records. Neither transport reads the other's task. | RED: stdio has no store today, so it creates no `stdio` subdirectory and no task |
| T13 | `an_explicitly_shared_store_names_the_holder` | Stdio A running. Start HTTP with `tasks.store_dir` = `<root>/tasks/stdio`. | HTTP exits non-zero, and its error names the path and "possibly a stdio gateway". | RED: stdio holds no lease today, so HTTP starts |

T3, T4 and T5 together are the row's "reopens or relocates … another store". T6 and T10 are its
"same-store HTTP owner cannot retrieve or alias". T4's file comparison and the absence of any
global index are its "no global lookup and no new instance UUID".

## In-crate rows (land with the fix)

| # | Test | Assertion |
|---|---|---|
| U1 | `a_stdio_task_dispatch_keeps_its_owner_mark` (`task_service/host_tests.rs`) | An `OwnedCallerContext` built through the stdio intent path, rebuilt by the worker's own `dispatch_context`: `owner_principal() == Some(LOCAL_OPERATOR_PRINCIPAL)`, `provenance()` is `LocalTransport`, and `caller_cache_principal(..)` is `Caller(_)`, not `Unresolved`. This is the lead's pinned path: the keyed inner call keeps its key. |
| U2 | `a_stdio_task_s_inner_keyed_call_is_duplicate_protected` | Through `TaskExecutor` with a `TaskHost::Stdio` and a counting fixture: a stdio task whose tool is a keyed `gateway_invoke`. After it completes, the meta idempotency cache holds an entry for that key under the reserved principal. A second dispatch of the same inner call within the cache window is served from the cache, so backend rounds = 1. |
| U3 | `http_owner_text_cannot_name_the_local_operator` (`task_route_tests.rs`) | `TaskOwnerText::Http` with each of `"\0local-operator.v1"`, `"\0"`, and `"\0local-operator.v1x"` resolves to not found against a store holding a stdio task. `"stdio"`, `local:auth-disabled:tasks:v1` and a `credential:` digest also miss it. |
| U4 | `a_stdio_worker_outliving_its_session_settles_before_dispatch` | Drop the `StdioTaskHost` before the worker upgrades it. The task settles `not_executed` / `gateway_interrupted_before_dispatch`, with backend rounds = 0. |
| U5 | `a_stdio_task_runs_under_the_current_tool_policy` | A stdio task whose target `ToolPolicy` denies is refused by the worker's authorizer: terminal with an error, backend rounds = 0. A permitted neighbour task completes. |

## Mutant batch

| M | Mutation | Must kill |
|---|---|---|
| N1 | the rebuilt context drops the carried mark (`stdio_nonce: None` again) | U1, U2 |
| N2 | `TaskOwnerText::Http` stops refusing NUL-prefixed text | U3 |
| N3 | stdio's owner is the text `"stdio"` instead of `LocalOperator` | U3, T6 (auth-off HTTP owner differs, so T6 alone may not kill it; U3's `"stdio"` probe does) |
| N4 | the degradation flag is ignored by discover and initialize | T7 |
| N5 | stdio opens a fresh temp store instead of `tasks.store_dir` | T3, T4 |
| N8 | stdio opens `tasks.store_dir` itself, not its `stdio` subdirectory | T12 (HTTP fails to start on the held lease) |
| N6 | the stdio creation path keeps HTTP's auth gate | T11 |
| N7 | the `Stdio` host's authorizer allows every target, skipping `ToolPolicy` | U5 |

## Out of this increment

- Leg (b), the independent functional drive of the digest-pinned image (D6 item 4), runs after
  merge and before grading.
- The lease direction is decided (D6 rev 5 item 7, option (d)). It is covered by T7, T12 and T13 and mutant N8.
