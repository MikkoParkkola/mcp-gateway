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
