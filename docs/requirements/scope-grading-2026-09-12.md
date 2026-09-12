# Scope grading — 2026-09-12 (corrective pass)

Supersedes the truncated pass that graded by counting `#[test]` attributes.
That instrument returns an empty count for files using other attribute forms,
and the previous agent read empty as "file absent". Every row below is graded
by **running** the tests or by reading production code, never by counting
attributes.

Criterion statements are recovered verbatim from
`docs/requirements/RELEASE-4.0.0-scope-update.md` (the approved-scope table);
acceptance shapes from `RELEASE-4.0.0-scope-tests.md`.

Buckets: MET / IMPLEMENTED-UNTESTED / PARTIAL / ABSENT / NO-REQUIREMENT.

Command environment for every cargo run below:
`export CARGO_TARGET_DIR=/Users/mikko/github/.cargo-target-shared`

---


## Rows 1-8 (SAFETY, ACCOUNTS-catalogue, BRIDGE)

| ID | Verdict | Evidence | Effort to close |
|---|---|---|---|
| GH462.CONFIG.1 | MET | `cargo test --test gh462_config_preservation` -> `test result: ok. 44 passed; 0 failed; 0 ignored`. | none |
| GH452.SESSION.1 | MET | `cargo test --test gh452_session_owner` -> `ok. 11 passed; 0 failed; 0 ignored`. | none |
| MIK-7377.SIGNING.1 | MET | `cargo test --test message_signing_delivery` -> `ok. 5 passed; 0 failed; 0 ignored`; six further `message_signing_*` binaries on disk (config, reload, nonce schema/metrics, stdio coverage/reload). | none |
| MIK-7334.CATALOGUE.1 | PARTIAL | Identity-scoped catalogue/cache keying reads as present: `rg -uu -l 'per_identity\|per-identity\|identity_scoped\|tool_cache\|list_tools_cache' src/` -> `src/backend/ops.rs`, `src/gateway/router/backend_handlers.rs`, `src/key_server/handler.rs`, `src/backend/pool_tests.rs`, `src/config/features/key_server.rs`. No test file names catalogue isolation or revocation; the 157 passing `personal_accounts::` tests cover credentials, not catalogue/result caches. | medium — one test: revoke, then assert the cached catalogue and cached result are gone for that caller only |
| MIK-7387.STDIO.1 | ABSENT | `cargo test --test mik_7212_mrtr7_stdio_acs` -> `test result: ok. 0 passed; 0 failed; 3 ignored`. `ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads` carries `#[ignore = "MIK-7387: stdio concurrent dispatch is a separate work package; this row is its spec"]`; its doc comment states the gateway "never asked anything at all, which is exactly today's behaviour". The file is a specification, not evidence. | large — the MIK-7387 work package itself |
| MIK-7387.STDIO.2 | ABSENT | Same binary, same ignore: `ac_mrtr_7a_bridged_request_follows_the_initialize_response` is in the 3 ignored, 0 passed. | large — same package |
| MIK-7387.STDIO.3 | ABSENT | Same binary, same ignore: `ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames` is in the 3 ignored, 0 passed. | large — same package |
| MIK-7388.CANCEL.1 | PARTIAL | `cargo test --test mik_7212_mrtr7_bridge_acs` -> `ok. 25 passed; 0 failed; 0 ignored`, covering bridged-round accounting, request/aggregate budgets, retry bound, decline/error refusals, malformed accepts, and two `mik_7388_*` answer-shape rows. No passing test cancels a live bridged exchange and asserts pending-state reclamation or non-delivery to another exchange. | medium — one test: cancel mid-exchange, assert pending map drained and no cross-delivery |

## Rows 9-13 (TASKS)

The previous pass graded this package ABSENT by counting `#[test]` attributes in
`task_*.rs`. These files use `#[tokio::test]`, so the count was zero. Running
them reverses two rows.

| ID | Verdict | Evidence | Effort to close |
|---|---|---|---|
| MIK-7311.LIFECYCLE.1 | MET | `cargo test --test mik_7272_task_1_acs` -> `ok. 20 passed; 0 failed; 0 ignored`. Named passing tests cover every clause: public-route dispatch (`dispatch::ac_task_1_1_a_created_task_id_resolves_immediately`), polling/status payloads (`ac_task_1_2_each_status_carries_its_own_payload_and_no_other`), input (`dispatch::ac_task_1_3_an_accepted_update_acknowledges_with_an_empty_result`, `..._an_input_response_with_no_outstanding_request_is_refused`), cooperative cancellation gated to the pinned revision (`ac_task_1_5_tasks_cancel_is_gated_as_a_2026_07_28_method`), terminal outcomes (`ac_task_1_6_a_failed_task_carries_an_error_object_not_a_string`, `..._an_is_error_tool_result_is_completed_and_not_failed`), and extension negotiation (`capabilities::ac_task_1_10_initialize_advertises_the_tasks_extension_to_a_2026_peer`). Expiry is pinned separately by `cargo test --test task_expiry_http_lifecycle` -> `ok. 1 passed; 0 failed; 0 ignored` (`a_configured_expiry_interval_reaps_a_real_task_and_shutdown_releases_the_store`). | none |
| MIK-7311.LIFECYCLE.2 | PARTIAL | Cross-principal isolation is fully pinned by passing tests: `ownership::ac_task_1_11_another_principals_task_is_indistinguishable_from_no_task`, `..._ac_task_1_12_subscription_admission_hides_another_principals_task`, `..._ac_task_1_18_an_unattributed_caller_owns_no_task`, `..._ac_task_1_9_a_task_subscription_is_admitted_for_its_owner`. No passing test drops a client connection and re-queries the same task as the same principal after reconnect; the one session-shaped candidate, `tests/nfr_compat_2_stdio_client_session.rs`, contains no `reconnect`/`disconnect` occurrence (`rg -N -c` -> no match), so the reconnect clause is unevidenced. | small — one test: accept a task, drop the transport, reconnect, query as the same principal |
| MIK-7311.LIFECYCLE.3 | MET | `cargo test --test task_upstream_recovery` -> `ok. 10 passed; 0 failed; 0 ignored`, including `a_durable_handle_survives_reopen_and_only_its_owner_reads_it` (restart-window resolution plus owner-only read) and `a_captured_handle_is_recorded_at_version_three_with_its_descriptor` (durable identity and descriptor). | none |
| MIK-7311.LIFECYCLE.4 | MET (was ABSENT) | Same binary, all passing. Never-silently-replay: `the_original_operation_is_submitted_once_and_never_resubmitted`. Recover-where-supported: `unavailable_then_live_then_complete_reuses_the_one_handle`. Explicit refusal instead of a guess when recovery is unsupported: `an_adapter_untrusted_at_restart_causes_zero_queries`, `with_no_configured_adapter_the_conservative_branch_is_unchanged`. Read-only positive control: `the_configured_output_policy_applies_to_a_recovered_result`. Graded off `tests/task_upstream_recovery.rs` only — `task_upstream_recovery_sdk.rs` is feature-gated and needs external services, so it is not load-bearing here. | none |
| MIK-7311.LIFECYCLE.5 | PARTIAL (was ABSENT) | Lifetime bound and store release are pinned by `task_expiry_http_lifecycle` (1 passed, real reaper). Creation-rate and retained-result bounds, and the "cancellation race cannot rewrite a settled outcome" clause, have no passing named test in either task binary. | medium — two tests: creation/retention cap rejection, and cancel-after-settle leaves the terminal outcome untouched |

## Rows 14-19 (ACCOUNTS)

Package-wide run for this section: `cargo test --lib personal_accounts::` ->
`test result: ok. 157 passed; 0 failed; 1 ignored; 0 measured; 4576 filtered out`.
The single ignored test was not identified; no row below rests on it.

| ID | Verdict | Evidence | Effort to close |
|---|---|---|---|
| MIK-6744.STORE.1 | MET | The 157-passing run covers the clauses by module: keying and load/save in `src/personal_accounts/store_tests.rs`, refresh in `service_refresh_tests.rs`, at-rest protection in `vault.rs`/`storage.rs`, wire bounds in `wire_bound_tests.rs`, and no-silent-loss under crash/repair in `crash_tests.rs`/`repair_tests.rs`/`fence_tests.rs`. The run's 1 ignored test is identified: `rg -n -B2 '#\[ignore' src/personal_accounts/` returns only private child-binary entrypoints (`crash_tests.rs`, `fifo_tests.rs`, and a linux-gated one in `store_tests.rs`), each driven by a passing parent regression. No clause of this row — migration included — is carried by an ignored test. | none |
| MIK-6744.STORE.2 | PARTIAL | Revocation and release paths exist and pass inside the 157 (`service_release_tests.rs`, `service_refresh_tests.rs`); `rg -uu -n 'refresh_job\|revoke\|credential_store\|token_replace' src/` -> `src/oauth/storage.rs`. No test asserts the specific failure the criterion names: an old refresh job or cached credential surviving a restart and becoming usable under a **new** grant. | medium — one test: revoke, re-grant, restart, assert the pre-revocation refresh job and cache entry are both dead |
| MIK-6745.JOURNEY.1 | ABSENT | Open WebUI on Spark against Google Workspace is a manual/recorded journey. Only `tests/openwebui_adapter_config.rs` exists, which is config-level. `rg -uu -l 'demo\|recording' docs/requirements/` returns prose files (`RELEASE-4.0.0-residue-triage.md`, `-gap-plan.md`, `-requirements.md`, `-performance-contract.md`), no recording artifact for connect/use/refresh/revoke/cancelled-consent. | large — the recorded journey itself |
| MIK-6745.JOURNEY.2 | PARTIAL | The unconnected-user and no-shared-fallback states are fixtured and pass inside the 157: `rg -uu -l 'two_users\|unconnected\|shared_account\|operator_account' src/` -> `src/personal_accounts/fixtures/lookup_states.json`, `src/personal_accounts/store_tests.rs`, `src/backend/ops.rs`, `src/gateway/server/mod.rs`. The concurrent two-user journey with an actionable refusal is not recorded end-to-end. | medium — folds into the JOURNEY.1 recording |
| MIK-6745.JOURNEY.3 | PARTIAL | Consistent personal-account authorization on list/search and call entry points is asserted in `src/backend/tests.rs` and `src/gateway/router/tests.rs` (both in the passing lib run). Prompts/resources entry-point parity has no named passing test. | small — one parity test over the prompts/resources routes |
| MIK-6746.CONTRACT.1 | PARTIAL | Audience handling is present: `rg -uu -n 'audience\|aud\b\|resource_indicator\|RFC ?8707' src/` -> `src/key_server/oidc.rs`, `src/personal_accounts/vault.rs`, `src/protocol/types.rs`, `src/backend/tests.rs`, `src/backend/pool_tests.rs`. No `resource_indicator` / RFC 8707 symbol exists anywhere in `src/`, and the ADR-008 + MIK-6746 custom-header reconciliation the scope update requires ("must be reconciled, not copied into new work") is not recorded. Route parity before expanding credential forwarding is therefore unproven. | medium — the reconciliation note plus a resource-indicator conformance test |

## Rows 20-25 (DISCOVERY, OPERATIONS)

| ID | Verdict | Evidence | Effort to close |
|---|---|---|---|
| MIK-3274.RANKING.1 | MET | `cargo test --lib ranking::` -> `test result: ok. 66 passed; 0 failed; 0 ignored; 4668 filtered out`. Implementation in `src/ranking/{mod.rs,scoring.rs}` with `src/ranking/tests.rs` + `src/ranking/tests/`. Abbreviation and word-boundary scoring, exact-identifier and glob reliability are all inside that passing set. | none |
| MIK-3274.RANKING.2 | PARTIAL | Usage-feedback ordering exists: `rg -uu -l 'rank_before_truncate\|usage_feedback\|usage_boost' src/` -> `src/ranking/tests.rs` (passing). Disclosure behaviour on the served route passes too: `cargo test --test discovery_tests` -> `ok. 19 passed; 0 failed; 0 ignored`. But no single passing test proves the conjunction the criterion demands — authorization applied **before** disclosure **and** ranking applied **before** truncation, on **both** discovery routes, with usage feedback unable to promote a forbidden tool over an allowed relevant one. | small — one test per route asserting a forbidden high-usage tool never outranks an allowed relevant one, and that truncation happens after ranking |
| MIK-3274.RANKING.3 | ABSENT (unrecoverable as written) | The criterion requires thresholds "frozen after baseline measurement and **before** ranking implementation". Ranking is already implemented (66 passing tests), and no frozen held-out corpus or threshold artifact exists — `benchmarks/` holds only `public_claims.json`, `token_savings.py`, `live_agent_*.py`, `discovery_response_fixture.json`, `BENCHMARK-RECOVERY.md`. The ordering clause cannot now be satisfied; the row needs a scope amendment or an explicitly retrospective threshold record. | decision, not work — amend the clause or accept a retrospective freeze |
| MIK-7332.DISCOVERY.1 | PARTIAL | `discovery_tests` 19 passed covers the served consumer surface; tiered disclosure and configured surfaced tools exist: `rg -uu -l 'tiered_disclosure\|surfaced_tools' src/` -> `src/config/mod.rs`, `src/config/tests.rs`, `src/gateway/router/tests.rs`, `src/gateway/meta_mcp_tool_defs.rs`. No test ties the four clauses together on the served surface (authorization-derived exposure + tiering + schema validity + configured surface with consistent guides and invocation permissions). | medium — one integration test over the served surface asserting all four at once |
| MIK-7235.PIN.1 | PARTIAL | SHA-256 pinning machinery is shipped: `rg -uu -l 'tool_integrity\|pinned_hash\|integrity_pin' src/` -> `src/security/mod.rs`, `src/security/firewall/mod.rs`. The criterion's process clauses are unmet: no classification record for the shipped catalogue, no recorded pinned high-privilege subset, no recorded intentional exclusions, and no re-pin check in CI. | medium — classification pass over the catalogue plus a CI re-pin check |
| MIK-6710.AUDIT.1 | ABSENT | `rg -uu -l 'newest_first\|scan_budget\|audit.*cursor' src/` returns nothing. Neither the index, the explicit scan budget, nor the cursor behaviour the criterion requires exists, so the documented work bound cannot be stated and the unsupported O(N) promise stands uncorrected. | medium — add a scan budget or cursor to the audit read path and document the bound |

## Rows 26-31 (VALIDATION / NFR)

These six are evidence-artifact checks, not code archaeology. Each verdict is
the result of looking for the artifact the criterion names.

| ID | Verdict | Evidence | Effort to close |
|---|---|---|---|
| NFR.CONFORMANCE.1 | PARTIAL | `docs/requirements/RELEASE-4.0.0-test-plan.md` exists and carries a matrix, but `rg -c 'N/A' docs/requirements/RELEASE-4.0.0-test-plan.md` -> `3`. Three reasoned N/A cells is far short of a complete role x transport x revision x outcome matrix, and the two cases the criterion names explicitly (modern URL-elicitation completion removal, arbitrary-JSON structured results) are not identifiable as covered cells. | medium — complete the matrix and give every N/A cell a reason |
| NFR.WORKLOAD.1 | ABSENT | The criterion requires the frozen 3.5.0 baseline preserved **and** 3.5.1 added as the current upgrade/comparison source. `rg -c '3\.5\.1' docs/requirements/RELEASE-4.0.0-performance-contract.md docs/requirements/RELEASE-4.0.0-performance.md` -> no matches in either file. The 3.5.1 source does not exist in the performance record. | medium — measure 3.5.1 and record it against the preserved 3.5.0 baseline |
| NFR.UPGRADE.1 | ABSENT | `rg -uu -c 'rehearsal\|rollback' docs/requirements/RELEASE-4.0.0-test-plan.md` -> no matches. Neither the 3.5.1 upgrade rehearsal nor the modern-off/rollback exercise is planned, let alone evidenced, so config/credentials/permissions/mounts/active-caller preservation is unverified. | large — run the rehearsal and record it |
| NFR.RELEASEGATE.1 | MET | `scripts/release/check_scope_acceptance.py` exists alongside `scripts/release/test_scope_contract_interface.py`, and `rg -n 'check_scope_acceptance' .github/workflows/release.yml` shows two call sites with different modes: line 92 `--check` (plan consistency, which prints "Plan check only; not release approval") and line 96 `--publish-check`, the rejecting mode on the publishing path. The row needs the publishing path to reject, and `--publish-check` is that path; `--check` alone would have made this PARTIAL. The gate is wired into the automated path, which is what this row requires; per the scope update it enforces reference existence and completeness, not the truth of a test report. | none |
| NFR.DEMO.1 | ABSENT | `rg -uu -l 'demo\|recording' docs/requirements/` -> `RELEASE-4.0.0-residue-triage.md`, `-gap-plan.md`, `-requirements.md`, `-performance-contract.md` — all prose that discusses demos, none a recording. No recorded demonstration exists for any of the five required scenarios (mixed-era interaction, reconnectable tasks, isolated personal accounts, large-catalogue discovery, error-budget diagnosis/recovery). | large — five recordings |
| NFR.BUILD.1 | ABSENT | `rg -uu -l 'mutants\|mutation' docs/ .github/` -> `docs/COMMUNITY_REGISTRY.md`, `docs/blog/sovereign-stack-2026-04.md`, `docs/control_plane.md`, `docs/release/v4.0.0-scope-contract-validation.md` — no mutation run, no mutation report, and nothing under `.github/`. No pinned reference client/backend version matrix or feature/build combination record grading the final integration revision either. | medium — pin the version/feature matrix and run mutation testing on the critical path |

---

## Tally

| Bucket | Count | IDs |
|---|---|---|
| MET | 9 | GH462.CONFIG.1, GH452.SESSION.1, MIK-7377.SIGNING.1, MIK-7311.LIFECYCLE.1, MIK-7311.LIFECYCLE.3, MIK-7311.LIFECYCLE.4, MIK-6744.STORE.1, MIK-3274.RANKING.1, NFR.RELEASEGATE.1 |
| PARTIAL | 12 | MIK-7334.CATALOGUE.1, MIK-7388.CANCEL.1, MIK-7311.LIFECYCLE.2, MIK-7311.LIFECYCLE.5, MIK-6744.STORE.2, MIK-6745.JOURNEY.2, MIK-6745.JOURNEY.3, MIK-6746.CONTRACT.1, MIK-3274.RANKING.2, MIK-7332.DISCOVERY.1, MIK-7235.PIN.1, NFR.CONFORMANCE.1 |
| ABSENT | 10 | MIK-7387.STDIO.1, .2, .3, MIK-6745.JOURNEY.1, MIK-3274.RANKING.3, MIK-6710.AUDIT.1, NFR.WORKLOAD.1, NFR.UPGRADE.1, NFR.DEMO.1, NFR.BUILD.1 |
| IMPLEMENTED-UNTESTED | 0 | — |
| NO-REQUIREMENT | 0 | — |

Row count check: 9 MET + 12 PARTIAL + 10 ABSENT = 31 = the approved supplemental
criteria count in `RELEASE-4.0.0-scope-update.md`.

## Verdict changes against the previous (attribute-counting) pass

| ID | Was | Now | Why it moved |
|---|---|---|---|
| MIK-7311.LIFECYCLE.4 | ABSENT | MET | The previous verdict rested on a zero `#[test]` count in `tests/task_upstream_recovery.rs`. The file uses `#[tokio::test]`; running it gives `10 passed; 0 failed; 0 ignored`, and the named tests pin both halves of the clause (no silent replay, recover-or-refuse-explicitly). |
| MIK-7311.LIFECYCLE.5 | ABSENT | PARTIAL | Same instrument error. The lifetime-bound half is genuinely pinned by a real-reaper expiry test; the creation/retention bounds and the cancellation-race clause are still unpinned, so it stops at PARTIAL rather than flipping all the way. |
| MIK-7311.LIFECYCLE.1 | ABSENT | MET | `mik_7272_task_1_acs` runs 20 passing tests that cover every clause by name. |
| MIK-7311.LIFECYCLE.3 | ABSENT | MET | `task_upstream_recovery` pins durable identity and owner-only resolution after reopen. |
| MIK-7387.STDIO.1/.2/.3 | ABSENT | ABSENT (confirmed, different reason) | The previous pass was accidentally right. The tests exist but the binary reports `0 passed; 3 ignored` with an ignore reason naming MIK-7387 as a separate work package — the file is the specification for the row, not evidence for it. |

## Instrument note

Nine test binaries were run for this pass. One returned `0 passed; 3 ignored`
(`mik_7212_mrtr7_stdio_acs`); a green `test result: ok` line from it would have
been read as MET by a summary-only reading. Every MET row above quotes the
passed/ignored counts and at least one named test from the passing set.
