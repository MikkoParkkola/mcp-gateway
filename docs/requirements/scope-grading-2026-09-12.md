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
| MIK-7388.CANCEL.1 | MET | `cargo test --test mik_7212_mrtr7_bridge_acs` -> `ok. 28 passed; 0 failed; 0 ignored`, including `mik_7388_cancel_1_a_cancelled_exchange_cannot_be_answered_into_another`: it cancels one of two live bridged exchanges on one session, POSTs the cancelled answer back, and asserts the refusal leaves the survivor's pending entry untouched, the survivor receives its own reply, and both entries are reclaimed. Mutating `resolve_pending` to deliver to the first pending entry fails this test and only this test. | — |

## Rows 9-13 (TASKS)

The previous pass graded this package ABSENT by counting `#[test]` attributes in
`task_*.rs`. These files use `#[tokio::test]`, so the count was zero. Running
them reverses two rows.

| ID | Verdict | Evidence | Effort to close |
|---|---|---|---|
| MIK-7311.LIFECYCLE.1 | MET | `cargo test --test mik_7272_task_1_acs` -> `ok. 20 passed; 0 failed; 0 ignored`. Named passing tests cover every clause: public-route dispatch (`dispatch::ac_task_1_1_a_created_task_id_resolves_immediately`), polling/status payloads (`ac_task_1_2_each_status_carries_its_own_payload_and_no_other`), input (`dispatch::ac_task_1_3_an_accepted_update_acknowledges_with_an_empty_result`, `..._an_input_response_with_no_outstanding_request_is_refused`), cooperative cancellation gated to the pinned revision (`ac_task_1_5_tasks_cancel_is_gated_as_a_2026_07_28_method`), terminal outcomes (`ac_task_1_6_a_failed_task_carries_an_error_object_not_a_string`, `..._an_is_error_tool_result_is_completed_and_not_failed`), and extension negotiation (`capabilities::ac_task_1_10_initialize_advertises_the_tasks_extension_to_a_2026_peer`). Expiry is pinned separately by `cargo test --test task_expiry_http_lifecycle` -> `ok. 1 passed; 0 failed; 0 ignored` (`a_configured_expiry_interval_reaps_a_real_task_and_shutdown_releases_the_store`). | none |
| MIK-7311.LIFECYCLE.2 | MET (2026-09-13) | Five rows in `tests/mik_7272_task_1_acs.rs` (`mod ownership`), committed as `d2481bb4`, `6337f44e`, `9a331fcb` and `ae4aa91f`. `cargo test --test mik_7272_task_1_acs lifecycle_2_` -> `ok. 5 passed; 0 failed`; whole file `ok. 25 passed; 0 failed`. The reconnect clause is now evidenced twice over: a dropped stream leaves the task resolvable and cancellable by its creator and byte-identically absent to every other principal *while the backend is provably still holding the dispatch*, and the held dispatch released after the stream is gone settles with the backend's own marker — the record and the work both survive. A second gateway over the same store re-answers the creating principal field for field and re-refuses every other one; the same steps over an EMPTY store answer the creator himself `no such task`, which is the falsifier that stops a read path succeeding for any well-formed id from satisfying the restart row. Four mutants run and observed: withholding `gate.release_all()` fails the completion row on the 5s bound at status `working`; pointing the fresh-store row at the populated store fails it `left: None, right: Some(-32602)`; running the foreign probe as `key-a` fails the disconnect row identically. The third inspect route is now covered rather than conceded. `subscriptions/listen` narrows a foreign `taskIds` to the empty list in silence (`src/gateway/router/handlers.rs:1050-1062`), so a fifth row holds both streams open and reads their frames. The owner's stream is drained FIRST and must carry a `notifications/tasks` frame with the terminal status the release causes; only then is the non-owner's stream judged, and on that side the predicate is deliberately WIDER — any task notification naming the task fails the row, so a gateway leaking a `working` frame while withholding the `completed` one cannot pass. Fourth mutant: deleting the narrowing (`if !caller_holds_ids`) fails the row with the foreign buffer quoted in full — the acknowledgement (`result._meta.subscriptionId`, naming no task) followed by `notifications/tasks` carrying `"status":"completed"` and the owner's `taskId`. Every mutant's exact inverse edit and verbatim failure is preserved in `docs/release/v4.0.0-lifecycle-2-mutants.md`. Reviewed by two non-Claude reviewers in parallel, both SHIP, no BLOCK; the improvements both raised are applied in `f7cdc0f9` (one deadline for the whole drain rather than one per chunk, and a rolling buffer so a split frame cannot read as no leak). | none |
| MIK-7311.LIFECYCLE.3 | MET | `cargo test --test task_upstream_recovery` -> `ok. 10 passed; 0 failed; 0 ignored`, including `a_durable_handle_survives_reopen_and_only_its_owner_reads_it` (restart-window resolution plus owner-only read) and `a_captured_handle_is_recorded_at_version_three_with_its_descriptor` (durable identity and descriptor). | none |
| MIK-7311.LIFECYCLE.4 | MET (was ABSENT) | Same binary, all passing. Never-silently-replay: `the_original_operation_is_submitted_once_and_never_resubmitted`. Recover-where-supported: `unavailable_then_live_then_complete_reuses_the_one_handle`. Explicit refusal instead of a guess when recovery is unsupported: `an_adapter_untrusted_at_restart_causes_zero_queries`, `with_no_configured_adapter_the_conservative_branch_is_unchanged`. Read-only positive control: `the_configured_output_policy_applies_to_a_recovered_result`. Graded off `tests/task_upstream_recovery.rs` only — `task_upstream_recovery_sdk.rs` is feature-gated and needs external services, so it is not load-bearing here. | none |
| MIK-7311.LIFECYCLE.5 | PARTIAL (was ABSENT) | Lifetime bound and store release are pinned by `task_expiry_http_lifecycle` (1 passed, real reaper). Creation-rate and retained-result bounds, and the "cancellation race cannot rewrite a settled outcome" clause, have no passing named test in either task binary. | medium — two tests: creation/retention cap rejection, and cancel-after-settle leaves the terminal outcome untouched |

## Rows 14-19 (ACCOUNTS)

Package-wide run for this section: `cargo test --lib personal_accounts::` ->
`test result: ok. 157 passed; 0 failed; 1 ignored; 0 measured; 4576 filtered out`.
The single ignored test was not identified; no row below rests on it.

| ID | Verdict | Evidence | Effort to close |
|---|---|---|---|
| MIK-6744.STORE.1 | PARTIAL (withdrawn MET, 2026-09-12) | The MET above was established by MODULE off a passing count, not conjunct by conjunct. A conjunct audit splits the criterion into seven parts and two have no covering construct. Covered: principal/backend/resource keying on load, save and refresh; at-rest protection (`seal_bytes` at `storage.rs:154`, `0o600` at `commit.rs:81`); no silent loss under crash. NOT covered: existing single-user 3.x data being READABLE and MIGRATED — no test, no code path, and the source states the opposite (`src/personal_accounts/mod.rs:779` "nothing is migrated into a store this command creates"; `src/commands/upgrade.rs:243` ships the user notice "Stored tokens from 3.x are not migrated"). `legacy_migration` (`mod.rs:207`) is a dead field, only ever written `None`. This is an implementation gap, not a test gap: the row cannot reach MET by adding tests. | blocked — operator decision: build the migration (which falsifies a published release note) or rewrite the criterion to the shipped re-authenticate-once behaviour |
| MIK-6744.STORE.2 | PARTIAL | Revocation and release paths exist and pass inside the 157 (`service_release_tests.rs`, `service_refresh_tests.rs`); `rg -uu -n 'refresh_job\|revoke\|credential_store\|token_replace' src/` -> `src/oauth/storage.rs`. No test asserts the specific failure the criterion names: an old refresh job or cached credential surviving a restart and becoming usable under a **new** grant. | medium — one test: revoke, re-grant, restart, assert the pre-revocation refresh job and cache entry are both dead |
| MIK-6745.JOURNEY.1 | ABSENT | Open WebUI on Spark against Google Workspace is a manual/recorded journey. Only `tests/openwebui_adapter_config.rs` exists, which is config-level. `rg -uu -l 'demo\|recording' docs/requirements/` returns prose files (`RELEASE-4.0.0-residue-triage.md`, `-gap-plan.md`, `-requirements.md`, `-performance-contract.md`), no recording artifact for connect/use/refresh/revoke/cancelled-consent. | large — the recorded journey itself |
| MIK-6745.JOURNEY.2 | PARTIAL | The unconnected-user and no-shared-fallback states are fixtured and pass inside the 157: `rg -uu -l 'two_users\|unconnected\|shared_account\|operator_account' src/` -> `src/personal_accounts/fixtures/lookup_states.json`, `src/personal_accounts/store_tests.rs`, `src/backend/ops.rs`, `src/gateway/server/mod.rs`. The concurrent two-user journey with an actionable refusal is not recorded end-to-end. | medium — folds into the JOURNEY.1 recording |
| MIK-6745.JOURNEY.3 | MET | Parity closed by `ff0e3626` (guard) plus `a12ff924` (ordering proof). The chokepoint refuses a personally-bound backend on the prompts/resources entry points before dispatch: `src/gateway/meta_mcp/mod.rs:1019`. Evidence in `src/gateway/meta_mcp/account_entry_point_authz_tests.rs`: pre-guard the 4 refusal tests were RED with `"served": Bool(true)` observed on the wire; post-guard 8/8 green, and the full lib suite is 4754 passed / 0 failed. Each refusal is paired with a single-user permissive control on the identical fixture, so neither arm can pass vacuously; the refusal arms additionally assert `calls == 0` (prompts/get and resources/read) while their controls assert the transport is actually reached. Direct-route `tools/list` at `src/backend/backend_handlers.rs:588` and the 20-site rename were declared out of scope for this row. | none |
| MIK-6746.CONTRACT.1 | PARTIAL | Audience handling is present: `rg -uu -n 'audience\|aud\b\|resource_indicator\|RFC ?8707' src/` -> `src/key_server/oidc.rs`, `src/personal_accounts/vault.rs`, `src/protocol/types.rs`, `src/backend/tests.rs`, `src/backend/pool_tests.rs`. **Corrected 2026-09-13: the claim that no `resource_indicator` / RFC 8707 symbol exists anywhere in `src/` is false.** `rg -c 'resource_indicator' src/` returns `src/oauth/client/mod.rs:5` and `src/oauth/client/tests.rs:4`; the indicator is bound at `mod.rs:685,724,755,771,789` and tested at `tests.rs:587,652,707,727,746`, which makes the downstream/outbound conjunct MET rather than absent. The search quoted above missed them because it was scoped to files matching a broad alternation and never reached `src/oauth/client/`. The PARTIAL verdict stands on different grounds -- inbound `aud` validation is opt-in (`audience: Option<String>`, every fixture `None`), direct/meta route parity is absent from `src/gateway/meta_mcp/`, and the conjunct evidence now lives in `RELEASE-4.0.0-scope-status.json`. The ADR-008 + MIK-6746 custom-header reconciliation the scope update requires ("must be reconciled, not copied into new work") is not recorded. Route parity before expanding credential forwarding is therefore unproven. | medium — the reconciliation note plus a resource-indicator conformance test |

## Rows 20-25 (DISCOVERY, OPERATIONS)

| ID | Verdict | Evidence | Effort to close |
|---|---|---|---|
| MIK-3274.RANKING.1 | ABSENT (withdrawn MET) | The earlier MET on this row is withdrawn. It inferred coverage from a passing count without checking that the construct exists: `rg -i 'abbrev|word_boundary|levenshtein|edit_distance|fuzzy|acronym' src/ranking/` returns **no matches**, so fuzzy/abbreviation/word-boundary ranking is not implemented and no passing test can cover it. `src/ranking/{scoring.rs,mod.rs,tests.rs}` are byte-identical on `origin/main` and this branch (blobs `a5d786ac`, `e351b088`, `e55c15fe`), so the row grades the same on both lineages — which is what `RELEASE-4.0.0-gap-assessment-2026-09-11.md` on `origin/main` had already recorded. | large — fuzzy matching is unbuilt, not untested |
| MIK-3274.RANKING.2 | MET (2026-09-13, second attempt) | 19 tests in `src/gateway/meta_mcp/search_ranking_authz_tests.rs`, `cargo test --lib search_ranking_authz` -> `ok. 19 passed; 0 failed`. Both invariants pinned on both public discovery routes. The residual this row previously carried -- the MCP-backend collectors at `search.rs:329` and `:238`, said to need `CachedMetadata::store_shared` (`pub(super)`) -- is **moot**: the in-file `mcp_backend` fixture (:731) and `meta_with_mcp_backend` (:765) seed a backend through a stub transport without touching `store_shared` (:676), pinned by `denied_mcp_backend_never_enters_the_candidate_set` (:826) and `code_mode_denied_mcp_backend_contributes_no_matches` (:864), each with the permissive control `permissive_profile_sees_the_mcp_backend_tools` (:788). No API visibility change is needed; do not propose one. The denial assertions are on `total_available`, the pre-truncation count computed at `search.rs:409` and emitted at `meta_mcp_helpers.rs:619`, so they distinguish never-collected from collected-then-filtered -- red-proofed by a late `retain`, under which the survivor assertions stayed green and both count assertions went red at 2. The remaining exception is the **glob carve-out**: `code_mode_search` skips the keyword ranker for glob queries (`search.rs:416`). It does not breach `ranking precedes truncation`, because `finalize_search_matches` stamps a uniform 1.0 on every unscored glob match at `search_disclosure.rs:165-173` before `matches.truncate(limit)` at `:174`, and no collector in `search.rs` assigns a score, so all retained candidates tie and truncation cannot discard a better-scored match. Pinned by `code_mode_glob_results_are_not_reranked` (:1072), which asserts the score rather than the order. Attribution for the `:302` line cited in earlier drafts of this row belongs to `85f49af7`. | closed -- commits 577b3cd3, 6eb03935 |
| MIK-3274.RANKING.3 | ABSENT (unrecoverable as written) | The criterion requires thresholds "frozen after baseline measurement and **before** ranking implementation". Ranking is already implemented (66 passing tests), and no frozen held-out corpus or threshold artifact exists — `benchmarks/` holds only `public_claims.json`, `token_savings.py`, `live_agent_*.py`, `discovery_response_fixture.json`, `BENCHMARK-RECOVERY.md`. The ordering clause cannot now be satisfied; the row needs a scope amendment or an explicitly retrospective threshold record. | decision, not work — amend the clause or accept a retrospective freeze |
| MIK-7332.DISCOVERY.1 | PARTIAL | `discovery_tests` 19 passed covers the served consumer surface; tiered disclosure and configured surfaced tools exist: `rg -uu -l 'tiered_disclosure\|surfaced_tools' src/` -> `src/config/mod.rs`, `src/config/tests.rs`, `src/gateway/router/tests.rs`, `src/gateway/meta_mcp_tool_defs.rs`. No test ties the four clauses together on the served surface (authorization-derived exposure + tiering + schema validity + configured surface with consistent guides and invocation permissions). | **re-sized, pending design review** — the acceptance row says the invalid-schema tool is *withheld*, which is a listing-time exclusion, and no such gate exists. Three independent probes this session: (1) `rg -n 'inputSchema' src/gateway/ --glob '!**/tests*' | rg -i 'valid|skip|filter|drop|withh'` -> nothing; (2) the served list is built by `handle_tools_list_with_url_override`, whose only filter is `meta_tool_exposure` (`src/gateway/meta_mcp/mod.rs:1687`), by name not schema; (3) `src/provider/transforms/filter.rs` filters tool NAMES via allow/deny patterns (`is_allowed`, line 66) — its `input_schema` mention at line 125 is a test fixture. Schema validation exists only at INVOKE time and only on the capability path (`validate_arguments`, `src/capability/backend.rs:498`; `validate_output`, `src/gateway/meta_mcp/invoke.rs:157`). So this row is build-then-test, not test-only. Exposure is also three axes, not the admin flag this grading implied: `can_access_backend` and `can_access_tool` (`src/gateway/auth.rs:436,440`, refusal -32003) move backend tools; `require_admin_tool_access` gates only `ADMIN_META_TOOLS`. |
| MIK-7235.PIN.1 | PARTIAL | SHA-256 pinning machinery is shipped: **Corrected 2026-09-13: neither cited file implements pinning.** The search terms above match unrelated symbols; the implementation is `src/capability/hash.rs`, `src/capability/parser.rs`, `src/capability/loader.rs` and `src/commands/cap.rs`. The PARTIAL verdict stands and the conjunct evidence now lives in `RELEASE-4.0.0-scope-status.json`. The criterion's process clauses are unmet: no classification record for the shipped catalogue, no recorded pinned high-privilege subset, no recorded intentional exclusions, and no re-pin check in CI. | medium — classification pass over the catalogue plus a CI re-pin check |
| MIK-6710.AUDIT.1 | ABSENT | `rg -uu -l 'newest_first\|scan_budget\|audit.*cursor' src/` returns nothing. Neither the index, the explicit scan budget, nor the cursor behaviour the criterion requires exists, so the documented work bound cannot be stated and the unsupported O(N) promise stands uncorrected. | medium — add a scan budget or cursor to the audit read path and document the bound |

## Rows 26-31 (VALIDATION / NFR)

These six are evidence-artifact checks, not code archaeology. Each verdict is
the result of looking for the artifact the criterion names.

| ID | Verdict | Evidence | Effort to close |
|---|---|---|---|
| NFR.CONFORMANCE.1 | PARTIAL | Re-graded 2026-09-13 against `docs/requirements/RELEASE-4.0.0-conformance-matrix.md`, which supersedes the test-plan reading in this row: the population is the 21 statements of the 2026-07-28 changelog, 18 COVERED, 3 UNCOVERED, 4 reasoned N/A axis cells. The two cases the criterion names are now identifiable cells and both are UNCOVERED - minor 11 (URL-elicitation completion removal) and minor 10's second clause (arbitrary-JSON structured results). The matrix is executable in `tests/mik_7272_conformance.rs`, so a cell citing a test that does not exist fails CI. | medium - five named tests close the three UNCOVERED statements |
| NFR.WORKLOAD.1 | ABSENT | The criterion requires the frozen 3.5.0 baseline preserved **and** 3.5.1 added as the current upgrade/comparison source. `rg -c '3\.5\.1' docs/requirements/RELEASE-4.0.0-performance-contract.md docs/requirements/RELEASE-4.0.0-performance.md` -> no matches in either file. The 3.5.1 source does not exist in the performance record. | medium — measure 3.5.1 and record it against the preserved 3.5.0 baseline |
| NFR.UPGRADE.1 | ABSENT | `rg -uu -c 'rehearsal\|rollback' docs/requirements/RELEASE-4.0.0-test-plan.md` -> no matches. Neither the 3.5.1 upgrade rehearsal nor the modern-off/rollback exercise is planned, let alone evidenced, so config/credentials/permissions/mounts/active-caller preservation is unverified. | large — run the rehearsal and record it |
| NFR.RELEASEGATE.1 | MET | `scripts/release/check_scope_acceptance.py` exists alongside `scripts/release/test_scope_contract_interface.py`, and `rg -n 'check_scope_acceptance' .github/workflows/release.yml` shows two call sites with different modes: line 92 `--check` (plan consistency, which prints "Plan check only; not release approval") and line 96 `--publish-check`, the rejecting mode on the publishing path. The row needs the publishing path to reject, and `--publish-check` is that path; `--check` alone would have made this PARTIAL. The gate is wired into the automated path, which is what this row requires; per the scope update it enforces reference existence and completeness, not the truth of a test report. | none |
| NFR.DEMO.1 | ABSENT | `rg -uu -l 'demo\|recording' docs/requirements/` -> `RELEASE-4.0.0-residue-triage.md`, `-gap-plan.md`, `-requirements.md`, `-performance-contract.md` — all prose that discusses demos, none a recording. No recorded demonstration exists for any of the five required scenarios (mixed-era interaction, reconnectable tasks, isolated personal accounts, large-catalogue discovery, error-budget diagnosis/recovery). | large — five recordings |
| NFR.BUILD.1 | PARTIAL | First half met: `docs/release/v4.0.0-supported-matrix.md` pins the toolchain, protocol revisions, reference clients, backends and the feature/build combinations, and the `feature-combos` job in `.github/workflows/ci.yml` builds all 17 of them under `-D warnings`. The combination list is being verified locally row by row rather than asserted (`cargo clippy <combo> -- -D warnings`, exit status recorded per row in the burndown tracker); all 17 rows returned 0 on this branch. Second half still absent: no mutation run, no mutation report, nothing under `.github/` (`rg -uu -l 'mutants|mutation' docs/ .github/` returns only prose mentions), and no critical-path coverage figure taken on the final integration revision. | large — critical-path coverage plus mutation evidence on the final integration revision |

---

## Tally

| Bucket | Count | IDs |
|---|---|---|
| MET | 11 | GH462.CONFIG.1, GH452.SESSION.1, MIK-7377.SIGNING.1, MIK-7311.LIFECYCLE.1, MIK-7311.LIFECYCLE.2, MIK-7311.LIFECYCLE.3, MIK-7311.LIFECYCLE.4, MIK-6745.JOURNEY.3, MIK-3274.RANKING.2, NFR.RELEASEGATE.1, MIK-7388.CANCEL.1 |
| PARTIAL | 10 | MIK-7334.CATALOGUE.1, MIK-7311.LIFECYCLE.5, MIK-6744.STORE.1, MIK-6744.STORE.2, MIK-6745.JOURNEY.2, MIK-6746.CONTRACT.1, MIK-7332.DISCOVERY.1, MIK-7235.PIN.1, NFR.CONFORMANCE.1, NFR.BUILD.1 |
| ABSENT | 10 | MIK-7387.STDIO.1, .2, .3, MIK-6745.JOURNEY.1, MIK-3274.RANKING.1, MIK-3274.RANKING.3, MIK-6710.AUDIT.1, NFR.WORKLOAD.1, NFR.UPGRADE.1, NFR.DEMO.1 |
| IMPLEMENTED-UNTESTED | 0 | — |
| NO-REQUIREMENT | 0 | — |

Row count check: 11 MET + 10 PARTIAL + 10 ABSENT = 31 = the approved supplemental
criteria count in `RELEASE-4.0.0-scope-update.md`.

## Verdict changes against the previous (attribute-counting) pass

| ID | Was | Now | Why it moved |
|---|---|---|---|
| MIK-7311.LIFECYCLE.4 | ABSENT | MET | The previous verdict rested on a zero `#[test]` count in `tests/task_upstream_recovery.rs`. The file uses `#[tokio::test]`; running it gives `10 passed; 0 failed; 0 ignored`, and the named tests pin both halves of the clause (no silent replay, recover-or-refuse-explicitly). |
| MIK-7311.LIFECYCLE.5 | ABSENT | PARTIAL | Same instrument error. The lifetime-bound half is genuinely pinned by a real-reaper expiry test; the creation/retention bounds and the cancellation-race clause are still unpinned, so it stops at PARTIAL rather than flipping all the way. |
| MIK-7311.LIFECYCLE.1 | ABSENT | MET | `mik_7272_task_1_acs` runs 20 passing tests that cover every clause by name. |
| MIK-7311.LIFECYCLE.3 | ABSENT | MET | `task_upstream_recovery` pins durable identity and owner-only resolution after reopen. |
| MIK-7387.STDIO.1/.2/.3 | ABSENT | ABSENT (confirmed, different reason) | The previous pass was accidentally right. The tests exist but the binary reports `0 passed; 3 ignored` with an ignore reason naming MIK-7387 as a separate work package — the file is the specification for the row, not evidence for it. |
| MIK-6745.JOURNEY.3 | PARTIAL | MET (2026-09-13) | The prompts/resources entry points now refuse a personally-bound backend at the same chokepoint `tools/call` uses; `cargo test --lib account_entry_point_authz` -> `ok. 8 passed; 0 failed`, every absence assertion paired with a single-user permissive control. |
| MIK-3274.RANKING.2 | PARTIAL | MET (2026-09-13, second attempt) | `cargo test --lib search_ranking_authz` -> `ok. 19 passed; 0 failed`; the first attempt was withdrawn because the coverage could not discriminate. |
| MIK-7311.LIFECYCLE.2 | PARTIAL | MET (2026-09-13) | Five committed rows cover the reconnect clause, the survival of the WORK as well as the record, a gateway restart, and the absence of task events on a non-owner's subscription stream, each with a paired negative; four mutants proved the assertions discriminate. Commits `d2481bb4`, `6337f44e`, `9a331fcb`, `ae4aa91f`. |
| MIK-6744.STORE.1 | MET | PARTIAL (withdrawn 2026-09-12) | The table above had not tracked the withdrawal already recorded in `RELEASE-4.0.0-scope-status.json` and in the burndown tracker. Two of seven conjuncts — 3.x data readable and migrated — have no covering construct and the source states the opposite; the row is blocked on an operator decision, not on tests. |

## Instrument note

Nine test binaries were run for this pass. One returned `0 passed; 3 ignored`
(`mik_7212_mrtr7_stdio_acs`); a green `test result: ok` line from it would have
been read as MET by a summary-only reading. Every MET row above quotes the
passed/ignored counts and at least one named test from the passing set.

## Which grades transfer to the release line

A grade is only as portable as the files it cites. Comparing every cited path's
blob against `origin/main`:

| Row | Grade | Transfers to main? | Decisive path |
|---|---|---|---|
| MIK-3274.RANKING.1 | ABSENT | **yes, invariant** | `src/ranking/{scoring.rs,tests.rs}` byte-identical on both refs |
| GH462.CONFIG.1 | MET | re-grade needed | `tests/gh462_config_preservation.rs` differs (`29f728ca` vs `c04b98f6`) |
| GH452.SESSION.1 | MET | re-grade needed | `tests/gh452_session_owner.rs` differs (`f6684518` vs `daf6b168`) |
| MIK-7377.SIGNING.1 | MET | no | both `tests/message_signing_*.rs` absent from main |
| MIK-7311.LIFECYCLE.1 | MET | no | `tests/task_expiry_http_lifecycle.rs` absent from main |
| MIK-7311.LIFECYCLE.3 | MET | no | `tests/task_upstream_recovery.rs` absent from main |
| MIK-7311.LIFECYCLE.4 | MET | no | `src/gateway/task_service/execution/upstream.rs` absent from main |
| MIK-6744.STORE.1 | MET | no | all of `src/personal_accounts/` absent from main |

The table above is a snapshot of what the 2026-09-12 pass graded MET. `MIK-6744.STORE.1` was withdrawn to PARTIAL later the same day; the transfer analysis on its row still holds, the grade on it does not.

Six of the eight grade code that is not on the release line. They are statements
about this branch, and they become statements about the release only when the
subsystems they cite land there — which is what the re-cut in
`RELEASE-4.0.0-gap-assessment-2026-09-11.md` step 3 exists to do. Reading them
as release readiness before that is the same error as grading against the stale
ledger.

Two rows cite files that exist on both refs but differ. Neither grade carries
across on its citation alone; each needs re-running against main's copy of the
test file.

Three rows cite this document as evidence for their own grade. A grading record
is a record of the reading, not an independent artefact of the behaviour, so
those citations establish nothing the named test files do not already establish.
