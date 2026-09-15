# Branch criteria survey — v4.0.0 pending release criteria vs unmerged branches (base: chore/v4-reconcile-main)

## feat/sub2b-outbound-mint (289 ahead)
- touched subsystems: src/backend/{era,lifecycle,metadata,mod,ops,pool,tests}.rs, src/gateway/{meta_mcp/*,proxy,recovery,router/*,server/mod,streaming}.rs, src/transport/{http/*,mod,notification_sink,stdio}.rs, src/idempotency.rs, src/security/{firewall,http_diagnostics,mod}.rs, docs/adr/ADR-014, docs/release/*, scripts/release/*
- candidate criteria: none
- evidence: src/backend/mod.rs:31 tools_cache still untyped by identity (no identity key added); src/gateway/server/mod.rs dispatch_streaming_notifications is progress-token/notification-sink plumbing (ADR-014), not concurrent non-initialize dispatch; src/transport/stdio.rs additions are outbound progress-token minting (gw-<uuid>), not inbound stdio concurrency
- verdict: NONE
- note: Branch is ADR-014 request-scoped notification/progress-token-mint work (SUB2b) plus release-tracking docs/scripts; touches backend & stdio files but not the identity-cache-key or concurrent-dispatch constructs the pending criteria ask for.

## fix/mrtr2-continuation-handle (157 ahead)
- touched subsystems: src/gateway/meta_mcp/{invoke,mod,direct_route,support,...}.rs, src/gateway/router/{handlers,helpers,mod}.rs, src/gateway/{server/mod,session_lifecycle,streaming,input_bridge,destructive_confirmation}.rs, src/protocol/{continuation,extensions,mrtr,trace}.rs, src/transport/{stdio,http/mod}.rs, src/idempotency.rs, src/security/firewall/mod.rs, src/config/mod.rs, src/capability/executor*
- candidate criteria: MIK-6745.JOURNEY.1/.2 (weak)
- evidence: src/gateway/meta_mcp/invoke.rs uses principal_fingerprint(caller.verified_identity) to scope MRTR continuation/confirmation state (e.g. invoke.rs:82,345,521,897) — principal-scoped but for continuation/confirmation bridging, not account-store keying or cross-account isolation; no touches to src/personal_accounts/, src/capability/execution_context.rs, src/gateway/oauth/jwt.rs, backend/metadata.rs identity cache, or audit/ranking/discovery/pin paths
- verdict: PARTIAL
- note: Branch is MRTR multi-round-trip continuation-handle wiring (bridged confirmation rounds via principal fingerprint) in the same subsystem as MIK-6745 but doesn't show account-store/isolation constructs the criterion asks for.

## task1-caller (125 ahead)
- touched subsystems: near-identical file set to fix/mrtr2-continuation-handle — src/gateway/meta_mcp/{invoke,mod,support,...}.rs, src/gateway/router/*, src/gateway/{server/mod,session_lifecycle,streaming,input_bridge,destructive_confirmation}.rs, src/protocol/{continuation,extensions,mrtr,trace}.rs, src/transport/{stdio,http/mod}.rs, src/idempotency.rs, src/security/firewall/mod.rs
- candidate criteria: MIK-6745.JOURNEY.1/.2 (weak, same as mrtr2-continuation-handle)
- evidence: src/gateway/meta_mcp/invoke.rs principal_fingerprint(caller.verified_identity) usage identical in shape to fix/mrtr2-continuation-handle (invoke.rs:61,92,250,360,719); appears to be the same MRTR continuation-handle feature at an earlier/parallel commit (merge-base warning: multiple merge bases with chore/v4-reconcile-main)
- verdict: PARTIAL
- note: Same underlying MRTR caller-side continuation work as fix/mrtr2-continuation-handle, likely overlapping/duplicate lineage; same weak PARTIAL read on MIK-6745.

## lane/roots-wiring (120 ahead)
- touched subsystems: src/gateway/meta_mcp/{invoke,mod,support,...}.rs, src/gateway/{proxy,router/*,server/mod,session_lifecycle,streaming,input_bridge}.rs, src/protocol/{continuation,mrtr,trace}.rs, src/transport/{stdio,http/mod}.rs, src/idempotency.rs
- candidate criteria: none
- evidence: no "roots" hits despite branch name; invoke.rs additions are MCP envelope/structured-content extraction (is_mcp_envelope) and order2 FSM tests, not account/identity/audit/ranking/discovery/pin constructs; no principal_fingerprint here (unlike mrtr2-continuation-handle/task1-caller)
- verdict: NONE
- note: Despite overlapping file set with the MRTR continuation branches, this one's actual additions are envelope-extraction/ordering-FSM work with no hits on any of the 19 criteria's subsystems or constructs.

## lane/error-budgets (120 ahead)
- touched subsystems: same file set as lane/roots-wiring plus fuller src/transport/stdio.rs (132 lines) — src/gateway/meta_mcp/*, src/gateway/{router/*,server/mod,session_lifecycle,streaming,input_bridge}.rs, src/protocol/{continuation,mrtr,trace}.rs, src/transport/{stdio,http/mod}.rs, src/idempotency.rs
- candidate criteria: none
- evidence: transport/stdio.rs additions are multiplexed-stdout progress-token capture (same "S-03 over stdio: two calls in flight on one stdout" content as fix/mrtr2-continuation-handle), not the stdout-owning-writer-task/spawned-dispatch construct MIK-7387 asks for; no "budget" hits despite branch name; no account/audience/ranking/discovery/pin/audit paths touched
- verdict: NONE
- note: Near-duplicate of lane/roots-wiring's diff (same MRTR/order2-FSM lineage); branch name "error-budgets" not reflected in the actual diff content.

## fix/gh517-protocol-negotiation (90 ahead)
- touched subsystems: src/backend/{annotations,lifecycle,metadata,mod,ops}.rs, src/gateway/{meta_mcp/invoke,meta_mcp/prompt_cache,router/backend_handlers,router/handlers,server/mod,server/warmstart,streaming}.rs, src/transport/{http/mod,http/sse_decoder,mod,notification_sink,stdio}.rs, src/idempotency.rs, src/security/{firewall,http_diagnostics,mod}.rs, src/error.rs, src/chains/retry.rs, src/failsafe/retry.rs
- candidate criteria: none
- evidence: src/backend/mod.rs:58-65 adds `resend_permitted: RwLock<HashSet<String>>` for ADR-012 resend-permission annotations, not an identity key on tools_cache/CachedMetadata (MIK-7334.CATALOGUE.1 not present); no audience-claim/account-store/ranking/discovery/pin/audit hits anywhere in the diff
- verdict: NONE
- note: Branch is HTTP/SSE protocol-negotiation + retry/resend-permission work (gh-517); touches backend/metadata.rs and mod.rs but for an unrelated feature (ADR-012 resend annotations), not per-identity metadata caching.

## fix/registry-metadata (41 ahead)
- touched subsystems: src/capability/definition/mod.rs, src/commands/*, src/config_reload/mod.rs, src/gateway/{auth,destructive_confirmation,meta_mcp/*,proxy,router/*,router/origin_guard(new),server/*,streaming,ui/*,ws_listener}.rs, src/key_server/mod.rs
- candidate criteria: none
- evidence: src/gateway/auth.rs additions are DashboardBootstrap/session-cookie admin-UI auth (auth.rs:77-347), not JWT audience-claim enforcement; no "audience"/"check_audience_claim"/jwt hits except an unrelated docs-comment mention of "install audiences" (line 3838 of raw diff); src/capability/definition/mod.rs has no sha256/pin hits
- verdict: NONE
- note: Branch is webui dashboard-bootstrap auth + origin-guard (new 771-line file) + config-reload work; no touches to oauth/jwt.rs, personal_accounts/, backend/metadata.rs identity cache, ranking, discovery, or audit paths.

## feat/v4-workload-harness (8 ahead)
- touched subsystems: benchmarks/workload/{eval_workload.py,mcp_backend.py,k6_workload.js,run_workload.sh,test_eval_workload.py,*.yaml}, docs/requirements/RELEASE-4.0.0-workload-contract.md, benchmarks/workload/results/rehearsal-2026-09-13/*
- candidate criteria: NFR.WORKLOAD.1
- evidence: benchmarks/workload/run_workload.sh:1 (new 310-line harness runner), benchmarks/workload/eval_workload.py:1 (new 223-line eval script), docs/requirements/RELEASE-4.0.0-workload-contract.md:1 (new 343-line workload contract spec) — matches a workload harness deliverable directly
- verdict: CARRIES
- note: Small, focused branch that is exactly the workload-harness deliverable NFR.WORKLOAD.1 asks for, including a rehearsal run's captured results.

## codex/v4-openwebui-runtime (7 ahead)
- touched subsystems: src/personal_accounts/{config,config/adapters,config/adapter_secret_tests,vault,mod}.rs, src/identity_propagation/{account_strategies(new),mod}.rs, src/capability/{backend,execution_context,executor/*}.rs, src/config/account_bindings.rs, src/gateway/{auth,meta_mcp/account_resolver_gateway,meta_mcp/account_rest_fixture(new),meta_mcp/account_rest_tests(new),meta_mcp/invoke,openwebui_adapter(new),router/*,server/account_bindings,server/mod}.rs, src/config_reload/*, tests/openwebui_adapter_config.rs
- candidate criteria: MIK-6745.JOURNEY.1/.2, MIK-6744.STORE.2 (revocation)
- evidence: src/gateway/meta_mcp/account_rest_tests.rs:565 "Alice's warm entry must survive Bob's miss — isolation, not a dead cache"; account_rest_tests.rs:1028 "the cross-user leak the isolation guard closes"; account_rest_tests.rs:2858 `a_revoked_grant_refuses_before_http`; account_rest_tests.rs:3261 `a_revocation_after_prepare_refuses_the_warm_cache_entry_and_the_wire`; account_rest_tests.rs:3664 "A REVOKED GRANT STILL REFUSES ON A MULTI-USER GATEWAY" — note `AccountKey`(principal_authority/principal_subject/backend_id/resource/oauth_issuer) and `validate_oauth_isolation` already exist on base chore/v4-reconcile-main (src/personal_accounts/mod.rs:49, src/capability/execution_context.rs:205), so MIK-6744.STORE.1 keying itself is not new here — this branch's contribution is the end-to-end multi-account isolation + revocation proof/wiring via a real REST backend (account_rest_fixture.rs) and the openwebui adapter
- verdict: CARRIES
- note: Largest concrete match in the survey so far — 1273-line test file exercising cross-user isolation and revocation-refuses-warm-cache scenarios against a real fixture, directly satisfying the "end to end" language of MIK-6745.JOURNEY and the revocation half of MIK-6744.STORE.

## feat/v4-stdio-concurrent-dispatch (6 ahead)
- touched subsystems: src/gateway/server/mod.rs, tests/mik_7212_mrtr7_stdio_acs.rs
- candidate criteria: MIK-7387.STDIO.1/.2/.3
- evidence: src/gateway/server/mod.rs:41 `fn spawn_stdio_writer()` (stdout-owning writer task, single writer serializing frames via mpsc), :65 spawns it in `run_stdio`, :94/:147 `carries_initialize` keeps `initialize` on the reader while :120/:192 `tasks.spawn(...)` dispatches every other (non-initialize) request concurrently
- verdict: CARRIES
- note: Small two-file branch that is precisely the concurrent-stdio-dispatch construct the criterion describes — stdout-owning writer task plus spawned non-initialize dispatch, with initialize serialized on the reader.

## feat/v4-mrtr-bridge-wiring (6 ahead)
- touched subsystems: src/gateway/{input_bridge,meta_mcp/invoke,meta_mcp/mod,router/handlers}.rs, src/protocol/meta.rs
- candidate criteria: MIK-6745.JOURNEY.1/.2 (weak)
- evidence: src/gateway/meta_mcp/invoke.rs:107 threads an existing `account_credential: Option<Arc<PreparedAccountCredential>>` and `verified_identity` through the MRTR bridge's `accounted_dispatch` call sites (invoke.rs:153,166,256,324,327) — reuses identity_propagation types already on base, does not add new isolation-guard or account-store logic; "for grants and audit" (invoke.rs:99) is a doc comment, not MIK-6710 audit-log pagination
- verdict: PARTIAL
- note: MRTR bridge continuation work threading existing account/identity plumbing through more call sites in the meta_mcp subsystem; no new construct for any of the 19 criteria.

## feat/v4-discovery (5 ahead)
- touched subsystems: src/backend/{metadata,tests}.rs, src/gateway/{meta_mcp_helpers,router/authorization(new),router/handlers,router/tests}.rs
- candidate criteria: MIK-7334.CATALOGUE.1, MIK-7332.DISCOVERY.1
- evidence: src/backend/metadata.rs:23 `fn withholds_shared_metadata()` explicitly labeled "(MIK-7334 CATALOGUE.1)" — withholds the shared tools_cache for `SessionMode::PerUser` backends since no per-identity catalogue fetch exists, so `has_cached_tools`/`cached_tools_count`/`get_cached_tool`/`get_cached_tools_snapshot` all withhold too; src/gateway/router/authorization.rs (new file) `filter_admin_tools_from_list` and `filter_routing_guide_for_client` explicitly commented "(MIK-7332 DISCOVERY.1 clause (a))" / "clause (c)"
- verdict: CARRIES
- note: Code comments cite the exact criterion IDs — strongest possible evidence in the survey; catalogue fix is a withhold-not-serve mitigation rather than true per-identity caching, but it is the concrete construct the criterion's subsystem calls for.

## control4-lifecycle-local (5 ahead)
- touched subsystems: src/gateway/{router/handlers,router/mod,server/mod,session_lifecycle,streaming}.rs, src/security/firewall/{anomaly,mod}.rs, src/config/features/streaming.rs, tests/mik_7215_control4_lifecycle_wiring.rs
- candidate criteria: none
- evidence: explicitly labeled "MIK-7215.CONTROL.4 — session-lifecycle TTL-reaping" (session_lifecycle.rs comment); SHA-256 use here (credential_identity, session_lifecycle.rs:678) hashes a caller's credential token for TTL-reap identity tracking, not capability pinning (MIK-7235.PIN.1 is a different subsystem — capability definitions); no spawn_stdio_writer/carries_initialize hits, so not MIK-7387.STDIO either
- verdict: NONE
- note: Own explicit ticket (MIK-7215 control4 session reaper) not among the 19 pending criteria; superficial keyword overlaps (identity, SHA-256) don't map to the actual criterion constructs.

## codex/v4-task-signing-composition (5 ahead)
- touched subsystems: src/gateway/task_service/{execution,execution/observe,execution/recovery,execution/upstream,worker,mod,record,store}.rs, src/transport/{http/mod,mod}.rs, tests/task_upstream_recovery*/{helper,authority,issuer,peer,pins}.rs, tests/fixtures/task_upstream_sdk/server.py
- candidate criteria: none
- evidence: tests/task_upstream_recovery_sdk/pins.rs is env-var "pinned SDK version" preconditions (fastmcp/pydocket), unrelated to MIK-7235 SHA-256 capability pinning; tests/task_upstream_recovery_sdk/issuer.rs mints test JWTs with `AUDIENCE = "mcp-gateway-upstream-vertical"` (issuer.rs:8004) to exercise an EXISTING `OidcVerifier`, but src/gateway/oauth/jwt.rs itself is untouched (`git diff --stat -- src/gateway/oauth/` empty) — not MIK-6746.CONTRACT.1's mandatory-audience-check construct; no src/personal_accounts/ or execution_context.rs touches
- verdict: NONE
- note: This is A2A task-upstream-recovery/signing work (MCP task delegation to an upstream SDK) with its own audience-tagged test tokens, but doesn't touch the jwt.rs enforcement path or any other of the 19 criteria's subsystems.
