# Supplemental acceptance test plan

The [approved requirement table](RELEASE-4.0.0-scope-update.md) owns the IDs.
The cases below are specifications for implementation, not claims that tests
exist or pass. No placeholder or ignored Rust test is added by this package.
Every product row starts unverified until the release integrator grades evidence.

## Safety and bridge

| Criteria | Discriminating test and positive control |
|---|---|
| GH462.CONFIG.1 | Admin API edits an invalid YAML file: reject and compare original bytes/hash; repeat with missing file and valid file to prove first setup and normal edits work. |
| GH452.SESSION.1 | Create sessions under two authenticated callers, delete as owner and nonowner, compare unauthorized versus unknown responses, then prove the other session still serves calls. |
| MIK-7377.SIGNING.1 | Start the real server with signing enabled and missing/invalid/valid keys; inspect emitted signatures when supported, or require explicit unsupported-config rejection. Disabled baseline retains its advertised behavior. |
| MIK-7387.STDIO.1 | Enable the existing real-stdio AC in tests/mik_7212_mrtr7_stdio_acs.rs; assert the client's answer reaches the backend, not merely that a timeout returns. |
| MIK-7387.STDIO.2 | Hold initialize write completion while a bridge request becomes ready; observe initialize first, then the input request. |
| MIK-7387.STDIO.3 | Concurrent peer exchanges share the real writer; parse each emitted line independently and assert expected complete frames and correlation. |
| MIK-7388.CANCEL.1 | With a live client peer waiting, cancel the production send task, await its join, then inspect pending state and verify a later exchange cannot receive the old response. |

## Tasks

| Criteria | Discriminating test and positive control |
|---|---|
| MIK-7311.LIFECYCLE.1 | Through POST /mcp and POST /mcp/{backend}, negotiate per request, start a real slow task, poll, supply requested input, and observe a typed terminal result; no capability produces the required refusal/core result. Cover JSON-RPC failure separately from completed isError tool results. |
| MIK-7311.LIFECYCLE.2 | Disconnect after accepting a task, reconnect as the same and a different principal; original caller can poll/control, other caller cannot learn existence or mutate it. |
| MIK-7311.LIFECYCLE.3 | Immediately poll the returned handle; kill/restart the gateway at create-before-ack and settlement boundaries; retained handles/outcomes remain queryable with owner checks. |
| MIK-7311.LIFECYCLE.4 | Backend records a write before response loss; restart gateway, recover a known upstream job or report interruption/uncertainty; count effects and prove no silent replay. A read-only recoverable job is the positive control. |
| MIK-7311.LIFECYCLE.5 | Race cancellation with completion; final state remains legal and stable. Fill count/byte bounds and advance a controlled clock past TTL; reject excess work and reclaim abandoned work without relying on sleeps. |

Also cover request-scoped progress, task notification transport where supported,
expiry during input, duplicate update/cancel, and modern/legacy client behavior.
Do not invent a nonstandard task state for uncertainty; map it to the documented
extension-compatible error/outcome. Test non-origin replica behavior against
the explicit topology contract rather than presuming transparent HA.

## Personal accounts

| Criteria | Discriminating test and positive control |
|---|---|
| MIK-7334.CATALOGUE.1 | One backend returns different tool names/schemas for two identities. Interleave cold/hot reads, rotate/revoke a grant during a fill and check both catalogue and call results. Invariant shared catalogue is a separate positive control. |
| MIK-6744.STORE.1 | Isolated temp credential store, two principals and resources: save/load/refresh never cross keys; migrate existing local data and inject failed writes. Inspect encrypted-at-rest bytes and absence of secrets in diagnostics. |
| MIK-6744.STORE.2 | Revoke during refresh and restart during token replacement; old task/cache/connection cannot restore a revoked grant. Re-consent creates a usable new grant without reviving the old one. |
| MIK-6745.JOURNEY.1 | Run Open WebUI on Spark → gateway → Google Workspace, including connect/use, browser cancellation, expired/replayed consent state, refresh and revoke. Pin client/adapter/provider configuration versions and record the actual route. The existing installation is a starting environment, not acceptance evidence. |
| MIK-6745.JOURNEY.2 | Two test accounts plus an unconnected user through the same gateway; verify each backend sees the intended account and no absent credential selects the operator account. Explicit shared-service-account configuration is the positive control. |
| MIK-6745.JOURNEY.3 | Repeat the identity discriminator through meta and direct calls, discovery, prompts/resources where supported, and a personal REST capability; exercise actual client→adapter→gateway request identity, not manually supplied test-only context. |
| MIK-6746.CONTRACT.1 | Test wrong audience, issuer/backend swap, absent identity, mixed credential strategies, direct/meta parity and expiry under the revised design. A custom header alone cannot pass the standard-interoperability cell. |

Use deterministic provider mocks for faults and test accounts for the real-client
journey. Do not print access/refresh tokens in fixtures, logs or published evidence.
Real consent and provider access require the selected operator-owned test setup;
this documentation change does not initiate either.

## Discovery and operations

| Criteria | Discriminating test and positive control |
|---|---|
| MIK-3274.RANKING.1 | Held-out abbreviations and word boundaries over realistic conflicting tool names; exact identifier, unsupported match, Unicode and Code Mode glob controls. |
| MIK-3274.RANKING.2 | Both public discovery routes, forbidden highly-used tool versus allowed relevant tool, low requested result limit and poisoned/global feedback; assert authorization precedes disclosure and ranking precedes truncation. |
| MIK-3274.RANKING.3 | Capture 3.5.1 baseline and freeze corpus/thresholds before changes; report top-k selection, completed-task rate, discovery turns, invalid calls and total task tokens, with exclusions and repetitions. |
| MIK-7332.DISCOVERY.1 | Admin/nonadmin and configured/unconfigured features: served list, routing guide, tiered schema detail and invoke permissions agree; surfaced tools actually appear and execute; invalid schema tool is withheld while healthy backend tools remain. |
| MIK-7235.PIN.1 | Check catalogue classification completeness; verify selected pins with the shipped command; tamper a pinned file and require rejection; intentionally unpinned development file remains supported. |
| MIK-6710.AUDIT.1 | Large log plus rare/no-match filters and pagination: measure records/bytes examined or index work, compare ordered results to a small full-scan oracle, and prove bounded behavior never silently truncates filtered results. |

## Release-level validation

| Criteria | Discriminating test and positive control |
|---|---|
| NFR.CONFORMANCE.1 | Matrix of required role/transport/revision/outcome cells, explicit N/A reasons, evidence existence, modern completion-removal versus retained legacy behavior, and scalar/array/object structured results with outputSchema preservation. |
| NFR.WORKLOAD.1 | Fixed valid tool and deterministic backend; assert successful semantic payloads. Same-host interleaved legacy comparison with 3.5.0 and 3.5.1; measure modern/mixed-era separately; preserve P50 ≤5% and P99 ≤10% regression budgets. Keep no-backend control separately labelled. |
| NFR.UPGRADE.1 | Copy realistic 3.5.1 config/token data into an isolated deployment; upgrade, verify permissions/mounts/callers, turn modern off, roll back; compare original and migrated data according to the documented migration contract. |
| NFR.RELEASEGATE.1 | A consistent pending ledger passes --check and fails --release; baseline blocker alone fails; missing/duplicate IDs, missing evidence and unanswered decisions cannot produce release success. Check every publishing workflow's dependency path including manual tag input. |
| NFR.DEMO.1 | Record mixed-era interaction, reconnectable task, two personal accounts, large-catalogue discovery and error-budget diagnosis/recovery; include versions, expected observations and actual outcomes. |
| NFR.BUILD.1 | Record concrete supported clients/backends/features and license availability; run agreed critical coverage/mutation on final integrated startup, OAuth, HTTP/stdio dispatch, bridge, tasks and account paths; don't grade the branch from an old protocol-only sample. |

## Checks implemented by this package

Only the release-contract checker tests are implemented here. They test a real
release-safety boundary using temporary ledgers and evidence files, including
negative cases. They do not prove any product row above. Run:

```sh
python3 scripts/release/test_scope_acceptance.py
python3 scripts/release/test_count_release_criteria.py
python3 scripts/release/check_scope_acceptance.py --check
python3 scripts/release/check_scope_acceptance.py --release
```

The final command must return 1 while acceptance work or required decisions are
pending. Exit 2 means invalid/unreadable contract data, not an ordinary pending
release. Exit 0 in check mode means a consistent plan only. Existing full Rust,
live-client and performance suites remain the implementation owner's work.
