# Approved capability scope update

Status: approved scope; implementation and acceptance evidence remain open.
Date: 2026-09-06.

This supplements [the original requirements](RELEASE-4.0.0-requirements.md).
It supersedes their deferral of MIK-6744/6745 and the release-level deferral of
legacy stdio bridging or tasks. It does not invalidate completed implementation
increments or silently turn their OUT lists into completed release work.

Decision provenance is in [the decision record](RELEASE-4.0.0-scope-decisions-2026-09-06.md).
[The delivery plan](RELEASE-4.0.0-scope-delivery.md) assigns work packages rather
than competing with an active agent for files. [The test plan](RELEASE-4.0.0-scope-tests.md)
defines acceptance; [the JSON ledger](RELEASE-4.0.0-scope-status.json) records
verdicts. A pending verdict means unverified against this contract, not a claim
that every underlying mechanism is absent.

## Required outcomes

Every row below is required for this release. Existing baseline requirements
remain binding. The IDs follow the existing ticket/component/number convention.
The approval source for these product requirements is the decision record;
protocol requirements additionally use the pinned specifications linked below.

| ID | Required outcome | Delivery package |
|---|---|---|
| GH462.CONFIG.1 | An admin edit of an invalid existing config refuses and preserves its original bytes; a missing file still supports first setup. | SAFETY |
| GH452.SESSION.1 | Legacy session deletion enforces authenticated ownership; unknown and unauthorized IDs do not disclose existence. | SAFETY |
| MIK-7377.SIGNING.1 | An enabled message-signing configuration produces validated signatures with a valid key, or startup rejects that unsupported configuration and the feature claim is corrected. | SAFETY |
| MIK-7334.CATALOGUE.1 | Supported identity-dependent backend catalogues, cached metadata and results are isolated by verified caller and authorization context, including changes and revocation. | ACCOUNTS |
| MIK-7387.STDIO.1 | A declared client input request reaches a legacy stdio client, whose answer reaches the backend while the gateway continues reading. | BRIDGE |
| MIK-7387.STDIO.2 | An input request cannot overtake the initialize response on legacy stdio. | BRIDGE |
| MIK-7387.STDIO.3 | Concurrent stdio requests and replies emit complete, non-interleaved JSON frames. | BRIDGE |
| MIK-7388.CANCEL.1 | Cancelling a real bridged exchange reclaims production pending state and does not deliver its response to another exchange or caller. | BRIDGE |
| MIK-7311.LIFECYCLE.1 | Negotiated tasks execute through public routes and support polling, input, cooperative cancellation, terminal outcomes and expiry under the pinned extension. | TASKS |
| MIK-7311.LIFECYCLE.2 | An accepted task survives client disconnect and is queryable by the same principal after reconnect; other principals cannot inspect or control it. | TASKS |
| MIK-7311.LIFECYCLE.3 | A returned task handle already resolves, including after gateway restart within its documented retention window; retain identity and terminal outcome durably. | TASKS |
| MIK-7311.LIFECYCLE.4 | After restart, recover an upstream job where supported or report an explicit interrupted/unknown execution outcome; never silently replay a side effect. | TASKS |
| MIK-7311.LIFECYCLE.5 | Task creation, retained results and lifetime have enforced bounds; cancellation races cannot rewrite settled outcomes or promise undo. | TASKS |
| MIK-6744.STORE.1 | Gateway-managed fallback credentials are keyed by principal/backend/resource for load, save and refresh, protected at rest, with readable/migrated single-user data and no silent loss. | ACCOUNTS |
| MIK-6744.STORE.2 | Revocation and restart preserve credential isolation and cannot leave an old refresh job or cached credential usable under a new grant. | ACCOUNTS |
| MIK-6745.JOURNEY.1 | Open WebUI on Spark completes connect, use, refresh, revoke and cancelled-consent journeys through the gateway against Google Workspace. | ACCOUNTS |
| MIK-6745.JOURNEY.2 | Two users reach their own personal accounts concurrently; an unconnected user gets an actionable refusal and cannot fall back to an operator/shared account. | ACCOUNTS |
| MIK-6745.JOURNEY.3 | List/search, calls, prompts/resources where supported, MCP backends and REST capabilities apply consistent personal-account authorization on their public entry points. | ACCOUNTS |
| MIK-6746.CONTRACT.1 | Gateway and downstream authorization boundaries conform to the current audience rules; document and test supported client mechanisms and route parity before expanding credential forwarding. | ACCOUNTS |
| MIK-3274.RANKING.1 | Fuzzy ranking improves supported abbreviation and word-boundary discovery while exact identifiers, existing relevant matches and Code Mode globs remain reliable. | DISCOVERY |
| MIK-3274.RANKING.2 | Both discovery routes apply authorization before disclosure and rank before truncation; usage feedback cannot promote an irrelevant or forbidden tool over a relevant allowed tool. | DISCOVERY |
| MIK-3274.RANKING.3 | Held-out selection quality, discovery turns, invalid invocations and total completed-task tokens meet thresholds frozen after baseline measurement and before ranking implementation. | DISCOVERY |
| MIK-7332.DISCOVERY.1 | Authorization-derived exposure, tiered disclosure, schema validity and configured surfaced tools work together on the served consumer surface with consistent guides and invocation permissions. | DISCOVERY |
| MIK-7235.PIN.1 | Classify the shipped catalogue before pinning, pin its stable high-privilege subset, record intentional exclusions and maintain re-pin checks. | OPERATIONS |
| MIK-6710.AUDIT.1 | Audit reads have a documented work bound with newest-first/filter semantics preserved; selective queries use an index or explicit scan-budget/cursor behavior rather than an unsupported O(N) promise. | OPERATIONS |
| NFR.CONFORMANCE.1 | The complete applicable role/transport/revision/outcome matrix has evidence references, including modern URL-elicitation completion removal and arbitrary-JSON structured results; every N/A cell has a reason. | VALIDATION |
| NFR.WORKLOAD.1 | A deterministic real-backend workload validates successful semantic results and measures legacy, modern and mixed-era paths; preserve existing latency thresholds and the frozen 3.5.0 baseline, adding 3.5.1 as current upgrade/comparison source. | VALIDATION |
| NFR.UPGRADE.1 | Upgrade from 3.5.1 and exercise modern-off/rollback with config, credentials, permissions, mounts and active callers preserved according to the documented lifecycle. | VALIDATION |
| NFR.RELEASEGATE.1 | Every automated 4.0.0 publishing path rejects unresolved baseline and supplemental criteria and decisions; plan consistency can still pass while work is pending. | VALIDATION |
| NFR.DEMO.1 | Recorded demonstrations prove mixed-era interaction, reconnectable tasks, isolated personal accounts, useful large-catalogue discovery and error-budget diagnosis/recovery. | VALIDATION |
| NFR.BUILD.1 | Pin supported reference client/backend versions and feature/build combinations under the existing license split; current critical-path coverage and mutation evidence grades the final integration revision. | VALIDATION |

## Boundaries

- Include MIK-6744/6745 as a fallback for clients unable to manage backend OAuth.
  Externally managed authorization remains preferred. ADR-008's old ticket
  bodies and MIK-6746's custom header must be reconciled, not copied into new work.
- Include legacy stdio bridging. MIK-7387's estimate/design work remains a
  prerequisite for implementation, not another inclusion decision.
- Include complete tasks and the recovery contract above. Transparent recovery
  on any replica and a distributed continuation store remain outside this
  expansion. Preserve the existing explicit-failure continuation behavior.
- Reuse per-user connections (MIK-6735), auth metadata (MIK-6750), provenance
  stamping/evaluation (MIK-6905/6906/6908) and existing semantic-search machinery.
  Verify current delivery before closing stale parents; do not rebuild them.
- Keep the broader MIK-7116 model-backed summary/response-attribution feature,
  MIK-6907 enforcement, Kubernetes operator GA, WebMCP/App Intents, ACP/editor
  integration and additional messaging connectors outside this expansion.
- MIK-7377 contributes only gateway obligations. Portfolio dependency cleanup
  stays outside this release. MIK-3233's current body belongs to Symphony+.

## Acceptance sources and evidence strength

[MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
requires audience-specific token handling. A custom forwarding header is not a
standards-conformance exemption. The design must establish the resource/server
boundary and separately authorized downstream credentials or valid exchange.
[Tasks 2026-07-28](https://tasks.extensions.modelcontextprotocol.io/specification/2026-07-28/tasks)
is the pinned extension; the broader restart guarantee above is an approved
product requirement. [The core changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
supplies the omitted conformance cases.

The recorded operator decision remains evidence-reference existence now;
automated execution-to-evidence binding is a later improvement. The supplemental
checker enforces reference existence and completeness, not the truth of a test
report. Reviewers must still assess evidence applicability and quality. Planned
test files and ignored tests are not completed feature evidence.
