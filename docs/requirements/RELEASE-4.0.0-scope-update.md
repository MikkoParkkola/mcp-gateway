# Approved capability scope update

Status: approved scope; implementation and acceptance evidence remain open.
Date: 2026-09-06.

This supplements [the original requirements](RELEASE-4.0.0-requirements.md).
It supersedes their deferral of MIK-6744/6745 and the release-level deferral of
legacy stdio bridging or tasks. It does not invalidate completed implementation
increments or silently turn their OUT lists into completed release work.

Decision provenance is in [the decision record](RELEASE-4.0.0-scope-decisions-2026-09-06.md).
[The delivery plan](../internal/requirements/RELEASE-4.0.0-scope-delivery.md) assigns work packages rather
than competing with an active agent for files. [The test plan](RELEASE-4.0.0-scope-tests.md)
defines acceptance; [the JSON ledger](RELEASE-4.0.0-scope-status.json) records
verdicts. A pending verdict means unverified against this contract, not a claim
that every underlying mechanism is absent.

## Required outcomes

Approved supplemental criteria: 73

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
| MIK-6745.JOURNEY.1 | Open WebUI on bench-host completes connect, use, refresh, revoke and cancelled-consent journeys through the gateway against Google Workspace. | ACCOUNTS |
| MIK-6745.JOURNEY.2 | Two users reach their own personal accounts concurrently; an unconnected user gets an actionable refusal and cannot fall back to an operator/shared account. | ACCOUNTS |
| MIK-6745.JOURNEY.3 | List/search, calls, prompts/resources where supported, MCP backends and REST capabilities apply consistent personal-account authorization on their public entry points. | ACCOUNTS |
| MIK-6746.CONTRACT.1 | Gateway and downstream authorization boundaries conform to the current audience rules; document and test supported client mechanisms and route parity before expanding credential forwarding. | ACCOUNTS |
| MIK-6746.IDENTITY.1 | Agent identity distinguishes a proven principal from a declared label: proof outranks declaration, a declared label contradicting a proven one is refused rather than silently applied, known_agents and require_id admit proven identities only, and the audit record carries both so a proved-A-claimed-B mismatch is detectable. | ACCOUNTS |
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

### Enterprise multi-user and security scope (MIK-7570)

Approved by the operator on 2026-09-24 (decision `enterprise_scope_in_4_0`): the multi-user and security features ship finished in 4.0.0 so enterprise users can adopt it. Designs and landing order are tracked in MIK-7570. Until matching rows exist in [the test plan](RELEASE-4.0.0-scope-tests.md), each item's reviewed design (its failing-first test table) is the acceptance source.

Deferred by the same ruling to a later release (tier 4, not criteria here): key revocation and auth reload without restart, the account-store rekey command (its runbook ships in 4.0.0), the single unified grant store, `init --profile team`, backend-level OAuth reconnect (the managed-account half is MIK-7570.RECONNECT.1), a shared multi-replica token store, Vault/KMS secret resolvers, and full RBAC roles.

| ID | Required outcome | Delivery package |
|---|---|---|
| MIK-7570.CACHE.1 | The response cache never serves one caller's cached result to another caller, on the meta route and the direct route (A0). | ENTERPRISE |
| GH555.DISCOVERY.1 | Every discovery surface (tools/list, list_tools, list_servers, search, initialize guide and counts, resolve, suggestions, direct-route listing) shows a caller exactly the backends and tools it could invoke; stats and webhook status are admin-only, and /health shows a non-admin caller only status and version (A3). | ENTERPRISE |
| MIK-7570.CHART.1 | The Helm chart installs and the gateway starts and serves with the chart's default values (B1). | ENTERPRISE |
| MIK-7570.GOVSTORE.1 | The governance store location is configurable; an explicit unwritable location refuses start, and a read-only store states its reason in the admin API (F6). | ENTERPRISE |
| GH612.CODEMODE.1 | The Code Mode authorization test asserts that an out-of-scope call is denied, not only which tool names are listed (GH #612). | ENTERPRISE |
| MIK-7570.IDHEADER.1 | Caller identity headers are honoured only from configured trusted proxies; a client cannot assert another identity by sending them (A8). | ENTERPRISE |
| MIK-7570.OIDC.1 | OIDC identity rules require an issuer and a verified email; an unverified email or issuer-only rule on a public identity provider confers nothing (A9). | ENTERPRISE |
| MIK-7570.NOTIFY.1 | Backend notifications reach only the sessions entitled to that backend, not every session (A5b). | ENTERPRISE |
| MIK-7570.NOTIFY.2 | subscriptions/listen is scoped per caller; an anonymous listener is refused with 401 (A5c). | ENTERPRISE |
| MIK-7570.LOGLEVEL.1 | Only an admin can change the gateway log level (A7). | ENTERPRISE |
| MIK-7548.ISOLATION.1 | A test proves one tenant cannot read or act through another tenant's session, credentials or cached results (MIK-7548). | ENTERPRISE |
| MIK-7570.ADMINGRANT.1 | Grant edits made in the admin panel are either enforced or refused with 409; none is accepted and then ignored (E2-min). | ENTERPRISE |
| MIK-7570.AGENTGRANT.1 | An exact agent grant is keyed by the verified proof source, not by a bare agent id, with a migration for 3.x grants (A4b, MIK-7526). | ENTERPRISE |
| MIK-7570.SCHEMA.1 | A tool call carrying nested input keys that the tool's schema does not declare is refused (R2). | ENTERPRISE |
| MIK-7570.CONFIG.1 | A configuration key the gateway does not recognise is a load error, not silently ignored (C1). | ENTERPRISE |
| MIK-7570.BACKENDGRANT.1 | A newly added backend is not reachable by any key until granted; an empty backend grant means none (A10). | ENTERPRISE |
| MIK-7570.CONFIG.2 | The gateway refuses a config file or env file readable by other users (C2). | ENTERPRISE |
| MIK-7570.TRANSPORT.1 | With auth on and a non-loopback bind, plain HTTP is refused at load unless `server.cleartext_http` is `tls_terminated_upstream`, `host_local_publish`, or `cluster_internal` with a `public_url` whose host is a Kubernetes Service name (ends in `.svc` or contains `.svc.`); every non-refuse value logs a warning on each start (C3). | ENTERPRISE |
| MIK-7570.SECRET.1 | A secret reference that cannot be resolved fails closed at load (C4). | ENTERPRISE |
| MIK-7570.SECRET.2 | Secrets can be referenced from files with the file: form, with the same fail-closed rules (C9). | ENTERPRISE |
| MIK-7570.METRICS.1 | /metrics requires authentication when auth is on (C7). | ENTERPRISE |
| MIK-7570.CONFIG.3 | max_body_size and request_timeout are enforced as documented, or removed (C8). | ENTERPRISE |
| MIK-7570.REPLICA.1 | The key server and personal accounts refuse to run with more than one replica, and the limit is documented (B2). | ENTERPRISE |
| MIK-7570.ATTEST.1 | Attestation is off by default and enforce mode refuses what it claims to refuse (C5). | ENTERPRISE |
| MIK-7570.AUDIT.1 | With auth on, every tool invocation writes an audit record with who, outcome and credential kind; a failed append fails the call closed (D1). | ENTERPRISE |
| MIK-7570.APIKEY.1 | API keys can be stored as sha256 digests and carry an expiry that is enforced (E4). | ENTERPRISE |
| MIK-7570.ADMINSSO.1 | Admins can be designated through SSO identity, requiring a verified email (E1). | ENTERPRISE |
| MIK-7479.STDIO.1 | A stdio backend call that never answers is accounted for and bounded; no call is left waiting indefinitely (MIK-7479). | ENTERPRISE |
| MIK-7325.RETRY.1 | Retried input responses are validated and never forwarded without a gateway-issued request state (MIK-7325). | ENTERPRISE |
| MIK-7547.SLOTS.1 | Per-user backend pool slots are capped at 64 per backend; over the cap the call is refused, never shared (MIK-7547). | ENTERPRISE |
| MIK-7570.BREAKER.1 | Circuit-breaker state is one typed value, so health, UI and metrics agree on an open breaker (B6). | ENTERPRISE |
| MIK-7570.CHART.2 | The Helm chart supports API-key and OIDC auth modes with secrets and persistent storage (B4). | ENTERPRISE |
| MIK-7570.AUDIT.2 | Direct-route tool calls write the same invocation audit record as the meta route (D2). | ENTERPRISE |
| MIK-7570.AUDIT.3 | Grant decisions, including refusals, are audited (D3). | ENTERPRISE |
| MIK-7570.METRICS.2 | Security-relevant events are exported as metrics without identities in labels (D4). | ENTERPRISE |
| MIK-7570.SESSION.1 | Dashboard sessions expire after 30 minutes idle and 8 hours absolute, and logout ends them (E5). | ENTERPRISE |
| MIK-7570.RECONNECT.1 | A managed personal account whose upstream token is rejected gets at most one forced refresh per token revision and then a reconnect prompt (A11). | ENTERPRISE |
| MIK-7570.OWASP.1 | The published OWASP self-assessment matches the shipped controls (D5). | ENTERPRISE |
| MIK-7570.PAGING.1 | The backend tool cache follows nextCursor, so tools past a backend's first tools/list page are listed and callable (F3). | ENTERPRISE |
| MIK-7570.STDIO.1 | A modern-era stdio caller that cannot be named is admitted to the input bridge (its elicitation reaches the stdio client) instead of being refused with -32003, pinned in `tests/mik_7212_mrtr7_stdio_acs.rs`; or this criterion is waived by a recorded ruling that moves R5 to 5.0 (R5). | ENTERPRISE |
| MIK-7570.DOCS.1 | The team deployment guide, backup/restore and key runbook, reconciled upgrade guide and client matrix ship with 4.0.0 (F docs). | ENTERPRISE |

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
