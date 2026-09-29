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

Approved supplemental criteria: 113

Every row below is required for this release. Existing baseline requirements
remain binding. The IDs follow the existing ticket/component/number convention.
The approval source for these product requirements is the decision record,
except MIK-7407.RESPONSE.1-5: MIK-7407 is a required 4.0 security issue the
ledger lacked, added 2026-09-29 on the lead's instruction under the operator's
full-4.0-scope ruling, with MIK-7407's own acceptance criteria as the text;
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
| MIK-7570.AUDIT.4 | Every grant approve, revoke or replacement made through the `identity grants` CLI is recorded in the governance audit log with verb, timestamp, grant id, content digest and expiry, and any other change to the grant file is recorded as an out-of-band edit. The `identity grants` CLI, which only edits the file and may run while a gateway is up, appends one entry per successful change to an append-only sidecar journal beside the grant file (mode 0600) with actor `unknown` and the OS account as an unauthenticated hint; it never writes the gateway's audit log. The gateway ingests unseen journal entries into its audit log at startup and on every reload. At startup it also records a `loaded` snapshot (one record per active grant plus a closing record with run id and count), and a mismatch between journal and snapshot is recorded as an out-of-band edit. No actor is ever synthesized. With auth disabled no governance log exists and the tracing event remains the only record. A failed audit append never reverts an applied change, and the outcome reports it as unrecorded (D3-e). | ENTERPRISE |
| MIK-7570.METRICS.2 | Security-relevant events are exported as metrics without identities in labels (D4). | ENTERPRISE |
| MIK-7570.SESSION.1 | Dashboard sessions expire after 30 minutes idle and 8 hours absolute, and logout ends them (E5). | ENTERPRISE |
| MIK-7570.RECONNECT.1 | A managed personal account whose upstream token is rejected gets at most one forced refresh per token revision and then a reconnect prompt (A11). | ENTERPRISE |
| MIK-7570.OWASP.1 | The published OWASP self-assessment matches the shipped controls (D5). | ENTERPRISE |
| MIK-7570.PAGING.1 | The backend tool cache follows nextCursor, so tools past a backend's first tools/list page are listed and callable (F3). | ENTERPRISE |
| MIK-7570.STDIO.1 | A modern-era stdio caller whose backend asks for input it declared on that request receives an `InputRequiredResult` carrying a redeemable `requestState`, and its retry completes, instead of being refused with -32003; the input bridge stays legacy-only, and a modern call declares per request, never by the `initialize` handshake. Pinned in `tests/r5_stdio_modern_continuation.rs`. Or this criterion is waived by a recorded ruling that moves R5 to a later 4.x release (R5; amended 2026-09-25 by the R5 PR from the coordinator's L0 wording, design R5-design.md rev 3). | ENTERPRISE |
| MIK-7570.DOCS.1 | The team deployment guide, backup/restore and key runbook, reconciled upgrade guide and client matrix ship with 4.0.0 (F docs). | ENTERPRISE |
| MIK-7596.OWNER.1 | Task methods on the per-backend route `POST /mcp/{name}` never reach the backend: every `tasks/*` method and `subscriptions/listen` naming `taskIds` is refused with -32601, so callers sharing a backend cannot read or cancel each other's tasks (F1, #1442). | ENTERPRISE |
| GH1941.SIGN.1 | Every release binary ships an SPDX SBOM of the crates linked into it, and each binary, each SBOM and SHA256SUMS.txt (which lists them all) carries a cosign keyless bundle whose identity is release.yml at the tag; the release job refuses to publish when any file is missing or a signature does not verify, and re-checks the published release afterwards (ASI04, #1941). | SECURITY |
| GH1942.HARDEN.1 | One opt-in hardened posture, raising the context-integrity preset floor to `team_shared`, forces message signing, anomaly blocking with per-identity learning (which also resolves #1756), SSRF checks on backend URLs, and per-caller identity on every HTTP MCP request (403 when no grant subject resolves; only an API key of kind `personal` counts as a per-person credential; stdio exempt), and refuses legacy clients that do not declare elicitation; a multi-user deployment running without it gets a startup WARN and a `doctor` finding (#1942). | SECURITY |
| GH1943.PROV.1 | With remote HTTP/A2A backends configured and signed provenance not required, startup logs a WARN naming the unverified backends and `doctor` reports a finding; no default changes (#1943). | SECURITY |
| GH1944.CHAIN.1 | A downstream gateway configured to verify a backend's signature chain checks every link against its trusted keys, the pinned origin and last signer, the link-to-link digests and its own nonce, strips and marks a chain that fails, and appends its own link, so a tampered, reordered or dropped hop or a re-signed chain fails verification (ASI07, #1944). | SECURITY |
| GH1945.COLLUDE.1 | Opt-in verbatim cross-principal relay detection: sensitive content one principal received that another principal then sends onward is reported, or refused under `block`, on the meta route and on the direct route once #1785 lands; one principal never flags itself and relays outside the window are not flagged. ASI10 stays PARTIAL, since other collusion patterns have no sound definition (#1945). | SECURITY |
| GH1625.BOTREVIEW.1 | Every automated pull-request reviewer finding on pull requests merged to the release line up to the release tip is resolved with a fix commit or an individual written disposition verified at source (no bulk won't-fix), and the #1625 backlog is closed (#1625). | SECURITY |
| MIK-7407.RESPONSE.1 | Meta HTTP and direct HTTP tool calls enforce the actual response verdict, replace blocked results with a generic JSON-RPC refusal, preserve the request ID and release no blocked payload. | SAFETY |
| MIK-7407.RESPONSE.2 | Direct and aggregated discovery honor tools/list response policy; allow, scan-disabled, Warn and redaction controls remain correct. | SAFETY |
| MIK-7407.RESPONSE.3 | The real stdio call/list serving path uses the same enforcement boundary, with one content scan and one response audit per response. | SAFETY |
| MIK-7407.RESPONSE.4 | Shared finalization happens after wrapping and before signing; blocked results and errors stay unsigned; a successful external gateway_invoke signs the final filtered bytes; detached tasks finalize retained backend results independently of admission acknowledgements. | SAFETY |
| MIK-7407.RESPONSE.5 | Counted backend negative and positive fixtures prove served behavior on every route, with scan-count and policy-target falsifiers; one immutable delivery-attempt event is recorded after final filtering and signing, hashing the final JSON-RPC response without payloads or credentials. | SAFETY |
| MIK-7406.VERIFY.1 | On the HTTP delivery path a message-signing test recomputes the HMAC over the delivered bytes with the configured key and rejects a tampered byte, not only the signature's shape; MIK-7377.SIGNING.1 stays met on its stdio evidence (MIK-7406). | SAFETY |
| MIK-7587.WINDOWS.1 | Every area the Windows CI job skipped is classified as a fixed test assumption, a product defect fixed in 4.0 red-first on the Windows job, or Unix-only by design (cfg-gated with a reason and documented as a Windows limitation), and the Windows job runs every test target (MIK-7587, #1142). | VALIDATION |
| MIK-7581.DOCS.1 | README, release notes and CHANGELOG lead with 4.0's headline improvements (MCP 2026-07-28 support and the multi-user/enterprise scope), the multi-user guide opens with the enterprise scope, and every highlight cites its file or test (MIK-7581). | VALIDATION |
| GH2294.AUDIT.1 | A restart that finds the audit log's high-water mark missing records that finding in the chain instead of re-minting the mark from a truncated tail, and live verification fails on it (#2294). | SAFETY |
| MIK-7116.MIN.1 | Tool responses carry a tenant attribution alongside the existing ContextDataClass, and the attribution is recorded in the audit trail whether or not it triggers a block (MIK-7116). | SECURITY |
| MIK-7116.MIN.2 | A caller that has read sensitive data attributed to tenant A is flagged (observe mode) or, when blocking is switched on, blocked from reading sensitive data attributed to tenant B; a test proves the verdict and the audit entries for both the read and the verdict (MIK-7116). | SECURITY |
| MIK-7116.MIN.4 | The tenant guard's false-positive rate is measured against a fixture corpus before blocking is enabled by default, and the guard ships observe-only first (MIK-7116). | SECURITY |
| MIK-7211.PARENT.1 | The RFC-0060 spike sub-issues U1 and U5 are closed with a recorded answer, not a plan to get one (MIK-7211 AC.1; U2 moved to MIK-7628). | VALIDATION |
| MIK-7211.PARENT.5 | The compatibility window is recorded as a decision in RFC-0060 with U1's measured data cited, replacing the unmeasured assumption (MIK-7211 AC.5). | VALIDATION |
| MIK-7211.PARENT.6 | No surface emits cacheScope public on a response computed from session-scoped state, enforced by a type or a lint that is named in the closing record (MIK-7211 AC.6). | SAFETY |
| MIK-7211.PARENT.7 | Every session-keyed behaviour in the gateway has a named stateless replacement in one inventory before any session code is removed (MIK-7211 AC.7). | VALIDATION |
| MIK-7217.SEARCH.1 | A test proves a backend speaking 2026-07-28 becomes visible to gateway_search and does not trip the circuit breaker (MIK-7217 AC DISCOVER.6). | VALIDATION |
| MIK-7217.CLAIMS.1 | The Meta-MCP tool count is asserted unchanged against benchmarks/public_claims.json, not only against a fixed band (MIK-7217 AC DISCOVER.8). | VALIDATION |
| MIK-7217.STDIO.1 | The stdio server/discover answer advertises 2026-07-28 when the modern protocol is on, asserted by an exact-version test (MIK-7217 AC DISCOVER.1 caveat). | VALIDATION |
| MIK-7272.OWNER.1 | On modern stdio, keyed writes execute once and replay without another effect; a keyless write executes (no refusal); legacy unkeyed repeats execute twice; all six management branches are tested (MIK-7272 SUB4.STDIO.OWNER.1, amended by operator ruling 2026-09-30). | SAFETY |
| MIK-7272.OWNER.2 | The same protected task store reopens or relocates and its typed local operator retrieves the task; another store and a same-store HTTP owner cannot retrieve or alias it; exercised through store integration and the independent functional gate, with no global lookup and no new instance UUID (MIK-7272 SUB4.STDIO.OWNER.2). | SAFETY |
| MIK-7272.OWNER.3 | An injected principal tag or HTTP credential string equal to the stdio serialized spelling cannot select or alias the stdio local operator; only the transport creates the typed tag; same-key owner-specific outputs stay separate and the real stdio owner works (MIK-7272 SUB4.STDIO.OWNER.3). | SAFETY |
| MIK-7272.OWNER.4 | A ToolPolicy denial refuses a local-operator mutation before retained-output delivery with zero dispatch to the denied target, while a permitted neighbouring target works (MIK-7272 SUB4.STDIO.OWNER.4). | SAFETY |
| MIK-7272.OWNER.5 | The real stdio-created context carries its execution principal but no verified identity, personal account or delegated grant; account-dependent calls are refused and an ordinary local mutation works (MIK-7272 SUB4.STDIO.OWNER.5). | SAFETY |
| MIK-7272.LIFE.1 | A held legacy RPC can be cancelled and joined: cancelling it releases the held exchange and its waiter gets a terminal answer, with nothing left pending (MIK-7272 SUB4.BRIDGE.LIFE.1). | BRIDGE |
| MIK-7324.COV.3 | Every coverage or mutation floor miss on the final revision is closed with tests or accepted as a written waiver naming the module and the reason (MIK-7324 COV.3). | VALIDATION |
| MIK-7216.IDEM.1 | Every exposed capability and tool is classified read-only or side-effecting as data, not only backend tools that declare annotations (MIK-7216 IDEM.1). | SAFETY |
| MIK-7216.IDEM.5 | One test kills the response stream mid-flight on a side-effecting call, re-issues it per the specification and asserts the backend effect happened exactly once (MIK-7216 IDEM.5). | SAFETY |
| MIK-7216.IDEM.6 | The same stream-kill test asserts a read-only call is unaffected by the idempotency path and is simply re-sent (MIK-7216 IDEM.6). | SAFETY |
| MIK-7217.ERA.1 | When a backend's transport is replaced by force_restart while a re-probe is in flight, the in-flight probe's answer is refused and the recorded era is unchanged (MIK-7217 ERA.1). | VALIDATION |
| MIK-7217.ERA.2 | In that sequence the refusal writes an era_probe_discarded record naming the reason (MIK-7217 ERA.2, the OBS.3 record). | VALIDATION |
| MIK-7217.ERA.3 | Without a restart a re-probe answer is committed as today, with no regression in a_contradiction_reprobes_and_the_whole_read_moves_with_it (MIK-7217 ERA.3). | VALIDATION |

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

### Linear tickets mapped onto existing rows (operator chat ruling C1)

Ruling C1 is recorded in `docs/requirements/RELEASE-4.0.0-operator-decisions.md`, section "Operator rulings given in chat" (added by #2385).

- MIK-7217 (server/discover): the MIK-7217.DISCOVER.* and MIK-7217.OUTBOUND.* baseline rows (MET), plus MIK-7217.SEARCH.1, CLAIMS.1, STDIO.1 and ERA.1-3 above. The other-repository half (Linear MCP728.DISCOVER.2: trvl, hebb, nab, metacognition, throttla) moved to MIK-7629: decision `portfolio_halves_outside_4_0` (operator ruling C5).
- MIK-7272 (two revisions behind): the MIK-7272.RESULT/ERROR/ORDER/SUB/EXT/OAUTH/OTEL/TASK baseline rows, all MET or N/A, plus MIK-7272.OWNER.1-5 and LIFE.1 above (the SUB4.STDIO.OWNER and SUB4.BRIDGE.LIFE ACs; ids shortened to the ledger's TICKET.COMPONENT.N form).
- MIK-7211 (portfolio-wide dual generation): for this repository, the MIK-7215.STATELESS.* baseline rows (MET) plus MIK-7211.PARENT.1, 5, 6 and 7 above. Gateway halves of AC.2-4: AC.2 -> MIK-7217.DISCOVER.1a/1b, AC.3 -> MIK-7272.RESULT.1, AC.4 -> NFR.COMPAT.1, all MET. The other-repository halves of AC.2-4 moved to MIK-7628: decision `portfolio_halves_outside_4_0` (operator ruling C5).
- MIK-7324 (coverage and mutation): NFR.BUILD.1 C5/C6 plus MIK-7324.COV.3 above.
- MIK-7216 (idempotency, sub-issue of MIK-7211): IDEM.2 -> MIK-7212.MRTR.10b, IDEM.3 -> MIK-7212.MRTR.10a, IDEM.4 -> MIK-7272.SUB.4 (keyless stdio calls admitted per operator ruling C4 unless server.idempotency_key is required; no HTTP exemption), IDEM.7 -> MIK-7212.MRTR.10a and NFR.COMPAT.1, all MET; IDEM.1, 5 and 6 are rows above.
- MIK-7219 (U2 hebb de-fork spike): moved to MIK-7628 with the MIK-7211 other-repository halves; MIK-7211.PARENT.1 no longer requires it.
- MIK-7407 (response firewall): the MIK-7407.RESPONSE.* rows added by #2387.
- MIK-7481 (container never started in CI): NFR.PKG.1 (MET), whose row names MIK-7481 as owner; the smoke runs on the scan image (.github/workflows/docker.yml:293-294, scripts/ci/smoke-image.sh), carried from #568 (c8803f066).
- MIK-7116 (data minimisation): MIK-7116.TENANT.1 (baseline) plus MIK-7116.MIN.1, MIN.2 and MIN.4 above. MIN.3, MIN.5 and MIN.6 are not 4.0.0 criteria: decision `mik_7116_min_kill_gate` in RELEASE-4.0.0-scope-status.json (operator ruling 2026-09-30); they are tracked in Linear MIK-7627, gated on the post-release MIN.KILL week.
- MIK-7406 (response signing): MIK-7377.SIGNING.1 (met) plus MIK-7406.VERIFY.1 above.
