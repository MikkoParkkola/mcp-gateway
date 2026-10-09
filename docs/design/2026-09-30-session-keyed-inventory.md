# Session-keyed behaviour inventory (RFC-0060 U7)

**Criterion**: MIK-7211.PARENT.7. Every session-keyed behaviour in the gateway has a named
stateless replacement in one inventory before any session code is removed.

**Supersedes**: the 12-row table in RFC-0061 §"U7 RESOLVED" (`:271-295`, 2026-08-29). That table
covers about 12 of the 28 behaviours below.

**Surveyed**: `e689b7a7c`, 2026-10-01, read-only. The survey was first run at `1b4e46b93`
(2026-09-30) and re-run at `e689b7a7c`, 71 commits later (280 files under `src/` changed). The
re-run checked every citation below at that revision. It also covered each non-test file matched
by `rg -l -i 'session_id|Mcp-Session-Id|SessionId' src` that changed or appeared since the first
survey. The set is 63 of the 120 matching files. A test file here is one whose name ends in
`_test.rs`, `_tests.rs` or `_fixture.rs`, is `tests.rs` or `test_*.rs`, or lies under a `tests/` or
`*_tests/` directory. The re-run also compared the files that pattern misses, because they name
the variable `session` or `sid`, against the first survey (see "Outside the pattern"). Every file
path below is relative to `src/` and given in full, because bare names such as `mod.rs`,
`invoke.rs` and `identity.rs` are ambiguous.

**Changed since `1b4e46b93`**: the Built or Replacement claim of rows 1, 2, 11, 13, 14, 17, 21
and 26 changed, and row 28 is new. The causes are #2411 (session owner), #2448 (cost scope), #2464
(audit key), #2468 (direct-route owner), #2501 (replay binding), #2461 and #2499 (stored task
delivery) and #2544 (hardened session opening). Row 15 moved to a new file. Stdio tasks (#2538)
add no row: see "Stdio". The re-run also added two sites to row 20 that the first survey missed
(`gateway/meta_mcp/surfaced.rs` and the initialize-time bind) and corrected the cost row of G2.

## How to read it

- **Path** says where the behaviour runs:
  - *legacy*: 2025-11-25 and earlier, which mint a session.
  - *modern*: 2026-07-28, which is sessionless.
  - *both*.
- **Replacement** names the stateless mechanism. **Built** says whether that mechanism exists in
  code today (file:line). The criterion requires the name. Building it is tracked separately, and
  a row whose replacement is not built says so.
- On the modern HTTP path the router carries the session id as an empty string, not as no value
  (`gateway/router/handlers.rs:599-604`, passed on as `Some("")`). These sites turn that into
  "no session":
  - `session_key` (`gateway/meta_mcp/mod.rs:1595-1597`);
  - task intent (`gateway/router/handlers/tasks.rs:162-164,408-411`);
  - cost recording and the cost snapshot (`cost_accounting/mod.rs:501,538`);
  - the prompt-cache key (`gateway/meta_mcp/invoke.rs:1967`);
  - audit correlation (`gateway/meta_mcp/invoke/audit.rs:338-340`);
  - stream delivery (`gateway/streaming.rs:371`);
  - the response session header (`gateway/router/helpers.rs:32-39`), which holds no state.

  Every other `if let Some(sid)` treats `""` as one session shared by every modern caller. Rows
  marked *shared ""* have that defect.
- The replacement key, where it is "the caller key", is `caller_key`
  (`gateway/router/identity.rs:350`): the resolved identity, else the API key. When neither
  exists the replacement key is *none*, never `""`.

## Inventory

| # | Behaviour | Where | Path | Replacement (named) | Built? | Ledger |
|---|---|---|---|---|---|---|
| 1 | Session mint, resume, ownership. The owner is the proven subject plus the presented credential, else the credential, else anonymous. Under `hardened`, only an `initialize` that declares elicitation opens a session | `gateway/router/handlers.rs:605-633`; owner check `gateway/streaming.rs:228-242`; owner rule `gateway/router/handlers/owner.rs:25-36,85-97` and `gateway/session_id.rs:31-35`; resume without minting `gateway/streaming_ownership.rs:24-38`; `hardened` gate `gateway/router/hardened_elicitation.rs:3-11` | legacy | None needed: modern mints nothing | yes, `gateway/router/handlers.rs:599-604` | STATELESS.3a/3b |
| 2 | GET /mcp stream, backend auto-subscribe, `send_to_session`. Under `hardened`, GET only resumes a session | `gateway/router/handlers.rs:248-306` (`hardened` branch `:256-270`); `gateway/streaming.rs:370-375,411-445` | legacy | `subscriptions/listen`, keyed on the held credential plus request id | yes, `gateway/subscription_registry.rs:199-208` | STATELESS.7 |
| 3 | DELETE /mcp termination | `gateway/router/handlers.rs:316-346` | legacy | None needed: no session to end | n/a | none |
| 4 | Stream-session TTL reaper | `gateway/streaming.rs:148-200` | legacy | TTL reap of identity deadlines, same tick | yes, `gateway/streaming.rs:165-168` | CONTROL.4 |
| 5 | Pending server-to-client requests (sampling, elicitation, roots) and POST-back resolution | `gateway/proxy.rs:106,176-184,228-267,295-332,427-458,534-562` | legacy | MRTR `InputRequired` with a continuation bound to the principal fingerprint | yes, `protocol/continuation.rs:98,339-356` | MIK-7212 |
| 6 | Client-sent `sampling/createMessage`, `elicitation/create` routed to "the session that asked" | `gateway/router/handlers.rs:1696-1731` | legacy | Refusal by design: `-32021` when the capability is undeclared, `-32002` when a declared request has no session to reach; server-initiated asks move to row 5 | yes, `gateway/router/handlers/request_checks.rs:136-152`; with no session the send is undeliverable (`gateway/proxy.rs:261-266`) | STATELESS.10a-c |
| 7 | Legacy input bridge | `gateway/meta_mcp/invoke.rs:2203-2229`; `gateway/input_bridge.rs:380,679-690` | legacy | Continuation mint in the same function | yes | MIK-7212 |
| 8 | Destructive-operation confirmation | `gateway/destructive_confirmation.rs:276-283`; `gateway/meta_mcp/confirmation.rs:207-213` | legacy | In-band continuation | yes, `gateway/router/handlers.rs:1521`, `gateway/meta_mcp/confirmation.rs:244` | MIK-7212 |
| 9 | Anomaly scoring | `security/firewall/mod.rs:409-445` | both | Caller key; refuse when absent (`Unobservable`) | yes, `gateway/router/identity.rs:350`, `security/firewall/anomaly.rs:65-80` | CONTROL.1a/1b |
| 10 | Firewall call budget | `security/firewall/mod.rs:567` (`check_budget`) | both | Principal-keyed window | yes, `security/firewall/budget_guard.rs` | CONTROL.2 |
| 11 | Transparency-log correlation key, on a live call and on an idempotent replay | `gateway/meta_mcp/invoke/audit.rs:331-354`; replay `:400-412,454-458` | both | OTel trace id from `_meta`, else a minted id; never an empty session | yes, `gateway/meta_mcp/invoke/audit.rs:338-340,350-353`; see gap G1 | CONTROL.3a/3b |
| 12 | Disconnect cleanup | `gateway/session_lifecycle.rs:141,160,192,282-319` | both | TTL expiry per registered store | yes: a session-end class fired by an owned `DELETE /mcp` and by each reaper removal (#2563), and a caller-key idle class (#2591). The idle sweep skips a caller key a running task's backend call holds and renews its deadline one `IDLE_TTL` out when the last hold drops (`gateway/session_lifecycle.rs:113,258,300,319`; `KeyHold::drop` at `:83-97`; held by `gateway/task_service/execution/worker.rs:201` and `gateway/task_service/execution/input_round.rs:299`), so a task that outlasts the idle TTL keeps its key (#3225) | CONTROL.4 |
| 13 | Cost accounting per session | `cost_accounting/mod.rs:434,439,488-523`; `gateway/meta_mcp/invoke/dispatch_guards.rs:164-173` | both | Caller key; no record when absent | partly: an empty id opens no per-session bucket and counts in the admin total only (`cost_accounting/mod.rs:499-514,581-585`); a real session id still keys the bucket | none |
| 14 | `gateway_cost_report` target | `gateway/meta_mcp/invoke.rs:3659-3735` | both | Report on the caller key only | partly: a non-admin report names only the caller's own session (`gateway/meta_mcp/invoke.rs:3683-3694`) and an empty id reports none (`cost_accounting/mod.rs:537-541`); the caller-key report is not built | none |
| 15 | REST cost endpoint `X-Cost-Session-Id` | `gateway/router/backend_handlers/costs.rs:21-102` | admin REST | `?key=` (existing) | yes, `gateway/router/backend_handlers/costs.rs:78-84` | none |
| 16 | Projection A/B arm, and the arm suffix in cache and idempotency keys | `projection/mode.rs:74-124`; `gateway/meta_mcp/invoke/dispatch.rs:334`; `gateway/meta_mcp/invoke.rs:215-217`; `gateway/meta_mcp/admission.rs:539,612` | both, shared "" | Hash of the caller key; a caller with no key gets the control arm, never a sticky one | yes, `MetaMcpCallerContext::experiment_key` (`gateway/meta_mcp/session_end.rs:13`): the caller key only, never a session id (MIK-7997); no key: control shape, no A/B event (#2591) | CONTROL.5 |
| 17 | Prompt-cache key derivation | `gateway/meta_mcp/invoke.rs:1959-1974` | both | Explicit `_meta.prompt_cache_key`, else the caller key; drop the session part | partly: override exists, and an empty id derives no key (`gateway/meta_mcp/invoke.rs:1967`) | none |
| 18 | Meta transition tracker (predict, prefetch) | `gateway/meta_mcp/invoke/budget.rs:78`, called at `gateway/meta_mcp/invoke.rs:704` and `gateway/meta_mcp/invoke/pre_dispatch.rs:156,313`; `transition.rs:100,194` | both, shared "" | Key on the caller key; no key records nothing and serves no hints | yes, `record_and_predict` takes the experiment key; a caller key's entry becomes eligible for the next sweep one `IDLE_TTL` after its last request, or after the last hold a running task's call took ends (`gateway/session_lifecycle.rs:113,258,385`; `KeyHold::drop` at `:83-97`; #2591, #3225) | CONTROL.5 |
| 19 | Cached-token stats | `gateway/meta_mcp/invoke.rs:3352`; `stats.rs:30,65-76` | both, shared "" | Delete: no production reader | yes, deleted (#2591) | CONTROL.5 |
| 20 | Routing profile (visibility and invoke gate) | `gateway/meta_mcp/mod.rs:440,1569-1580,1723-1725`; `routing_profile/mod.rs:456-490`; `gateway/meta_mcp/visibility.rs:52-60,136-142`; `gateway/meta_mcp/surfaced.rs:121-141,222-234` | legacy | Per-request `X-MCP-Profile` selection (RFC-0061 correction table); until then modern gets the registry default or a refusal | no; refusal built (`gateway/meta_mcp/mod.rs:1603`) | none |
| 21 | `gateway_set_profile`, `gateway_get_profile`; the replay binding of a keyed `gateway_set_profile` retry is the session | `gateway/meta_mcp/mod.rs:2544-2585`; `gateway/meta_mcp/admission.rs:516-524` | legacy | Same as row 20 | refusal built | none |
| 22 | FSM workflow state and search visibility | `gateway/state.rs:22-54`; `gateway/meta_mcp/mod.rs:2482-2526`; `gateway/meta_mcp/search.rs:105-110` | legacy | Refusal on modern (ratified reading) | yes, `gateway/meta_mcp/mod.rs:1614` | MIK-7272.ORDER.2 |
| 23 | Spec-preview promoted tools | `gateway/meta_mcp/mod.rs:543,1528-1551`; `gateway/meta_mcp/spec_preview.rs:311-335` | legacy | Refusal on modern, as row 22 | a modern promotion is a deliberate no-op today; a refusal is needed only if ORDER.2 requires one | MIK-7272.ORDER.2 |
| 24 | Negotiated-revision binding (cache revision bucket, telemetry) | `protocol_revision_telemetry.rs:401-438,583-605` | legacy | Revision echoed per request | yes, `gateway/router/handlers.rs:802-805` (`cache_protocol_revision`) | NFR.OBS.1 |
| 25 | Upstream `MCP-Session-Id` buckets (backend affinity) | `transport/http/mod.rs:313,1114-1122,1469-1486`; `backend/ops.rs:191,508-523` | legacy upstream | Keyed on caller identity already; header stripped for modern peers | yes, `transport/http/mod.rs:411,1243` | STATELESS.3a |
| 26 | Direct-route profile and cost key | `gateway/router/backend_handlers.rs:672-677,1036` | both | Caller key, as row 27 | partly: a presented id counts only for its owner (`gateway/router/backend_handlers.rs:672-677`, `gateway/streaming_ownership.rs:14-18`); the key is still that session id, not the caller key; see G6 | none |
| 27 | Direct-route firewall identity | `gateway/router/backend_handlers.rs:59-73,137`; `gateway/router/direct_guards.rs:139` | both | Caller key, else `direct:{backend}` | yes | CONTROL.1a/2 |
| 28 | Stored task result delivery re-checks the active routing profile | `gateway/meta_mcp/task_replay.rs:24-40,100`; callers `gateway/router/handlers/tasks.rs:263-269`, `gateway/meta_mcp/mod.rs:2276`, `gateway/server/stdio_tasks.rs:275` | legacy | Same as row 20 | no; a modern read gets the registry default (`gateway/meta_mcp/mod.rs:1569-1580`) | none |

**Dormant** (session-keyed, no production caller): `simhash.rs:379-439`,
`gateway/meta_mcp/prompt_cache.rs:110`, `gateway/meta_mcp/mod.rs:1555`, and `remove_session` in
`cost_accounting/mod.rs:612` and `gateway/state.rs:52`. Replacement: delete them together with the
session code.

**Outside the pattern**: `gateway/meta_mcp/admission.rs`, `gateway/meta_mcp/admission_plan.rs`
(rows 16, 20, 21, 22); `gateway/router/backend_handlers/notification_key.rs`,
`backend/identity_slots.rs` (row 25); `gateway/subscription_registry.rs` (row 2);
`gateway/streaming_ownership.rs` (rows 1 and 26); `gateway/meta_mcp/task_replay.rs` (row 28);
`gateway/meta_mcp/surfaced.rs` (row 20); `gateway/router/hardened_elicitation.rs` (row 1).
`gateway/auth_dashboard.rs:27`, `gateway/auth.rs` (`SessionCheck`), `gateway/auth_handoff.rs`,
`gateway/router/hardened_identity.rs` and `gateway/ui/session.rs` are web-UI cookie sessions, not
MCP sessions, so they are out of scope.

**Stdio**: a stdio connection is one local operator, so it is not session-keyed in the sense of
this document. It passes the fixed id `stdio-session` (`gateway/server/mod.rs:86-87,2424`), which
leaves at most one entry per process in the keyed stores of rows 13 to 22. Its durable tasks
(`gateway/server/stdio_tasks.rs`) are owned by the local-operator principal, and its retained
results are keyed by the transport's own mark, not by a session
(`gateway/meta_mcp/mod.rs:134-138,272-278`, #2494). Row 28 includes the stdio caller of the same check.

**Plumbing only** (the id is carried, logged or fingerprinted, and no state is keyed on it): `commands/doctor/health.rs`,
`commands/upgrade_notice_items.rs`, `gateway/meta_mcp_tool_defs.rs`, `gateway/meta_mcp/grant_audit.rs`,
`gateway/meta_mcp/invoke/r2_check.rs`, `gateway/meta_mcp/response_security.rs`, `gateway/mod.rs`,
`gateway/router/helpers.rs:32-51` (omits the header when empty),
`gateway/router/handlers/tasks.rs` (task owner is the credential, `:44`),
`gateway/router/meta_refusal_audit.rs`, `gateway/server/stdio_channel.rs`,
`gateway/server/stdio_tasks.rs` (carries the id into the task caller), `gateway/session_id.rs`,
`gateway/task_service/execution/{context,worker,input_round}.rs`,
`security/firewall/{anomaly_gate,audit,budget_guard}.rs`, `security/response_policy.rs`,
`security/transparency_log{,_verify,_attributed}.rs`, `transport/{mod,websocket}.rs`,
`backend/ops.rs` (row 25 pass-through), `security/firewall/mod.rs` (logging; `on_session_end` via
row 12), `gateway/ui/mod.rs:720-724` and `gateway/ui/index.html` (the admin cost view reads row 13).
Test-only: `gateway/meta_mcp/test_callers.rs`, `gateway/meta_mcp/direct_route.rs:163`,
`gateway/meta_mcp/account_resolver_gateway.rs:333` (inferred),
`gateway/router/direct_guards_fixture.rs`, `gateway/router/response_pass.rs:97`.

## RFC-0060 U7 categories

| Category | Session-keyed? | Where / replacement |
|---|---|---|
| Authentication | no | Per request. The legacy session is keyed on its authenticated owner (`gateway/router/handlers/owner.rs:25-36,85-97`). |
| Subscriptions | legacy only | Rows 2, 4. `resources/subscribe` is refused in both eras (`gateway/router/handlers.rs:1667-1671` legacy; `protocol/meta.rs:291-299` modern). |
| Progress | no | A request-scoped sink (`transport/notification_sink.rs`). |
| Cancellation | no | `tasks/cancel` is keyed on the task owner. Outbound cancel uses the identity bucket (`backend/ops.rs:508-523`). Inbound `notifications/cancelled` is dropped in both eras (`gateway/router/handlers.rs:832-834`): a functional gap, not a session one. |
| Backend affinity | caller identity | Row 25. |

## Gaps found by this inventory

These are recorded here, not fixed here. Each is routed through the 4.0 lane rules.

- **G1** (confirmed by a red test, fixed by #2464, 143d332c3). A modern `tools/call` without a `_meta` traceparent was
  logged under `session_id: ""` with `correlation_source: session_id`
  (`gateway/router/handlers.rs:1606-1612`, `gateway/meta_mcp/invoke.rs:1210-1220`,
  `gateway/meta_mcp/invoke/audit.rs:346`). The fix is at `gateway/meta_mcp/invoke/audit.rs:338-340`.
  - This contradicts MIK-7215.CONTROL.3a, whose evidence covers only the task path.
  - Falsifier: send that request through the real router and read the log entry.
- **G2** (fixed by #2563, 8703bc7be). At the survey only `firewall-anomaly` registered with lifecycle cleanup (`gateway/session_lifecycle.rs:199`).
  Six session-keyed stores had no production cleanup (the sixth, cached tokens, was deleted by #2591). Their `remove_session` and
  `clear_session_promoted` helpers are called only from tests. Each distinct legacy session id
  that reaches the store adds one entry, and the entry is never removed:

  | Store | Where | Entry added when | Growth per legacy session |
  |---|---|---|---|
  | `session_promoted` | `gateway/meta_mcp/mod.rs:543` | a spec-preview tool is promoted | id + `Vec` of promoted tool names |
  | `SessionProfileStore` | `routing_profile/mod.rs:456` | `gateway_set_profile` | id + profile name |
  | `SessionStateStore` | `gateway/state.rs:22` | an FSM state transition | id + state name |
  | cost `per_session` | `cost_accounting/mod.rs:434` | first costed call under a non-empty id | id + `SessionCost`, whose `records` vector gains one entry per call (`:121,154`) |
  | `last_per_session` | `transition.rs:62` | each meta invoke | id + `Mutex<Option<String>>` (last tool key) |

  - Bound: none. The growth is linear in distinct legacy session ids over the process lifetime.
  - The cost row also grows per call within a session. `evict_old_records`
    (`cost_accounting/mod.rs:603-608`) trims only the per-key records and has no production caller.
  - Whether MIK-7215.CONTROL.4 covers these is open. That depends on whether disconnect ever
    reclaimed them before, which was not verified here. They are an unbounded-growth defect either
    way.
  - Fixed: `MetaMcp::forget_session` (`gateway/meta_mcp/session_end.rs:24`) clears every store when
    a session ends, fired by an owned `DELETE /mcp` (`gateway/router/handlers.rs:339`) and by each
    reaper removal (`gateway/streaming.rs:170`); the reaper expires on last activity
    (`gateway/streaming.rs:197`); an ended session's cost folds into the aggregate. A call still
    running at the end holds its session until its last write, and the last hold on an ended
    session runs the end handlers again (MIK-7996, `gateway/session_lifecycle/session_hold.rs`), so
    a late write never outlives its call. The pass 120 s after the end stays as a backstop.
  - Fixed, outside G2 (MIK-8000, 7a7ab58b4): a live session's cost is kept as one row per tool
    with running totals, so it no longer grows per call.
- **G3.** A security finding, routed privately to the release coordinator on 2026-09-30 and tracked
  in #2448, which has since merged (dc9d2e012).
- **G4** (fixed by #2591). Rows 16, 18 and 19 keyed on the shared `""` on the modern path. Rows 13 and 17 no longer do
  (#2448, `cost_accounting/mod.rs:501`, `gateway/meta_mcp/invoke.rs:1967`).
- **G5** (fixed by #2577, 434017e49: the HTTP start is refused, `security/firewall/anomaly_config.rs:70`,
  called from `gateway/server/mod.rs:1289`; UPGRADING-4.0 item 76).
  - Setup (before the fix): modern protocol, the firewall on with `anomaly_detection` on (default
    off, `security/firewall/mod.rs:147`), and no source of a caller key: `auth.enabled`,
    `mtls.enabled` and `agent_auth.enabled` all off and `security.caller_identity.mode` off.
  - Effect (before the fix): every meta-route call had an empty caller key, so the firewall refused all of them. The gateway now refuses to start in exactly that configuration (`refuse_keyless_http_anomaly`); any one caller-key source, or the firewall or anomaly detection off, lets it start. Stdio is not checked.
- **G6.** A security finding, routed privately to the release coordinator on 2026-09-30.
- **G7.** MIK-7215.CONTROL.5 cites the 12-row RFC-0061 table as complete. This inventory replaces
  it as the governing list.
