# Session-keyed behaviour inventory (RFC-0060 U7)

**Criterion**: MIK-7211.PARENT.7. Every session-keyed behaviour in the gateway has a named
stateless replacement in one inventory before any session code is removed.

**Supersedes**: the 12-row table in RFC-0061 §"U7 RESOLVED" (`:271-293`, 2026-08-29). That table
covers about 12 of the 27 behaviours below.

**Surveyed**: release tip `1b4e46b93`, 2026-09-30, read-only. The survey read every non-test file
matched by `rg -l -i 'session_id|Mcp-Session-Id|SessionId' src`: 57 of the 100 matching files, the
rest being tests. It also covered the files that pattern misses because they name the variable
`session` or `sid` (see "Outside the pattern").

## How to read it

- **Path** says where the behaviour runs:
  - *legacy*: 2025-11-25 and earlier, which mint a session.
  - *modern*: 2026-07-28, which is sessionless.
  - *both*.
- **Replacement** names the stateless mechanism. **Built** says whether that mechanism exists in
  code today (file:line). The criterion requires the name. Building it is tracked separately, and
  a row whose replacement is not built says so.
- On the modern HTTP path the router carries the session id as an empty string, not as no value
  (`src/gateway/router/handlers.rs:626-631`, passed on as `Some("")`). Only two sites turn that
  into "no session": `session_key` (`src/gateway/meta_mcp/mod.rs:1576-1577`) and task intent
  (`src/gateway/router/handlers/tasks.rs:187-188`). Every other `if let Some(sid)` treats `""` as
  one session shared by every modern caller. Rows marked *shared ""* have that defect.
- The replacement key, where it is "the caller key", is `caller_key`
  (`src/gateway/router/identity.rs:328`): the resolved identity, else the API key. When neither
  exists the replacement key is *none*, never `""`.

## Inventory

| # | Behaviour | Where | Path | Replacement (named) | Built? | Ledger |
|---|---|---|---|---|---|---|
| 1 | Session mint, resume, ownership | `handlers.rs:633-641`; owner check `streaming.rs:228-242` | legacy | None needed: modern mints nothing | yes, `handlers.rs:626-631` | STATELESS.3a/3b |
| 2 | GET /mcp stream, backend auto-subscribe, `send_to_session` | `handlers.rs:268-307`; `streaming.rs:370-375,411-445` | legacy | `subscriptions/listen`, keyed on the held credential plus request id | yes, `subscription_registry.rs:199-208` | STATELESS.7 |
| 3 | DELETE /mcp termination | `handlers.rs:330-350` | legacy | None needed: no session to end | n/a | none |
| 4 | Stream-session TTL reaper | `streaming.rs:148-200` | legacy | TTL reap of identity deadlines, same tick | yes, `streaming.rs:~165` | CONTROL.4 |
| 5 | Pending server-to-client requests (sampling, elicitation, roots) and POST-back resolution | `proxy.rs:106,176-184,228-267,295-332,427-458,534-562` | legacy | MRTR `InputRequired` with a continuation bound to the principal fingerprint | yes, `protocol/continuation.rs:98,339-356` | MIK-7212 |
| 6 | Client-sent `sampling/createMessage`, `elicitation/create` routed to "the session that asked" | `handlers.rs:1811-1845` | legacy | Refusal by design (`-32021`); server-initiated asks move to row 5 | yes | STATELESS.10a-c |
| 7 | Legacy input bridge | `meta_mcp/invoke.rs:2304-2330`; `input_bridge.rs:380,679-690` | legacy | Continuation mint in the same function | yes | MIK-7212 |
| 8 | Destructive-operation confirmation | `destructive_confirmation.rs:276-283`; `meta_mcp/confirmation.rs:207-213` | legacy | In-band continuation | yes, `handlers.rs:1639`, `confirmation.rs:244` | MIK-7212 |
| 9 | Anomaly scoring | `security/firewall/mod.rs:405-441` | both | Caller key; refuse when absent (`Unobservable`) | yes, `identity.rs:328`, `anomaly.rs:65-80` | CONTROL.1a/1b |
| 10 | Firewall call budget | `firewall/mod.rs` `check_budget` | both | Principal-keyed window | yes, `firewall/budget_guard.rs` | CONTROL.2 |
| 11 | Transparency-log correlation key | `meta_mcp/invoke/audit.rs:101-114` | both | OTel trace id from `_meta`, else a minted id; never an empty session | partly: see gap G1 | CONTROL.3a/3b |
| 12 | Disconnect cleanup | `session_lifecycle.rs:85,194-203` | both | TTL expiry per registered store | partly: one store registered, see G2 | CONTROL.4 |
| 13 | Cost accounting per session | `cost_accounting/mod.rs:434,482-499`; `dispatch_guards.rs:164-173` | both, shared "" | Caller key; no record when absent | no | none |
| 14 | `gateway_cost_report` target | `invoke.rs:3736-3778` | both | Report on the caller key only | in #2448 (open) | none |
| 15 | REST cost endpoint `X-Cost-Session-Id` | `backend_handlers.rs:1395-1421` | admin REST | `?key=` (existing) | yes | none |
| 16 | Projection A/B arm, and the arm suffix in cache and idempotency keys | `projection/mode.rs:81-121`; `invoke.rs:1702,3588,3607`; `admission.rs:366-372` | both, shared "" | Hash of the caller key; a caller with no key gets the control arm, never a sticky one | no | none |
| 17 | Prompt-cache key derivation | `invoke.rs:2083-2092` | both, shared "" | Explicit `_meta.prompt_cache_key`, else the caller key; drop the session part | partly: override exists | none |
| 18 | Meta transition tracker (predict, prefetch) | `invoke.rs:2735-2746`; `transition.rs:62,88-95` | both, shared "" | Merge into the firewall's caller-keyed tracker: one store | no; the firewall tracker exists (`server/mod.rs:497-506`) | none |
| 19 | Cached-token stats | `invoke.rs:3432`; `stats.rs:30,65-76` | both, shared "" | Delete: no production reader (`stats.rs:98` is test-only) | no | none |
| 20 | Routing profile (visibility and invoke gate) | `meta_mcp/mod.rs:403,1550-1561`; `routing_profile/mod.rs:456-490`; `visibility.rs:52-60,136-142` | legacy | Per-request `X-MCP-Profile` selection (RFC-0061 correction table); until then modern gets the registry default or a refusal | no; refusal built (`mod.rs:1584`) | none |
| 21 | `gateway_set_profile`, `gateway_get_profile` | `mod.rs:2508-2545` | legacy | Same as row 20 | refusal built | none |
| 22 | FSM workflow state and search visibility | `gateway/state.rs:22-55`; `mod.rs:2446-2490`; `search.rs:105-110` | legacy | Refusal on modern (ratified reading) | yes, `mod.rs:1595` | MIK-7272.ORDER.2 |
| 23 | Spec-preview promoted tools | `mod.rs:506,1509-1532`; `spec_preview.rs:311-335` | legacy | Refusal on modern, as row 22 | skipped silently today: needs the same refusal | MIK-7272.ORDER.2 |
| 24 | Negotiated-revision binding (cache revision bucket, telemetry) | `protocol_revision_telemetry.rs:401-438,583-605` | legacy | Revision echoed per request | yes, `handlers.rs` `cache_protocol_revision` | NFR.OBS.1 |
| 25 | Upstream `MCP-Session-Id` buckets (backend affinity) | `transport/http/mod.rs:314,1112-1120,1467-1486`; `backend/ops.rs:191,508-523` | legacy upstream | Keyed on caller identity already; header stripped for modern peers | yes, `http/mod.rs:412,1241` | STATELESS.3a |
| 26 | Direct-route profile and cost key | `backend_handlers.rs:665-673,994` | both | Caller key, as row 27; never the raw unverified header | no; gap G6 | none |
| 27 | Direct-route firewall identity | `backend_handlers.rs:58-72,136`; `direct_guards.rs:119` | both | Caller key, else `direct:{backend}` | yes | CONTROL.1a/2 |

**Dormant** (session-keyed, no production caller): `simhash.rs:379-439`, `prompt_cache.rs:110`,
`mod.rs:1536`, and `remove_session` in `cost_accounting/mod.rs:593` and `state.rs`. Replacement:
delete them together with the session code.

**Outside the pattern**: `meta_mcp/admission.rs`, `admission_plan.rs` (rows 16, 20, 22);
`backend_handlers/notification_key.rs`, `backend/identity_slots.rs` (row 25);
`subscription_registry.rs` (row 2). `auth_dashboard.rs:27` and `ui/session.rs` are web-UI cookie
sessions, not MCP sessions, so they are out of scope.

**Plumbing only** (the id is carried, logged or fingerprinted, and no state is keyed on it): `commands/doctor/health.rs`,
`commands/upgrade_notice_items.rs`, `meta_mcp_tool_defs.rs`, `meta_mcp/grant_audit.rs`,
`meta_mcp/invoke/r2_check.rs`, `meta_mcp/response_security.rs`, `gateway/mod.rs`,
`router/helpers.rs:32-51` (omits the header when empty), `router/handlers/tasks.rs` (task owner is
the credential, `:52`), `server/stdio_channel.rs`, `gateway/session_id.rs`,
`task_service/execution/{context,worker}.rs`, `firewall/{anomaly_gate,audit,budget_guard}.rs`,
`security/response_policy.rs`, `security/transparency_log{,_verify}.rs`, `transport/{mod,websocket}.rs`,
`backend/ops.rs` (row 25 pass-through), `security/firewall/mod.rs` (logging; `on_session_end` via
row 12). Test-only: `meta_mcp/test_callers.rs`, `meta_mcp/direct_route.rs:163`,
`meta_mcp/account_resolver_gateway.rs:333` (inferred), `router/direct_guards_fixture.rs`,
`router/response_pass.rs:97`.

## RFC-0060 U7 categories

| Category | Session-keyed? | Where / replacement |
|---|---|---|
| Authentication | no | Per request. The legacy session is keyed on its authenticated owner (`handlers.rs:55-66`). |
| Subscriptions | legacy only | Rows 2, 4. `resources/subscribe` is refused in both eras (`handlers.rs:1781`). |
| Progress | no | A request-scoped sink (`transport/notification_sink.rs`). |
| Cancellation | no | `tasks/cancel` is keyed on the task owner. Outbound cancel uses the identity bucket (`backend/ops.rs:508-523`). Inbound `notifications/cancelled` is dropped in both eras (`handlers.rs:958-960`): a functional gap, not a session one. |
| Backend affinity | caller identity | Row 25. |

## Gaps found by this inventory

These are recorded here, not fixed here. Each is routed through the 4.0 lane rules.

- **G1** (a red test is in #2464; the CI result decides it). A modern `tools/call` without a `_meta` traceparent may be
  logged under `session_id: ""` with `correlation_source: session_id`
  (`handlers.rs:1724`, `invoke.rs:1345-1352`, `audit.rs:106`).
  - This contradicts MIK-7215.CONTROL.3a, whose evidence covers only the task path.
  - Falsifier: send that request through the real router and read the log entry.
- **G2.** Only `firewall-anomaly` registers with lifecycle cleanup (`session_lifecycle.rs:199`).
  Six session-keyed stores have no production cleanup. Their `remove_session` and
  `clear_session_promoted` helpers are called only from tests. Each distinct legacy session id
  that reaches the store adds one entry, and the entry is never removed:

  | Store | Where | Entry added when | Growth per legacy session |
  |---|---|---|---|
  | `session_promoted` | `meta_mcp/mod.rs:506` | a spec-preview tool is promoted | id + `Vec` of promoted tool names |
  | `SessionProfileStore` | `routing_profile/mod.rs:456` | `gateway_set_profile` | id + profile name |
  | `SessionStateStore` | `gateway/state.rs:22` | an FSM state transition | id + state name |
  | cost `per_session` | `cost_accounting/mod.rs:434` | first costed call | id + `SessionCost`; its records are trimmed to 30 days (`:342-346`), but the entry stays |
  | `last_per_session` | `transition.rs:62` | each meta invoke | id + `Mutex<Option<String>>` (last tool key) |
  | `cached_tokens_by_session` | `stats.rs:30` | a cached-token record | id + `AtomicU64` |

  - Bound: none. The growth is linear in distinct legacy session ids over the process lifetime.
  - Whether MIK-7215.CONTROL.4 covers these is open. That depends on whether disconnect ever
    reclaimed them before, which was not verified here. They are an unbounded-growth defect either
    way.
- **G3.** A security finding, routed privately to the release coordinator on 2026-09-30 and tracked
  in #2448.
- **G4.** Rows 13, 16, 17, 18 and 19 key on the shared `""` on the modern path.
- **G5** (conditional, inferred).
  - Setup: modern protocol, auth off, `anomaly_detection` on (default off,
    `firewall/mod.rs:143`).
  - Effect: every meta-route call has an empty caller key, so the firewall refuses all of them.
- **G6.** The direct route keys its profile and cost on the raw inbound `mcp-session-id` header,
  with no ownership check (row 26).
- **G7.** MIK-7215.CONTROL.5 cites the 12-row RFC-0061 table as complete. This inventory replaces
  it as the governing list.
