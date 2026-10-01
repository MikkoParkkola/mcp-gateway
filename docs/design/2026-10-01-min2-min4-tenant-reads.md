# MIN.2 and MIN.4: cross-tenant read verdict at a type-enforced outbound writer

Status: DRAFT until the lead confirms (design option C). Criteria:
MIK-7116.MIN.2 and MIK-7116.MIN.4
(docs/requirements/RELEASE-4.0.0-scope-update.md:132-133). Decision
`mik_7116_min_kill_gate` sets the frame: 4.0.0 ships observe-first, and
blocking by default waits for the MIN.KILL week (MIK-7627). Citations marked
`PR:` refer to `origin/fix/min1-gap3-uninspected:src/security/firewall/tenant_guard.rs`
(PR #2593).

**Why this design.** Rounds 1-6 placed the check at writers, then at route
boundaries, then at stream yields. Each round found one more channel that
bypassed it. This design puts the check in the one place every frame must
pass through, and lets the compiler enforce that.

## 1. Threat model

- **Asset:** content attributed to a tenant through `arg_keys`. This covers
  request arguments and backend output, including output that has been
  transformed, cached or stored.
- **Actor:** an authenticated principal (API key, OAuth or OIDC subject, mTLS
  identity, or the stdio client). It may call any method it is authorised
  for, retry, replay, run playbooks, and hold several sessions.
- **Channels:** every JSON-RPC frame the gateway writes to the principal,
  whether result, error, notification or server-to-client request, on every
  transport. Sampling and elicitation forward backend text (proxy.rs:226-420),
  so they are in scope.
- **Out of scope, with reasons:**
  - `roots/list` (proxy.rs:425): a gateway-originated request carrying no
    backend content.
  - HTTP headers and status codes: the gateway sets these and copies no
    backend payload into them.
  - Timing and size channels: the criterion is about attributed content, not
    inference.
  - Operator logs and metrics: they reach the operator, not the actor.
  - Ids under keys outside `arg_keys`: the operator's configuration defines
    tenant data.
  - Non-MCP HTTP APIs (`/health`, `/api/costs`, accounts, the web UI,
    key-server routes; router/mod.rs:444-470): they serve no backend tool
    content.
  - `src/a2a`: a backend-side client (client.rs, provider.rs), not an inbound
    transport.

## 2. What exists

- **Attribution (MIN.1).**
  - `TenantGuard::scan_response` makes one private walk that returns tenants
    and `uninspected` (PR:181-188). `response_tenants` and
    `response_uninspected` (PR:163-177) each call it.
  - `request_tenants` walks request params (PR:154-158).
  - Attribution is off when `arg_keys` is empty (PR:168-170, :182-184).
- **`PrincipalWindow`** (principal_window.rs) drops the oldest observation at
  4,096 (:109-112) and evicts a whole principal when full (:173-180). Both
  fail open, so it is not reused.
- **Caller key.** `identity::caller_key` (identity.rs:350) is the canonical
  key. HTTP is stateless under 2026-07-28 (handlers.rs:602-606), and a
  `SessionOwner` is credential-specific (session_id.rs:31-35). One principal
  can therefore hold several sessions and credentials, and only `caller_key`
  joins them.
- **stdio already has one writer.** `run_stdout_writer`
  (stdio_writer.rs:17-27) is the only consumer of the frame queue
  (server/mod.rs:2435-2436). Its producers are `send_frame`
  (server/mod.rs:147-152; called at :2510, :2568, :2844),
  `stdio_channel.rs:68` and `:140` (notifications and bridged requests), and
  `stdio_dispatches.rs:48`.
- **HTTP has no single writer.** Every place that builds an MCP body is listed
  in §4.1.
- **Late replacers.**
  - On HTTP, `slot_http` can swap the answer after the handler
    (grant_audit.rs:303-323).
  - On stdio, `slot_rpc` can swap it (grant_audit.rs:285-301, called at
    server/mod.rs:2978), and so can finalization (server/mod.rs:3050).
  - HTTP finalization (handlers.rs:1826-1828;
    response_security.rs:168-276) can refuse through the response firewall,
    a signing failure, or the fail-closed delivery event.

## 3. The rule

- Inside `window_secs`, the frames committed to one `caller_key` may name at
  most one tenant, and the frame being judged counts toward that.
- A frame that is `uninspected` adds a fresh unknown tenant `U`. `U` is
  distinct from everything, including another `U`, so it conflicts in either
  order.
- Not configured (`arg_keys` empty) or mode `off` means no judgement.
- "Sensitive" means attributed to a tenant. `data_classes` are not used,
  because the kernel reports `public` when it finds nothing
  (kernel.rs:437-438).

**Config.** `tenant_guard.cross_tenant_reads: off | observe | block`, a
lowercase serde enum on `TenantGuardConfig` (PR:56-69), default `observe`.
`block` is opt-in (`mik_7116_min_kill_gate`). The unknown-key check
(UPGRADING-4.0.md §29, :778) must accept the new key.

## 4. Design: `OutboundFrame`, built only by `judge_frame`

```rust
// src/security/firewall/outbound.rs
pub(crate) struct OutboundFrame { value: Value, ticket: Option<ReadTicket> } // private fields
pub(crate) enum FrameOrigin<'a> {
    Delivered { request: Option<&'a Value>, hidden: Option<&'a ReadAttribution> },
    Gateway,  // a gateway-built refusal or status frame: scan its own content only
}
pub(crate) fn judge_frame(guard: &TenantGuard, key: Option<&str>,
    value: Value, origin: FrameOrigin<'_>) -> OutboundFrame
impl OutboundFrame { pub(crate) fn into_parts(self) -> (Value, Option<ReadTicket>) }
```

`judge_frame` is the only constructor of `OutboundFrame`. Every MCP body and
SSE event takes an `OutboundFrame`, so a path that does not judge does not
compile. `judge_frame` works as follows:

- **Fast path.** When `arg_keys` is empty or the mode is `off`, it returns
  `OutboundFrame { value, ticket: None }`. That is a move: no allocation, no
  lock, no walk.
- **Otherwise:**
  1. One scan of the whole frame (`result`, `error.message`, `error.data`,
     `params`) through a new `frame_attribution`. It wraps the private
     `scan_response` (PR:181-188), so no existing symbol is widened.
  2. For `Delivered`, union in the request's params tenants (PR:154-158) and
     the hidden attribution (§4.4).
  3. `assess_read_at` (§4.5). `Blocked` replaces the frame with the delivery
     refusal, built as `Gateway`. The reserved ticket travels inside the
     frame.
  4. For `Gateway`, request-derived and hidden attribution are excluded, so a
     refusal never charges the caller for what it withheld (round 6, MEDIUM).

**Commit rule.** The ticket commits when the frame is consumed by its byte
sink. That means the axum body, an SSE event, or `write_response` returning
`true` (stdio_writer.rs:22). A late replacer can only swap in another
`OutboundFrame`, built through `judge_frame`, and that drops the original
ticket uncommitted. Commit therefore always follows the last thing that can
replace a frame.

### 4.1 Inventory of HTTP delivery paths

Every place that builds an MCP JSON-RPC body today, and how it routes:

| # | Today (file:line) | Frames | Routed through the writer by |
|---|---|---|---|
| H1 | `build_session_response` (helpers.rs:18-29), used by `build_json_response` :57, `build_response` :66, `build_error_response` :75, `build_error_response_with_data` :95 | POST `/mcp` answers and gateway errors | The helpers take `OutboundFrame`; `Json(...)` moves into `outbound.rs` |
| H2 | handlers.rs:1876 `(status, axum::Json(response))` and :1878 | the final POST answer | `meta_mcp_dispatch` (handlers.rs:476) returns `OutboundHttp { frame, status, session }`; judged at handlers.rs:1826, before finalize |
| H3 | `slot_http` replacement (grant_audit.rs:303-323) | grant-audit failure answer | Takes and returns `OutboundHttp`. The replacement is `judge_frame(.., Gateway)` and drops the original ticket. Re-parsing the body (:309-313) goes away, because the id is on the typed frame |
| H4 | `meta_mcp_handler` (handlers.rs:443-472), buffered arm :466-470 | POST answer without SSE | The single entry; converts `OutboundHttp` to the body. The JSON body commits here |
| H5 | `first_event_wins_stream` (streaming.rs:812-874): `message_frame` :762, `terminal_frame` :783, yields at :838, :845, :854, :857 | POST-SSE notifications and the terminal answer | The notification channel carries `OutboundFrame` (judged where the notification is made, §4.3); the terminal frame is `OutboundHttp`; each yield consumes one and commits |
| H6 | `request_scoped_event_stream` (streaming.rs:711-759), notification loop :736, result bytes :729 | dispatch-first fallback: drained notifications, then the result | Takes `Vec<OutboundFrame>` plus `OutboundHttp`, not bytes. This is the round-6 CRITICAL path |
| H7 | `create_sse_response` (streaming.rs:466-529): events at :487, :498, :502, :521; broadcast via `send_to_session`/`broadcast` (:381, :401) from proxy.rs:250-559 and webhooks/mod.rs:605 | GET session stream: notifications and server-to-client requests | `TaggedNotification` (streaming.rs:37) carries data the stream judges at yield with the stream's `caller_key`. The `connected` and `lagged` events are built as `Gateway` |
| H8 | `subscription_stream` (streaming.rs:540-600), ack :556, events :579 | `subscriptions/listen` | Judged at the yield with the `caller_key` captured when it opens (handlers.rs:1089) |
| H9 | Direct route `Answer` (direct_audit.rs:23); `build_http_response` / `build_http_error_response` (helpers.rs:111-128); `audited_call` single return (direct_audit.rs:114-118) | every `/mcp/{name}` answer | `Answer` becomes `OutboundHttp`, judged in `audited_call` for every method. Its notifications are drained and discarded (backend_handlers.rs:425-430) |
| H10 | http_error.rs:12-19 `json_body` / `json_response` | plain HTTP errors | Kept for non-MCP bodies; an MCP use moves to H1 |

The guard is a source test, `mcp_bodies_only_in_outbound`. It fails if
`axum::Json(` or `Event::default()` appears in `src/gateway/router/**` or
`src/gateway/streaming.rs` outside `outbound.rs` and an allowlist of the
non-MCP APIs above. Its limit: it is lexical, so a renamed import evades it.
The structural guard is the type. It is the reviewer's tripwire against
accidental regressions, not an adversarial control.

### 4.2 Keys

Every writer instance holds the canonical `caller_key` (identity.rs:350),
captured once when its stream opens. It is never a `SessionOwner` (round 6,
CRITICAL), and it is never revalidated mid-stream.

| Path | Where the key is captured |
|---|---|
| POST `/mcp` (H1-H6) | `caller_key` computed in `meta_mcp_dispatch` (handlers.rs:1499-1503), hoisted above the method match (handlers.rs:1011), so every method and the early returns have it |
| GET stream (H7) | `mcp_sse_handler` (handlers.rs:200) computes `identity::caller_key` from the same subject, certificate and client before `create_sse_response` (:285), and stores it in the stream. The session's `owner` (streaming.rs:72) stays an ownership check only |
| `subscriptions/listen` (H8) | the `caller_key` in scope at handlers.rs:1089, passed into `subscription_stream` |
| Direct (H9) | `identity::caller_key` over the request's subject, certificate and client (backend_handlers.rs:515) |
| stdio | the constant `stdio`: one process serves one client (stdio_nonce.rs:4-10) |

An empty key is `Unattributable` (refused in block mode). The session-id and
per-backend fallbacks are never used (handlers.rs:1295-1302;
backend_handlers.rs:59-73). Two sessions, or two stateless requests, under
one `caller_key` share one history.

### 4.3 Notifications and server-to-client requests

- **POST-scoped notifications.** These go through
  `notification_sink::publish` (transport/notification_sink.rs:109) into the
  scope opened by `meta_mcp_handler` (`scope` :64, `collect` :86). The scope
  now also carries the guard and `caller_key`, so `publish` builds an
  `OutboundFrame` through `judge_frame(.., Delivered{request: None, hidden:
  None})`. The H5 stream and the H6 fallback consume them, and commit as they
  write. In the buffered arm (handlers.rs:466-470) they are dropped, so their
  tickets drop uncommitted.
- **Session-stream items** (H7). These come from proxy.rs (sampling and
  elicitation, :226-420; list-changed, :482) and webhooks (webhooks/mod.rs:605),
  and are judged at the H7 yield. In block mode a notification is dropped,
  and a request is answered locally with a refusal to its pending waiter
  (proxy.rs:153-201).
- **stdio.** The queue type (server/mod.rs:2435) becomes
  `mpsc::Sender<OutboundFrame>`, so every producer must judge:
  - `send_frame` (:147);
  - stdio_channel.rs:68 and :140;
  - stdio_dispatches.rs:48.

  The writer commits after `write_response` returns `true`
  (stdio_writer.rs:22-26).

### 4.4 Hidden attribution (what the frame does not show)

A delivered response frame's `FrameOrigin::Delivered.hidden` comes from a
non-wire field, `JsonRpcResponse.read: Option<ReadAttribution>`. It sits
beside `discovery_inspected` and `chain_source` (messages.rs:78-81). A
gateway-built response starts as `None`. The field is filled from four
sources:

- **Inner dispatches.**
  - Each dispatch's request tenants, raw pre-gate response tenants (noted at
    audit.rs:93) and `uninspected` flag are collected in a request-scoped
    task-local, shaped like `DispatchNotes` (audit.rs:75-78, :147-156).
  - A dispatch contributes only if its own outcome was delivered into the
    caller's result (`Ok` after its gates). A refused step under
    `ErrorStrategy::Continue` adds nothing (round 6, MEDIUM).
  - The collection happens before `audit_invocation`'s no-logger return
    (audit.rs:338).
  - Playbook steps call `invoke_tool` on the request's own task
    (support.rs:391-398).
- **Caches.** Each of these keeps the pre-transform `read` beside its value:
  - the response cache: set at invoke.rs:2543, hit at :1903;
  - `StoredDelivery` (admission.rs:100-108);
  - the inner idempotency store: idempotency.rs:729, hit at invoke.rs:1787;
  - the direct idempotency store: hit at backend_handlers.rs:1118.

  A hit restores the stored `read`. An entry without one restores `U`.
- **Stored task results.** The task row stores `read_tenants` and
  `read_uninspected` in the same write as the payload. A version bump goes
  next to `TARGET_VERSION` (record.rs:35-38; precedent
  store_targets.rs:118-196). Settlement stops passing the empty set it
  passes today (audit.rs:475). A row without the fields restores `U`.
- **Request params.** These are always passed as `Delivered.request` by the
  frame's builder, on stdio too, including `prompts/get` paths that bypass
  `invoke_tool`. This takes the round-6 improvement.

### 4.5 History (`ReadHistory`)

`TenantGuard` gains `reads: ReadHistory`. It is the only lock on the path: a
`DashMap` shard lock, and only when a frame carries a tenant or `U`. For each
principal it keeps:
- `committed: HashMap<TenantHash, Instant>`, which leaves by expiry only;
- `pending: HashMap<TenantHash, u32>`, a reference count per open ticket;
- `pending_overflow: u32`;
- `overflow_until: Option<Instant>`.

A ticket owns the hashes it incremented. Commit decrements its counts and
upserts `committed`. Drop decrements only its own counts. The bound is 256
distinct hashes per principal, counting committed and pending together. Past
it, only `pending_overflow` grows: block mode refuses, and observe mode
flags. The principal map is capped at 100,000. Expired entries are swept
first; if the map is still full, a new principal is `Unattributable`. Live
history is never evicted.

The judge (`assess_read_at`) checks in this order:
1. Off or unconfigured: no verdict.
2. Empty and complete: no verdict.
3. No key: `Unattributable`.
4. Under the entry lock, `distinct` over committed, pending, overflow, the
   frame's tenants and a fresh `U`. `distinct > 1` gives `Flagged` or
   `Blocked`.
5. Unless `Blocked`, reserve the frame's entries under a ticket.

Ids are hashed once with `hash_argument` (data_flow.rs:139).

### 4.6 Ordering against late replacers

| Route | Replacers, in order | Where `judge_frame` runs | Commit |
|---|---|---|---|
| HTTP POST | finalization (handlers.rs:1826-1828), then `slot_http` (grant_audit.rs:303-323) | handlers.rs:1826, before finalization | H4/H5/H6 body consumption, after both |
| stdio | `slot_rpc` (grant_audit.rs:285-301, server/mod.rs:2978), then finalization (server/mod.rs:3050) | before finalization; finalization takes and returns `OutboundFrame` | writer, after `write_response` (stdio_writer.rs:22) |
| Direct | `record`'s fail-closed write (direct_audit.rs:194-203) | `audited_call`, before `record` | `audited_call`'s single return (:116-118), on every `record` path |

Finalization and the grant slots take an `OutboundFrame` and can replace it
only with another one built by `judge_frame(.., Gateway)`. Doing so drops the
original ticket. The stdio `response_delivery_attempt` event therefore
records the verdict, and it hashes the frame actually sent, including a
replacement refusal (round 6, HIGH).

### 4.7 Records

Each judged frame that has tenants, `U` or a verdict writes one event:
- a response on meta or stdio: the existing `response_delivery_attempt`
  (response_security.rs:263, :284-330);
- any other frame on any route: a `tenant_read` event through `append_event`
  (response_security.rs:325-326);
- the direct route: one `tenant_read` event in `audited_call`'s common path
  for every method, independent of `DirectCall::of`, which skips everything
  except `tools/call` (direct_audit.rs:47, :117) (round 6, HIGH).

Each event carries the `caller_key` beside the display name, `tenants`
(hashed), `attribution` (`uninspected` when it applies) and
`cross_tenant_read` (`flagged` | `blocked` | `unattributable`). Events honour
`FailClosed`: a failed write turns the frame into a refusal through
`judge_frame(.., Gateway)`, which drops the ticket. Tenant ids are compared
across all backends and keys (§6).

### 4.8 Performance (NFR.WORKLOAD.1 already shows an 8% p50 regression)

- **No new task, channel or `Mutex`.** The writer is a type and a function
  call at each existing sink. stdio keeps its existing queue
  (server/mod.rs:2435); HTTP adds nothing per session.
- **Fast path.** When `arg_keys` is empty or the mode is `off`,
  `judge_frame` is one branch plus a move: zero allocations and zero locks
  per frame. That is the default deployment.
- **Configured path.**
  - One walk per frame through `frame_attribution`, replacing the second walk
    `response_tenants` and `response_uninspected` would make.
  - A walk allocates only for parsed JSON-in-text and for found ids.
  - The only lock is one `DashMap` shard lock, taken only when the frame
    carries a tenant or `U`.
- **H3 gets cheaper.** It drops a full body re-parse
  (grant_audit.rs:309-313).

The test plan (§6) measures all of this:
- a counting global allocator and a lock counter assert zero allocations and
  zero lock acquisitions per frame on the fast path;
- a `criterion` bench row runs `judge_frame` on and off;
- the NFR.WORKLOAD.1 k6 run (tests/load/k6_gateway.js) is repeated at the
  tip, with the default config, before merge.

### 4.9 Increment split

The task-row fields (§4.4) can ship later without a bypass, because their
absence restores `U`. The type, the inventory routing, the keys, the history
and the records ship together.

## 5. MIN.4: fixture corpus and false-positive measurement

**Corpus.** `tests/fixtures/tenant-reads-corpus.jsonl` holds one line per
outbound frame: `session`, `caller_key`, `t_secs`, `pattern`, the incoming
request params (for answers), and the full outbound frame (result, error,
notification or server-to-client request). The test runs each line through
`judge_frame`, the writer's own check, so a regression in extraction moves
the measurement. Labels come from the generating pattern, never from the
guard. A header line gives each pattern's session count.

Patterns, with their label:
- **Legitimate:** `single_tenant`, `retry_same_tenant`, `mixed_workload`,
  `opaque_only`, `support_handoff_slow`, `window_boundary`.
- **Legitimate, known false positives:** `support_handoff_fast`,
  `admin_sweep`, `large_single_tenant`.
- **Cross-tenant:**
  - `a_then_b`;
  - `a_then_b_request_only`;
  - `a_then_opaque` / `opaque_then_b`;
  - `a_result_then_b_notification`;
  - `a_then_b_error_data`;
  - `two_sessions_one_key`.

**Measurement.** `src/security/firewall/tenant_read_corpus_tests.rs` is an
ordinary unit test with no network, built from `TenantGuardConfig { arg_keys,
..Default::default() }`. It counts per principal-session (the MIN.KILL unit)
and asserts three gates:
1. Zero flags on the legitimate patterns.
2. Every cross-tenant session is flagged.
3. Exact pinned counts and FP rate, following
   tests/provenance_eval_binary.rs:26-32.

There is no FP-rate ceiling. The known-FP patterns are flagged by
construction, the deployment number comes from the MIN.KILL week, and the
remedy is MIN.3 (MIK-7627).

## 6. Tests (red first)

Every row is written and seen failing before its code exists, and goes red
under its mutant. Row 1 opens the plan.

| # | Test | Asserts | Mutant |
|---|---|---|---|
| 1 | `dispatch_first_post_b_notification_after_a_result` | POST with `Accept: text/event-stream` and dispatch finishing first (H6): an A result, then a B notification drained into the fallback body. Observe: B frame flagged, event written. Block: B notification absent from the body | fallback serializes raw notifications (streaming.rs:736) |
| 2 | `concurrent_stateless_and_two_sessions_one_key` | Concurrent stateless POSTs plus two GET sessions under one `caller_key`, reading A and B: exactly the B side flagged. Counting allocator and lock counter: fast path 0/0; configured path one shard lock per tenant frame | key taken from `SessionOwner` or session id; a per-frame allocation or lock on the fast path |
| 3 | `a_then_b_two_events` (POST JSON, POST-SSE, GET stream, listen, stdio, direct) | A event with `tenants=[h(A)]` and no verdict; B event with `cross_tenant_read=flagged` | a sink built without `judge_frame` |
| 4 | `a_then_b_block_refuses` (each transport) | B replaced by the refusal (response) or dropped (notification); event `blocked` | verdict computed but not applied |
| 5 | `request_only_tenant_any_method` | `prompts/get` with `customer_id: B` in args and an unkeyed result, after A: flagged (HTTP and stdio) | request params not passed to `Delivered` |
| 6 | `error_data_is_a_read` | backend error whose `error.data` names B, after A: flagged and committed | only `result` scanned |
| 7 | `gateway_refusal_charges_nothing` | refused B request, then A: not flagged | refusal built as `Delivered` |
| 8 | `grant_slot_replacement_commits_nothing` | `slot_http`/`slot_rpc` failure on a B answer, then A: not flagged | ticket committed before the slot |
| 9 | `finalization_replacement_commits_nothing` | firewall, signing or fail-closed event refusal on B (HTTP, stdio), then A: not flagged; the stdio event hashes the refusal sent | commit at judge time; stdio event before judge |
| 10 | `sampling_request_is_judged` | elicitation/sampling text naming B on the GET stream after A: flagged; block answers the waiter with a refusal | session-stream items unjudged |
| 11 | `listen_keyed_on_caller_key` | `subscriptions/listen` event naming B after a POST read of A under the same key: flagged | listen keyed on its listener |
| 12 | `direct_every_method_event` | `completion/complete` naming B on `/mcp/{name}` after A: flagged, `tenant_read` written | event tied to `DirectCall` |
| 13 | `playbook_continue_refused_step` | a refused B step under `ErrorStrategy::Continue`, then A: not flagged; a delivered B step: flagged | collecting refused steps |
| 14 | `cache_hit_restores_pre_transform` | B cached after a key-stripping transform, hit after A: flagged; an entry without `read` gives `U` | cache without `read` |
| 15 | `task_request_only_tenant` / legacy row | a B-only-in-request task read after A: flagged; a row without fields gives `U` | empty set at settlement |
| 16 | `uninspected_both_orders` | A then opaque, and opaque then B: flagged; a lone opaque frame: none | `U` not distinct |
| 17 | `history_bounds_and_ownership` | 10,000 tenants: hashes stay at 256 or fewer; overlapping tickets; a drop keeps a committed A | eviction; a drop clearing others |
| 18 | `hidden_attribution_without_logger` | no transparency log: a playbook step naming B after A is flagged | collection after audit.rs:338 |
| 19 | `mcp_bodies_only_in_outbound` | no `axum::Json(`/`Event::default()` outside `outbound.rs` and the non-MCP allowlist | a new direct body builder |
| 20 | `unconfigured_is_noop` / `config_mode` | `arg_keys` empty: no fields, no refusal; `observe` default; bool rejected | judge before the attribution check |
| 21 | `tenant_read_corpus_fp_measurement` | §5 gates 1-3 | window, threshold or default changed |
| 22 | bench `judge_frame_fast_path` plus the NFR.WORKLOAD.1 k6 run | no regression beyond the NFR.WORKLOAD.1 budget at the default config | per-frame work on the fast path |

Rows 1 and 2 are the gate for the design: they must be red on the release tip
before any implementation lands.

## 7. UPGRADING-4.0.md

Add one row next to row 110 (UPGRADING-4.0.md:137); its number is assigned at
merge. Proposed text:

> With `tenant_guard.arg_keys` set, every frame the gateway sends a caller
> (results, errors, notifications and server requests, on every transport) is
> checked. A caller whose frames name more than one tenant inside
> `window_secs` is marked `cross_tenant_read: flagged`, or `unattributable`
> without an identity. An unreadable response counts as an unknown tenant.
> The new key `tenant_guard.cross_tenant_reads` takes `off|observe|block` and
> defaults to `observe`. Ids are compared across backends, so namespace any
> that backends reuse. No action is needed; set `off` to silence it.

## 8. Decisions

1. Security findings are fixed in 4.0, and the guard fails closed (lead,
   2026-10-01).
2. The task-row fields are accepted. The 256 cap is a constant.
   `large_single_tenant` is a measured, deliberate false positive.
3. **Option C** (merge lane, confirmed by both cross-checks): a type-enforced
   last hop. `judge_frame` is the only constructor of an outbound MCP JSON
   body or SSE event. It is keyed on `caller_key`, with no session channel.
4. **No automatic fallback to option B.** MIN.2 stays an open release gate.
   If the design is not reviewed and red tests are not in by 2026-10-04 12:00,
   the lane reports B to the lead with a written reason, as a proposal for the
   operator. A lane checkpoint does not narrow a security criterion.
5. The threshold is fixed at 1.

**Open for the lead:**
- (a) Should the `tenant_read` event stay a new event name, or extend
  `response_delivery_attempt` to non-response frames?
- (b) Test 19 is lexical. Accept it as a tripwire behind the type, or
  require a dedicated `clippy` `disallowed_methods` rule instead?
- (c) Confirm that no middleware layered after the handlers rewrites MCP
  bodies (router/mod.rs:360 auth layer); verify at implementation.

## 9. Superseded

Rounds 1-6 reviewed earlier placements of the check (writers, route
boundaries, stream yields). Their findings are closed by construction here:
every frame is an `OutboundFrame`. The history is in git, up to commit
9f55c2e2e.

**Draft decisions (merge lane):** `tenant_read` stays a separate event, so `response_delivery_attempt` keeps its response-only meaning. The tripwire behind the type is a clippy `disallowed_methods` rule (constructing an MCP body or SSE event outside the outbound module), not a text scan. No middleware after the handlers rewrites MCP bodies: auth, agent-auth and the OpenWebUI adapter do not map response bodies, `CompressionLayer` preserves content, and `CatchPanicLayer` answers a panic with a gateway-built 500 that carries no backend content (src/gateway/router/mod.rs:350-360, :501-502).
