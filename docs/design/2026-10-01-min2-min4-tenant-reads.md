# MIN.2 and MIN.4: cross-tenant read verdict and its false-positive corpus

Status: draft for review. Criteria: MIK-7116.MIN.2 and MIK-7116.MIN.4
(docs/requirements/RELEASE-4.0.0-scope-update.md:132-133). Decision
`mik_7116_min_kill_gate` (RELEASE-4.0.0-scope-status.json) fixes the frame:
4.0.0 ships observe-first, and blocking by default waits for the MIN.KILL week
(MIK-7627). Tenant-guard citations marked `PR:` refer to
`origin/fix/min1-gap3-uninspected:src/security/firewall/tenant_guard.rs`
(PR #2593). This design is written against that version.

## 1. Threat model and what exists

### Threat model

**Asset.** The asset is content attributed to a tenant through `arg_keys`.
That covers request arguments and backend output, including output the
gateway transformed, cached or stored.

**Actor.** The actor is an authenticated principal: an API key, an OAuth or
OIDC subject, an mTLS identity, or the stdio client. It may call any method
it is authorised for and may retry, replay or run playbooks.

**Channels.** Every frame the gateway writes to that principal (§3.2):
- results and errors on HTTP POST, on its SSE arm, on stdio and on the
  direct route;
- notifications on the POST stream, the session stream and
  `subscriptions/listen`;
- server-to-client requests. Sampling and elicitation forward backend text
  (proxy.rs:226-420), so they are in scope.

**Out of scope, with reasons:**
- `roots/list` requests (proxy.rs:425): the gateway asks the client for its
  own roots, and no backend content is involved.
- HTTP headers and status codes: the gateway sets these itself and copies no
  backend payload into them.
- Timing and size side channels: the criterion is about attributed content,
  not inference.
- Operator-facing logs and metrics: they reach the operator, not the actor.
- Tenant ids in fields that are not configured in `arg_keys`: the operator's
  configuration is the definition of what counts as tenant data.
- `src/a2a` is a backend-side client and provider (client.rs, provider.rs),
  not an inbound transport, so it writes no frames to the actor.

### What exists

- **Read attribution (MIN.1).** `TenantGuard::response_tenants` and
  `response_uninspected` scan a result (PR:163-177). The scan fails closed on
  unreadable text (PR:218-238). `noted_response` records the result before any
  response gate runs (audit.rs:93; called at invoke.rs:1351). `noted_classes`
  records the kernel's data classes (audit.rs:113; invoke.rs:2737).
  `DispatchNotes::attribution` combines request tenants, response tenants and
  the `cached_delivery`/`uninspected` marker into the record fields
  (audit.rs:186-236).
- **Record writers that attribute.** The meta writer is `audit_invocation`
  (audit.rs:324, attribution at :348). The #2472 replay writer is
  `audit_replay` (audit.rs:530, cached notes at :579). The direct writer is
  `record` (direct_audit.rs:123, attribution at :147-148). Upstream-task
  settlement is `audit_settlement` (audit.rs:455, :475). Request-firewall
  refusals use `meta_refusal_audit.rs:89`, which has no response side. Both
  HTTP writers attribute through `state.meta_mcp`'s firewall
  (direct_audit.rs:147-148), so one `TenantGuard` instance sees both routes.
- **Request guard (TENANT.1).** `TenantGuard::check` records the tenants in the
  request arguments in a `PrincipalWindow` and refuses a caller over
  `max_tenants_per_window` (PR:119-149). The config defaults are disabled, limit
  3 and window 300 s (PR:77-84). A tenant-scoped request with no principal is
  `Unattributable` and is force-blocked (PR:50, mod.rs:538). The key is
  `anomaly_identity` (mod.rs:444, :451). On the meta route that key is
  `caller_key`, falling back to the session id (handlers.rs:1295-1302). On the
  direct route it falls back to a shared per-backend bucket
  (backend_handlers.rs:59-73).
- **`PrincipalWindow`** keeps observations per principal and returns
  `Usage::Counted{distinct}` or `Unkeyed` (principal_window.rs:57-67). It has an
  injectable clock through `record_at` (:101) and caps of 100k principals and
  4,096 observations (:37, :45).
- **The response firewall cannot host the verdict.** `check_response` takes the
  client display name as `caller` (mod.rs:614; direct_guards.rs:140), not the
  authenticated principal. Cached deliveries never reach it: the response cache
  goes through `GuardedValue::from_cache` (guarded.rs:34-37), and idempotent
  replays go through `note_cached` (invoke.rs:1751; backend_handlers.rs:1118,
  :1127). The verdict therefore goes at every outbound frame, where the
  reader, the request and the bytes sent are all known (§3.2).
- **Withholding after attribution.** A gate refusal keeps the response tenants
  on the record (tests `gate_refused_response_keeps_response_tenants`,
  meta_mcp/audit_record_tests/tenants.rs:93; and
  `direct_gate_refusal_keeps_response_tenants`,
  router/direct_audit_tests/tenants.rs:90). The response-firewall refusal error
  is `Error::ResponseFirewallRefused`. On the direct route it is answered as an
  HTTP 200 delivery refusal (direct_guards.rs:91-92, :108-111) and recorded
  through `direct_outcome` (direct_audit.rs:84-99).
- **Corpus precedent.** `tests/fixtures/provenance-corpus.jsonl` with
  `tests/provenance_eval_binary.rs:26-32`, which pins exact counts and the rate
  for a committed fixture. No tenant corpus and no false-positive measurement
  exist (MIN.4 ledger note).

## 2. Definitions

- **A frame** is one JSON-RPC message the gateway writes to a caller on any
  transport: a result, an error, a notification, or a server-to-client
  request (§3.2).
- **A frame's tenants** are the union of three things:
  - the tenants named in the incoming request's `params`, for a frame that
    answers a request (walked with `request_tenants`, PR:154-158);
  - one scan of the whole outgoing frame, covering `result`, `error.message`,
    `error.data` and `params`;
  - the frame's hidden attribution (§3.3).

  A frame is `uninspected` when any part of it, or of its hidden attribution,
  was unread (PR:175-177). The single scan is a new
  `TenantGuard::frame_attribution(&Value) -> ReadAttribution`, which calls the
  existing private `scan_response` (PR:181-188) once and hashes the result.
  The two walks in `response_tenants` / `response_uninspected` are not repeated,
  and no existing symbol is widened.
- **Sensitive** means attributed to at least one tenant. `data_classes` are
  not used: the kernel reports `public` when it finds nothing
  (kernel.rs:437-438), and the field is absent on cached and refused calls.
- **The rule:** inside `window_secs`, a principal's committed frames may name
  at most one tenant, and the frame being judged counts toward that.
  An `uninspected` delivery adds a fresh unknown tenant `U`. `U` is distinct
  from every other entry, including another `U`, so it conflicts in both
  orders. When `arg_keys` is empty, `TenantGuard::attributes` is false
  (PR:168-170) and the judge returns `None`.

## 3. Design

**Config.** Add to `TenantGuardConfig` (PR:56-69) a new key,
`cross_tenant_reads: off | observe | block`. It is a lowercase serde enum
that defaults to `observe`, and it is independent of the request guard's
`enabled`. Without `arg_keys` it does nothing. `block` is opt-in, as decision
`mik_7116_min_kill_gate` requires. The unknown-key check (UPGRADING-4.0.md
§29, :778) must accept the key; verify this at implementation.

### 3.1 History and judge

`TenantGuard` gains `reads: ReadHistory`. `PrincipalWindow` is not reused: it
drops the oldest observation at 4,096 (principal_window.rs:109-112) and evicts
whole principals when full (:173-180). Both fail open. For each principal,
`ReadHistory` holds three structures:

- `committed: HashMap<TenantHash, Instant>`: last delivery time per tenant.
  Entries leave by expiry only.
- `pending: HashMap<TenantHash, u32>`: a reference count per tenant reserved
  by an open ticket. `pending_overflow: u32` counts open overflow
  reservations.
- `overflow_until: Option<Instant>`: while in the future, counts as one extra
  distinct tenant.

Ticket ownership works as follows. A ticket owns a list of the hashes it
incremented and an overflow flag. `commit` decrements each of its counts and
upserts `committed`. A committed overflow raises `overflow_until` to
`now + window`. `Drop` of an uncommitted ticket decrements only its own
counts. Overlapping tickets on the same tenant each hold one count, so neither
can erase the other's reservation or a committed entry.

The bound is 256 distinct hashes per principal, counting committed and
pending entries together. Past that bound, a read stores nothing new in the
map: it only increments `pending_overflow`, a `u32`. In `block` mode such a
read is refused outright. In `observe` mode it is flagged and delivered,
holding an allocation-free overflow ticket.

A principal's stored state is therefore at most 256 hashes plus two counters,
however many requests are open. The request objects themselves are bounded
by the transports' own admission limits (server/mod.rs:2446-2452 on stdio).
The principal map is capped at 100,000: expired principals are swept first,
and if the map is still full, a new principal's read is `Unattributable`.
Live history is never evicted. Every bound fails closed, flagging or
refusing.

```rust
pub(crate) struct ReadAttribution { tenants: BTreeSet<TenantHash>, uninspected: bool }
pub(crate) fn assess_read_at(&self, principal: Option<&str>,
    read: &ReadAttribution, now: Instant) -> (ReadVerdict, Option<ReadTicket>)
// ReadVerdict { None, Flagged { distinct }, Blocked { distinct }, Unattributable }
```

The judge checks, in order:

1. Mode `off`, or attribution unconfigured: `None`.
2. Empty and complete: `None`.
3. No principal: `Unattributable`.
4. Under the principal's entry lock, distinct is counted over live committed
   entries, pending entries, overflow, the read's tenants, and a fresh `U` if
   the read is uninspected. `distinct > 1` gives `Flagged` or `Blocked`.
5. Unless the verdict is `Blocked`, the read reserves its entries under a new
   ticket. A fresh `U` is reserved as its own random hash.

Ids are hashed once, with `hash_argument` (data_flow.rs:139). The same hashes
go to the judge, the records and any stored attribution, so live and stored
ids compare equal.

### 3.2 One judge, at every outbound frame

Every frame the gateway writes to a caller passes `judge_frame(key, frame,
hidden)` immediately before it is written. Commit happens after the write is
handed to the transport. Only stdio has a single writer for every frame. The
other transports are judged at their smallest funnel:

| Transport | Writer / smallest funnel (judge here) | Commit | Frames |
|---|---|---|---|
| stdio | the one stdout writer, `run_stdout_writer` (stdio_writer.rs:17-27), the only consumer of the queue at server/mod.rs:2435-2436 ("everything … queues here", :2426-2430) | `write_response` returned `true` (stdio_writer.rs:22) | responses (via `send_frame`, server/mod.rs:147-152, at :2510, :2568, :2844), notifications, outbound bridged requests |
| HTTP `/mcp`, POST result | the one result producer, just before `finalize_response_after_inspection` (handlers.rs:1826). Its bytes are reused verbatim by the SSE arm (streaming.rs:705-710) | its return (handlers.rs:1827-1828) | result and error frames |
| HTTP `/mcp`, POST request-scoped notifications | the stream arm, `first_event_wins_stream` (streaming.rs:812), at each notification yield. The buffered arm discards them (handlers.rs:466-470), so they are never written and never judged | at yield | progress, logging, any backend notification |
| HTTP `/mcp`, GET session stream | `create_sse_response` (streaming.rs:466), its single `yield Ok(event)` (:514); fed by `send_to_session` / `broadcast` (streaming.rs:381, :401) from proxy.rs and webhooks/mod.rs:605 | at yield | sampling and elicitation requests (proxy.rs:226-420), list-changed, webhook events |
| HTTP `subscriptions/listen` | `subscription_stream` (streaming.rs:540), its event yield | at yield | subscribed notifications |
| Direct `/mcp/{backend}` | the single return of `audited_call` (direct_audit.rs:114-118), on the full answer body: `result` or `error` | that return, on every `record` path (:141-143, :193, :204-207) | results and errors. Backend notifications are drained and discarded (backend_handlers.rs:425-430), so there are none to judge |

SSE gives no write acknowledgement, so the yield is the last point the gateway
controls, and its commit counts as delivered. Errors are judged like results:
a backend error whose `data` names B counts as a read of B. A gateway-built
refusal carries no hidden attribution (§3.3), so a refusal that withholds
content commits nothing it withheld.

**Block.** A frame with a `Blocked` verdict is replaced before it is written:
- a response becomes the delivery refusal (`delivery_refusal_error`; on the
  direct route `refusal(id, &Error::ResponseFirewallRefused)`,
  direct_guards.rs:108-111);
- a notification is dropped;
- a server-to-client request is answered locally with a refusal error to its
  pending waiter (proxy.rs:153-201).

For the HTTP POST result the replacement happens before finalization and
before `complete_delivery` (handlers.rs:1829-1831), so a blocked answer is
stored, and replays, as a refusal.

**Reader key.**
- HTTP POST: `caller_key` (handlers.rs:1529).
- HTTP session and subscription streams: the session's `owner`
  (streaming.rs:72), the same `SessionOwner` that resumption checks
  (:239-243).
- stdio: the constant `stdio`, since one process serves one client
  (stdio_nonce.rs:4-10).
- Direct: `identity::caller_key` (identity.rs:350, fed by
  backend_handlers.rs:515).

Session and per-backend fallbacks are never used (handlers.rs:1295-1302;
backend_handlers.rs:59-73). A principal-less key is `Unattributable`.

### 3.3 Hidden attribution travels with the frame

The wire does not show every tenant a frame reached. That attribution rides
on the frame itself, in a non-wire field. `JsonRpcResponse` gains `read:
Option<ReadAttribution>`, beside the existing non-wire `discovery_inspected`
and `chain_source` (messages.rs:78-81). The stdio queue item becomes `{
value, read }` (server/mod.rs:2435). A response built fresh by the gateway,
which is every refusal, starts with `read: None`, so nothing hidden is judged
or committed for content the gateway withheld. Hidden attribution comes from
five places:

- **Inner dispatches.** Each backend dispatch's attribution is collected in a
  request-scoped task-local, shaped like `DispatchNotes` (audit.rs:75-78,
  :147-156). That attribution is the dispatch's request tenants, its raw
  pre-gate response tenants (noted at audit.rs:93, before any gate or
  transform), and its `uninspected` flag. Playbook and code-mode steps run
  `invoke_tool` (support.rs:391-398) on the request's task, so they are
  collected too. The collected set is moved onto the response's `read` where
  the response is built: handlers.rs:1826 on HTTP, and the dispatch's frame on
  stdio. The collection happens before `audit_invocation`'s no-logger return
  (audit.rs:338), so it works without a transparency log.
- **Response cache.** The entry stored at invoke.rs:2543 keeps the dispatch's
  pre-transform `ReadAttribution` beside the value. A hit (invoke.rs:1903)
  restores it, so a cached B whose transform stripped the keys still counts
  as B. An entry without it restores `uninspected`.
- **Idempotency caches.** The meta store (`StoredDelivery`, admission.rs:100-108,
  written at `complete_delivery`, handlers.rs:1829-1831), the inner idempotency
  result (idempotency.rs:729; hit at invoke.rs:1787) and the direct-route
  result (hit at backend_handlers.rs:1118) each keep `read` the same way. A
  missing field restores `uninspected`.
- **Stored task results.** `tasks/get` and `tasks/result` carry only an id.
  The task row stores `read_tenants` and `read_uninspected` in the same write
  as the payload. They hold the admitted request's tenants plus the dispatch's
  attribution, instead of the empty set at audit.rs:475. The version bump
  goes next to `TARGET_VERSION` (record.rs:35-38; precedent
  store_targets.rs:118-196). A row without the fields restores `uninspected`.
- **Notifications and server-to-client requests** carry no hidden attribution.
  Their content is entirely on the wire, and the frame scan covers it.

### 3.4 Records

A response frame on meta and stdio already writes one
`response_delivery_attempt` event in finalization (response_security.rs:263,
:284-330). Every other judged frame writes one `tenant_read` event through the
same `append_event` (response_security.rs:325-326). Those other frames are
notifications, server-to-client requests, and direct-route answers; the
direct route writes through `record`, direct_audit.rs:123. Either event
carries the reader's caller key beside the display name, and three fields:
`tenants` (hashed), `attribution` (`uninspected` when it applies), and
`cross_tenant_read` (`flagged` | `blocked` | `unattributable`).
An event is written only when attribution is configured and the frame has
tenants, `U`, or a verdict. It honours `FailClosed`: a failed write withholds
the frame, and nothing commits.

"Audit entries for both the read and the verdict" is asserted as two events:
A's, with `tenants=[h(A)]` and no verdict, and B's, with `tenants=[h(B)]` and
`cross_tenant_read`. Tenant ids are compared across all backends and keys, so
operators must namespace ids that backends reuse (§6).

### 3.5 Increment split

The task-row fields (§3.3) can ship later without a bypass. Until then every
stored task frame restores `uninspected`, which over-flags and never
under-flags. The rest ships together.

## 4. MIN.4: fixture corpus and false-positive measurement

**Corpus.** The corpus is `tests/fixtures/tenant-reads-corpus.jsonl`, one
line per delivery. Each line holds `session`, `principal`, `t_secs`,
`pattern`, the raw `request` params and the raw `result`. Tenants are not
pre-attributed: the test passes each line through `request_tenants`,
`response_tenants` and `response_uninspected`, so a regression in extraction
also moves the measurement. A header line gives each pattern's session count.
Each session's label comes from the pattern that generated it, never from
running the guard.

| Pattern | Label | Shape |
|---|---|---|
| `single_tenant` | legitimate | 1 tenant, 5-40 deliveries over 1-60 min |
| `retry_same_tenant` | legitimate | the same A delivery, repeated |
| `mixed_workload` | legitimate | many principals interleaved, each single-tenant |
| `opaque_only` | legitimate | one unreadable result, nothing else in the window |
| `support_handoff_slow` | legitimate | A, then B after more than `window_secs` |
| `window_boundary` | legitimate | A, then B at exactly `window_secs` and at `window_secs + 1` |
| `support_handoff_fast` | legitimate, known FP | A, then B inside the window |
| `admin_sweep` | legitimate, known FP | one result, or a burst, naming 3-20 tenants |
| `large_single_tenant` | legitimate, known FP | A, then an unreadable page of A |
| `a_then_b` | cross_tenant | A, then B inside the window |
| `a_then_b_request_only` | cross_tenant | B named only in the request, result unkeyed |
| `a_then_opaque`, `opaque_then_b` | cross_tenant | an unreadable result, in either order |

**Measurement.** The measurement is an ordinary unit test with no network,
`src/security/firewall/tenant_read_corpus_tests.rs`, wired in like
`tenant_attribution_tests.rs` (PR:282-284). It builds
`TenantGuard::new(TenantGuardConfig { arg_keys, ..Default::default() })`,
replays every line through `assess_read_at` at `base + t_secs`, and commits
each ticket. It counts per principal-session, which is the MIN.KILL unit, and
asserts three gates:

1. No flags on the first six patterns.
2. Every `cross_tenant` session is flagged.
3. The exact counts per pattern and the overall FP rate match pinned values
   (the pattern of tests/provenance_eval_binary.rs:26-32).

There is no ceiling on the FP rate. The one-tenant rule flags the known-FP
patterns by construction. The deployment number comes from the MIN.KILL week,
and the admin-sweep remedy is MIN.3 (MIK-7627).

## 5. Tests (red first)

Each row is seen failing before its code exists, and goes red under the named
mutant.

| Test | Asserts | Mutant |
|---|---|---|
| `a_then_b_observe_two_delivery_events` (HTTP, stdio, direct) | A event `tenants=[h(A)]`, no verdict; B event with `cross_tenant_read=flagged`, data delivered | threshold `> 2`; field not written; keyed on session |
| `a_then_b_block_refuses` (each route) | B answered with the delivery refusal; event `blocked`; tenants keep `h(B)` | verdict computed but not applied |
| `request_only_tenant_any_method` | A, then `prompts/get` with `customer_id: B` in arguments and an unkeyed result: flagged | boundary scans only the result |
| `catalogue_delivery_is_judged` | A, then `prompts/list` whose description is JSON naming B (HTTP, stdio, cached): flagged | catalogue methods skipped |
| `playbook_step_tenant_counts` | live playbook whose step arguments (from the definition) name B, unkeyed output, after A: flagged | inner attribution not merged into the response's `read` |
| `playbook_mapping_introduces_b` | step result unattributed; output mapping produces `customer_id: B`: flagged | judged at a writer, not on the final result |
| `playbook_replay_keeps_step_tenants` | replay of that playbook after A: flagged; a pre-field `StoredDelivery` adds `U` | replay judged on the result alone |
| `task_result_judged_on_reader` | subjects S1 and S2 share credential K; S2 holds A and reads B's task result: flagged against S2 | admitting caller's key |
| `task_request_only_tenant` | task naming B only in its request, unkeyed result, read after A: flagged; a row without the field adds `U` | settlement passes the empty set |
| `finalization_refusal_no_history` | B refused in finalization (firewall, signing, fail-closed event), then A: not flagged | commit before finalization |
| `direct_every_audit_policy_commits` | no log, non-fatal failure: history kept; `FailClosed` failure: 503, no history | commit tied to one `record` branch |
| `uninspected_both_orders` | A then opaque, opaque then B, opaque then opaque, and an opaque read naming held A: all flagged; a lone opaque read: `None` | `U` equal to a tenant, or not stored |
| `overlapping_tickets` | barrier: A assessed and held, B assessed, then A commits: B flagged; two A tickets, one drops: A still pending | commit-only history; drop clears another's count |
| `history_bounds` | 10,000 tenants and 300 concurrent requests in observe mode: stored hashes ≤ 256, past it only `pending_overflow` grows and reads are flagged; block mode refuses past the bound; full principal map: `unattributable`, no eviction | unbounded storage; overflow allocating; eviction |
| `notification_frames_are_judged` | A result, then a backend `notifications/message` or progress frame naming B on the POST stream, the session stream and stdio: flagged; block drops it | notifications not judged |
| `sampling_request_is_judged` | A, then a backend sampling/elicitation request whose text names B: flagged; block answers the waiter with a refusal | server-to-client requests skipped |
| `error_payload_is_a_read` | A, then a backend error whose `error.data` names B (direct and meta, and its replay): flagged and committed | only `result` scanned; tickets dropped on every error |
| `gateway_refusal_commits_nothing_hidden` | a withheld B answer (refusal frame) then A: not flagged | refusal frame inherits `read` |
| `cache_hit_restores_pre_transform_attribution` | B cached after a key-stripping transform; A, then the cache hit: flagged; an entry without `read` restores `U` | cache entry without attribution |
| `hidden_attribution_without_logger` | no transparency log: a playbook step naming B after A is flagged | merge placed after audit.rs:338 |
| `one_scan_per_frame` | `frame_attribution` walks the frame once (counting walker) and returns tenants and `uninspected` | two walks |
| `refused_retry_keeps_committed_a` | A committed, a repeat A refused, then B: flagged | drop erasing committed |
| `window_expiry_clears` | A, then B after `window_secs + 1`: `None` | window ignored |
| `principal_not_session` | one key across two sessions: flagged; two keys sharing one session: not | session key |
| `anonymous_is_unattributable` | no caller key, session present: `unattributable`; block refuses | session fallback |
| `unconfigured_is_noop` | `arg_keys` empty, including a legacy task row: no fields, no refusal | judge before the attribution check |
| `config_mode` | `observe` default; `"Block"` and `true` rejected | bool, or default `block` |
| `tenant_read_corpus_fp_measurement` | §4 gates 1-3 | default window, threshold or mode changed |

## 6. UPGRADING-4.0.md

Add a row next to row 110 (UPGRADING-4.0.md:137); its number is assigned at
merge. Proposed text:

"With `tenant_guard.arg_keys` set, every outbound frame event names the tenants it
reached (hashed). A caller whose deliveries name more than one tenant inside
`window_secs` is marked `cross_tenant_read: flagged`, or `unattributable`
when it has no caller identity. A response the gateway could not fully read
counts as an unknown tenant. New key: `tenant_guard.cross_tenant_reads`
(`off|observe|block`, default `observe`). `block` refuses with the
response-firewall refusal. Tenant ids are compared across all backends, so
namespace any ids that backends reuse. Action: none. Set `off` to silence it,
and read the flags before choosing `block`."

## 7. Decisions taken

1. Security findings are fixed in 4.0, and the guard fails closed (lead
   ruling, 2026-10-01).
2. The task-row fields are accepted. Resources, prompts and catalogues are
   judged.
3. The 256 cap is a constant. `large_single_tenant` is a deliberate,
   measured FP.
4. Round 4 (merge lane): one judgement point per route at the final delivery
   boundary, with no per-writer assessment. Delivery records reuse the
   existing `response_delivery_attempt` event.
5. The threshold is fixed at 1. Whether a separate knob is needed is a
   MIN.KILL question.

### Review dispositions

Rounds 1-3 raised 21 findings. All were confirmed and fixed; their fixes are
part of the structure above. The round-4 findings are closed by construction:

| Round-4 finding | Closed by |
|---|---|
| `prompts/get` request-only B | The boundary walks the incoming `params` for every method (§2; PR:154-158). Test `request_only_tenant_any_method`. |
| Playbook replay loses step tenants | `StoredDelivery.read` (admission.rs:100-108), written at `complete_delivery` (handlers.rs:1829-1831); a missing field adds `U`. Test `playbook_replay_keeps_step_tenants`. |
| Writer suppresses the final assessment | No writer assesses or suppresses. The boundary scans the final assembled result (handlers.rs:1826; server/mod.rs:3050; direct_audit.rs:114-118). Test `playbook_mapping_introduces_b`. |

Both round-4 improvements were taken: ticket ownership (§3.1) and raw
fixtures (§4).

**Round 4 decisions (merge lane):** one judgement point per route, at the final delivery boundary, replaces per-writer assessment. The delivery event records the caller key beside the display name, so the verdict names its actor exactly. Inner playbook steps must stay on the request task; `playbook_step_tenant_counts` fails if a future spawn drops step attribution.

**Round 5 (merge lane):** the judgement point moves down to every outbound
frame on each transport (§3.2). All four findings are fixed:

| Finding | Closed by |
|---|---|
| Notifications reach the caller before the judge (CRITICAL) | Frames are judged at each stream's yield (streaming.rs:514, :540, :812) and at the stdio writer (stdio_writer.rs:17-27). Tests `notification_frames_are_judged` and `sampling_request_is_judged`. |
| Error payloads escape (CRITICAL) | One frame scan covers `error.message` and `error.data`. A backend error commits; a gateway refusal has `read: None` and commits nothing hidden. Tests `error_payload_is_a_read` and `gateway_refusal_commits_nothing_hidden`. |
| A cache hit loses pre-transform attribution (CRITICAL) | Cache and idempotency entries keep `read` (invoke.rs:2543 and :1903; admission.rs:100-108; idempotency.rs:729; backend_handlers.rs:1118). A missing field means `U`. Test `cache_hit_restores_pre_transform_attribution`. |
| The 256-ticket bound was unenforced (MEDIUM) | Past the bound, only a `u32` counter grows, and block mode refuses (§3.1). Test `history_bounds`. |

Both improvements were taken: a test with no logger, and one scan per frame
through a new `frame_attribution` that wraps the private `scan_response`
(PR:181-188), with no visibility widening. Threat model: §1.

**Round 5 decisions (merge lane):** every outbound frame is judged (results, errors, notifications, server-to-client requests). SSE commits at yield: that can over-record a frame a dropped connection never delivered, never under-record, so it fails closed.
