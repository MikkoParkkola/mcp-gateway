# MIN.2 and MIN.4: cross-tenant read verdict and its false-positive corpus

Status: draft for review. Criteria: MIK-7116.MIN.2 and MIK-7116.MIN.4
(docs/requirements/RELEASE-4.0.0-scope-update.md:132-133). Decision
`mik_7116_min_kill_gate` (RELEASE-4.0.0-scope-status.json) fixes the frame:
4.0.0 ships observe-first, and blocking by default waits for the MIN.KILL week
(MIK-7627). Tenant-guard citations marked `PR:` refer to
`origin/fix/min1-gap3-uninspected:src/security/firewall/tenant_guard.rs`
(PR #2593). This design is written against that version.

## 1. What exists

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
  :1127). The record writers know the caller and see every delivery, so the
  verdict goes there.
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

- **A read** is a delivered result (`Ok`, or a 200 with a `result` on the
  direct route), served live or from a cache. Refused and failed calls deliver
  nothing and are not reads.
- **A read's tenants** are the union `attribution()` already computes: request
  tenants plus response tenants, or the delivered value's tenants on a cached
  delivery (audit.rs:186-200). Request tenants are included because a call
  naming `customer_id: B` that returns B's rows without echoing the key is
  still a read of B. With the union, the verdict and the recorded `tenants`
  cannot disagree.
- **Sensitive** means attributed to at least one tenant. The verdict does not
  depend on `data_classes`, for three reasons. The kernel reports `public`
  whenever it finds nothing (kernel.rs:437-438), so a plain customer row reads
  as public. `data_classes` are absent on cached deliveries and on refusals
  before classification (tenants.rs:104-105). And `arg_keys` is the operator's
  own declaration of which data is tenant data. `data_classes` stays on the
  record, so the MIN.KILL week can narrow the definition post hoc
  (`ContextDataClass`, context_integrity/mod.rs:48).
- **The cross-tenant pattern:** a principal whose reads inside `window_secs`
  span more than one distinct tenant. This includes one response naming two
  tenants. The threshold is fixed at 1 because the criterion is "A, then B".
  The window is the only tuning knob.

## 3. Design

**Config.** Add to `TenantGuardConfig` (PR:56-69):
`cross_tenant_reads: off | observe | block`, a `#[serde(rename_all = "lowercase")]`
enum that defaults to `observe`. It is independent of `enabled`, which is the
request guard's switch and stays as it is. `observe` does nothing until
`arg_keys` is set, because no tenants means no reads to judge (PR:182-184). So
the default changes nothing on a deployment without attribution. `block` is
opt-in, as decision `mik_7116_min_kill_gate` requires. The key lives on the
serde struct. The unknown-key check (UPGRADING-4.0.md §29, :778) must accept
it: verify this at implementation.

### 3.1 The model

The rule has one sentence and one exception class.

- **Rule:** the reads a principal had delivered inside `window_secs` may name
  at most one tenant. The read being judged counts.
- **Unknown tenant:** a read whose attribution is `uninspected` contributes a
  fresh unknown tenant `U`. `U` is distinct from every other entry, including
  any other `U`. So one rule covers every case: A then opaque, opaque then A,
  opaque then opaque, and an opaque read whose inspected part names A. A read is
  single-tenant only when its attribution is complete. An opaque read with no
  other history passes, but it leaves `U` in the window, so the next read of
  anything conflicts. This is fail-closed in both orders, with no special case
  in the judge.
- **Off switch:** when attribution is unconfigured (`arg_keys` empty,
  `TenantGuard::attributes` is false, PR:168-170), the judge returns `None`
  before anything else, legacy task rows included. A deployment without
  `arg_keys` keeps its behaviour and its record schema.

### 3.2 History (`ReadHistory`)

`PrincipalWindow` is not reused. It drops the oldest observation at 4,096
(principal_window.rs:109-112) and evicts an arbitrary principal's whole history
when full (:173-180). Both fail open. `TenantGuard` instead gains `reads:
ReadHistory`. For each principal (the key is in §3.4) it holds three things:

- `committed: HashMap<TenantHash, Instant>`: the last delivery time of each
  hashed tenant (`hash_argument`, as on the record). `U` entries use a fresh
  random id.
- `pending: HashMap<TicketId, Reservation>`: what unfinished reads have
  reserved. A pending tenant counts as live.
- `overflow_until: Option<Instant>`: set when `committed` would exceed 256
  entries. The tenant is then not inserted. Instead `overflow_until` becomes
  `max(overflow_until, now + window)`, and while it is in the future it counts
  as one extra distinct tenant.

**One bound covers committed and pending together.** The bound is 256
distinct hashes per principal, counting committed and pending entries
together, plus at most 256 open tickets. A read that would cross either limit
reserves only an overflow reservation: a single slot that counts as one extra
distinct tenant until its ticket commits (then it becomes `overflow_until`) or
drops. A pending tenant that is already held is not stored again. The read's
own tenant set is transient and is freed when the request ends.

Peak memory per principal is therefore fixed in both modes, and an
overflowing principal is flagged or refused, never silently trimmed.

Expiry is by time alone. A committed entry is never removed by anything except
expiry, so a refused retry of A cannot erase A. Dropping an uncommitted ticket
removes only that ticket's `pending` entry. The principal map is capped at
100,000. When it is full, expired principals are swept first. If it is still
full, a new principal's read is `Unattributable` (refused in block mode). Live
history is never evicted.

### 3.3 Judge API

```rust
pub(crate) struct ReadAttribution { tenants: BTreeSet<TenantHash>, uninspected: bool }
pub(crate) fn assess_read_at(&self, principal: Option<&str>,
    read: &ReadAttribution, now: Instant) -> (ReadVerdict, Option<ReadTicket>)
// ReadVerdict { None, Flagged { distinct }, Blocked { distinct }, Unattributable }
// ReadTicket::commit(self, now): pending -> committed. Drop: removes its own pending entry.
```

`ReadAttribution` holds hashes only. Each raw id is hashed once, with
`hash_argument` (data_flow.rs:139), at the point where the record fields are
built, and the same `TenantHash` values go to the record, the judge and the
task row. Nothing hashes twice, and live and stored ids compare equal. `U` is
never an id: `uninspected` travels as a boolean (on the task row,
`read_uninspected`), and the judge mints a fresh `U` slot each time it sees
`true`.

The judge applies these steps in order. Steps 4 and 5 run under the
principal's map-entry lock, so two concurrent reads see each other's
reservations, and the second is judged against the first (fail closed):

1. Mode `off`, or attribution unconfigured: `None`, no ticket.
2. Empty tenants and not uninspected: `None`, no ticket (nothing tenant-bearing
   was read).
3. No principal: `Unattributable`, no ticket.
4. Distinct is computed over live committed entries, live pending entries,
   `overflow_until`, and this read's tenants (plus a fresh `U` if
   `uninspected`). `distinct > 1` gives `Flagged` or `Blocked`, by mode.
5. Unless the verdict is `Blocked`, this read's entries go into `pending`
   under a new ticket. A blocked read reserves nothing.

### 3.4 Where it runs, and the one commit point per route

**Assessment** runs where the delivered value and the reader are both known.
The writer computes the attribution fields first, from the value before any
swap, so a blocked cache hit still records the tenants that exist only in its
response (audit.rs:193-197; direct_audit.rs:148). On `Blocked`, the result
becomes the existing `Error::ResponseFirewallRefused`. Assessment runs before
the D4 count and before any `let Some(log)` return, so `block` works without a
transparency log. The ticket is parked in a request-scoped task-local,
`ReadTickets`, which uses the same `tokio::task_local!` scope shape as
`DispatchNotes` (audit.rs:75-78, :147-156).

**Commit** happens at exactly one point per route. That point is a single
return that every audit-policy outcome passes through: no log, a non-fatal
write failure, and a successful write all reach it. It sits after the last
code that can still turn the answer into a refusal. Tickets commit only if the
final answer carries a `result` and no `error`. Otherwise the scope ends and
every ticket drops. The table below lists each route; the "last refusal before
it" column names what can still refuse before the commit point.

| Route | Methods | Assessed at | Single commit point | Last refusal before it |
|---|---|---|---|---|
| HTTP `/mcp` | all, matched at handlers.rs:1011 | tool calls: `audit_invocation` (audit.rs:324), `audit_replay` (:530, before :539/:546); stored tasks: `refuse_stored_delivery` (task_replay.rs:24); **every other method**, catalogues included: on the assembled `response.result`, just before finalization (handlers.rs:1826) | right after `finalize_response_after_inspection` returns (handlers.rs:1826-1828), beside `complete_delivery` (:1829-1831) | finalization: response firewall, signing failure, fail-closed delivery-attempt audit (response_security.rs:168-276); its no-log and non-fatal paths return the response, so they reach the commit too |
| stdio | all | as HTTP; other methods (stdio_catalogue.rs:60-75 included, dispatched at server/mod.rs:3034-3035) just before finalization (server/mod.rs:3050) | right after `finalize_response_for_delivery` returns (server/mod.rs:3050) | same finalization |
| Direct `/mcp/{backend}` | **every** forwarded method; one funnel, `dispatch_in_scope` (backend_handlers.rs:431-458) | `audited_call` (direct_audit.rs:102-119) on the inner answer, for every method | the single return of `audited_call` (direct_audit.rs:114-118), after `record` returns, whatever path `record` took: no log (:141-143), success (:193), non-fatal failure (:204-207) | fail-closed record write (direct_audit.rs:194-203), which returns a 503 error, so nothing commits; signing and response firewall already ran inside (backend_handlers.rs:1121; direct_guards.rs:91-92) |

**Catch-all assessment** ("every other method") applies `response_tenants` and
`response_uninspected` (PR:163-177) to the final assembled result. It covers
`prompts/list`, `resources/list` and `resources/templates/list`, whose handlers
assemble catalogues without `forward_for_caller` (protocol.rs:150,
resources.rs:294), as well as `resources/read`, `prompts/get` and cached
catalogues. It runs only if no writer assessed the request already: writers
mark the `ReadTickets` scope. That keeps one assessment and one record per
request. A blocked catch-all answer becomes the existing finalization refusal
before finalization runs.

The direct route is judged generically. `DirectCall::of` (direct_audit.rs:42-73)
returns a call for every method, not only `tools/call`. It carries
`caller_key` from `identity::caller_key` (identity.rs:350), fed `cert_identity`
(backend_handlers.rs:515, :615). It attributes `result` whatever the method,
so `completion/complete` (backend_handlers.rs:222) and any future method are
covered without a list. A non-`tools/call` answer writes a record only when
attribution is non-empty, so the record set does not change for tenantless
traffic.

**Reader key.** On HTTP the key is `caller_key` (handlers.rs:1529). On stdio
it is the constant `stdio`: one process serves one client (stdio_nonce.rs:4-10),
and `caller_key` is `None` there (server/mod.rs:3242, :3787). On the direct
route it is `DirectCall.caller_key`. For a stored task, the key is the reader
in front of the gateway: HTTP builds it from `RecoveryCaller`
(tasks.rs:188-200, set where tasks.rs:237 has `None`), and stdio uses
`stdio`. The admitting caller is never used. The firewall's session or
per-backend fallbacks are never used either (handlers.rs:1295-1302;
backend_handlers.rs:59-73). The task worker's own dispatch (worker.rs:353;
context.rs:206) delivers to nobody, so it is not assessed.

### 3.5 Records

- **Live and cached tool calls:** the MIN.1 record gains `cross_tenant_read`
  (`flagged` | `blocked` | `unattributable`), absent on `None`.
- **#2472 replays, composite tools included:** a record is written whenever
  attribution is non-empty, whatever the verdict. A single-tenant replay of A
  therefore leaves evidence before a later flag. On a block, the replayed facts
  (audit.rs:552-553) give way to `ReplayAudit::new(Denied, None)`.
- **Stored task deliveries:** `refuse_stored_delivery` writes one attributed
  invocation record under the reader's identity whenever attribution is
  non-empty. It honours `FailClosed` like `write_invocation` (audit.rs:434-437),
  and a failed write withholds the
  delivery, so the ticket drops.
- **Every other method (catch-all, §3.4; direct non-`tools/call`):** one
  `log_invocation_attributed` record, with the method as the tool, when
  attribution is non-empty.
- **Not recorded:** `meta_refusal_audit.rs:89` (nothing delivered). The task
  settlement keeps its own record (audit.rs:455). It is not a delivery.

"Entries for both the read and the verdict" is asserted as two records: the A
read (`tenants=[h(A)]`, no `cross_tenant_read`) and the B read (`[h(B)]`, with
the field). A flagged read also emits `tracing::warn!` with server, tool and
distinct count, never tenant ids.

### 3.6 Task attribution persistence

Settlement carries the request tenants from admission instead of the empty set
(audit.rs:475), together with the response tenants and `uninspected`. They are
stored as hashed `read_tenants` on the task row, with a version bump next to
`TARGET_VERSION` (record.rs:35-38). The invariant: every row write that stores
or replaces a deliverable payload writes the payload's `read_tenants` in the
same write. That covers completion, a parked `input_required` round, the
completion of a resumed task, and upstream recovery. The precedent is
`store_targets.rs:118-196`, which writes `targets` with the record. A row
without the field, from an older version or an unrecorded path, is judged on
`ReadAttribution { tenants: response_tenants(stored payload), uninspected:
true }`. That is its visible tenants plus `U`. The stored payload is the
task's output or its pending input requests (`CommittedTask.task`,
record.rs:322; task_replay.rs:18-22). A first delivery that visibly names A
and B is therefore flagged even when there is no history, and request-only
tenants that could not be recovered are covered by `U`. This applies only when
attribution is configured.

**Cached deliveries and replays** are reads. The caller receives the data
whoever fetched it first. A repeat read of the same tenant only refreshes its
committed time.

**Tenant ids** are compared as strings across every backend and every
`arg_keys` key. Operators whose backends reuse local ids must namespace them;
UPGRADING says so (§6).

### 3.7 Increment split

If 4.0 needs it smaller, §3.6 can ship as a second increment with no bypass.
Until it lands, every stored task delivery has no `read_tenants`, so it is
judged on its visible tenants plus `U` (§3.6). The result is fail-closed and
over-flagging, never under. The
rest is one increment, because each part closes a bypass the others depend
on: the model, the history, the generic direct funnel, the commit points and
the records.

## 4. MIN.4: fixture corpus and false-positive measurement

**Corpus.** `tests/fixtures/tenant-reads-corpus.jsonl` holds one line per
read: `{"session","principal","t_secs","tenants":[...],"uninspected","pattern"}`.
The tenant ids are synthetic. Sessions are generated from named patterns, and
each pattern carries its label: `legitimate` or `cross_tenant`. The label
comes from the pattern that generated the session, never from running the
guard. The header line records each pattern's session count (its weight), so
the pinned rate can be read against the mix. The patterns are:

| Pattern | Label | Shape |
|---|---|---|
| `single_tenant` | legitimate | one principal, 1 tenant, 5-40 reads over 1-60 min |
| `support_handoff_slow` | legitimate | tenant A, then B more than `window_secs` later |
| `support_handoff_fast` | legitimate | tenant A, then B inside the window (a known FP) |
| `window_boundary` | legitimate | A, then B at exactly `window_secs` and at `window_secs + 1` |
| `admin_sweep` | legitimate | one response, or a burst, naming 3-20 tenants |
| `retry_same_tenant` | legitimate | the same A read repeated as cached deliveries |
| `mixed_workload` | legitimate | many principals interleaved, each single-tenant |
| `large_single_tenant` | legitimate | A, then an uninspected page of A (a known FP under §3.1: the unread part is `U`) |
| `opaque_only` | legitimate | one uninspected read, no other read in the window |
| `a_then_b` | cross_tenant | A read, then B read inside the window |
| `a_then_b_unkeyed` | cross_tenant | B named only in the request, response unkeyed |
| `a_then_opaque` | cross_tenant | A, then an uninspected read with no request tenant key |
| `opaque_then_b` | cross_tenant | an uninspected read, then B inside the window |

**Measurement.** This is an ordinary unit test with no network,
`src/security/firewall/tenant_read_corpus_tests.rs`, wired in as
`tenant_attribution_tests.rs` is (PR:282-284). It reads the corpus through
`include_str!` and builds `TenantGuard::new(TenantGuardConfig { arg_keys,
..Default::default() })`, so the default window and default mode are under
test. It replays each line through `assess_read_at` with `now = base +
t_secs` and commits every ticket, since observe mode delivers. The unit of
count is the principal-session, matching the MIN.KILL "sessions that would
have been blocked". The test prints and asserts three gates:

- **Gate 1:** zero flags on `single_tenant`, `retry_same_tenant`,
  `mixed_workload` and `opaque_only` sessions.
- **Gate 2:** every `cross_tenant` session is flagged (recall 1.0).
- **Gate 3:** exact pinned counts per pattern, plus the overall FP rate (flagged
  legitimate sessions over legitimate sessions), following
  tests/provenance_eval_binary.rs:26-32. A guard or default change then
  re-measures visibly.

There is no ceiling on the overall FP rate. A one-tenant rule flags
`admin_sweep` and `support_handoff_fast` by construction, so a ceiling would
either fail or invite tuning the corpus until it passes. The pinned rate is the
4.0.0 measurement MIN.4 asks for. The corpus is synthetic, so the deployment
number comes from the MIN.KILL week, and the admin-sweep remedy is MIN.3
(MIK-7627).

## 5. Tests (red first)

Every row is written and seen failing before the code it covers. A row named
for a mutant must go red with that mutant applied.

| Test | Asserts | Mutant that turns it red |
|---|---|---|
| `meta_a_then_b_observe_flags_and_records_both` | two records; A: `tenants=[h(A)]`, no `cross_tenant_read`; B: `tenants=[h(B)]`, `cross_tenant_read="flagged"`, outcome ok, data returned | threshold `> 2`; field not written; keyed on session |
| `meta_a_then_b_block_withholds` | B answer is `ResponseFirewallRefused`; B record `blocked`, outcome denied, tenants keep `h(B)` | swap skipped; attribution after the swap |
| `meta_block_without_transparency_log_still_refuses` | no log; B refused | assess below the `let Some(log)` return |
| `direct_a_then_b_block_withholds` | 200 delivery refusal body; record `blocked`, tenants `h(B)` (no outcome-class assertion) | direct writer not judged |
| `blocked_cache_hit_keeps_response_only_tenants` (meta and direct) | blocked cached B whose tenant is only in the response: record tenants `h(B)` | attribution computed from the swapped answer |
| `blocked_replay_records_denied_facts` | blocked #2472 replay: record outcome denied, no response hash | first-run facts reused |
| `composite_replay_is_judged` (HTTP and stdio) | `gateway_execute` replay delivering B after A: flagged / refused | assess after audit.rs:546 return |
| `resource_read_after_tool_read_flagged` | tool read A, then `resources/read` of B (meta and direct): flagged, record written | resource path not judged |
| `prompt_get_after_tool_read_flagged` | as above for `prompts/get` | prompt path not judged |
| `meta_then_direct_share_one_window` | A on `/mcp`, B on `/mcp/{backend}`, same API key: B flagged | direct key from `direct_control_identity`, or a second guard |
| `unkeyed_response_read_counts_request_tenant` | request names B, response has no key: flagged | response tenants only |
| `task_result_judged_on_reader` | task admitted under credential K by subject S1 holding A; subject S2 on K reads B result: judged against S2's history, and against S1's when S1 reads it | key taken from the admitting caller |
| `task_request_only_tenant_survives_settlement` | task naming B only in request, unkeyed upstream result: a later `tasks/result` after an A read is flagged | settlement passes the empty set (audit.rs:475) |
| `legacy_task_row_fails_closed` | row without `read_tenants`, after an A read: flagged / refused | missing field read as empty |
| `legacy_task_first_delivery_a_and_b` | row without `read_tenants` whose stored output names A and B, no history: flagged / refused | legacy row judged on `U` alone |
| `direct_no_log_retains_history` | direct route, no transparency log: A then B flagged | commit only on the `Ok(())` write branch |
| `direct_nonfatal_write_failure_retains_history` | direct route, write fails under the non-fatal policy: A then B flagged | same |
| `direct_failclosed_write_failure_no_history` | write fails under `FailClosed`: 503, then B unflagged | committing before the policy resolves |
| `catalogue_delivery_is_judged` | tool read A, then `prompts/list` whose description is JSON naming `customer_id` B (HTTP, stdio, and cached catalogue): flagged / refused, record written | catch-all assessment missing |
| `pending_storage_is_bounded` | 300 open tickets and one 1,000-tenant read held before commit: stored hashes ≤ 256, tickets ≤ 256, the excess reads flagged; drop restores | no bound on pending |
| `hash_once_live_matches_stored` | a task row's `read_tenants` equals the live record's `tenants` for the same id | double hashing |
| `uninspected_is_unknown_tenant_both_orders` | A then opaque; opaque then B; opaque then opaque; one opaque read whose inspected part names held A: each flagged / refused. A lone opaque read: `None` | empty-set return before the `U` step; `U` equal to A; `U` not stored |
| `finalization_refusal_records_no_history` | B refused at finalization (response firewall, signing failure, fail-closed delivery-attempt audit), then A read: not flagged; stdio and direct-route fail-closed write likewise | commit before handlers.rs:1826-1828 / server/mod.rs:3050 / direct_audit.rs:193 |
| `refused_retry_keeps_committed_a` | A committed; a repeat A read refused at finalization; then B: still flagged | Drop removing the committed entry |
| `refused_floods_do_not_evict` | 5,000 refused B reads after A (block), then B: still refused; A still readable | `PrincipalWindow` reuse; recording refused reads |
| `observe_overflow_is_bounded` | observe mode, 10,000 distinct tenants for one principal: `committed` length stays 256, `overflow_until` set, every read past the cap flagged; after the window, clean | inserting past the cap; no overflow marker |
| `principal_map_full_fails_closed` | full principal map with live entries: new principal `unattributable`, no live entry removed | evicting live history |
| `overlapping_assessment_sees_pending` | read A assessed and held before commit (a barrier between assess and commit), read B assessed, then A commits: B flagged | commit-only history (no pending entry) |
| `direct_every_method_is_judged` | A via `tools/call`, then B via `completion/complete` on `/mcp/{backend}`: flagged, record written | method allow-list in `DirectCall::of` |
| `stored_task_delivery_writes_reader_record` | B task result read after A: one record under the reader with `tenants=[h(B)]` and the verdict; under `FailClosed` a failed write withholds it and leaves no history | no delivery-time record |
| `single_tenant_composite_replay_is_recorded` | composite replay of A, verdict `None`: record with `tenants=[h(A)]` | record only on non-`None` |
| `no_arg_keys_legacy_row_is_noop` | `arg_keys` empty, legacy task row: no field, no refusal in block mode | legacy-row rule before the attribution check |
| `principal_not_session_key` | one API key across two `mcp-session-id`s: A then B flagged; two keys sharing one session: not flagged | key taken from session |
| `single_tenant_never_flagged` | 50 reads of A, none flagged | `>=` for `>` |
| `window_expiry_clears` | A, then B after `window_secs + 1` via `assess_read_at`: none | window not applied |
| `cached_replay_is_judged` | idempotent replay of A after a B read: flagged | `cached` notes skipped |
| `anonymous_read_is_unattributable` | no caller key, with a session id present: `unattributable`; block refuses | session-id fallback |
| `stdio_reads_keyed_on_process` | stdio A then B: flagged, not unattributable | stdio key left `None` |
| `off_mode_writes_no_field` / `no_arg_keys_no_field` | no `cross_tenant_read` field | unconditional write |
| `refused_call_is_not_a_read` | a gate-refused B call adds nothing: later A read unflagged | judging `Err` results |
| `config_mode_parses_and_defaults_observe` | `observe` default; `"Block"` and `true` rejected | bool, or default `block` |
| `tenant_read_corpus_fp_measurement` | §4 gates 1-3 | default window, threshold, mode default |

The meta tests extend `audit_record_tests/tenants.rs` with a context whose
`caller_key` is set (today `None`, audit_record_tests.rs:142). The direct tests
use `Caller::Key` (direct_audit_tests.rs:235-252).

## 6. UPGRADING-4.0.md

Add one row next to row 110 (UPGRADING-4.0.md:137). The row number is assigned
at merge. The row reads:

"With `tenant_guard.arg_keys` set, a caller that reads data attributed to more
than one tenant inside `window_secs` is flagged on its invocation record as
`cross_tenant_read: flagged` (or `unattributable` with no caller identity).
This covers every delivered backend result: tool calls, replays, resources,
prompts, completions and task results. A non-tool read that names a tenant now
writes a record. A response the gateway could not fully read counts as an
unknown tenant that conflicts with any other tenant. New
key `tenant_guard.cross_tenant_reads` (`off|observe|block`, default
`observe`). `block` refuses the read with the response-firewall refusal.
Tenant ids are compared across all backends: namespace ids that backends
reuse. Action: none. To silence it, set `off`. Read the flags before choosing
`block`."

## 7. Decisions taken (lead rulings 2026-10-01: security findings are fixed in 4.0; fail closed)

1. **Task paths are judged at delivery, keyed on the reader.** Settlement
   stores the full read attribution on the task row (§3.6). Every stored-result
   delivery is judged against, and recorded under, whoever is reading (§3.4,
   §3.5). The admitting key keys only the worker's execution record.
2. **An uninspected read is an unknown tenant `U`** that conflicts with any
   other entry, in both orders (§3.1). Legacy task rows are `U`, but only when
   attribution is configured.
3. **History is recorded at one commit point per route**, after finalization
   (§3.4). Committed and pending entries are kept apart, and a ticket's `Drop`
   removes only its own reservation.
4. **The threshold is fixed at 1.** Whether MIK-7627 needs its own knob is a
   MIN.KILL question. The design adds none.

### Review dispositions (first review seat)

All nine findings were confirmed at source and are fixed above:
- Composite replays: early return at audit.rs:546.
- Resource and prompt reads: resources.rs:394, protocol.rs:281,
  backend_handlers.rs:451.
- Window eviction: principal_window.rs:109-112, :173-180.
- Reader versus admitting caller: tasks.rs:45-58 owner versus tasks.rs:188-200
  reader.
- Request-only tenants lost at settlement: audit.rs:475.
- Judge API lacked `uninspected`: the earlier §3 judge.
- Cache swap lost tenants: direct_audit.rs:148, audit.rs:193-197.
- Replay facts reused: audit.rs:552-553.
- History recorded before the outer firewall: invoke.rs:1228 before
  handlers.rs:1661-1675.

Both improvements were taken: tenant-id scope (§3, §6) and corpus weights plus
boundary and mixed fixtures (§4). None was refuted.

**Decisions on the two points the revision raised (merge lane, under the fail-closed ruling):**
- The read attribution is stored as a versioned field on the existing task row. That adds a field to a durable record, with precedent in `targets` / `targets_recorded`; it is not a new store.
- `resources/read` and `prompts/get` are reads of tenant data, so they are judged and recorded when attribution is on. This widens the record set beyond `tools/call` on purpose; UPGRADING states it.

### Review dispositions (second round)

All eight findings were confirmed and are fixed:
1. **Opaque reads hid B.** Confirmed against the earlier judge step 3. Fixed
   by the `U` model (§3.1).
2. **A refused retry erased committed A.** Confirmed: one map held both
   committed and pending entries. Fixed by separating them (§3.2).
3. **Direct forwards outside the method list.** Confirmed: `completion/complete`
   is forwarded (backend_handlers.rs:222) through the single funnel
   (backend_handlers.rs:431-458). Fixed by judging every method (§3.4).
4. **Commit before finalization.** Confirmed: finalization can still refuse
   (response_security.rs:176-276), and it runs at handlers.rs:1826-1828 and
   server/mod.rs:3050. Fixed by one commit point per route (§3.4).
5. **Unbounded history in observe mode.** Confirmed: flagged reads committed
   without limit. Fixed by the 256-entry cap and the `overflow_until` marker
   (§3.2).
6. **No delivery-time record for task results.** Confirmed. Fixed by a record
   under the reader, with `FailClosed` honoured (§3.5).
7. **Unrecorded single-tenant composite replay.** Confirmed. Fixed: a record is
   written whenever attribution is non-empty (§3.5).
8. **Legacy rows without `arg_keys`.** Confirmed. Fixed: attribution
   unconfigured means `None` first (§3.1, judge step 1).

Both improvements were taken: an overlap barrier and two-session key tests
(§5), and the `read_tenants` write invariant (§3.6). None was refuted.

**Round 2 decisions (merge lane):** the per-principal cap stays a constant (256); a knob waits for a measured need. `large_single_tenant` (A, then an unreadable page of A) is a deliberate false positive of failing closed, measured by the corpus and carried into the post-release MIN.KILL week. The stdio stored-task finalize path is checked at implementation.

### Review dispositions (third round)

All four findings were confirmed and are fixed:
1. **Direct history lost on no-log and non-fatal paths.** Confirmed: `record`
   returns early at direct_audit.rs:141-143 and again at :204-207. Fixed by
   moving the commit to the single return of `audited_call` (§3.4).
2. **Catalogue deliveries were not assessed.** Confirmed: `prompts/list`,
   `resources/list` and templates are assembled without `forward_for_caller`
   (protocol.rs:150, resources.rs:294; stdio_catalogue.rs:60-75). Fixed by the
   catch-all assessment before finalization (§3.4).
3. **Legacy task row judged on `U` alone.** Confirmed against the earlier
   §3.6. Fixed: visible tenants plus `U` (§3.6).
4. **Pending reservations were unbounded.** Confirmed against the earlier
   §3.2. Fixed: one bound covering committed and pending entries, plus a
   ticket cap with overflow reservations (§3.2).

Both improvements were taken: hash-once ids and a boolean `read_uninspected`
(§3.3), and the named witnesses in §5.
