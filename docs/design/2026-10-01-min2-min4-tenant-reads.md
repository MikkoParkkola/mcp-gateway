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
  :1127). The verdict therefore goes at each route's final delivery boundary,
  which sees the caller, the request and the final answer (§3.2).
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

- **A delivery** is one answer the gateway sends a caller, for any method, at
  the route's final delivery boundary (§3.2).
- **A delivery's tenants** come from three sources, unioned:
  - the tenants named in the incoming request's `params`, walked with
    `request_tenants` (PR:154-158);
  - the tenants named in the final assembled `result`, scanned with
    `response_tenants` (PR:163-165);
  - the attribution recorded during this delivery, or stored with it (§3.3).

  A delivery is `uninspected` when any part of that result, or of the recorded
  attribution, was unread (PR:175-177).
- **Sensitive** means attributed to at least one tenant. `data_classes` are
  not used: the kernel reports `public` when it finds nothing
  (kernel.rs:437-438), and the field is absent on cached and refused calls.
- **The rule:** inside `window_secs`, a principal's committed deliveries may
  name at most one tenant, and the delivery being judged counts toward that.
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

The bounds are 256 distinct hashes per principal, counting committed and
pending entries together, and 256 open tickets. A read that would cross
either bound takes only an overflow reservation. The principal map is capped
at 100,000: expired principals are swept first, and if the map is still full,
a new principal's read is `Unattributable`. Live history is never evicted.
Every bound fails closed, flagging or refusing.

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

### 3.2 One judgement point per route

Each route judges once, where its final answer is assembled and before the
last code that can refuse it. Tickets live in a request-scoped task-local,
`ReadScope`, which has the same shape as `DispatchNotes` (audit.rs:75-78,
:147-156). The ticket commits after the final refusal point, and only if the
answer still carries a `result` and no `error`. Otherwise it drops.

| Route | Judge (before) | Commit (after) | Covers |
|---|---|---|---|
| HTTP `/mcp` | `finalize_response_after_inspection` (handlers.rs:1826) | its return (handlers.rs:1827-1828), before `complete_delivery` (:1829-1831) | every method matched at handlers.rs:1011 |
| stdio | `finalize_response_for_delivery` (server/mod.rs:3050) | its return | every method, catalogue (server/mod.rs:3034-3035) and tasks included |
| Direct `/mcp/{backend}` | `audited_call` on the inner answer, before `record` (direct_audit.rs:114-116) | the single return of `audited_call` (:116-118), whichever path `record` took (no log :141-143, written :193, non-fatal :204-207) | every forwarded method (one funnel, backend_handlers.rs:431-458) |

Finalization can still refuse a delivery: through the response firewall, a
signing failure, or a fail-closed delivery-event write
(response_security.rs:168-276). Each of those returns an error, so nothing
commits. Its no-log and non-fatal paths return the response, so they commit.
On a `Blocked` verdict the answer becomes the existing delivery refusal
(`delivery_refusal_error`, as finalization's firewall builds it), and
finalization then runs on the refusal. On the direct route the answer becomes
`refusal(id, &Error::ResponseFirewallRefused)` (direct_guards.rs:108-111).
Because a block is judged before `complete_delivery` stores the answer, a
blocked answer is stored as a refusal and replays as one.

**Reader key.** On HTTP, `caller_key` (handlers.rs:1529). On stdio, the
constant `stdio`: one process serves one client (stdio_nonce.rs:4-10). On the
direct route, `identity::caller_key` (identity.rs:350) over the request's
subject, certificate and client (backend_handlers.rs:515). The session and
per-backend fallbacks are never used (handlers.rs:1295-1302;
backend_handlers.rs:59-73). A stored task is judged on whoever reads it,
because the judgement point is the reader's own delivery.

**No per-writer assessment.** The writers (`audit_invocation`, `audit_replay`,
`refuse_stored_delivery`, the catalogue handlers) judge nothing and suppress
nothing. They only add attribution to `ReadScope` (§3.3).

### 3.3 Attribution the wire does not show

The request and the final result do not show every tenant a delivery reached.
Three cases fill the gap:

- **Inner dispatches in a live delivery.** Playbook and code-mode steps run as
  `invoke_tool` calls on the request's own task (support.rs:391-398;
  invoke.rs:3991-4020). Each step's `audit_invocation` already builds that
  step's attribution: its request tenants, its raw response tenants, and its
  `uninspected` flag (audit.rs:186-236, :348). It adds them to `ReadScope`.
  A step whose arguments come from the playbook definition, or whose raw
  response is mapped away, still counts. An output mapping that introduces a
  new tenant is caught by the final-result scan.
- **Replays** (#2472). An incoming replay request is the original request, so
  its own tenants are walked live. The inner-step attribution is not visible,
  though. `StoredDelivery` (admission.rs:100-108) gains `read: Option<{
  tenants, uninspected }>`, written from `ReadScope` at `complete_delivery`
  (handlers.rs:1829-1831). A replay adds the stored `read` to `ReadScope`. A
  record from before the field existed (`None`) adds `uninspected`. Persisting
  this is needed because a composite replay's result alone cannot carry its
  steps' request-only tenants.
- **Stored task results.** The incoming request is `tasks/get` or
  `tasks/result` with only a task id, so the original arguments are absent.
  Settlement stores `read_tenants` and `read_uninspected` on the task row in
  the same write as the payload, with a version bump next to `TARGET_VERSION`
  (record.rs:35-38; precedent store_targets.rs:118-196). The stored values are
  the admitted request's tenants plus the dispatch's attribution, instead of
  the empty set passed today (audit.rs:475). Delivery adds them to
  `ReadScope`. A row without the field adds `uninspected`, which fails closed;
  the result's visible tenants are scanned at the boundary anyway.

Cached deliveries need nothing extra: the cached value is the final result,
and the incoming request is the caller's own.

### 3.4 Records

On meta and stdio, every delivery already writes one immutable
`response_delivery_attempt` event in finalization (response_security.rs:263,
:284-330). When attribution is configured and the delivery has tenants, `U`,
or a verdict, that event gains three fields: `tenants` (hashed), `attribution`
(`uninspected` when it applies), and `cross_tenant_read` (`flagged` |
`blocked` | `unattributable`). It honours `FailClosed`, and a failed write
withholds the answer, so nothing commits. On the direct route, `record`
(direct_audit.rs:123) writes the same fields. `DirectCall::of`
(direct_audit.rs:42-73) returns a call for every method, and a
non-`tools/call` call is recorded only when it carries those fields. The MIN.1
invocation record stays the per-dispatch execution record.

"Audit entries for both the read and the verdict" are then asserted as two
delivery events: A's, with `tenants=[h(A)]` and no verdict, and B's, with
`tenants=[h(B)]` and `cross_tenant_read`.

**Tenant ids** are compared as strings across all backends and keys.
Operators whose backends reuse local ids must namespace them (§6).

### 3.5 Increment split

The task-row fields (§3.3, third bullet) can ship later without a bypass.
Until then every stored task delivery adds `U`, which over-flags and never
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
| `playbook_step_tenant_counts` | live playbook whose step arguments (from the definition) name B, unkeyed output, after A: flagged | inner attribution not added to `ReadScope` |
| `playbook_mapping_introduces_b` | step result unattributed; output mapping produces `customer_id: B`: flagged | judged at a writer, not on the final result |
| `playbook_replay_keeps_step_tenants` | replay of that playbook after A: flagged; a pre-field `StoredDelivery` adds `U` | replay judged on the result alone |
| `task_result_judged_on_reader` | subjects S1 and S2 share credential K; S2 holds A and reads B's task result: flagged against S2 | admitting caller's key |
| `task_request_only_tenant` | task naming B only in its request, unkeyed result, read after A: flagged; a row without the field adds `U` | settlement passes the empty set |
| `finalization_refusal_no_history` | B refused in finalization (firewall, signing, fail-closed event), then A: not flagged | commit before finalization |
| `direct_every_audit_policy_commits` | no log, non-fatal failure: history kept; `FailClosed` failure: 503, no history | commit tied to one `record` branch |
| `uninspected_both_orders` | A then opaque, opaque then B, opaque then opaque, and an opaque read naming held A: all flagged; a lone opaque read: `None` | `U` equal to a tenant, or not stored |
| `overlapping_tickets` | barrier: A assessed and held, B assessed, then A commits: B flagged; two A tickets, one drops: A still pending | commit-only history; drop clears another's count |
| `history_bounds` | 10,000 tenants in observe mode: stored hashes ≤ 256, overflow flags; 300 open tickets: ≤ 256; full principal map: `unattributable`, no eviction | unbounded storage; eviction |
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

"With `tenant_guard.arg_keys` set, every delivery event names the tenants it
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
