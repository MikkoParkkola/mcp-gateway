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

**History.** `PrincipalWindow` is not reused for reads. Its per-principal
deque drops the oldest observation at 4,096 (principal_window.rs:109-112), so
4,096 repeated B reads would evict a live A and let B pass. When full, it
evicts an arbitrary principal's whole history (:173-180). Either way the guard
fails open. `TenantGuard` instead gains `reads: ReadHistory`, a
`DashMap<String, HashMap<String, Instant>>` that maps principal to hashed
tenant id (`hash_argument`, as on the record) to last delivery. It uses the
same `window_secs`, and expiry is by time alone. A repeat read of a tenant
refreshes its entry instead of growing the map, so the size is bounded by
distinct tenants, not reads. Saturation fails closed:
- A principal holding more than 4,096 live tenants judges every further read
  as `Flagged`/`Blocked`.
- With 100,000 principals tracked, expired entries are swept first. If the map
  is still full, a new principal's read is `Unattributable` (refused in
  block). Live history is never evicted.

**Judge API.** One input type carries everything the policy needs, and both
production and the corpus call the same two functions:

```rust
pub(crate) struct ReadAttribution { tenants: BTreeSet<String>, uninspected: bool }
pub(crate) fn assess_read_at(&self, principal: Option<&str>,
    read: &ReadAttribution, now: Instant) -> (ReadVerdict, ReadTicket)
// ReadVerdict { None, Flagged { distinct }, Blocked { distinct }, Unattributable }
// ReadTicket::commit(self, now) records the read; dropping it uncommitted records nothing
```

`assess_read_at` checks, in this order:
1. Mode `off` returns `None`.
2. No principal, with any tenant or `uninspected` set, returns `Unattributable`.
3. `uninspected` is evaluated before the empty-tenant test: an uninspected read
   by a principal holding a live tenant other than this read's is `Flagged` or
   `Blocked`, because the unread part may name any tenant (§7.2). An
   uninspected read with no other tenant held is `None`.
4. An empty tenant set returns `None`.
5. The read's tenants plus the principal's live tenants: `distinct > 1` is
   `Flagged` or `Blocked`, by mode.

**Recording after the last refusal point.** `assess_read_at` writes the read's
tenants into the principal's entry as pending, under the entry lock, so two
concurrent reads of A and B see each other and the second is judged
cross-tenant. A pending entry counts as live. `ReadTicket::commit` makes the
entry durable, and dropping the ticket removes it. This is the
release-on-`Drop` shape the idempotency reservation uses
(invoke.rs:1738-1740). A ticket is committed only where the answer can no
longer be refused (§3 table). So a refused read, whether refused by this
verdict, the outer response firewall, or a fail-closed audit write, leaves no
history. A flood of refused B reads therefore cannot lock the principal out of
A, and observe-mode counts match block-mode refusals.

**Where it runs.** There is one helper per writer, `MetaMcp::assess_read(key,
&notes, request_tenants, delivered) -> (ReadVerdict, ReadTicket,
Map<String, Value>)`. It computes the attribution fields first, from the
undelivered value, and only then judges. When a block replaces the result, the
record still carries the tenants found only in a cached or replayed response
(audit.rs:193-197). On a block, the refusal is the existing
`Error::ResponseFirewallRefused`. The assessment runs before the D4 denial
count and before any `let Some(log)` early return, so `block` also works
without a transparency log. Every path that delivers backend data is covered:

| Path | Assess at | Reader key | Commit after |
|---|---|---|---|
| HTTP meta `tools/call`, live/cached | `audit_invocation` start (audit.rs:324, before :334/:338) | `caller.caller_key` (handlers.rs:1529) | outer response pass (handlers.rs:1661-1675) returns no refusal |
| stdio meta `tools/call` | same | `stdio` per process (server/mod.rs:3242, :3787; stdio_nonce.rs:4-10) | record written (no outer pass, server/mod.rs:3425-3434) |
| #2472 replay, every tool incl. `gateway_execute`/`gateway_run_playbook` | `audit_replay`, before both early returns (audit.rs:539, :546) | as the route above (handlers.rs:1635; server/mod.rs:3410) | as the route above |
| Direct `tools/call` | `record`, before :133/:141 (direct_audit.rs) | `DirectCall.caller_key` from `identity::caller_key`, fed `cert_identity` (backend_handlers.rs:515, :615) | record written |
| Meta `resources/read`, `prompts/get` | before returning `forward_for_caller` (resources.rs:394; protocol.rs:281) | as the route (HTTP handlers.rs:1686-1713; stdio stdio_catalogue.rs:62-65) | as the route |
| Direct non-`tools/call` reads | at the generic forward (backend_handlers.rs:451), `resources/read`/`prompts/get` only | as direct `tools/call` | answer built |
| Stored task result (`tasks/get`, `tasks/result`) | `refuse_stored_delivery` (task_replay.rs:24; HTTP tasks.rs:265, stdio stdio_tasks.rs:275, meta mod.rs:2276) | the reader in front of the gateway, not the admitting caller: HTTP `identity::caller_key` over `RecoveryCaller` (tasks.rs:188-200), set where tasks.rs:237 has `None`; stdio `stdio` | answer built |

Several rows need more detail:
- **Replay facts.** `audit_replay` reuses the first run's outcome and response
  hash (audit.rs:552-553). A blocked replay replaces those facts with
  `ReplayAudit::new(Denied, None)`, so the signed record describes the refusal
  the caller received. The first run's own record keeps its own facts.
- **Composite replays** used to be unrecorded (audit.rs:546). With
  attribution on, a non-`None` verdict now writes a record over the arguments,
  with the tool name as the target.
- **Resource and prompt reads** have no invocation record today (D2 records
  `tools/call` only, direct_audit.rs:47). Their attribution reads `uri`/`name`
  and `arguments` as request tenants. When attribution yields a tenant or
  `uninspected`, they write one `log_invocation_attributed` record with the
  method as the tool. A tenantless read writes nothing, keeping the T9/T10
  schema property.
- **Tasks.** Settlement (audit.rs:455, worker.rs:394, tasks.rs:357) is not a
  delivery and is not judged. It now stores the read's attribution: the request
  tenants are carried from admission instead of the empty set (audit.rs:475),
  together with the response tenants and `uninspected`. They are stored as
  hashed ids in a versioned `read_tenants` field on the task row, following
  `targets`/`targets_recorded` (record.rs:328-346). Judging happens at each
  delivery, keyed on whoever reads. A row from before the field existed is
  judged as `uninspected`, which fails closed.
- **Not judged.** `meta_refusal_audit.rs:89`: nothing was delivered. The
  task worker's own dispatch (worker.rs:353; context.rs:206) is not judged
  either: it executes but delivers to nobody. It carries the admitting
  `caller_key` for its record only, never for read history.

The reader key is always `identity::caller_key` (identity.rs:350) or the stdio
constant. The firewall's session or per-backend fallback is never used: under
stateless transport it is not an identity, and on the direct route it pools
every anonymous caller (handlers.rs:1295-1302; backend_handlers.rs:59-73).

**Cached deliveries and replays** are reads. The caller receives the data
whoever fetched it first. Re-reading the same tenant only refreshes its entry,
so honest retries are never flagged. A stored success whose live delivery was
blocked replays as blocked while the window holds. After the window passes it
is allowed, which is exactly what a fresh read would get then.

**Tenant ids** are compared as strings across every backend and every
`arg_keys` key. `cust-1` on two backends is one tenant. Operators whose
backends reuse local ids must namespace them, or reads of unrelated tenants
merge and go unflagged. UPGRADING says so (§6).

**Audit.** The read is the MIN.1 invocation record. The verdict is one more
field on that same record, `cross_tenant_read`, with the value `flagged`,
`blocked` or `unattributable`. It is absent when the verdict is `None`, so a
deployment without `arg_keys` keeps its schema (the T9/T10 property). Writing
the verdict on the record that carries the read's `tenants` puts both in the
signed chain in one line, with no join key to keep. A test then asserts "both"
as two records: the A read (tenants `[h(A)]`, no `cross_tenant_read`) and the B
read (tenants `[h(B)]`, `cross_tenant_read` set). A flagged read also emits a
`tracing::warn!` with server, tool and distinct count, never tenant ids.

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
| `large_single_tenant` | legitimate | A, then an uninspected read, no other tenant held |
| `a_then_b` | cross_tenant | A read, then B read inside the window |
| `a_then_b_unkeyed` | cross_tenant | B named only in the request, response unkeyed |
| `a_then_opaque` | cross_tenant | A, then an uninspected read with no request tenant key |

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
  `mixed_workload` and `large_single_tenant` sessions.
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
| `uninspected_after_a_fails_closed` | A, then an oversize reply with no tenant key: flagged / refused | empty-set return before the uninspected test |
| `outer_firewall_refusal_records_no_history` | B refused by the outer response pass, then A read: not flagged | commit before handlers.rs:1661-1675 |
| `refused_floods_do_not_evict` | 5,000 refused B reads after A (block), then B: still refused; A still readable | `PrincipalWindow` reuse; recording refused reads |
| `history_saturation_fails_closed` | principal with 4,097 live tenants: next read flagged; full principal map: new principal `unattributable` | evicting live history |
| `concurrent_a_and_b_one_flagged` | two parallel reads A and B, no prior history: exactly one flagged | commit-only history (no pending entry) |
| `single_tenant_never_flagged` | 50 reads of A, none flagged | `>=` for `>` |
| `window_expiry_clears` | A, then B after `window_secs + 1` via `assess_read_at`: none | window not applied |
| `cached_replay_is_judged` | idempotent replay of A after a B read: flagged | `cached` notes skipped |
| `anonymous_read_is_unattributable` | no caller key: `unattributable`; block refuses | session-id fallback |
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
This covers tool calls, replays, `resources/read`, `prompts/get` and task
results. Resource and prompt reads that name a tenant now write a record. New
key `tenant_guard.cross_tenant_reads` (`off|observe|block`, default
`observe`). `block` refuses the read with the response-firewall refusal.
Tenant ids are compared across all backends: namespace ids that backends
reuse. Action: none. To silence it, set `off`. Read the flags before choosing
`block`."

## 7. Decisions taken (lead rulings 2026-10-01: security findings are fixed in 4.0; fail closed)

1. **Task paths are judged at delivery, keyed on the reader.** Settlement
   stores the full read attribution on the task row. Every stored-result
   delivery is judged against the history of whoever is reading (§3 table).
   The admitting key keys only the worker's execution record.
2. **`uninspected` fails closed.** It is an input to the judge, and an
   uninspected read is refused when the principal holds another tenant (§3,
   judge step 3). Legacy task rows count as uninspected.
3. **History is recorded only after the last refusal point**, through
   `ReadTicket`. Pending entries make concurrent reads fail closed.
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
