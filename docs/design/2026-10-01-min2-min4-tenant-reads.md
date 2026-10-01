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

**Guard.** `TenantGuard` gains a second window, `reads: PrincipalWindow`, built
with the same `window_secs`. It is separate from `seen` so that request reach
and read history never mix. It also gains one function, the one both production
and the corpus call:

```rust
pub(crate) fn judge_read_at(&self, principal: Option<&str>,
    tenants: &BTreeSet<String>, now: Instant) -> ReadVerdict
// ReadVerdict { None, Flagged { distinct }, Blocked { distinct }, Unattributable }
```

The function behaves as follows:

- Mode `off`, or an empty tenant set, returns `None` and records nothing.
- No principal returns `Unattributable`. In `block` mode that refuses, matching
  TENANT.1 (PR:50).
- Otherwise it records each tenant through `reads.record_at`, and
  `distinct > 1` returns `Flagged` or `Blocked` depending on the mode.

A blocked read is still recorded, matching `check` (PR:133-148). The attempt
shows intent, and recording it keeps the function single-pass. The consequence:
after a refused B read, that principal's A reads are refused until the window
passes. The observe week counts a flag on that A read too, so observe-mode flag
counts predict block-mode refusals one for one.

**Where it runs.** Add one helper, `MetaMcp::judge_read(principal, &notes,
request_tenants, delivered) -> ReadVerdict`. It reuses the tenant set
`attribution()` builds. It is called in three writers:

1. `audit_invocation` (audit.rs:324). Call it first, before `meta_denial`
   (:334) and before the `let Some(log)` early return (:338), so that `block`
   also works on a deployment without a transparency log. On `Blocked` or a
   blocked `Unattributable`, replace `result` with
   `Err(Error::ResponseFirewallRefused)`. From there the record, D4 metric and
   caller all see the same refusal as a response-firewall block, and the
   attribution still names the tenants (the T8 property).
2. `audit_replay` (audit.rs:530). Same rule, applied to the delivered value
   (:571-582). Call it before the log check (:539). A blocked replay is
   answered as that function answers a failed write (:596-599).
3. Direct `record` (direct_audit.rs:123). Call it before :133 and :141. On a
   block, replace `answer` with the existing refusal, `refusal(call.request_id,
   &Error::ResponseFirewallRefused)` sent as HTTP 200 (direct_guards.rs:108-111),
   so the route's refusal shape stays unchanged.

The following writers are not judged: `meta_refusal_audit.rs:89` (nothing was
delivered) and `audit_settlement` (audit.rs:455; see Open decisions).

**Principal per entry path.** The key is the caller's `caller_key`
(identity.rs:350). The session-id fallback is not used: under stateless
transport it is not an identity, and on the direct route it pools every
anonymous caller (backend_handlers.rs:59-73). The key on each path:

- HTTP meta: `MetaMcpCallerContext::caller_key` (handlers.rs:1529).
- Direct: `DirectCall` gains `caller_key: Option<String>`, computed in
  `DirectCall::of` (call site backend_handlers.rs:615, which gains
  `cert_identity`, available at :515) with the same `identity::caller_key`.
  Both routes therefore share one key and one window.
- stdio: the literal `stdio` when `stdio_nonce` is set. One process serves one
  client (stdio_nonce.rs:4-10), and the window is process memory, so a
  constant per process is unique. Today `caller_key` is `None` there
  (server/mod.rs:3242, :3787).
- Task worker (task_service/execution/context.rs:206) and the HTTP task read
  (router/handlers/tasks.rs:237): `None` today, so their reads are
  `Unattributable`. See Open decisions.

**Cached deliveries and replays** are reads. The caller receives the data
whoever fetched it first. Re-reading the same tenant adds no distinct tenant,
so honest retries are never flagged. A stored success whose live delivery was
blocked replays as blocked while the window holds, and after the window it is
allowed, which is exactly what a fresh read then would get. That is no leak
beyond the policy.

**Uninspected responses** add only the tenants that were read. Unread parts
cannot be counted, and the record already says `uninspected` (audit.rs:226-233).
Block mode does not refuse on `uninspected` alone (see Open decisions).

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
read: `{"session","principal","t_secs","tenants":[...],"pattern"}`. The tenant
ids are synthetic and never hashed. Sessions are generated from named patterns,
and each pattern carries its label: `legitimate` or `cross_tenant`. The label
comes from the pattern that generated the session, never from running the
guard. The patterns are:

| Pattern | Label | Shape |
|---|---|---|
| `single_tenant` | legitimate | one principal, 1 tenant, 5-40 reads over 1-60 min |
| `support_handoff_slow` | legitimate | tenant A, then B more than `window_secs` later |
| `support_handoff_fast` | legitimate | tenant A, then B inside the window (a known FP) |
| `admin_sweep` | legitimate | one response, or a burst, naming 3-20 tenants |
| `retry_same_tenant` | legitimate | the same A read repeated as cached deliveries |
| `a_then_b` | cross_tenant | A read, then B read inside the window |
| `a_then_b_unkeyed` | cross_tenant | B named only in the request, response unkeyed |

**Measurement.** This is an ordinary unit test with no network,
`src/security/firewall/tenant_read_corpus_tests.rs`, wired in as
`tenant_attribution_tests.rs` is (PR:282-284). It reads the corpus through
`include_str!`, builds `TenantGuard::new(TenantGuardConfig { arg_keys,
..Default::default() })`, so the default window and default mode are under
test, and replays each line through `judge_read_at` with `now = base +
t_secs`. The unit of count is the principal-session, matching the MIN.KILL
"sessions that would have been blocked". The test prints and asserts:

- **Gate 1:** zero flags on `single_tenant` and `retry_same_tenant` sessions.
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
| `meta_a_then_b_observe_flags_and_records_both` | two records; A: `tenants=[h(A)]`, no `cross_tenant_read`; B: `tenants=[h(B)]`, `cross_tenant_read="flagged"`, outcome ok, data returned | threshold `> 2`; field not written; verdict keyed on session |
| `meta_a_then_b_block_withholds` | B answer is `ResponseFirewallRefused`; B record `blocked`, outcome denied, tenants keep `h(B)` | swap skipped; attribution taken after the swap |
| `meta_block_without_transparency_log_still_refuses` | no log configured; B refused | judge moved below the `let Some(log)` return |
| `direct_a_then_b_block_withholds` | 200 delivery refusal body; record `blocked`, tenants `h(B)` (no outcome-class assertion) | direct writer not judged |
| `meta_then_direct_share_one_window` | A on `/mcp`, B on `/mcp/{backend}`, same API key: B flagged | direct key from `direct_control_identity` or a second guard |
| `unkeyed_response_read_counts_request_tenant` | request names B, response has no key: flagged | judging response tenants only |
| `single_tenant_never_flagged` | 50 reads of A, none flagged | `>=` for `>` |
| `window_expiry_clears` | A, then B after `window_secs + 1` via `judge_read_at`: none | window not applied |
| `cached_replay_is_judged` | idempotent replay of A after a B read: flagged | `cached` notes skipped |
| `anonymous_read_is_unattributable` | no caller key: `unattributable`; block mode refuses | falls back to session id |
| `stdio_reads_keyed_on_process` | stdio A then B: flagged, not unattributable | stdio key left `None` |
| `off_mode_writes_no_field` / `no_arg_keys_no_field` | no `cross_tenant_read` field | unconditional write |
| `refused_call_is_not_a_read` | a gate-refused B call adds nothing: a later A read is unflagged | judging `Err` results |
| `config_mode_parses_and_defaults_observe` | `observe` default; `"Block"` and `true` rejected | bool or default `block` |
| `tenant_read_corpus_fp_measurement` | §4 gates 1-3 | default window, threshold, mode default |

The meta tests extend `audit_record_tests/tenants.rs` with a context whose
`caller_key` is set (today `None`, audit_record_tests.rs:142). The direct tests
use `Caller::Key` (direct_audit_tests.rs:235-252).

## 6. UPGRADING-4.0.md

Add one row next to row 110 (UPGRADING-4.0.md:137); the row number is assigned
at merge. It reads: "With `tenant_guard.arg_keys` set, a caller that reads data
attributed to more than one tenant inside `window_secs` is flagged on its
invocation record as `cross_tenant_read: flagged` (or `unattributable` with no
caller identity). New key `tenant_guard.cross_tenant_reads`
(`off|observe|block`, default `observe`); `block` refuses the read with the
response-firewall refusal. Action: none. To silence it, set `off`. Read the
flags before choosing `block`."

## 7. Decisions taken (lead rulings 2026-10-01: security findings are fixed in 4.0; fail closed)

1. **Task paths are judged.** The admitting `caller_key` is carried into the
   task context, where the worker and the task read have none today
   (context.rs:206, tasks.rs:237). A task read and an upstream-task settlement
   (audit.rs:455) are then judged against the admitting caller's window, like
   a live call. Without this, block mode is bypassed through upstream tasks.
   Tests: a settlement and an owner read of a task attributed to B, after a
   live read of A, are flagged (observe) and refused (block).
2. **`uninspected` fails closed in block mode.** An uninspected read is
   refused when the principal already holds another tenant in the window,
   because the unread part may name any tenant. Observe mode flags it the
   same way. Test: a read of A, then an oversize reply, is flagged/refused.
3. **The threshold is fixed at 1.** Whether MIK-7627 needs its own knob is a
   MIN.KILL question. The design adds none.
