# MIK-7116 4.0 slice: MIN.1 attribution, MIN.2 observe, MIN.4 measurement

Status: v5, adopted by lead ruling (2026-09-30). Delta-only review of the two
HIGH dispositions on a non-OpenAI seat (synthetic-review, GLM-5.3): SHIP,
three improvements, no findings (disposition table). Verdicts by version: v3 read by
seat 1 (gpt-6-astra): REWORK, MED/LOW only. v4 read by seat 2 (degraded:
gpt-5.4, same vendor as seat 1; synthetic-review 429 on three attempts):
REWORK, 2 HIGH + 1 MED, all verified and folded into v5. Earlier: v2 was reviewed by two seats (both SHIP-WITH-FIXES); a later
seat raised H1-H3 and M6 (folded into v3). v3 seat 1: REWORK on MEDIUM/LOW
findings only, each verified at source and folded in (disposition table).
Base: `docs/ranking-1-release-line` @ `d5fa1ac66` (after #2421, #2448, #2449,
#2456).

## Criterion

> MIK.MCPGW.MIN.1: Tool responses carry a tenant attribution alongside the
> existing `ContextDataClass`. Attribution is recorded in the audit trail
> whether or not it triggers a block.

Operator ruling C3: 4.0 builds MIN.1, MIN.2 in **observe mode**, and MIN.4
(fixture false-positive measurement plus the one-week observe runbook that
implements MIN.KILL). MIN.3/5/6 come after 4.0. §1-6 are MIN.1; §7 is
MIN.2-observe; §8 is MIN.4.

## What exists at the base

| Fact | Source |
|---|---|
| Tenant ids are read from request arguments only, under operator-configured `arg_keys`, at any depth | `security/firewall/tenant_guard.rs:63,138-158` |
| `TenantGuard::check` records tenants into a principal window as a side effect | `tenant_guard.rs:100-130` |
| Both routes run the guard on the tool's own arguments (`target.arguments`, not the `gateway_invoke` envelope) | `router/handlers.rs:1403-1410`, `router/backend_handlers.rs:138-145` |
| Meta and direct build **separate** `Firewall` instances, so separate `TenantGuard` windows | `gateway/server/mod.rs:1228-1238` ("each keeps its own") |
| `ContextDataClass` comes from the context-integrity kernel; never empty (defaults to `Public`) | `context_integrity/kernel.rs` |
| **Both** routes run the kernel: direct `after_dispatch` → `MetaMcp::gate_payload` → `apply_response_gates` → `apply_context_integrity` | `router/direct_guards.rs:57`, `meta_mcp/invoke/dispatch_guards.rs:184`, `meta_mcp/invoke.rs:1463-1523` |
| Three D1 writers call `log_invocation_correlated`: meta invoke (D1-d), direct (D2), meta pre-dispatch refusal (#2421) | `meta_mcp/invoke/audit.rs:132`, `router/backend_handlers/direct_audit.rs:149`, `router/meta_refusal_audit.rs:101` |
| D1 domain fields are a `serde_json::Map`; the chain hash covers every field but `entry_hash`/`sig`/`key_id`, and the HMAC also authenticates `key_id` | `security/transparency_log.rs:379-411,621-630,694-725` |
| A record over `MAX_RECORD_BYTES` (4 MiB) fails the append; under `FailClosed` the call is then refused | `transparency_log_append.rs:73`, `transparency_log_rotation.rs:51` |
| `DISPATCH_FAILURE` is a task-local read inside `with_dispatch_scope` and returned as an owned value; `audit_invocation` runs **after** the scope ends | `meta_mcp/invoke/audit.rs:29-50`, `invoke.rs:1352-1363` |
| Three cache hits return before `apply_response_gates`: meta idempotency, meta response cache, direct idempotency | `invoke.rs:1890-1903`, `invoke.rs:~2015`, `router/backend_handlers.rs:1044-1047` |
| Caches are partitioned per resolved caller (grant subject, OIDC actor, credential digest); unresolved authenticated callers bypass caching; anonymous callers share one namespace | `meta_mcp/support.rs:163-193,221-233` |
| The canonical firewall key: length-prefixed, subject outranks credential, a certificate subject re-derived from the certificate (never its display name) | `router/identity.rs:340-363` (`caller_key`, `pub(super)`) |
| The context-integrity kernel classifies at most the first and last 32 KiB of a larger text; no finding → `Public` | `context_integrity/kernel.rs:28-29,437-442,592-601` |

## Design

### 1. Source of attribution (deterministic)

One walker, factored out of `TenantGuard`'s private `collect`, with the
**same `arg_keys`**; no new configuration. Two `pub(crate)` pure entry points
(no principal-window write):

- `request_tenants(&Value) -> BTreeSet<String>`: today's walk, over the value
  the guard is given (`target.arguments`). `check` is rewritten on top of it,
  so the guard and the attribution cannot disagree.
- `response_tenants(&Value) -> BTreeSet<String>`: the same walk, plus every
  `content[].text` block that parses as a JSON object/array. `ponytail:` text
  blocks over 1 MiB are skipped (attribution miss); response inspection
  already scans the same text linearly.

Extraction uses `MetaMcp`'s firewall (built from the same
`security.firewall` config as the router's), so both routes read one
`arg_keys`. Attribution is active whenever `arg_keys` is non-empty,
independent of `tenant_guard.enabled`, which keeps governing only whether the
guard may refuse. Nothing is refused that was not before.

### 2. Capture: one point, one scope, both routes (H1, M6)

- **Capture point:** top of `MetaMcp::apply_response_gates`, on the raw
  backend result, before the contract gate or inspection can return `Err`.
  `data_classes` are noted in `apply_context_integrity` from the kernel's
  classification. Both routes pass through here (H1).
- **Scope:** `with_dispatch_scope` becomes `pub(crate)` and returns
  `(Output, DispatchNotes)`; `DispatchNotes { failure: Option<i32>,
  response_tenants: BTreeSet<String>, data_classes: BTreeSet<ContextDataClass> }`
  replaces the bare `Option<i32>`. One task-local (`RefCell<DispatchNotes>`)
  replaces `DISPATCH_FAILURE`. Notes are read inside the scope and returned
  owned, so they survive to `audit_invocation`, which runs after the scope
  ends (M6). Several gate runs in one scope union their sets.
- **Direct route:** `backend_handler` wraps `backend_handler_inner` in the
  same scope (`backend_handlers.rs:512`) and hands the notes to
  `direct_audit::record` with the answer. Without this the note would be
  dropped silently on direct.
- **Outside a scope** (upstream task recovery, `upstream.rs:427,462`) the note
  is a no-op; that record keeps request-side tenants only.
- **Cache hits (H2, v3 seat 1 F1/F2):** all three hit returns note
  `tenants` from the **delivered** cached value and mark the record
  `attribution: "cached_delivery"`; they carry no `data_classes` and feed no
  MIN.2 observation. A cached value is post-gate (summarised, stripped or
  withheld content may have lost the raw tenants), so re-classifying it cannot
  reproduce the miss; hit ≠ miss is stated, not hidden. MIN.2 loses nothing
  that matters: caches are partitioned per resolved caller
  (`support.rs:163-193`), so a hit replays to the principal whose miss was
  already observed, and pooled anonymous callers are unkeyed, never observed.
  Recorded undercount: a replay after the window expires does not re-enter the
  window. The direct idempotency hit (`backend_handlers.rs:1044`) runs inside
  the direct scope once `backend_handler_inner` is wrapped.

### 3. Representation and records

- **In memory:** raw ids in `BTreeSet<String>`; MIN.2 compares these.
- **On disk:** `tenants` = sorted `hash_argument(id)` (`security/data_flow.rs:139`,
  16 hex of SHA-256). Raw argument values are never logged; residual:
  guessable ids are reversible by enumeration ("not written raw", not
  "unlinkable").
- **Alongside `ContextDataClass`** = in the same D1 record: `data_classes`
  (snake_case, sorted) next to `tenants`. Kernel public types are unchanged.
- **Emission rule:** `tenants`, `data_classes` and the MIN.2 field are written
  only when the tenant set is non-empty, or when the response could not be
  inspected (below), so default-config records keep their schema
  (`data_classes` is never empty and would otherwise appear on every record).
- **`attribution` marker (gap 2, lead ruling 2026-10-01):** one value states how
  far the record's attribution reaches. `cached_delivery` means the value was
  delivered past the gates (a cache hit or a replay), so it is attributed from
  the delivered value. `uninspected` means part of the response was not read
  for tenants: a `content[].text` block exceeded the 1 MiB parse bound, or the
  reply was refused at raw receipt for its signature chain (unverified content
  is not read). Gap 3 (lead ruling 2026-10-01): any response string that opens
  like JSON must parse or is unread (depth limit, malformed text, bracket-led
  prose: fail closed); JSON carried in a string, double-encoded text included,
  is decoded and read up to three layers, and deeper encoding is unread. The
  record says so even when it names no tenant; `tenants` is then a lower bound. `cached_delivery_uninspected` means both. The parse
  bound stays, as a DoS limit.
- **Cap (H3):** one crate-private writer,
  `TransparencyLogger::log_invocation_attributed(.., extra: serde_json::Map)`,
  used by all three D1 writers; `pub fn log_invocation_correlated` keeps its
  signature and delegates with an empty map. The writer keeps at most
  `MAX_RECORDED_TENANTS = 1024` sorted hashes and, when truncated, adds
  `tenants_total: N` as the overflow marker. A `const` assertion ties the cap
  to `MAX_RECORD_BYTES` (1024 × 19 B ≈ 19 KiB, far under 4 MiB), so a large
  tenant set adds at most ~19 KiB. This bounds the **addition**, not the
  whole record: a record already within 19 KiB of 4 MiB could now cross it.
  No existing record comes near (the largest fields are fixed-size hashes and
  short names), so the qualified claim is: attribution cannot by itself refuse
  a call.
  The writer rejects an `extra` key that collides with a domain or chain
  field.

| Call outcome | Firewall NDJSON `request` entry | D1 record |
|---|---|---|
| Meta, allowed (miss or cache hit) | `tenants` (request) | `tenants` (request ∪ response) + `data_classes` |
| Meta, refused before dispatch (scope pre-check, request firewall incl. tenant guard) | `tenants` + the refusal finding | #2421 record + `tenants` (request); no `data_classes` |
| Meta, response gate refuses (contract / inspection) | `tenants` (request) | `tenants` (request ∪ response); no `data_classes` (never classified) |
| Meta, context integrity withholds | `tenants` (request) | `tenants` + `data_classes` of the raw content |
| Direct, allowed | `tenants` (request) | `tenants` (request ∪ response) + `data_classes` |
| Direct, response gate refuses | `tenants` (request) | `tenants` (request ∪ response); no `data_classes` |
| Direct, refused by request firewall | `tenants` + refusal finding | `tenants` (request) |

"Whether or not it triggers a block" is met on every route: each row above
has a D1 record carrying `tenants`. Attribution adds fields; it never adds a
record. Firewall NDJSON: the private `AuditEntry` gains `tenants` (skipped
when empty) via a new `pub(crate) log_request_attributed`; `pub fn
log_request` keeps its signature.

### 4. Known gaps, not fixed here

- Upstream task recovery runs outside a scope and writes no record of its own,
  so the recovered response is not attributed. Closed in a separate design
  increment: a settlement record per recovered task (lead ruling 2026-10-01).
- **Meta secured-execution replay writes no D1 record at the base** (v4 seat 2
  H-b): `SyncAdmission::Replay` (`meta_mcp/admission.rs:210`) is served from
  the router (`handlers.rs:1673,1699`) without `invoke_tool`, so
  `audit_invocation` never runs, contrary to D1-d's "one record per call".
  Pre-existing and outside MIN.1's diff: tracked as #2472 (4.0-gating) and fixed in
  its own PR, which increment 1 then extends with `tenants` +
  `attribution: "cached_delivery"` like the other hits. MIN.1 is not moved to
  met until that record exists.
- Attribution needs the `firewall` feature (default-on) and `arg_keys`;
  records need the transparency log.
- Text blocks over 1 MiB are not parsed for tenants. Closed as a gap: the
  record is marked `attribution: "uninspected"` (§3), not left silent.
- The kernel classifies only the first and last 32 KiB of a larger text, so
  sensitive data only in the middle is classed `Public` and MIN.2 misses it.
  Pre-existing classifier bound, not changed here; MIN.4 measures it (§8).

### 5. Public API

**None added.** Untouched: `AuditLogger::log_request`/`log_response`,
`TransparencyLogger::log_invocation_correlated` signatures; fields of
`ContextProvenance`, `ContextIntegrityClassification`, `FirewallVerdict`;
`TenantGuardConfig` keys. New items are `pub(crate)`; `with_dispatch_scope`
widens `pub(super)` → `pub(crate)` (crate-internal); `identity::caller_key`
widens `pub(super)` → `pub(crate)` if the direct writer needs it outside
`router`; `MetaMcpCallerContext` gains a `pub(crate)` field (the struct lives
in the private `gateway::meta_mcp` module and is not re-exported). Doc-only change on
`TenantGuardConfig::enabled`/`arg_keys`: attribution runs with
`enabled = false`.

### 6. What MIN.2 gets

Per call, on both routes, the tenant set and data classes, owned, at the D1
writer. The key is recorded in §7 so it is not reopened.

### 7. MIN.2 in observe mode

> A session that has read sensitive data attributed to tenant A is blocked
> from reading sensitive data attributed to tenant B. Test proves the block
> fires, and proves the audit entry exists for both the read and the block.

Observe mode: the rule is evaluated and its verdict recorded; **nothing is
withheld**. "The block fires" = the would-block verdict fires and is recorded.
Enforcement is a later switch, after MIN.KILL.

- **Sensitive** = `data_classes` contains any of `Internal`, `PersonalData`,
  `FinancialData`, `HealthData`, `GuardedMaterial`.
- **One window for both routes:** a `PrincipalWindow` of sensitive reads owned
  by `MetaMcp` (not by either `Firewall`: the two routes' firewalls are
  separate instances, `server/mod.rs:1228-1238`, so a per-firewall window would
  let a caller read tenant A on `/mcp` and tenant B on `/mcp/{name}`
  unobserved). Window length = `tenant_guard.window_secs`.
- **Rule:** on a sensitive response with response tenants `R`, record each
  `t ∈ R` for the principal. Distinct count > 1 → **would-block**. One
  response carrying two tenants' sensitive data would-blocks on its own.
  Non-sensitive responses record nothing (a directory listing is not a
  cross-tenant read).
- **Where:** in the meta and direct D1 writers, which hold the caller and
  the owned notes. Cache hits do not observe (§2).
- **Criterion wording (lead condition on H-a):** the ledger says "A caller
  that **has read** sensitive data attributed to tenant A is flagged (observe
  mode) or, when blocking is switched on, blocked from **reading** sensitive
  data attributed to tenant B" (`docs/requirements/RELEASE-4.0.0-scope-update.md:132`).
  It says "read", not "delivered", so a fetch reading is within the text; its
  lean toward delivery is why the move-after-delivery precondition binds
  enforcement.
- **What an observation means (v4 seat 2 H-a):** a *sensitive fetch* made
  for the principal, i.e. the backend returned it under their call. On
  `/mcp` the router's response-firewall pass (`handlers.rs:1716-1738`) runs
  after `invoke_tool`, so a response it then blocks has already been
  observed. Accepted for observe mode: nothing is withheld on the verdict,
  the overcount is bounded by response-firewall blocks (secret or
  exfiltration findings, each already in the firewall NDJSON), and the MIN.4
  corpus holds one such session so the rate carries it. Before enforcement
  the observation moves after the delivery pass (the notes would have to
  leave `handle_tools_call`); recorded as the enforcement precondition next
  to the key.
- **Key (v3 seat 1 F3):** exactly `identity::caller_key(subject, cert,
  client)`, the firewall's canonical key, computed at the router while the
  certificate and client are in hand (the raw `caller_key` value, **not** `control_identity`: both routes'
  `control_identity` replaces an empty key with a session / per-backend
  fallback, `handlers.rs:1385-1409`, `backend_handlers.rs:58-69`, which would
  hide unkeyed callers). Meta carries it in a new `pub(crate) observer_key`
  field on `MetaMcpCallerContext`; direct carries it in `DirectCall`. Empty
  key → no observation, recorded as `cross_tenant: "unkeyed"`. Route parity is
  by construction (one function, same inputs), which closes the v3 mTLS
  `ponytail:`.
- **Record:** `cross_tenant: "would_block"` (or `"unkeyed"`) only when it
  applies, and on every observed sensitive read `observer` = 16 hex of
  SHA-256 over the canonical key (not raw; the key embeds credential
  principals). The read and the would-block records correlate by `observer`,
  not by `who` (v3 seat 1 F4: one subject on five credentials is five `who`
  values but one observer). The first read's record already carries `tenants` +
  `data_classes`, so "an audit entry for both the read and the block" is two
  D1 records correlated by `who`.
- The request-side breadth guard (`tenant_guard.enabled`,
  `max_tenants_per_window`) is unchanged and independent.
- "Session" under statelessness = the principal over the window, for the
  reason `tenant_guard.rs:11-19` gives.

### 8. MIN.4 measurement and the MIN.KILL runbook

> False-positive rate is measured against a fixture corpus before any
> blocking is enabled by default. Ship in observe-only mode first.

- **Corpus:** `tests/fixtures/mik_7116_min4_corpus.json`, ~15 labelled
  sessions of `(principal, arguments, backend_result)` steps (text-JSON and
  `structuredContent`), `expect: "flag" | "clean"`: single-customer support,
  repeated reads, directory listing, public docs, a legitimate cross-tenant
  incident review (`clean`, an expected false positive, the case MIN.3 is
  for), a numeric id the phone pattern misreads, a sensitive row only in the
  middle of a > 64 KiB text (expected false negative), and true cross-tenant copy
  sessions (`flag`). Each step runs through the production extractor, the
  production kernel and the §7 rule, so classifier false positives are
  measured.
- **Check:** a lib test computes TP/FP/TN/FN and asserts them against the
  table in `docs/release/mik-7116-min4-fp-measurement.md`; a classifier
  change that moves the rate fails CI until that document is updated.
- **Default:** no enforcing mode exists, so "blocking not enabled by default"
  holds by construction; a test asserts a would-block response is delivered
  unchanged.
- **Runbook** (`docs/release/mik-7116-min-kill-observe-runbook.md`): set
  `arg_keys` with `enabled: false`, run one week, count distinct `observer` with a
  `cross_tenant == "would_block"` record (unique principals, not episodes) (checked-in `jq`), apply MIN.KILL:
  fewer than 5 → MIN.1 only, no enforcement.

### Increments (one per PR)

1. MIN.1: §1-3 (extractor, scope, cap, three writers, NDJSON field).
2. MIN.2-observe: §7.
3. MIN.4: §8 corpus, measurement doc, runbook.

## Review disposition

| Seat | Finding | Disposition |
|---|---|---|
| v2 glm F1 HIGH | direct route unattributed | fixed (§2 direct scope, §3) |
| v2 glm F2 MED | refusals have no D1 record | closed by #2421; refusal record gains `tenants` (§3) |
| v2 glm F3 MED | task-local may not reach audit | superseded by M6 fix (§2) |
| v2 grok HIGH | direct route has a D1 record | correct (§3) |
| v2 grok MED | `data_classes` never empty | emission rule (§3) |
| H1 | direct route also runs `apply_response_gates` | verified (`direct_guards.rs:57`); single capture point, and direct now gets `data_classes` and MIN.2 (v2 said neither) |
| H2 | cache hits skip the gates | verified; superseded by v3 seat 1 F2 below |
| H3 | large tenant set → record > 4 MiB → call refused | verified (`transparency_log_append.rs:73`); cap 1024 + `tenants_total` (§3) |
| M6 | task-local ends before `audit_invocation` | verified; notes returned owned from the scope (§2) |
| v3 self-check | meta and direct firewalls are separate instances | MIN.2 window on `MetaMcp` (§7) |
| v3 seat 1 F1 MED | direct idempotency hit unattributed | verified (`backend_handlers.rs:1044`); third hit site covered (§2) |
| v3 seat 1 F2 MED | re-classifying cached (post-gate) content ≠ raw attribution | accepted; hits carry delivered-content tenants, marked, no classes, no MIN.2 (§2) |
| v3 seat 1 F3 MED | ad-hoc observer key loses `caller_key` guarantees | accepted; `caller_key` carried crate-private on both routes (§7) |
| v3 seat 1 F4 MED | counting `who` ≠ counting principals | accepted; `observer` fingerprint, runbook counts it (§7, §8) |
| v3 seat 1 F5 LOW | cap bounds the addition, not the record | claim qualified (§3) |
| v3 seat 1 F6 LOW | kernel 64 KiB sampling blind spot | documented (§4), corpus session added (§8) |
| v3 seat 1 citations | writer lines, task-local lines, HMAC `key_id`, cache-shared claim | corrected |
| v4 seat 2 H-a HIGH | MIN.2 observes content the later response firewall blocks | verified; observation defined as sensitive fetch, overcount bounded and measured, move-after-delivery set as an enforcement precondition (§7) |
| v4 seat 2 H-b HIGH | meta replay bypasses attribution and audit | verified; pre-existing D1-d gap, split to its own issue/PR; MIN.1 extends it and waits for it (§4) |
| v4 seat 2 M | `control_identity` ≠ raw `caller_key` | accepted; claim corrected, raw key used (§7) |
| v5 delta (GLM-5.3) SHIP, impr 1 | enforcement precondition is prose only | taken: T30 pins today's fetch semantics, so a change that adds enforcement without moving the observation must rewrite T30 in the same diff |
| v5 delta impr 2 | no test that a replay record carries `tenants` | taken: T31 |
| v5 delta impr 3 | carry the firewall finding id on an overcounted observation | deferred to 4.0.1: the D1 record and the NDJSON line already share `session_id` and time; not needed for observe mode |
