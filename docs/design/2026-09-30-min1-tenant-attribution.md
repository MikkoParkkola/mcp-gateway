# MIK-7116 4.0 slice: MIN.1 attribution, MIN.2 observe, MIN.4 measurement

Status: v3. v2 was reviewed by two seats (both SHIP-WITH-FIXES); a later
seat raised H1-H3 and M6, all verified at source and folded in below.
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
| Three D1 writers call `log_invocation_correlated`: meta invoke (D1-d), direct (D2), meta pre-dispatch refusal (#2421) | `meta_mcp/invoke/audit.rs:207`, `router/backend_handlers/direct_audit.rs:94`, `router/meta_refusal_audit.rs:51` |
| D1 domain fields are a `serde_json::Map`; the chain hash and HMAC cover every field but `entry_hash`/`sig`/`key_id` | `security/transparency_log.rs:379-411` |
| A record over `MAX_RECORD_BYTES` (4 MiB) fails the append; under `FailClosed` the call is then refused | `transparency_log_append.rs:73`, `transparency_log_rotation.rs:51` |
| `DISPATCH_FAILURE` is a task-local read inside `with_dispatch_scope` and returned as an owned value; `audit_invocation` runs **after** the scope ends | `meta_mcp/invoke/audit.rs:168-190`, `invoke.rs:1352-1363` |
| Idempotency and response-cache hits return before `apply_response_gates` | `invoke.rs:1890-1903`, `invoke.rs:~2015` |
| The response cache is shared across principals unless identity propagation binds it | `invoke.rs:45-49` |

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
- **Cache hits (H2):** both hit returns (`invoke.rs:1903`, `~2015`) are inside
  the scope. Each calls `note_cached_response(&cached)`, which notes response
  tenants and runs `ContextIntegrityKernel::evaluate` on the cached value for
  its `data_classes` (pure; same cost as the miss path's evaluation). A hit
  is recorded like a miss. This matters because the default cache is shared
  across principals (`invoke.rs:45-49`), so a hit can be the cross-principal
  read MIN.2 must see.

### 3. Representation and records

- **In memory:** raw ids in `BTreeSet<String>`; MIN.2 compares these.
- **On disk:** `tenants` = sorted `hash_argument(id)` (`security/data_flow.rs:139`,
  16 hex of SHA-256). Raw argument values are never logged; residual:
  guessable ids are reversible by enumeration ("not written raw", not
  "unlinkable").
- **Alongside `ContextDataClass`** = in the same D1 record: `data_classes`
  (snake_case, sorted) next to `tenants`. Kernel public types are unchanged.
- **Emission rule:** `tenants`, `data_classes` and the MIN.2 field are written
  only when the tenant set is non-empty, so default-config records keep their
  schema (`data_classes` is never empty and would otherwise appear on every
  record).
- **Cap (H3):** one crate-private writer,
  `TransparencyLogger::log_invocation_attributed(.., extra: serde_json::Map)`,
  used by all three D1 writers; `pub fn log_invocation_correlated` keeps its
  signature and delegates with an empty map. The writer keeps at most
  `MAX_RECORDED_TENANTS = 1024` sorted hashes and, when truncated, adds
  `tenants_total: N` as the overflow marker. A `const` assertion ties the cap
  to `MAX_RECORD_BYTES` (1024 × 19 B ≈ 19 KiB, far under 4 MiB), so a large
  tenant set can no longer push a record past the cap and refuse the call.
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

- Upstream task recovery runs outside a scope: request-side tenants only.
- Attribution needs the `firewall` feature (default-on) and `arg_keys`;
  records need the transparency log.
- Text blocks over 1 MiB are not parsed for tenants.

### 5. Public API

**None added.** Untouched: `AuditLogger::log_request`/`log_response`,
`TransparencyLogger::log_invocation_correlated` signatures; fields of
`ContextProvenance`, `ContextIntegrityClassification`, `FirewallVerdict`;
`TenantGuardConfig` keys. New items are `pub(crate)`; `with_dispatch_scope`
widens `pub(super)` → `pub(crate)` (crate-internal). Doc-only change on
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
  the owned notes. Cache hits count (§2).
- **Key:** `identity::caller_key` inputs as available per route:
  `grant_subject` → `subject:<authority>:<subject>`, else credential
  principal → `credential:<principal>`. No key → no observation, recorded as
  `cross_tenant: "unkeyed"`. `ponytail:` the meta caller context carries no
  `CertIdentity`, so an mTLS-only caller may key differently on the two
  routes; carry `caller_key` in `MetaMcpCallerContext` before enforcement.
- **Record:** `cross_tenant: "would_block"` (or `"unkeyed"`) only when it
  applies. The first read's record already carries `tenants` +
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
  for), a numeric id the phone pattern misreads, and true cross-tenant copy
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
  `arg_keys` with `enabled: false`, run one week, count distinct `who` with a
  `cross_tenant == "would_block"` record (checked-in `jq`), apply MIN.KILL:
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
| H2 | cache hits skip the gates | verified; hits note tenants and classify the cached value (§2); needed because the cache is shared across principals |
| H3 | large tenant set → record > 4 MiB → call refused | verified (`transparency_log_append.rs:73`); cap 1024 + `tenants_total` (§3) |
| M6 | task-local ends before `audit_invocation` | verified; notes returned owned from the scope (§2) |
| v3 self-check | meta and direct firewalls are separate instances | MIN.2 window on `MetaMcp` (§7) |
