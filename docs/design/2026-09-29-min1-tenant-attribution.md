# MIK-7116 4.0 slice: MIN.1 attribution, MIN.2 observe, MIN.4 measurement

Status: v2, after design review (grok SHIP-WITH-FIXES, glm SHIP-WITH-FIXES;
gpt seat unavailable, usage limit). Base: `docs/ranking-1-release-line` @ `e83b5fd5a`.

## Criterion

> MIK.MCPGW.MIN.1: Tool responses carry a tenant attribution alongside the
> existing `ContextDataClass`. Attribution is recorded in the audit trail
> whether or not it triggers a block.

Lead/operator scope decision 2026-09-29: the 4.0 slice is MIN.1, MIN.2 in
**observe mode**, and MIN.4 (fixture false-positive measurement plus the
one-week observe runbook implementing MIN.KILL). MIN.3/5/6 are post-4.0,
gated on that measurement. §1-6 are MIN.1; §7 is MIN.2-observe; §8 is MIN.4.

## What exists at the base

| Fact | Source |
|---|---|
| Tenant ids are read from request arguments only, under operator-configured `arg_keys`, at any depth | `firewall/tenant_guard.rs:62-63,138-158` |
| `TenantGuard::check` *records* tenants into a principal window as a side effect | `tenant_guard.rs:100-130` |
| A tenant reaches a record only on refusal, and then only as a count in a finding description | `firewall/mod.rs:471-514` |
| `ContextDataClass` is produced per response by the context-integrity kernel; never empty (defaults to `Public`) | `context_integrity/mod.rs:48`, `kernel.rs:432-442` |
| Firewall NDJSON audit writes a `request` entry for **every** request, allowed or refused, on both routes | `firewall/mod.rs:459-462`, `firewall/audit.rs:100-125` |
| D1 transparency log: one record per meta `gateway_invoke` (D1-d) and one per direct `/mcp/{name}` `tools/call` (D2) | `meta_mcp/invoke/audit.rs:68-140`, `router/backend_handlers/direct_audit.rs:94-147`, `backend_handlers.rs:510-515` |
| A meta-route firewall request refusal returns from `router/handlers.rs` (~1416-1452) **before** `invoke_tool`, so it has no D1 record | `handlers.rs`, `router/helpers.rs:75` |

## Design

### 1. Source of attribution (deterministic, the ticket's "phase 1")

One walker, factored out of `TenantGuard`'s private `collect`, using the
**same `arg_keys`**; no new configuration. Two `pub(crate)` entry points on
`TenantGuard`, both pure (no principal-window write):

- `request_tenants(&Value) -> BTreeSet<String>`: exactly today's walk. `check`
  is rewritten on top of it, so the guard and the attribution cannot disagree.
- `response_tenants(&Value) -> BTreeSet<String>`: the same walk, plus every
  `content[].text` block that parses as a JSON object/array (most MCP backends
  return JSON as text, not `structuredContent`). `ponytail:` text blocks over
  1 MiB are skipped (attribution miss); the response inspector already
  regex-scans the same text, so one linear parse is the same order of cost.

Sites:

| Side | Meta route | Direct `/mcp/{name}` route |
|---|---|---|
| Request | `Firewall::check_request` (feeds the NDJSON `request` entry and the guard) and `audit_invocation` (re-extracts from `args.arguments` for the D1 record) | `Firewall::check_request`, and `DirectCall` carries the set to `direct_audit::record` |
| Response | top of `MetaMcp::apply_response_gates`, on the **raw** backend result, before the contract gate or inspection can return `Err` and before context integrity can withhold it; carried to `audit_invocation` by a task-local | `direct_audit::record`, on the delivered `result` (after the firewall response pass; tenant ids are not credentials and survive redaction; a firewall-refused response yields request-side tenants only) |

Attribution is **active whenever `arg_keys` is non-empty**, independent of
`tenant_guard.enabled`; `enabled` continues to govern only whether the guard
may *refuse*. This is the observe-only rollout MIN.4 asks for. The `enabled`
doc comment changes to say so. Behaviour change: audit records gain fields;
nothing is refused that was not before.

No model passes (the ticket's phases 2-3); the KILL gate names
deterministic-only as the fallback.

### 2. Representation

- **In memory:** `BTreeSet<String>` of raw tenant ids. MIN.2 compares these
  in memory.
- **On disk:** each tenant as `hash_argument(id)` (the existing helper,
  `security/data_flow.rs:139`, 16 hex of SHA-256), sorted, field `tenants`.
  `firewall/audit.rs` states raw argument values are never logged, and a
  tenant id is an argument value. Operators correlate by hashing their own
  tenant list. Residual, recorded: short numeric or guessable ids are
  reversible by enumeration; the invariant is "not written raw", not
  "unlinkable".
- **"Alongside `ContextDataClass`"** is read as *in the same audit record*:
  the meta D1 record gets `tenants` next to `data_classes` (the kernel's
  `classification.data_classes`). The direct route runs no kernel, so its
  record has `tenants` only. The kernel's public types are **not** changed:
  `ContextProvenance` / `ContextIntegrityClassification` are `pub` structs
  with all-`pub` fields in a `pub mod`, so any field is a public-API break.
  Clean tool results stay byte-identical.
- **Emission rule:** `tenants` (and, on the meta route, `data_classes`) are
  written **only when the tenant set is non-empty**. A deployment without
  `arg_keys`, or a call touching no tenant, sees an unchanged schema. This
  matters because `data_classes` is never empty and would otherwise appear on
  every default-config record.

### 3. Where records are written

| Call outcome | Firewall NDJSON `request` entry | D1 record |
|---|---|---|
| Meta, allowed | `tenants` (request) | `tenants` (request ∪ response) + `data_classes` |
| Meta, refused by any firewall request rule incl. the tenant guard | `tenants` + the refusal finding | none (pre-existing D1-d gap) |
| Meta, response gate refuses (contract / inspection) | `tenants` (request) | `tenants` (request ∪ response), outcome not `ok`, no `data_classes` (never classified) |
| Meta, context integrity withholds | `tenants` (request) | `tenants` + `data_classes` of the raw content |
| Direct, allowed | `tenants` (request) | `tenants` (request ∪ delivered response) |
| Direct, refused by firewall | `tenants` + refusal finding | `tenants` (request); the D2 slot is filled at `backend_handlers.rs:624`, before the firewall check at `:1042`, so the refusal is recorded |

**Refusals are recorded in the firewall NDJSON audit.** On the meta route a
refusal has no D1 record before or after this change. MIN.1's "whether or not
it triggers a block" is met by the `request` entry, written for every request
on both routes. *Question for the lead:* is that acceptable, or must the
pre-existing D1-d gap be closed first (separate lane)?

Mechanics, all crate-private:

- Firewall NDJSON: private `AuditEntry` gains `tenants`, skipped when empty.
  New `pub(crate) fn log_request_attributed(.., tenants)`; the `pub fn
  log_request` keeps its signature and delegates with none.
- D1: new `pub(crate) fn TransparencyLogger::log_invocation_attributed(..,
  attribution)`; `pub fn log_invocation_correlated` keeps its signature and
  delegates with none. `recompute_entry_hash` (`transparency_log.rs:625`)
  hashes every field except `entry_hash`/`sig`/`key_id`, so the new fields are
  inside the chain and the HMAC; a test runs `verify_log` over such a record.
- Meta task-local: `gate_payload` → `apply_response_gates` is awaited inline
  at `invoke.rs:2559` inside `invoke_tool_traced`, which `invoke_tool` runs
  under `with_dispatch_scope`; `DISPATCH_FAILURE` already depends on this. The
  note is a no-op outside the scope (upstream task recovery: its D1 record
  keeps request-side tenants only).
- Direct: `DirectCall` (private) gains a `tenants` field, filled after
  `DirectCall::of` from `state.firewall`.

Attribution adds fields to existing records; it never adds a record.

### 4. What MIN.2 gets

Per call, tenant set + data classes in memory at `apply_response_gates`, and
the same in the D1 record. Recommended key for MIN.2, recorded so it is not
reopened: `caller_key`, the principal the tenant and budget guards already
use, so a block and the breadth limiter cannot be evaded through each other.
§7 implements the observe half of that.

### 5. Known gaps, not fixed here

- Meta-route firewall request refusals write no D1 record (pre-existing D1-d gap).
- Direct route: no `data_classes` (no kernel on that route).
- Attribution needs the `firewall` feature (default-on) and a configured
  firewall with `arg_keys`; response-side attribution needs the transparency
  log.

### 6. Public API

**None added.** Deliberately untouched: `AuditLogger::log_request` /
`log_response` and `TransparencyLogger::log_invocation_correlated`
signatures; fields of `ContextProvenance`, `ContextIntegrityClassification`,
`FirewallVerdict`; `TenantGuardConfig` keys. New items are `pub(crate)` only.
Doc change on a public item: `TenantGuardConfig::enabled` / `arg_keys`
(attribution runs when `enabled = false`).

### 7. MIN.2 in observe mode

> A session that has read sensitive data attributed to tenant A is blocked
> from reading sensitive data attributed to tenant B. Test proves the block
> fires, and proves the audit entry exists for both the read and the block.

Observe mode: the rule is evaluated and its verdict recorded; **nothing is
withheld**. "The block fires" is read as "the would-block verdict fires and
is recorded". Enforcement is a later switch, after MIN.KILL.

- **Sensitive** = the response's `data_classes` contains any of `Internal`,
  `PersonalData`, `FinancialData`, `HealthData`, `GuardedMaterial`. The other
  classes are not sensitive (instruction-likeness is a different threat, and
  the kernel already handles it).
- **Rule:** on a sensitive response with response tenants `R`, record each
  `t ∈ R` into a principal window of sensitive reads (a second
  `PrincipalWindow` inside `TenantGuard`, same `window_secs`). If the
  principal's distinct count exceeds 1, the verdict is **would-block**. One
  response carrying two tenants' sensitive data would-blocks on its own.
  Non-sensitive responses record nothing: a tenant directory listing is not
  a cross-tenant read.
- **Where:** `audit_invocation`, which already holds the caller and, via the
  task-local, the response tenants and data classes. `apply_response_gates`'
  signature is unchanged.
- **Key:** `grant_subject` → `subject:<authority>:<subject>`, else
  `credential_principal` → `credential:<principal>`. With no key there is no
  observation, recorded as `cross_tenant: "unkeyed"`. This matches
  `identity::caller_key` except for a certificate-derived subject, where
  `caller_key` uses the cert's id. `ponytail:` the meta caller context
  carries no `CertIdentity`, so the observe key can split one mTLS caller from
  its firewall key; carry `caller_key` in `MetaMcpCallerContext` before
  enforcement.
- **Record:** the D1 record gains `cross_tenant: "would_block"` (or
  `"unkeyed"`) only when it applies. The first read's record already carries
  `tenants` + `data_classes`, so "an audit entry for both the read and the
  block" is two D1 records, correlated by `who`.
- The request-side breadth guard (`tenant_guard.enabled`,
  `max_tenants_per_window`) is unchanged and independent.
- Direct route: no kernel, no `data_classes`, so no MIN.2 observation.
  Recorded gap.
- "Session" under statelessness is the principal over the window, for the
  reason `tenant_guard.rs:11-19` already gives.

### 8. MIN.4 measurement and the MIN.KILL runbook

> False-positive rate is measured against a fixture corpus before any
> blocking is enabled by default. Ship in observe-only mode first.

- **Corpus:** `tests/fixtures/mik_7116_min4_corpus.json`, a list of labelled
  sessions. Each session is a sequence of `(principal, arguments,
  backend_result)` steps, where `backend_result` is a real-shaped MCP tool
  result (text-JSON and `structuredContent`), plus a label `expect: "flag" |
  "clean"`. The measurement runs each step through the production extractor,
  the production `ContextIntegrityKernel` and the §7 rule, so classifier false
  positives are measured, not assumed away. About 15 sessions:
  single-customer support work, repeated reads, a directory listing, public
  docs, an incident review across tenants (labelled `clean`: legitimate, the
  case MIN.3 exists for, and an expected false positive), and true
  cross-tenant copy sessions (`flag`).
- **Check:** a lib test (the extractor is `pub(crate)`) computes the
  confusion counts (TP/FP/TN/FN) and asserts them against the numbers written
  in `docs/release/mik-7116-min4-fp-measurement.md`. A classifier change that
  moves the rate fails CI until that document is updated.
- **Default:** no enforcing mode exists, so "blocking not enabled by default"
  holds by construction; a test asserts a would-block response is delivered
  unchanged.
- **Runbook** (`docs/release/mik-7116-min-kill-observe-runbook.md`): set
  `arg_keys` with `enabled: false`, run one week, count distinct `who` with at
  least one `cross_tenant == "would_block"` record in the transparency log
  (the `jq` command is checked in), and apply MIN.KILL: fewer than 5 → ship
  MIN.1 only, no enforcement.

### Lead-relayed finding: direct path keyed to the backend

Refuted as written. `direct_control_identity` (`backend_handlers.rs:58`) keys
on `identity::caller_key`, the same function the meta route uses
(`handlers.rs:1398`). It falls back to the per-backend bucket only when there
is no key (authentication off). There the meta route falls back to a
per-request session id, which under statelessness pools nothing, so the
direct fallback is the stricter of the two. `session_owner_key` is the task
owner key and says so itself ("the firewall keys on
`identity::caller_key`"). No change.

## Review disposition

| Seat | Finding | Disposition |
|---|---|---|
| glm F1 HIGH | direct route unattributed | fixed: D1 direct record carries tenants (§1, §3) |
| glm F2 MED | refusals have no D1 record | acknowledged in body; question to lead (§3) |
| glm F3 MED | task-local may not reach audit | verified at source (§3); test T7 guards |
| grok HIGH | design wrongly said direct route has no D1 record | correct; fixed (§3) |
| grok MED | `data_classes` never empty → schema change | fixed: emission rule (§2) |
| grok MED | firewall response entry skipped when `scan_responses` off | moot: firewall response entry dropped in v2 |
| grok impr | reuse `hash_argument` | adopted |
| grok impr | plumb `caller_key` now | superseded by §7 (observation key) |
| grok impr | limit response extraction to tool results | moot: extraction only on tool-call results in v2 |

## Scope note

MIK-7116 carries a 2026-09-24 comment deferring the ticket to 4.1+. MIN.1
alone is the KILL gate's fallback ("implement the audit trail only"); the lead
owns the release decision.
