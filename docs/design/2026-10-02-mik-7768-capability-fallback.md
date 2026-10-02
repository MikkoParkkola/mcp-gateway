# MIK-7768: capability `providers.fallback` is parsed and never executed

Status: accepted and implemented in #2677 (2026-10-02). Decides between MIK-FALLBACK.EXEC.1-3 (execute fallbacks) and
MIK-FALLBACK.EXEC.4 (refuse or warn at load, plus docs) for 4.0.0.

## Facts (base e5ba1a35f)

1. `ProvidersConfig::fallback` is filled by the custom deserializer
   (`src/capability/definition/mod.rs:183-206`) and validated per entry
   (`src/capability/validator/checks.rs:166-176`). `CapabilityDefinition::fallback_providers`
   (`definition/mod.rs:1051`) has no caller. The executor takes `primary_provider()` only
   (`src/capability/executor/mod.rs:371-373`).
2. The deserializer drops a malformed fallback entry silently (`if let Ok(provider) = ...`,
   `definition/mod.rs:192-199`); a malformed named provider is a parse error (`map.next_value()?`).
3. The other reads are the callback/mutating classification (`definition/mod.rs:1136-1146`), which
   counts fallback methods on the safe side, and trust inference (`src/trust/inference.rs:15`, `:30`),
   which uses the first fallback for transport and source URI only when no named provider exists.
   Both stay.
4. **No shipped capability declares `providers.fallback`.** The ticket's example,
   `capabilities/productivity/openpencil_design.yaml:70`, nests `fallback:` under
   `providers.primary.config`. `RestConfig` has no such field, so serde drops it; executing
   `providers.fallback` would not change that capability. (It also uses `service: mcp`, which
   `protocol_config` maps to REST with an empty `base_url`; a separate defect, filed separately.)
5. No public doc describes `providers.fallback`.

## What executing fallbacks would require (AC1-3)

- Error classification the executor does not have: "retryable or unavailable" (connect error,
  timeout on an idempotent method, 429/502/503/504) vs refusal (401/403, policy, firewall, account
  refusal, URL/egress refusal). Today errors are flattened into `Error` variants after
  `send_with_retry`.
- No fall-through once a non-idempotent request may have reached the primary (POST/PUT/PATCH after
  a timeout or 5xx): a second provider would repeat a side effect.
- Account binding and cache key are built from the capability and primary before dispatch
  (`executor/mod.rs:388-397`); a fallback answer would be cached under the primary's key.
- Egress is validated per provider inside `execute_provider_with_context`, so that part holds.
- Audit (AC3): the executor has no audit sink; per-attempt records mean threading provider names
  into the invoke-level audit in `gateway/meta_mcp`.
- `executor/mod.rs` is 812 lines; a split first.

That is a new resilience feature on the outbound path with zero consumers, landed during release
hardening.

## Decision proposed: AC4 for 4.0, execution later as a designed feature

1. New structural check **CAP-011** (CAP-010 is the file-name check) in `check_providers`: a capability that declares
   `providers.fallback` gets a **Warning**: "providers.fallback is not executed in 4.0; only
   providers.primary serves calls. Remove the block." The loader already logs every structural
   warning with path and code (`src/capability/loader.rs:117-139`). `cap validate` does not run the
   structural validator today (`src/commands/cap.rs:78-102`); that pre-existing gap is filed
   separately rather than widened here.
   Warning, not Error: the primary still works, and the retired-key precedent in
   `config::strict_keys` (`RETIRED_BACKEND_KEYS`) warns for keys that never had an effect.
   An Error would remove a working capability from the catalog.
2. A malformed fallback entry (null and blank included) becomes a parse error, like a malformed named provider, instead of
   being dropped (fact 2). Otherwise a capability whose only fallback entry is malformed would
   have an empty list and no CAP-011 warning.
3. Delete the dead nested `fallback:` from `openpencil_design.yaml` and re-pin its `sha256`.
4. Docs: one `UPGRADING-4.0.md` entry (load-time warning; capability still served; execution not in
   4.0) and a changelog fragment.
5. Delete the uncalled `CapabilityDefinition::fallback_providers` accessor, so the type stops
   advertising an execution path it does not have.
6. Out of scope, filed in Linear: `service: mcp` unsupported; unknown keys inside a provider
   `config` block load silently (the generic form of fact 4).

Alternative for reviewers: CAP-011 as Error (refuse the capability). Stronger signal, but turns a
working primary into a missing tool.

## Tests (red first on CI)

`src/capability/validator/tests/fallback.rs`:
- T1: a well-formed `providers.fallback` yields exactly one CAP-011 Warning on field
  `providers.fallback` saying it is not executed; red today (no such check).
- T2: a malformed fallback entry, list or single-map form, fails to parse; red today (dropped).
- T3: no `fallback`, no CAP-011 (control).
- T4: a capability with a fallback still loads through `CapabilityLoader` (Warning, not Error).

## Review (2026-10-02)

gpt-review and grok-review: both SHIP-WITH-FIXES, AC4 with a Warning. Fixes applied: CAP-011 not
CAP-010 (both); `cap validate` claim removed (gpt: remove; grok: wire it in, filed as follow-up);
trust inference readers listed; loader test added (T4); accessor deleted; UPGRADING wording.

## Falsifier

If any shipped or documented capability relies on `providers.fallback` executing, AC4 is wrong and
execution is required. Checked: `rg -n "fallback" capabilities docs` finds only the nested
openpencil key and unrelated prose.
