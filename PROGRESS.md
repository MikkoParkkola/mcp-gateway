# v4-discovery progress (mid-investigation, pre-code)

Worktree `feat/v4-discovery` @ 738c7cee, clean. No edits/tests/commits yet.
No `gitnexus_impact` run yet (owed, project MUST). No gpt/kimi review yet (brief not written).

## Criteria owned
- **MIK-7332.DISCOVERY.1** (scope-update.md:51 / test row scope-tests.md:60): served-list vs routing-guide vs
  tiered-schema vs invoke-permission consistency, admin/nonadmin + configured/unconfigured.
- **MIK-7334.CATALOGUE.1** (scope-update.md:32 / test row scope-tests.md:40): backend catalogues/cached
  metadata isolated by verified caller+auth context, incl. rotation/revocation.

Authority: docs/requirements/RELEASE-4.0.0-scope-update.md + -scope-tests.md, supersedes design docs
dated <2026-09-06. scope-status.json rows both `pending`/`evidence:[]` — cite, don't edit.

## CATALOGUE.1 — verdict: not_met (evidence solid)
- `src/backend/mod.rs:59-66`: one `CachedMetadata` per backend (tools/resources/templates/prompts), not
  identity-keyed.
- `src/backend/metadata.rs`: `get_cached_list_shared` (generic, ~96-131) backs all 4 `get_*_shared`
  accessors; none take an identity/caller param.
- `src/backend/lifecycle.rs:157-159` `ensure_started()` hardcodes `PoolKey::Shared`.
- `src/backend/ops.rs:20-30` `request_internal` uses `shared_transport()` only.
- `src/backend/pool.rs` (392L): `PoolKey::{Shared,PerUser}` isolates transport/session only, never
  metadata caches.
- `src/gateway/router/backend_handlers.rs:586-659`: direct route resolves per-user creds for caller-data
  methods but exempts `initialize|tools/list|ping` (line 604); line 625 comment confirms "no per-user
  cache" on this route.
- Contrast: call-RESULT caching already IS identity-isolated — `response_cache_key_for` takes
  `caller_principal` (invoke.rs:1442-1457,2102-2115), test asserts two principals differ
  (tests.rs:807-822). So results✅, catalogue/metadata❌.
- Prior ruling to cite: `docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md:544` — GPT pass
  confirmed cache not identity-scoped, ruled out of scope, filed as MIK-7334 — dated BEFORE the
  2026-09-06 scope-update that supersedes it.
- **Fix shape (advisor-corrected)**: do NOT re-key all 4 caches. Requirement text says "**Supported**
  identity-dependent... catalogues" + test's "Invariant shared catalogue is a separate positive control"
  ⇒ gateway never fetches a per-identity catalogue today. Minimal honest fix = ONE guard in
  `get_cached_list_shared` (the shared chokepoint): bypass/refuse the shared cache when backend
  `session_mode=per_user`, rather than identity-keying 4 caches. Ceiling to state explicitly in
  design+comment: "per-identity catalogues remain unfetched; isolation holds by construction (no
  per-user catalogue fetch exists yet), not by cache keying."
- **OPEN, not yet checked** (advisor's sharper lead, do this before writing code): does the direct route
  in `backend_handlers.rs` actually call `get_resources_shared()`/`get_prompts_shared()` (the ONE shared
  cache) *after* resolving per-user creds for `resources/list`/`prompts/list`? backend_handlers.rs:593-598
  lists those as caller-data methods needing per-user creds, but metadata.rs:159-232 still serves them
  from the single shared cache — need to confirm whether that's a live cross-identity leak (sharper than
  "unkeyed cache") or dead code on that path.

## DISCOVERY.1 — verdict: not_met (evidence solid, framing corrected by advisor)
- `src/gateway/search_disclosure.rs` (full file, 296L): L0/L1/L2 tiered disclosure works correctly — NOT
  the gap.
- `src/gateway/meta_mcp_helpers.rs:314-364` `build_routing_instructions`: builds the "Routing Guide" from
  ALL `cap.list_capabilities()`, grouped by category — no identity/scope filter.
- `src/gateway/meta_mcp/mod.rs:1322-1343` `build_instructions()`: calls `build_routing_instructions` with
  no caller/auth param anywhere in the chain.
- `handle_initialize` sig (mod.rs:1270-1319): `(id, params, session_id, header_profile, era)` — no
  `AuthenticatedClient`. Confirmed at dispatch site too: `router/handlers.rs:1135-1141` passes no auth
  object into `handle_initialize`. ~20 call sites total incl. `spec_preview.rs:582` + test corpus (not
  yet fully enumerated via gitnexus).
- `src/gateway/auth.rs:330-380`: `AuthenticatedClient{allowed_tools,denied_tools,admin,backends,...}`,
  `can_access_backend()` (366), `check_tool_scope()` (378, allow→deny→fallback glob).
- `mod.rs:1699-1701`: `is_admin_meta_tool && !caller.is_admin` — this gate is for META-TOOL invocation
  only, NOT for what the routing guide lists.
- **Advisor's key correction — brief must use this framing**: admin-gate axis and routing-guide axis
  don't intersect (guide lists `capability_backend`/`cap.name` categories, not meta-tools). The real
  disagreement axis is **client tool scope** (`allowed_tools`/`denied_tools` globs + `backends` list):
  e.g. a key scoped to `fulcrum/gmail_*` still receives a guide naming ~20 unrelated categories it can't
  use. Do NOT frame this as admin/nonadmin meta-tool gating.
- `check_tool_scope`/`can_access_backend` callers found: `authorization.rs:113` (`can_access_backend`),
  `:131` (`check_tool_scope`); `backend_handlers.rs:460`; `config/features/auth.rs:181` (separate impl);
  `ui/control_plane.rs:757`.
- **OPEN, not yet checked** (queued next before compaction hit): open `src/gateway/router/authorization.rs`
  ~lines 100-140 to confirm which JSON-RPC method(s) it gates — tools/call only, or also tools/list? This
  determines whether the served tools/list itself already filters by scope while the routing guide text
  doesn't (a sharper, more precise mismatch than a blanket "no filtering anywhere").
- `tests/tool_list_tests.rs` (43L), `tests/schema_2020_12_validity.rs` (517L, hits @150/159/170/275 —
  2020-12 schema validator/falsifier, relevant to the "invalid schema tool withheld" test-row clause) —
  not yet cross-read against the scope-mismatch finding above.

## Next steps (in order)
1. Read `src/gateway/router/authorization.rs` ~100-140 → confirms tools/list scope-filtering status.
2. Confirm/deny the backend_handlers.rs resources/prompts shared-cache leak lead above.
3. Run `gitnexus_impact` on `get_cached_list_shared` and on `build_instructions`/`build_routing_instructions`
   (owed MUST, not yet done).
4. Write design doc (2 short sections, one per criterion) with the corrected fix shapes above.
5. gpt-review/kimi-review the brief.
6. Failing tests first, then implement, then `gitnexus_detect_changes`, then commit.

Status: **mid-investigation, zero code changes**. This file itself is the durable checkpoint requested by
team lead after output-token-ceiling kills on peer agents.
