# v4-discovery progress

Worktree `feat/v4-discovery` @ 738c7cee. CATALOGUE.1 fix implemented, tested, gated,
committed. DISCOVERY.1 graded per-clause; clauses (a) and (c) (the two real gaps found)
are now also fixed, tested, and gated.

## Criteria owned
- **MIK-7332.DISCOVERY.1** (scope-update.md:51 / test row scope-tests.md:60): served-list vs
  routing-guide vs tiered-schema vs invoke-permission consistency, admin/nonadmin +
  configured/unconfigured.
- **MIK-7334.CATALOGUE.1** (scope-update.md:32 / test row scope-tests.md:40): backend
  catalogues/cached metadata isolated by verified caller+auth context, incl. rotation/revocation.

Authority: docs/requirements/RELEASE-4.0.0-scope-update.md + -scope-tests.md, supersedes design
docs dated <2026-09-06. scope-status.json rows both `pending`/`evidence:[]` — cite, don't edit.

## MIK-7334.CATALOGUE.1 — FIXED, landed

Root cause: `Backend::get_cached_list_shared` (src/backend/metadata.rs) always fetched/cached
over `PoolKey::Shared` — one connection shared by every caller regardless of identity
(`lifecycle.rs::ensure_started` hardcodes `PoolKey::Shared`; `ops.rs::request_internal` uses
`shared_transport()` only). A `session_mode = per_user` backend has no per-identity catalogue
fetch anywhere in the codebase, so serving the shared answer under any caller's identity is a
cross-identity leak of tool/resource/template/prompt catalogues.

**Dead lead ruled out during investigation**: the direct per-backend HTTP route
(`backend_handlers.rs`) is a raw live passthrough for every method — never touches these caches —
so it has no leak. The gap is exclusively in the meta_mcp aggregation path that reads these 4
caches.

**Fix** (advisor-gated, correcting an earlier "bypass the cache" framing that would have re-fetched
the same shared-credential answer and bought nothing): added `Backend::withholds_shared_metadata()`
— `true` when `session_mode() == Some(SessionMode::PerUser)` (the real discriminator, confirmed
live in `pool.rs::session_mode`/`pool_key_for`, not the `session_mode=per_user` string I'd
originally guessed at). `get_cached_list_shared` checks it first and returns `Ok(Arc::new(Vec::new()))`
without ever populating the cache — one guard at the single chokepoint all 4 `get_*_shared`
accessors share, so every downstream reader (`has_cached_tools`, `cached_tools_count`,
`get_cached_tool`, `get_cached_tools_snapshot`) naturally withholds too, since they all read
`tools_cache` etc. directly rather than re-deriving from a fetch. Isolation now holds by
construction (no per-user catalogue fetch exists), documented as such in the method's doc comment.

- `gitnexus_impact(get_cached_list_shared, upstream)`: impactedCount 8, **risk LOW**, 0 processes
  affected, 1 module (Backend, direct). Unchanged from the pre-edit baseline — the guard adds no
  new call-graph edges.
- Failing-test-first: `per_user_backend_withholds_shared_tool_cache` (src/backend/tests.rs) —
  constructs a `per_user` backend with **no transport configured**; asserts `get_tools()` returns
  `Ok(vec![])` rather than a transport error (proving the guard short-circuits before
  `ensure_started`/`request_internal`), and that `has_cached_tools`/`cached_tools_count`/
  `get_cached_tool` all read empty.
- `cargo test --quiet backend::`: 91/91 pass (new test included). Full `cargo test --quiet`: ran in
  background, see below for result.
- `cargo clippy --all-targets -- -D warnings`: clean. `cargo fmt --check`: clean (after `cargo fmt`).
- Files touched: `src/backend/metadata.rs` (+guard, +doc), `src/backend/tests.rs` (+1 test).

## MIK-7332.DISCOVERY.1 — graded per-clause (conjunction, not one verdict), NOW FIXED

Advisor correction accepted: grade each clause of the test row separately rather than one
monolithic not_met. (a) and (c) were `not_met`; both are now fixed with a thin post-filter
at the dispatch layer (no signature change to `handle_tools_list_for_session` or
`build_routing_instructions` — both were HIGH-risk-blast-radius per `gitnexus_impact`).

| Clause | Verdict | Evidence |
|---|---|---|
| (a) admin vs served list | **met** (fixed) | `filter_admin_tools_from_list` (`router/authorization.rs`) strips `ADMIN_META_TOOLS`-named entries from the `tools/list` response unless `client.is_some_and(|c| c.admin)`. Wired into the `"tools/list"` arm in `router/handlers.rs`, after `handle_tools_list_with_url_override`. Tests: `tools_list_withholds_admin_meta_tools_from_non_admin_caller`, `tools_list_serves_admin_meta_tools_to_admin_caller` (`router/tests.rs`). |
| (b) configured/unconfigured | **met** | Unchanged — same `MetaToolGates` struct reflecting live attachment state. |
| (c) routing guide vs client scope | **met** (fixed) | `filter_routing_guide_for_client` (`router/authorization.rs`) post-filters `initialize`'s finished `instructions` string: locates the `ROUTING_GUIDE_MARKER` (shared const, `meta_mcp_helpers.rs`), and rebuilds only the guide portion from `cap_backend.list_capabilities()` filtered through `client.can_access_backend(&cap_backend.name)` (whole-backend gate — `capability_backend_name` is one string shared by every capability in that backend, so this is a two-level check) AND per-capability `client.check_tool_scope(&cap_backend.name, &cap.name)`. Wired into the `"initialize"` arm in `router/handlers.rs`. No-op for an unscoped/anonymous client or when no capability backend is configured, preserving `b01_a_two_modern_connections_are_shown_the_same_tool_set`. Tests: `initialize_routing_guide_omits_capability_outside_allowlist` (per-capability filtering within an in-scope backend), `initialize_routing_guide_omits_backend_outside_scope` (whole-backend drop when out of scope), `initialize_routing_guide_unfiltered_for_unscoped_client` (regression guard for the invariant) — all in `router/tests.rs`. |
| (d) tiered schema (L0/L1/L2) | **met** | `search_disclosure.rs` (full file read) — correct, independent of scope. |
| (e) surfaced tools appear + execute | **met** | `tools_list_includes_surfaced_tool_when_in_backend_cache` and `tools_call_surfaced_tool_name_bypasses_meta_tool_dispatch` (meta_mcp/tests.rs) cover both halves. |
| (f) invalid-schema tool withheld, healthy tools remain | **met** | `prepare_tool_metadata_drops_only_the_violating_tool` / `..._drops_a_crlf_injection_attempt` / `..._excludes_and_annotates_in_one_pass` (backend/tests.rs). |

**Net**: row is now `met` — all 6 clauses pass. Deliberately left out of scope for clause (c) (noted
per advisor): `build_instructions`'s tool/server counts stay unfiltered — that's a different,
lower-stakes surface (aggregate counts, not named categories) and refiltering it would have meant
touching `build_instructions` itself, reopening the HIGH-risk blast radius this fix was designed
to avoid.

**Verification**: `cargo build --quiet` clean. `cargo test --quiet --lib -- gateway::router::` →
168/168 (was 165, +3 new). `cargo test --quiet --lib -- gateway::meta_mcp::` → 291/291 (unchanged,
including the `b01_a_two_modern_connections...` invariant). Full `cargo test --quiet` → 5347
passed, 26 ignored, 0 failed. `cargo clippy --all-targets --quiet -- -D warnings` clean.
`cargo fmt --check` clean. `detect_changes` (gitnexus) reports `risk_level: high` on the raw symbol
count touched (18 symbols across 6 files, largely doc/test churn) but the one named process it
flags — `b01_a_two_modern_connections_are_shown_the_same_tool_set → build_routing_instructions` —
is inside the 291/291 green meta_mcp suite; empirically no regression.

## Commits this branch (feat/v4-discovery)
- `69fbc31b`, `6566147c`, `febeb017` — docs-only PROGRESS.md checkpoints (superseded by this file).
- `728754c7` — CATALOGUE.1 fix (`fix(backend): withhold shared metadata cache for per_user backends`).
- DISCOVERY.1 (a)+(c) fix — see `git log` for SHA (committed after this file).

## Handback for team lead
- CATALOGUE.1: ship-ready, tested, gated, committed.
- DISCOVERY.1: all 6 clauses now `met`, tested, gated, committed.
