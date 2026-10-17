# MIK-8387 PR-B: a compiler-enforced boundary between a caller and the backend registry

Status: design **v2**, for a second review before any code. Base: release line `19ca01f07` (PR #3907, which carries PR-A). Ticket: MIK-8387, criterion ORACLE.5. Gap ticket: MIK-8447. The v1 review (two seats, SHIP-WITH-FIXES) is answered in §9.

## 1. Problem

ORACLE.5, as the ticket states it: a backend outside a scoped key's scope must be indistinguishable from a missing one on every route and response shape, the record must keep the scope reason, and this must be "enforced by a type boundary: caller-request code reaches backends only through a caller-scoped view (`ScopedBackends`), so the compiler finds every lookup site; `authorize_backend`'s refusal stays for non-call readers."

PR-A made the behaviour hold on every route that has a row, at eight hand-picked sites (S0 to S7). Each asks `ScopedBackends::absence` / `absent_step` before it reads the registry. Nothing stops the next change from adding a ninth read that skips the question: the field is a plain `Arc<BackendRegistry>`, so `self.backends.get(name)` compiles anywhere in the meta layer.

Two facts show the risk is real:
- **The d1 hand inventory missed reads.** It missed 20 multi-line reads.
- **One read sat in the wrong class.** `prepare_stored_read_kind` (`task_replay.rs:92`) runs before the stored-read scope check. Its warm path touches a per-user slot (`task_replay.rs:221-223`) before the scope-aware `refused_without_catalogue` (`:244`). That is gap S7a in MIK-8447.

## 2. The boundary

### 2.1 Types (all in `src/gateway/meta_mcp/scoped_backends.rs`)

The v1 design returned `&BackendRegistry` from `unscoped(class)`. Both seats found the hole: one pinned read could be wrapped in a helper, or its result stored, and every read after it compiles unclassified. v2 has **no path to the raw registry outside this module**. The registry's read shapes become operations that take a class at every call.

```rust
/// The meta layer's only handle on the registry. Its field is private to this
/// module; no method returns `&BackendRegistry` or `Arc<BackendRegistry>`
/// outside `#[cfg(test)]`.
pub(in crate::gateway) struct Registry(Arc<BackendRegistry>);

/// Why a read needs no caller grant. Documented per variant in the class table
/// file (§3.2), which T1 pins.
pub(in crate::gateway) enum Unscoped {
    Visibility,  // listings, surfaced names, the A3 predicate: decide through authorize_backend / admits_backend
    Discovery,   // search, catalogue fill and its accounting, code-mode candidates
    Background,  // upstream task polling and recovery, fan-outs that answer no backend name to the caller
    Admin,       // operator-only tools: stats, revive, reload
}

impl Registry {
    pub(in crate::gateway) fn new(inner: Arc<BackendRegistry>) -> Self;

    /// Call-path view. The capability provider's name is an input, because
    /// absence needs it: a name that is neither registered nor the provider
    /// is `Unregistered`.
    pub(in crate::gateway) fn scoped<'a>(
        &'a self,
        grant: BackendGrant<'a>,
        capability: Option<&'a str>,
    ) -> ScopedBackends<'a>;

    // Class-taking operations, one per read shape the meta layer uses today
    // (the counts are from §3):
    pub(in crate::gateway) fn get_for(&self, why: Unscoped, name: &str) -> Option<Arc<Backend>>;      // 'get'
    pub(in crate::gateway) fn all_for(&self, why: Unscoped) -> Vec<Arc<Backend>>;                     // 'all'
    pub(in crate::gateway) fn membership_for<R>(&self, why: Unscoped,
        read: impl FnOnce(u64) -> R) -> R;                                                            // 'with_membership'
    pub(in crate::gateway) fn subscribe_started_for(&self, why: Unscoped, ..);                       // 1 site
    pub(in crate::gateway) fn nudge_catalogue_for(&self, why: Unscoped, ..);                         // 1 site

    /// Tests reach the full registry without a class.
    #[cfg(test)]
    pub(in crate::gateway) fn for_test(&self) -> &Arc<BackendRegistry>;
}

impl ScopedBackends<'_> {
    /// New in PR-B. Scoped grant: `None` when `absence(name)` is `Some`.
    /// Empty grant: `None` for every name. Unscoped grant: the registry's answer.
    pub(in crate::gateway) fn get(&self, name: &str) -> Option<Arc<Backend>>;
    // absence() and absent_step() are unchanged from PR-A.
}
```

- **`ScopedBackends` holds what it needs.** It changes from holding `&MetaMcp` to holding `&BackendRegistry`, the capability name and the grant. Only `scoped_backends.rs` can build one.
- **`MetaMcp::scoped(grant)` stays as a forwarder.** It passes `self.get_capabilities()`'s name, so PR-A's eight call sites keep one signature. The capability name is read once per view and held there, the same name PR-A's `absence` reads today. A reload that changes the provider between two views of one request is out of scope, as it is today.
- **`MetaMcp.backends` changes type, not visibility.** It goes from `pub(super) Arc<BackendRegistry>` to `pub(super) Registry`. `MetaMcp::new(Arc<BackendRegistry>)` keeps its signature and wraps the argument.
- **`Unscoped` has four variants, down from v1's five.** v1's `Lifecycle` held two reads. The re-derivation in §3 moved `accessors.rs:74` to Visibility, as the review asked, and the other is the `events_hook.rs` accessor, which §2.4 deletes. Construction and registration happen on the startup `Arc` (`gateway/server/run.rs`, `self.backends`), never through `MetaMcp`.
- **`BackendRegistry` and its `pub fn get` (public API) do not change.**

### 2.2 What becomes impossible to write

- **A class-free read.** `Registry` has no `get`, `all`, `with_membership`, `subscribe_started` or `nudge_catalogue`, and no method that hands out the inner registry. Every read states either a grant (`scoped(grant, cap).get(..)`) or a class (`get_for(Unscoped::X, ..)`) at the read itself.
- **Escaping through a helper.** A helper that wraps a classified read returns backends, not the registry. Any further read it wants is again a class-taking call, which T1 finds and pins (§4).
- **Reaching the inner `Arc`.** The field is private to `scoped_backends.rs`. `for_test` is `#[cfg(test)]`, so a release build cannot call it. T1 also counts `for_test(` outside test files, and expects 0.

### 2.3 What the compiler cannot do, and what covers it

- **Whether a class is right.** Covered by T1 and the committed class table (§3.2, §4).
- **The router's `AppState.backends`** (`router/mod.rs:279`, `pub`, reachable through the doc-hidden `gateway::test_helpers`). Wrapping it would widen visibility; the lead ruled no widening. Covered by T2's token scan and ordering check (§4).
- **Readers that decide through `may_invoke` / `tool_visible_to`** rather than a lookup. Covered by rows only, as today.

### 2.4 Every production path that hands out the raw registry today, and how each closes

Found with `rg -n -U 'fn \w+[^{]*->\s*[^{]*BackendRegistry' src/gateway --glob '!*test*'` plus `rg -n -U 'Arc::clone\(\s*&self\s*\.\s*backends\s*\)|&self\.backends\b[^.]'` over `meta_mcp`:

| Path | Today | v2 |
|---|---|---|
| `MetaMcp::events_backend_registry` (`events_hook.rs:22`), used by `gateway/server/events_wiring.rs:39,61` and one stdio test | returns `Arc::clone(&self.backends)` | **Deleted.** `events_wiring::install` takes the startup `Arc` from its caller, `gateway/server/run.rs:290` (the `Gateway` already holds `self.backends`). The stdio test (`server/tests/route_matrix_stdio_tasks.rs:324`) reads its fixture's own `Arc`. |
| `ReloadContext.registry` (`config_reload/reload_context.rs:150`, a `pub` field of a `#[doc(hidden)] pub` module), reachable through `MetaMcp::reload_context()` (`accessors.rs:28`, `pub`) and `get_reload_context()` (`:23`) | the startup `Arc`, read only inside `src/config_reload` (reload is lifecycle: it registers and removes backends) | **Kept**, since changing a public field is an API change, and **pinned instead**. T1 adds the token class `reload_registry`: every `.registry` access on a `ReloadContext` in `src/`. It expects exactly the reads inside `src/config_reload` and **zero** in `src/gateway`. The UI handlers that call `reload_context()` pass the context to `config_reload` functions and never read `.registry`; T1 makes that a pinned fact. |
| `judge_stored_accounts` → `Self::unfilled_outcome_read(&self.backends, server)` (`task_replay.rs:553`) | passes `&BackendRegistry` to a helper that uses it only under `#[cfg(test)]` (`#[cfg(not(test))] let _ = backends;`) | The registry argument becomes `#[cfg(test)]`-only; the production call passes nothing. |
| `AccountDirectBridge::backends` (`account_direct_bridge.rs:181`) | returns the `Arc` | Test fixture: the module is `#[cfg(test)]` (`meta_mcp/mod.rs:529-530` → `account_resolver_fixture.rs:796`). It switches to `for_test()`. |

## 3. Call sites that change, counted

### 3.1 The search

Every read of `MetaMcp.backends`, at `19ca01f07`. `-U` makes a `self` and `.backends` split across two lines count. The enclosing fn and test status come from a scan of each hit, and the scan script lands with T1 so the table can be re-derived:

```
rg -U -n --no-heading '\bself\s*\.\s*backends\b' src/gateway/meta_mcp --glob '!*test*'
```

- **80 hit lines.** 7 of them are `#[cfg(test)]`: `direct_route.rs:246`, `invoke/propagation.rs:158`, `discovery_fetch.rs:372-373` (in `#[cfg(test)]` fns), `account_direct_bridge.rs:182,302` (a `#[cfg(test)]` fixture module) and `task_replay.rs:112` (a `#[cfg(test)]` statement). They leave the production table and switch to `for_test()`.
- **73 production reads in 27 files.**
- **By shape:** get 49, all 18, (handle) 2, with_membership 2, subscribe_started 1, nudge_catalogue 1.
- **By class:** scoped (caller grant) 26, Visibility 23, Discovery 14, Background 5, Admin 3, deleted (2.4) 1, cfg(test) argument (2.4) 1.
- **Test reads:** 47 lines in 26 files (`rg -U -c '\b(meta|meta_mcp|fx\.meta|m)\s*\.\s*backends\b' src/gateway --glob '*test*'`). Each becomes `for_test()`.
- **Router:** `rg -U -n '\.\s*backends\b' src/gateway/router` (all tokens, T2's grammar, §4) is pinned, not converted.

### 3.2 The class table

Re-derived from the scan in §3.1, with v1's errors corrected:
- `promoted_tools_for_session` (`accessors.rs:74`) is Visibility, not Lifecycle.
- The `#[cfg(test)]` reads leave the production table.

The table lands as one committed file, `src/gateway/meta_mcp/scoped_backends_classes.tsv`, with columns file, fn, class, count and reason. Each variant is documented in the file header. T1 reads the file, so the seat review of the classes is a review of one file, and every later class change is a one-file diff.

| File | Enclosing fn | Lines (shape) | Class |
|---|---|---|---|
| `accessors.rs` | `promoted_tools_for_session` | 74 (get) | Visibility |
| `account_outcome.rs` | `judge_account` | 161 (get) | scoped (caller grant) |
| `account_outcome.rs` | `judge_capability_accounts_for_task` | 113 (get) | scoped (caller grant) |
| `account_outcome.rs` | `target_account` | 37 (get) | scoped (caller grant) |
| `admission_replay.rs` | `mints_per_caller` | 102 (get), 103 (get) | scoped (caller grant) |
| `audience.rs` | `visible_digest` | 46 (get) | Visibility |
| `chain_receipt.rs` | `chain_mode_of` | 246 (get) | scoped (caller grant) |
| `chain_receipt.rs` | `chain_receive_for` | 227 (get) | scoped (caller grant) |
| `discovery_fetch.rs` | `code_mode_backend_candidates` | 305 (get), 306 (get), 311 (all) | Discovery |
| `discovery_fetch.rs` | `revalidate_caller_slots` | 155 (all) | Discovery |
| `events_hook.rs` | `events_backend_registry` | 23 ((handle)) | deleted (2.4) |
| `handlers.rs` | `backend_counts` | 194 (all) | Visibility |
| `handlers.rs` | `served_tools_list` | 275 (get) | Visibility |
| `invoke/admin.rs` | `get_stats` | 133 (all) | Admin |
| `invoke/admin.rs` | `reload_capabilities` | 317 (nudge_catalogue) | Admin |
| `invoke/admin.rs` | `revive_server` | 219 (get) | Admin |
| `invoke/caller_verdict.rs` | `caller_verdict` | 157 (get), 158 (get) | scoped (caller grant) |
| `invoke/caller_verdict.rs` | `dispatch_resolution` | 397 (get) | scoped (caller grant) |
| `invoke/caller_verdict.rs` | `live_refusal` | 120 (get) | scoped (caller grant) |
| `invoke/chokepoint.rs` | `authorize_requested_target` | 238 (get) | scoped (caller grant) |
| `invoke/gate.rs` | `fill_marks` | 294 (with_membership), 297 (get) | Discovery |
| `invoke/gate.rs` | `filled_since` | 316 (with_membership), 318 (get) | Discovery |
| `invoke/gate.rs` | `invisible_at_route` | 351 (get) | scoped (caller grant) |
| `invoke/gate.rs` | `named_gate_answer` | 564 (get) | scoped (caller grant) |
| `invoke/gate.rs` | `withheld_invoke_target` | 55 (get) | scoped (caller grant) |
| `invoke/policy.rs` | `check_invocation_policy` | 52 (get), 53 (get), 65 (get) | scoped (caller grant) |
| `invoke/propagation.rs` | `resolve_propagation_credential` | 47 (get) | Discovery |
| `invoke/step_fingerprint.rs` | `step_fingerprint` | 39 (get) | scoped (caller grant) |
| `listing_view.rs` | `listing_names` | 128 (get) | Visibility |
| `listing_view.rs` | `promoted_tools_for_caller` | 202 (get) | Visibility |
| `passthrough.rs` | `passthrough_instance` | 38 (get) | scoped (caller grant) |
| `protocol.rs` | `handle_logging_set_level` | 335 (all) | Background |
| `protocol.rs` | `handle_prompts_get` | 264 (get) | scoped (caller grant) |
| `protocol.rs` | `handle_prompts_list` | 165 (all) | Visibility |
| `resources.rs` | `find_resource_owner` | 460 (all) | Discovery |
| `resources.rs` | `handle_resources_list` | 309 (all) | Visibility |
| `resources.rs` | `handle_resources_templates_list` | 411 (all) | Visibility |
| `search.rs` | `collect_search_backend_matches` | 293 (all) | Discovery |
| `search.rs` | `list_tools` | 597 (all) | Visibility |
| `search.rs` | `list_tools_single_server` | 512 (get), 513 (get) | Visibility |
| `spec_preview.rs` | `collect_all_cached_tool_names` | 288 (all) | Discovery |
| `spec_preview.rs` | `collect_filtered_backend_tools` | 93 (all) | Discovery |
| `spec_preview.rs` | `resolve_tool_by_name` | 219 (all) | Discovery |
| `surfaced.rs` | `list_servers` | 261 (all) | Visibility |
| `surfaced.rs` | `resolve_surfaced_tool` | 179 (get) | Visibility |
| `surfaced.rs` | `surfaced_schema_withheld` | 134 (get) | Visibility |
| `task_confirmation.rs` | `classify_surfaced` | 309 (get) | Visibility |
| `task_replay.rs` | `cold_lease_remaining` | 376 (get) | scoped (caller grant) |
| `task_replay.rs` | `judge_stored_accounts` | 553 ((handle)) | cfg(test) argument (2.4) |
| `task_replay.rs` | `settle_caller_view` | 185 (get) | scoped (caller grant) |
| `task_replay.rs` | `settle_shared_view` | 271 (get) | scoped (caller grant) |
| `task_replay.rs` | `target_refused_without_catalogue` | 308 (get) | scoped (caller grant) |
| `task_replay.rs` | `unknown_server_refusal` | 520 (get) | scoped (caller grant) |
| `upstream.rs` | `cancel` | 266 (get) | Background |
| `upstream.rs` | `eligible` | 165 (get) | Background |
| `upstream.rs` | `recover_gated` | 523 (get) | Background |
| `upstream.rs` | `started` | 219 (subscribe_started) | Background |
| `visibility.rs` | `admits_tool_named` | 340 (all) | Visibility |
| `visibility.rs` | `admitted_counts` | 262 (all), 263 (all) | Visibility |
| `visible.rs` | `descriptor_blocked` | 251 (get) | Visibility |
| `visible.rs` | `keeps_per_user_catalogues` | 128 (get) | Visibility |
| `visible.rs` | `stored_target_view` | 173 (get) | Visibility |
| `visible.rs` | `visible_tool` | 87 (get) | Visibility |

Why the call-path reads are scoped and not classed: every "scoped" row above runs for one caller request with an `InvokeScope` in hand (§7.2 shows where the grant comes from for the two that do not take a scope today). On a correctly gated path no absent name reaches them, so `ScopedBackends::get` answers as today. If an absent name ever does arrive, `get` gives `None`, so a gating bug fails closed rather than leaking.

## 4. Rows

### 4.0 Step 0: the S7a fixture, settled before any row

`settle_caller_view` resolves its principal through `principal_for` (`direct_route.rs:199`) → `caller_principal` (`invoke/propagation.rs:166-174`):
- a managed-vault backend asks its vault (`vault.principal(caller)`);
- every other backend uses `caller.verified().map(Principal::Verified)`, the verified OIDC identity.

So:
- **A static API key alone has no principal on a per-user backend.** `CallerProof::Operator` carries no identity, and `settle_caller_view` returns at `:202` before any touch. Two static keys cannot share a slot, so v1's candidate (b), identity-mapped static keys, does not exist.
- **The caller that can reach the touch carries both a scoped client and a verified identity.** In production that is a key-server bearer. `auth.rs`'s key-server path inserts both the `AuthenticatedClient`, with `backends` from the token's scope, and the `VerifiedIdentity` (`identity.insert_into`). Two tokens for one OIDC subject with different `backends` scopes share `Principal::Verified(subject)`, and with it the warm slot.
- **The fixture:** the per-user fixture `meta_mcp::slot_verdict_fixture` (identity-bound, with resolve and list counters) combined with two key-server-style callers for one subject: one scoped `[beta]` (or `*`), one scoped `[alpha]`. If the key-server harness cannot be combined with that fixture in one router, the fallback is a static scoped key plus the same `VerifiedIdentity` extension on the request. That gives the same (client, identity) pair the key-server path produces, and step 0 confirms the auth middleware leaves the extension in place.

### 4.1 Rows, with their colour on the tip

T1 and T4 name types and operations that do not exist on the tip, so on the tip they do not compile. They land in the same commit as the types, and the commit before it is their red evidence. T2 is green on the tip: it pins today's router reads. FW1, C2 and R3 pin behaviour PR-A shipped, so they are expected green; they are guards and mutant killers, and if one is red, that is a new defect. S7a is the one behavioural red row.

| Row | What it asserts | Tip | Kills |
|---|---|---|---|
| **T1** class pin | Scan grammar in §4.2. Every class-taking operation in non-test `src/gateway`, keyed by (file, enclosing fn, op, variant) with a count, equals `scoped_backends_classes.tsv`. Plus three zero-pins: `for_test(` outside test files; `BackendRegistry` as a type in signatures and `let` bindings outside the allowlist; `.registry` on a `ReloadContext` inside `src/gateway` | no compile | M19: a `get_for(Unscoped::Visibility, ..)` added in `gate_answer` (new key). M19b: one Discovery read reclassed as Visibility, total unchanged. M19c: a helper returning `&BackendRegistry` added in `meta_mcp` (type zero-pin) |
| **T2** router pin | Scan grammar in §4.2. Every `.backends` token in `src/gateway/router`, including bindings made from one, keyed by (file, fn, use) and equal to a pinned list. Plus an ordering check on the direct route | green | M20: a `state.backends.get(name)` added in `read_envelope` before S4 (new key). M20b: `direct_caller::route(..)` moved before `direct_caller::read_envelope(..)` in `backend_handler_inner` (`backend_handlers.rs:467-484`), or `route`'s lookup moved into `read_envelope` above the S4 block (ordering) |
| **T4** view table | Registry `{alpha, beta}` plus capability `cap`. Grants `Scoped([alpha, ghost])`, `Scoped([alpha, cap])`, `Empty`, `Unscoped` (from `*` and from no client). Names alpha, beta, ghost, nosuch, cap. Each cell pins `get(name).is_some()`, `absence(name)`, and `absent_step(name, "t")` with and without a recorded `Withheld(Absent)`. The capability cells are built through `Registry::scoped(.., Some("cap"))` and through `MetaMcp::scoped`, which must agree | no compile | M31 (registration before scope), M32 (`Empty` as `Scoped([])`), M33 (`get` ignores the grant), M34 (`MetaMcp::scoped` passes `None` for the capability: `cap` turns `Unregistered`) |
| **FW1** response targets | A response-firewall rule keyed on target `X` and one keyed on the gateway's own target. Asserts the three cells are equal, **and** pins the verdict: the `X` rule applies to no cell, the gateway-target rule to all. Observed through the response firewall's own audit projection, the record of which rule fired, with no new seam | green | **M10, M23** (§5) |
| **C2** capability out of scope | Fixture with a capability provider outside the key's scope, against `nosuch`, on `/mcp` invoke: one answer, pinned | green | C2-mutant: S3's absent check moved below the capability arm (`gate.rs`) → `ToolNotFound` |
| **R3** stored-read reason | R2 (T0)'s `beta` cell emits the `audit_refusal` warning (tracing capture) naming -32003 and the scope; `ghost` emits none; answers equal under a failing log | green | M16: S7's `check_visible_policy` call removed |
| **S7a** warm and cold, excluded target | Fixture from §4.0. **Positive witnesses first:** the two callers resolve the same `stable_actor_id`, and the first one's call leaves a warm slot for it on `beta` (`holds_per_user_slot_for_test`). **Then the excluded read:** a `tasks/get` by the `[alpha]` caller of a task targeting `beta` must not touch the slot (slot age unchanged after `age_per_user_slot_for_test`). A cold variant, with the slot evicted first, asserts no custody read (the fixture's resolve counter is unchanged), no cold claim (`cold_lease_remaining` stays `None`) and no catalogue refresh (`beta`'s list counter is unchanged) | **red** | the §6 fix; mutant: the fix removed |

### 4.2 Scan grammars (T1, T2)

Both scanners are plain Rust tests: `include_str!`-free, reading the source tree from `CARGO_MANIFEST_DIR`, the way the repo's file-size and inventory checks read source. They are specified here so a reviewer can judge what they cannot see.

- **Files.** Every `*.rs` under the root; a file whose path contains `test`, or that is reached only through a `#[cfg(test)] mod`, is a test file and is skipped.
  - The list of `#[cfg(test)]`-only modules comes from the parent declarations: a `#[cfg(test)]` line directly above `mod x;` or `#[path = ..] mod x;`.
- **Masking.** Comments, `"…"` strings and raw strings are masked before matching, so a token in a doc comment or a string is not a read.
- **Enclosing fn.** For each match, the nearest preceding `fn <ident>` whose indentation is lower than the match's line. An item under `#[cfg(test)]`, the attribute anywhere in the item's attribute run, is skipped.
- **T1 operation tokens:** `(get_for|all_for|membership_for|subscribe_started_for|nudge_catalogue_for)\s*\(\s*Unscoped::(\w+)`, across lines. The key is (file, fn, op, variant). A call that names the class through a variable rather than a literal `Unscoped::X` fails T1 by itself: the class must be visible at the call.
- **T1 zero-pins:**
  - `\bfor_test\s*\(` in a non-test file;
  - `\bBackendRegistry\b` in a non-test file outside the allowlist: `backend/registry.rs`, `scoped_backends.rs`, `router/mod.rs` (the `AppState` field), `gateway/server/*` startup files, `config_reload/*`. Each allowlisted file's own count is pinned too;
  - `\.registry\b` in a `src/gateway` file that names `ReloadContext`.
- **T2 tokens:** `\.\s*backends\b` across lines in `src/gateway/router` non-test files.
  - A `let <ident> = <expr containing .backends>` makes `<ident>` a tracked binding for the rest of that fn, and each `<ident>.<method>` use is its own key.
  - A destructuring `backends` field pattern (`AppState { backends, .. }`) is tracked the same way.
  - The key is (file, fn, use), where use is `.backends.<method>` or `<binding>.<method>`.
- **T2 ordering:** in `backend_handler_inner`, the byte offset of `direct_caller::read_envelope(` must precede `direct_caller::route(`. In `read_envelope`, the `MIK-8387 S4` block must precede every `.backends` token in that fn, of which there are 0 today.

## 5. The surviving mutants M10 and M23

PR-A's mutant run left two alive:
- **M10** removes S1's `record_absent` (`chokepoint.rs`).
- **M23** keeps that write only for `OutOfScope`.

On an all-absent call S2 records the absence again, and mixed chains judge live at S2b′ and S3. So S1's memo matters only to the readers between S1 and S2: the route-stage caller verdicts, and `without_withheld`, which filters the response targets.

- **Under M10,** no cell is recorded at S1. Since PR-A, S1 returns early for `beta` too, so the registered arm never records it. `without_withheld` keeps target `X` for all three cells. The cells agree, but the verdict changes: the rule keyed on `X` now fires, where on the tip every target falls back to the gateway's own.
- **Under M23,** `beta` and `nosuch` are dropped, and `ghost` keeps `X`.

FW1 asserts both equality and the pinned verdict. The pin kills M10; equality kills M23.

**Observable (Kimi's improvement).** FW1 reads the response firewall's own audit projection, which records which rule fired for which target. If that projection cannot tell the targets apart on the miss answer, the next existing observable is the firewall verdict on a rule that refuses: the cell answers with the delivery refusal for `X` or does not. A new `#[cfg(test)]` seam is the last resort, taken only if both fail, and it would be reported as such.

## 6. The S7a fix, and the size

**S7a fix.** `prepare_stored_read_kind` (`task_replay.rs:92-146`) drops every stored target whose backend is absent for the reading caller's grant, before `fill_account_outcomes`, `keep_permanent_refusal`, `settle_caller_view` and `settle_shared_view`. That means `Scoped` grants only; `Empty` and `Unscoped` keep their behaviour, including MIK-8441's.
- After PR-B those helpers read through `scoped(..).get(..)`, which is `None` for an absent name, so the type closes the same hole. The explicit filter stays, so the row does not depend on every helper being converted.
- The S7a row checks the cold path too: no custody read, no claim, no catalogue refresh for an excluded target.

**Commits** (Kimi's improvement). The conversion is split per submodule, each commit compiling and keeping every PR-A row green:
1. types, `Registry::new`, the class table file, T1 and T4, with `MetaMcp.backends` still raw (T1 pins zero operation sites);
2. `invoke/` (gate, chokepoint, caller_verdict, policy, step_fingerprint, propagation, admin);
3. the stored-read files (`task_replay`, `account_outcome`, `admission_replay`, `chain_receipt`);
4. listing and visibility (`visible`, `visibility`, `listing_view`, `surfaced`, `handlers`, `audience`, `task_confirmation`, `accessors`);
5. discovery (`search`, `discovery_fetch`, `spec_preview`, `resources`, `protocol`);
6. background (`upstream`, `events_hook` deletion with `events_wiring`, `passthrough`);
7. the type flip: `MetaMcp.backends: Registry`, which the compiler accepts only once 2 to 6 are done.

The T1 table grows with each commit.

**Size** (from §3; the ± is a guess, not a measurement):

| Part | Files | Lines |
|---|---|---|
| Types, operations, `ScopedBackends::get`, forwarder | `scoped_backends.rs`, `meta_mcp/mod.rs` | +110 |
| Class table file | 1 new | +80 |
| 73 production reads, 2 escape closures | 27 + `events_wiring.rs`, `run.rs` | ~75 changed, +45 net |
| 7 cfg(test) reads + 47 test reads → `for_test()` | ~30 | ~54 changed |
| T1 scanner and pins, T2 scanner, pins and ordering | 2 new | +350 |
| T4 | 1 new | +130 |
| FW1, C2, R3, S7a rows and fixture | 4–5 new, 1–2 fixture edits | +550 |
| S7a fix | `task_replay.rs` | +10 |
| Docs, inventory rows | 3–4 | +40 |
| **Total** | **~75 files** | **~+1,300 / −130** |

## 7. Risks, visibility, and the reads with no grant in hand

### 7.1 Visibility. No widening; every new or changed item

| Item | Visibility | Note |
|---|---|---|
| `Registry` | `pub(in crate::gateway)` | Field private to `scoped_backends.rs` |
| `Registry::new`, `scoped`, `get_for`, `all_for`, `membership_for`, `subscribe_started_for`, `nudge_catalogue_for` | `pub(in crate::gateway)` | |
| `Registry::for_test` | `pub(in crate::gateway)`, `#[cfg(test)]` | |
| `Unscoped` (4 variants) | `pub(in crate::gateway)` | |
| `ScopedBackends::get` | `pub(in crate::gateway)` | |
| `MetaMcp.backends` | `pub(super)`, unchanged | Type changes to `Registry` |
| `MetaMcp::events_backend_registry` | `pub(crate)` → **removed** | A narrowing |
| `events_wiring::install` | `pub(super)`, unchanged | Gains a `&Arc<BackendRegistry>` parameter |
| `target_account` | `pub(crate)`, unchanged | Takes the caller's view (§7.2) |

- `BackendRegistry` and its `pub` methods are unchanged.
- `AppState.backends` (`pub`) and `ReloadContext.registry` (`pub` field) are unchanged. Both are covered by pins (T2, T1), not by the type, because changing them is API surface. The lead ruled out the widening that wrapping `AppState.backends` would need.
- The surface check (`scripts/release/check_surface_inventory.py`) must still exit 0; `src/lib.rs` does not change.

### 7.2 Grantless helpers and public compatibility methods (GPT improvement)

- **`target_account(server, tool)`** (`account_outcome.rs:36`, `pub(crate)`, 11 production callers). It changes to `target_account(&ScopedBackends, server, tool)`. Every caller already holds a scope:
  - `caller_verdict.rs:216`, `stored_proof.rs:126,201`, `task_replay.rs:159,212,233,548`, `account_outcome.rs:62,116` and `admission_replay.rs:101` take a `MetaMcpCallerContext` or an `InvokeScope`;
  - `call_dispatch.rs:574` sits in `first_unproven`, which takes the `MetaMcpCallerContext`.
  If implementation finds one with no caller, that site is classed `Unscoped::Visibility` in the table, with the reason, and the seat round sees it. It does not get a grant invented for it.
- **`resolve_propagation_credential`** (`invoke/propagation.rs:40`, `pub`, identity-only, no grant). Its signature is unchanged, because it is a public method. Its read is `get_for(Unscoped::Discovery, server)`: its one production caller is `discovery_fetch.rs:367`, the catalogue fill (the `pub` `resolve_propagation_headers` wrapper has no production caller), and it resolves a credential, not a name answer. T1 pins it, so a new call-path caller of this method is a new key in review.
- **`resolve_caller_credential`** (`propagation.rs:151`) is `#[cfg(test)]` and switches to `for_test()`.

### 7.3 Other risks

- **Misclassification.** The compiler forces a class but cannot check it.
  - Mitigation: one seat review of the one class-table file, then T1 makes every later change a one-file diff.
  - Residual: a read merged once and never touched again rests on that one review.
- **Answers that change where a call-path read was reachable with an absent name.** `ScopedBackends::get` is `None` there. On gated paths no answer changes, and every PR-A row must stay green unchanged. A row that turns red has found a reachable site: it gets a row and a reported fix, never an `Unscoped` to silence it.
- **Merge churn.** Each per-submodule commit is small (§6). The final type flip is one line plus the compiler's verdict. The open lanes rebase per commit, in a window agreed with them.
- **S7a fixture.** If neither the key-server harness nor the extension fallback (§4.0) gives one principal with two grants, S7a closes N/A with that trace. The §6 filter still ships, covered by a unit row on `prepare_stored_read_kind`'s target list.
- **Coverage and inventory.** New non-test functions on the COV.3 paths get rows: `Registry::*`, `ScopedBackends::get`, and the S7a filter if it becomes a helper. `check_inventory_rows.py <base> HEAD` and `--all` must exit 0.
- **Not done here:** `authorize_backend`, listing and search decisions, MIK-8441's empty-grant behaviour, and MIK-8446.

## 8. Order of work

0. **Step 0:** confirm the S7a fixture (§4.0). It decides whether S7a is red evidence or an N/A.
1. **Rows first, with their evidence:**
   - FW1, C2 and R3 as guards, with M10, M23, M16 and the C2 mutant run against them;
   - T2 with M20 and M20b;
   - S7a red.
2. **The conversion commits of §6, 1 to 7,** each on the fast gate (fmt, clippy with `--all-features` and with `--no-default-features`, the touched modules). T1 and T4 come with commit 1; M19, M19b, M19c and M31 to M34 are run once commit 7 lands.
3. **The S7a fix,** which turns S7a green.
4. **MIK-8447's gaps leave the pinned gap set** (`backend_oracle/gaps.rs`) as each gets its row, and the pin moves in the same commit.
5. **Mutants run in a scratch worktree:** anchor asserted once, VOID on a compile failure or an empty filter. The full suite runs in CI.

## 9. The v1 review, item by item

| Finding (seat) | v2 |
|---|---|
| HIGH: `unscoped()` returns `&BackendRegistry`, so a helper escapes T1 (both) | §2.1: class-taking operations only, with no raw return; T1 zero-pins `BackendRegistry` types and `for_test(` (§4.2) |
| HIGH: production accessors expose the registry, starting with `events_hook.rs:22` and `reload_context().registry` (GPT) | §2.4: the events accessor is deleted and wired from the startup `Arc`; `ReloadContext.registry` is pinned (zero reads in `src/gateway`); the two other paths close |
| MEDIUM: `scoped` has no capability input (GPT) | §2.1: `Registry::scoped(grant, capability)`; `MetaMcp::scoped` forwards it; T4's M34 |
| MEDIUM: T2 is textual and one hop (GPT, Kimi) | §4.2: full token scan with binding tracking and destructuring; ordering check; M20b |
| LOW: §4 header named T2 as non-compiling (Kimi) | §4.1: T1 and T4 only |
| Inventory errors: `accessors.rs:60`, cfg(test) readers (GPT) | §3: re-derived with the scan shown; one class-table file (Kimi) |
| Grantless helpers and public methods (GPT) | §7.2 |
| S7a fixture as step 0, positive witnesses, cold-path assertions (Kimi, GPT) | §4.0, S7a row, §8 step 0 |
| Per-submodule commits; FW1 fallback through an existing observable (Kimi) | §6 commits; §5 |
