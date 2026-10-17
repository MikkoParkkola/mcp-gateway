# MIK-8387 PR-B: a compiler-enforced boundary between a caller and the backend registry

Status: design **v4**, the last revision before code. The boundary is enforced by a clippy lint banning every `BackendRegistry` method (§2). Rounds 1 to 3 are answered in §9 to §11. Base: release line `19ca01f07` (PR #3907, which carries PR-A). Ticket: MIK-8387, criterion ORACLE.5. Gap ticket: MIK-8447. 

## 1. Problem

ORACLE.5, as the ticket states it: a backend outside a scoped key's scope must be indistinguishable from a missing one on every route and response shape, the record must keep the scope reason, and this must be "enforced by a type boundary: caller-request code reaches backends only through a caller-scoped view (`ScopedBackends`), so the compiler finds every lookup site; `authorize_backend`'s refusal stays for non-call readers."

PR-A made the behaviour hold on every route that has a row, at eight hand-picked sites (S0 to S7). Each asks `ScopedBackends::absence` / `absent_step` before it reads the registry. Nothing stops the next change from adding a ninth read that skips the question: the field is a plain `Arc<BackendRegistry>`, so `self.backends.get(name)` compiles anywhere in the meta layer.

Two facts show the risk is real:
- **The d1 hand inventory missed reads.** It missed 20 multi-line reads.
- **One read sat in the wrong class.** `prepare_stored_read_kind` (`task_replay.rs:92`) runs before the stored-read scope check. Its warm path touches a per-user slot (`task_replay.rs:221-223`) before the scope-aware `refused_without_catalogue` (`:244`). That is gap S7a in MIK-8447.

## 2. The boundary

### 2.0 Enforcement is a clippy lint (since v3)

The repo already bans calls this way for the wall clock (MIK-8202) and the home directory (MIK-8001). `clippy.toml` lists `disallowed-methods`, and CI runs `clippy --all-targets -D warnings` on both feature sets. v3 showed the lint resolves every access shape (§2.2). v4 makes the list complete and pins it.

### 2.1 The ban, complete by construction (v4)

`BackendRegistry` (`backend/registry.rs:133`) has no derives and one trait impl, `Default` (`:600`). It has no `Deref`, `IntoIterator`, `Serialize` or `Debug`. Its inherent methods are `new` plus 18 more:

`subscribe_started`, `reload_read_slot`, `lock_reload`, `register`, `observe_breakers`, `enforce_destinations`, `set_change_feed`, `catalogue_hook`, `nudge_catalogue`, `nudge_catalogue_scanned`, `resolve_unwarmed`, `with_membership`, `get`, `all`, `statuses`, `remove`, `is_stopping`, `stop_all`.

v3 banned five reads. GPT r3 showed that `remove` leaks membership through its `bool`, and so does `register`. v4 therefore bans **all 18**: every method except `new` and `Default::default`. That way none has to be judged "harmless", and each call site states its class at a leaf allow.

T1(e) pins this surface: the method list, the trait-impl list (`Default` only) and the derive list (none). A new method, derive or trait impl on `BackendRegistry` is a red test and a reviewed diff (Kimi r3).

The `clippy.toml` block gets 18 entries, each with the reason "go through `Registry` or a leaf allow naming its class (MIK-8387)". **T1(f) pins the block itself, entry for entry** (Kimi r3 HIGH): it is the whole enforcement, so weakening it is a red test, not a green build.

### 2.2 Evidence (Spark, 2026-10-17)

**A. Standalone crate** (§2.2 of v3). Every access shape was flagged: field chain, chain through a call, alias, function-item binding, fully qualified call, inferred binding, and test code. A module allow silenced only its own module. v4 commits that crate as a **negative compilation fixture**, `scripts/lint-fixtures/registry-ban/` (GPT r3). Each violating line carries a `//~ disallowed` marker. A small script runs `cargo clippy` there and asserts that the set of flagged lines equals the marked set. CI runs it with the other script checks, so a toolchain change that stops resolving a path, an alias or a function-item binding turns it red.

**B. The real crate at `19ca01f07`, all 18 methods banned** (probe 2), with `spark-cargo clippy --all-targets --all-features -D warnings`. No unresolved-path warning.
- **Production (lib target): 126 sites in 59 files.**
  - Reads: `get` 70, `all` 31, `with_membership` 2, `statuses` 1, `subscribe_started` 1.
  - Other operations: `register` 3, `enforce_destinations` 3, and 2 each of `nudge_catalogue`, `lock_reload`, `set_change_feed`, `stop_all` and `catalogue_hook`. Then 1 each of `nudge_catalogue_scanned`, `remove`, `reload_read_slot`, `resolve_unwarmed` and `observe_breakers`.
  - By area: `gateway/meta_mcp` 66, `gateway/server` 21, `config_reload` 12, `events` 10, `gateway/ui` 7, `gateway/router` 6, `capability` 2, `backend` 1, `streaming_session.rs` 1.
- **All targets: 634 sites in 280 files**, nearly all in test fixtures (`register` 272, `get` 241, `remove` 29).

### 2.3 Types (in `src/gateway/meta_mcp/scoped_backends.rs`)

As v3, with two changes: the scoped read has its own operation name (both seats, r3), and `Lifecycle` returns as an allow-reason class.

```rust
pub(in crate::gateway) struct Registry(Arc<BackendRegistry>);       // field private to this module

pub(in crate::gateway) enum Unscoped { Visibility, Discovery, Background, Admin, Lifecycle }

impl Registry {
    pub(in crate::gateway) fn new(inner: Arc<BackendRegistry>) -> Self;
    pub(in crate::gateway) fn scoped<'a>(&'a self, grant: BackendGrant<'a>,
                                         capability: Option<String>) -> ScopedBackends<'a>;
    pub(in crate::gateway) fn get_for(&self, why: Unscoped, name: &str) -> Option<Arc<Backend>>;
    pub(in crate::gateway) fn all_for(&self, why: Unscoped) -> Vec<Arc<Backend>>;
    pub(in crate::gateway) fn membership_for<R>(&self, why: Unscoped, read: impl FnOnce(u64) -> R) -> R;
    pub(in crate::gateway) fn statuses_for(&self, why: Unscoped) -> HashMap<String, BackendStatus>;
    pub(in crate::gateway) fn subscribe_started_for(&self, why: Unscoped) -> broadcast::Receiver<String>;
    pub(in crate::gateway) fn nudge_catalogue_for(&self, why: Unscoped, name: &str);
    #[cfg(test)] pub(in crate::gateway) fn for_test(&self) -> &Arc<BackendRegistry>;
}

impl ScopedBackends<'_> {
    /// The scoped read. Named distinctly, so its receiver class follows from the
    /// name, whether the view is chained or bound (`let view = ..; view.scoped_get(..)`).
    pub(in crate::gateway) fn scoped_get(&self, name: &str) -> Option<Arc<Backend>>;
    // absence(), absent_step(): unchanged
}
```

- `scoped_backends.rs` holds the only `#[allow(clippy::disallowed_methods)]` in the meta layer. It sits on each operation's one raw call expression, not on the module.
- `MetaMcp::scoped(grant)` forwards the owned provider name.
- `MetaMcp::registry(&self) -> &Registry` (`pub(in crate::gateway)`) is new, for the router choke point (§2.5).

### 2.4 Leaf allows, and the allows that already exist

**Rule (GPT r3 HIGH, Kimi r3 LOW).** A sanctioned raw call carries `#[allow(clippy::disallowed_methods, reason = "<Unscoped variant>: <why>")]` on the **statement or expression** that holds it, never on a fn, impl or module. The reason starts with one of the five `Unscoped` names (Kimi r3). The production sites outside the meta layer get leaf allows: 54 of the 60, with the router's 6 going through the choke point (§2.5). By class:

| Area | Sites | Class |
|---|---|---|
| `gateway/server` | 21 | Lifecycle (startup, registration, stop) and Background (warmstart, tools-changed feed) |
| `config_reload` | 12 | Lifecycle (reload registers and removes) |
| `events` | 10 | Background |
| `gateway/ui` | 7 | Admin |
| `capability` | 2 | Lifecycle (catalogue hook) |
| `backend` | 1 | Lifecycle (the registry's own internal call) |
| `streaming_session.rs` | 1 | Background |

**T1(b)** pins every production allow of `clippy::disallowed_methods`, crate-wide, by (file, enclosing fn, reason class) **with its complete contents**: the raw `BackendRegistry` calls inside the attributed statement. One raw call per allow is the rule. A second call inside an allowed statement, or a growing allowed block, is a red diff.

**Allows that already exist** (for MIK-8202's clock and MIK-8001's home directory; a clippy allow is lint-wide, not per path):
- **Production:** item-level allows in `home_dir.rs` and `commands/paths.rs`, and the inner allow of the `clock.rs` module itself. None contains a `BackendRegistry` call. T1(b) pins their registry-call content at 0, so a registry read added inside one is red.
- **Test modules:** 11 `#![allow(..)]` / `#![cfg_attr(test, allow(..))]` inside `#[cfg(test)]` modules of production files, and about 90 test files with module allows for the clock. These exempt registry reads in that test code too. That is accepted, see §2.7.

### 2.5 The router choke point

- `router/backend_choke.rs` holds the router's only registry reads: `backend_for(state, grant, name)` and `backends_for(state, why)`.
- They read through `state.meta_mcp.registry()`, the `Registry` `MetaMcp` already stores, over the same `Arc` as `AppState.backends` (Kimi r3). Nothing is re-wrapped per call, and `AppState` is unchanged.
- **Capability (Kimi r3).** Router grants can name the capability provider: a key's `backends` list may hold its name. So `backend_for` builds its view with the provider name from `state.meta_mcp.get_capabilities()`, the same as `MetaMcp::scoped`, and its answer equals `ScopedBackends::scoped_get` for every grant. T4 gets a router cell to show that.
- **References (GPT r3 HIGH).** T2(c) pins **every production reference** to `backend_for` and `backends_for` across the crate, function-item references included, by (file, enclosing fn). A new indirect reader, such as a helper called before S4, changes the inventory and is red.

### 2.6 The grantless propagation APIs (GPT r3 HIGH and MEDIUM)

`MetaMcp::resolve_propagation_credential` and `MetaMcp::resolve_propagation_headers` (`invoke/propagation.rs:20,40`, both `pub`, identity-only) join `clippy.toml`'s `disallowed-methods` too, with reason "grantless: thread the caller's view, or take a leaf allow (MIK-8387)".
- **Correction to v3's "zero" baseline:** there is one production reference, the forwarding edge `resolve_propagation_headers` → `resolve_propagation_credential` at `propagation.rs:26`. It takes the only leaf allow (reason `Discovery: the headers API forwards to the credential API`).
- The other reference, `discovery_fetch.rs:367`, is in the `#[cfg(test)]` fn `seed_caller_slot_for_test`.
- T1(b) pins the forwarding allow. Any new production reference, a function-item binding included, is a clippy error (§2.2 A covers that shape).

### 2.7 Test code

The test target holds 508 of the 634 sites. Clippy has no per-entry test exemption for `disallowed-methods`. The repo's existing practice for MIK-8202 is a module-level `#![cfg_attr(test, allow(clippy::disallowed_methods, reason = ".."))]` in each test module that reads the clock (AC.14).
- **v4 follows it:** each test module that builds or reads a registry takes the same one-line inner allow, with reason `Lifecycle: test fixture builds and reads the registry (MIK-8387)`. That is about 221 test files, the 280 with violations less the 59 production files. The roughly 90 test files already allowed for the clock reported none and need nothing.
- **Test code is outside ORACLE.5.** It is not a caller path, so T1 pins production allows only.
- **The rejected alternative:** one crate-root `#![cfg_attr(test, allow(clippy::disallowed_methods))]` would be a single line. But it would also lift MIK-8202's per-module test discipline for the clock, which is that ticket owner's call, not this one's.

## 3. Call sites that change, counted

### 3.1 The search

**v4:** this lexical scan predates the lint. It uses a filename filter (`--glob '!*test*'`) and is kept only as the key for the class table. The authoritative inventory is the lint (§2.2 B), and test-ness in every pin comes from cfg ancestry (§4.2), never filenames (Kimi r3).

Probe 2 (§2.2 B) finds 126 production sites in 59 files, 66 of them in the meta layer. The lexical count below covers only `MetaMcp.backends` in `meta_mcp`; one multi-line chain can hold two reads.

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

The table lands as one committed file, `src/gateway/meta_mcp/scoped_backends_classes.tsv`, with columns file, enclosing fn, operation (`scoped_get`, `get_for`, `all_for`, `membership_for`, `statuses_for`, `subscribe_started_for`, `nudge_catalogue_for`), class, count and reason (GPT r2). **v4 drops the receiver-type column** (GPT r3): the receiver follows from the operation name, `scoped_get` on `ScopedBackends` and every `*_for` on `Registry`. A reason starts with its `Unscoped` variant name. Each variant is documented in the file header. T1 reads the file, so the seat review of the classes is a review of one file, and every later class change is a one-file diff.

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

Why the call-path reads are scoped and not classed: every "scoped" row above runs for one caller request with an `InvokeScope` in hand (§7.2 shows where the grant comes from for the two that do not take a scope today). On a correctly gated path no absent name reaches them, so `ScopedBackends::scoped_get` answers as today. If an absent name ever does arrive, `scoped_get` gives `None`, so a gating bug fails closed rather than leaking.

## 4. Rows

### 4.0 Step 0: the S7a fixture, settled before any row

`settle_caller_view` resolves its principal through `principal_for` (`direct_route.rs:199`) → `caller_principal` (`invoke/propagation.rs:166-174`):
- a managed-vault backend asks its vault (`vault.principal(caller)`);
- every other backend uses `caller.verified().map(Principal::Verified)`, the verified OIDC identity.

So:
- **A static API key alone has no principal on a per-user backend.** `CallerProof::Operator` carries no identity, and `settle_caller_view` returns at `:202` before any touch. Two static keys cannot share a slot, so v1's candidate (b), identity-mapped static keys, does not exist.
- **The caller that can reach the touch carries both a scoped client and a verified identity.** In production that is a key-server bearer. `auth.rs`'s key-server path inserts both the `AuthenticatedClient`, with `backends` from the token's scope, and the `VerifiedIdentity` (`identity.insert_into`). Two tokens for one OIDC subject with different `backends` scopes share `Principal::Verified(subject)`, and with it the warm slot.
- **Status (v3, GPT r2):** S7a stays **unresolved** until its positive-witness integration row passes. The trace above shows the touch is reachable in production, through the key-server path. Fixture trouble would show only that the fixture cannot reach it, never that production cannot.
- **The fixture:** the per-user fixture `meta_mcp::slot_verdict_fixture` (identity-bound, with resolve and list counters) combined with two key-server-style callers for one subject: one scoped `[beta]` (or `*`), one scoped `[alpha]`. If the key-server harness cannot be combined with that fixture in one router, the fallback is a static scoped key plus the same `VerifiedIdentity` extension on the request. That gives the same (client, identity) pair the key-server path produces, and step 0 confirms the auth middleware leaves the extension in place.

### 4.1 Rows, with their colour on the tip

L (the lint) is red on the tip with 126 production violations (634 across all targets); it turns green with the type flip. T1 and T4 name types and operations that do not exist on the tip, so on the tip they do not compile. They land in the same commit as the types, and the commit before it is their red evidence. T2 lands with the choke point (§6 commit 4); the commit before it, with the six router reads inline, is its red evidence. FW1, C2 and R3 pin behaviour PR-A shipped, so they are expected green; they are guards and mutant killers, and if one is red, that is a new defect. S7a is the one behavioural red row.

| Row | What it asserts | Tip | Kills |
|---|---|---|---|
| **L** the lint | `clippy.toml` bans all 18 `BackendRegistry` methods (all but `new` and `Default`) and the two grantless propagation APIs (§2.1, §2.6). CI runs `clippy --all-targets -D warnings` with both feature sets, plus the negative-fixture script (§2.2 A) | 126 production violations are the red evidence (§2.2 B); green from the type-flip commit | M19: a raw read added anywhere in production. M19c: a helper that returns the raw registry and is then read. M19f: a new production reference to `resolve_propagation_credential`, a function-item binding included |
| **T1** pins (§4.2) | (a) The class-taking operation call sites, by (file, enclosing fn, operation, class), equal `scoped_backends_classes.tsv`. The receiver follows from the operation name: `scoped_get` is the scoped view, `*_for` is `Registry`. (b) Every production `disallowed_methods` allow, crate-wide, by (file, fn, reason class), with its complete raw-call content. (d) `Registry::new` call sites. (e) `BackendRegistry`'s method set, trait impls and derives. (f) The `clippy.toml` `disallowed-methods` block, entry for entry | no compile (the types are absent) | M19b: one class swapped, total unchanged. M19d: a new allow, or a second raw call inside one. M19g: a `clippy.toml` entry deleted or its path changed. M19h: a new `pub fn` on `BackendRegistry` |
| **T2** router choke point | (a) The router holds no `disallowed_methods` allow at all once commit 5 lands: the choke point reads through `Registry` (via T1(b)). (b) Order, structurally: `route` takes `&Envelope`, and `Envelope { .. }` literals in production occur only in `read_envelope`. (c) Every production reference to `backend_for` / `backends_for`, function-item references included, by (file, enclosing fn), equals the pinned list. `read_envelope` is not in it | green after the choke-point commit | M20: a `backend_for` call added in `read_envelope` before S4 (c). M20b: `route` called before `read_envelope` (b). M20c: a helper called from `read_envelope` that calls `backend_for` (c: new key) |
| **T4** view table | Registry `{alpha, beta}` plus capability `cap`. Grants `Scoped([alpha, ghost])`, `Scoped([alpha, cap])`, `Empty`, `Unscoped` (from `*` and from no client). Names alpha, beta, ghost, nosuch, cap. Each cell pins `scoped_get(name).is_some()`, `absence(name)`, and `absent_step(name, "t")` with and without a recorded `Withheld(Absent)`. The capability cells are built through `Registry::scoped(.., Some("cap"))` and through `MetaMcp::scoped`, which must agree. **Router cell (v4):** `backend_for(state, grant, name)` equals `scoped_get` for every grant and name | no compile | M31 (registration before scope), M32 (`Empty` as `Scoped([])`), M33 (`scoped_get` ignores the grant), M34 (`MetaMcp::scoped` passes `None` for the capability: `cap` turns `Unregistered`), M35 (`backend_for` passes `None` for the capability) |
| **FW1** response targets | A response-firewall rule keyed on target `X` and one keyed on the gateway's own target. Asserts the three cells are equal, **and** pins the verdict: the `X` rule applies to no cell, the gateway-target rule to all. Observed through the response firewall's own audit projection, the record of which rule fired, with no new seam | green | **M10, M23** (§5) |
| **C2** capability out of scope | Fixture with a capability provider outside the key's scope, against `nosuch`, on `/mcp` invoke: one answer, pinned | green | C2-mutant: S3's absent check moved below the capability arm (`gate.rs`) → `ToolNotFound` |
| **R3** stored-read reason | R2 (T0)'s `beta` cell emits the `audit_refusal` warning (tracing capture) naming -32003 and the scope; `ghost` emits none; answers equal under a failing log | green | M16: S7's `check_visible_policy` call removed |
| **S7a** warm and cold, excluded target | Fixture from §4.0. **Positive witnesses first:** the two callers resolve the same `stable_actor_id`, and the first one's call leaves a warm slot for it on `beta` (`holds_per_user_slot_for_test`). **Then the excluded read:** a `tasks/get` by the `[alpha]` caller of a task targeting `beta` must not touch the slot (slot age unchanged after `age_per_user_slot_for_test`). A cold variant, with the slot evicted first, asserts no custody read (the fixture's resolve counter is unchanged), no cold claim (`cold_lease_remaining` stays `None`) and no catalogue refresh (`beta`'s list counter is unchanged) | **red** | the §6 fix; mutant: the fix removed |

### 4.2 What is still a scan, and its grammar (v4)

The lint carries the ban. The pins only record what it cannot: claimed classes, allow contents, reference sets, the banned surface, and the config itself.
- **Item tree and test-ness.** Parse with `syn` (in `Cargo.lock` at 2.0.119 and 3.0.5; it becomes a dev-dependency, with no new crate downloaded), from `src/lib.rs` down the module declarations. An item is test-only when it or any ancestor has `#[cfg(test)]` (or a `cfg` whose predicate includes `test`, as in `cfg(all(test, ..))`). Filenames are never used (GPT r2). `router/latest.rs` is production.
- **T1(a).** Method calls whose name is one of `scoped_get`, `get_for`, `all_for`, `membership_for`, `statuses_for`, `subscribe_started_for` and `nudge_catalogue_for`, in production items.
  - The class is the `Unscoped::X` path argument. For `scoped_get` it is "scoped". A non-literal class argument fails T1.
  - Any other reference to these names, such as a path `Registry::get_for` not in call position, fails T1 (GPT r2).
  - Bound views need no binding tracking: the receiver class follows from the operation name.
- **T1(b).** Every attribute `allow`, `expect` or `cfg_attr(.., allow(..))` naming `clippy::disallowed_methods` on a production item, statement or expression. Recorded: the attributed node's kind (statement or expression; anything else fails), its reason's leading class word, and the list of `BackendRegistry`-banned method names called inside the node. The pin compares those lists exactly.
- **T1(d) and T2(c).** Paths and method calls resolving by name to `Registry::new`, `backend_for` and `backends_for` in production items: calls and non-call path references alike, keyed by enclosing fn.
- **T1(e).** In `backend/registry.rs`: the names of the inherent `pub` and `pub(crate)` fns of `impl BackendRegistry`, the trait names of `impl _ for BackendRegistry`, and the derive list. Each set must equal its pin.
- **T1(c)** is gone: the lint now carries the propagation ban (§2.6), and T1(b) pins its one allow.
- **T1(f).** The `toml` crate is not in `Cargo.lock`, so no parser. `clippy.toml` already groups its entries under a ticket comment; the MIK-8387 entries sit between `# MIK-8387 begin` and `# MIK-8387 end` lines, and T1(f) compares that span byte for byte with the pin. Deleting or editing an entry is red. Moving one outside the span means deleting it inside, so that is red too. The MIK-8202 and MIK-8001 entries are left to their owners.

`syn` sees names, not resolved types. That is enough here: every pinned name is unique to its item in the crate (`scoped_get`, the `*_for` operations, `backend_for`), and T1 fails if a second definition of any of them appears.

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
- After PR-B those helpers read through `scoped(..).scoped_get(..)`, which is `None` for an absent name, so the type closes the same hole. The explicit filter stays, so the row does not depend on every helper being converted.
- The S7a row checks the cold path too: no custody read, no claim, no catalogue refresh for an excluded target.

**Commits (v4; v3 corrected per GPT r2).** v2's sequence did not compile: its conversions called `Registry`-only operations while `MetaMcp.backends` was still an `Arc<BackendRegistry>`. v3 splits only what compiles alone:
1. **Types and operations, unused.** `Registry`, `Unscoped`, the operations, `ScopedBackends::scoped_get` and the owned capability name, with T4 (the router cell lands with commit 5). `MetaMcp.backends` is unchanged. This compiles alone: nothing calls the new operations yet.
2. **Grant threading, no type change.** `fill_account_outcomes`, `live_refusal`, `mints_per_caller`, `target_account` and their callers take the caller's `ScopedBackends` from the request entry points (§7.2). They still read through the old field. This compiles alone, and the PR-A rows stay green.
3. **Escape closures.** `events_backend_registry` is deleted and wired from the startup `Arc`; `unfilled_outcome_read`'s argument becomes `cfg(test)`. Compiles alone.
4. **Router choke point** (`backend_choke.rs`) and its six reads, with T2. Until commit 5 the choke point reads `AppState.backends` directly, so it compiles alone; commit 5 switches it to `state.meta_mcp.registry()`.
5. **The type flip, atomic.** `MetaMcp.backends: Registry` and `MetaMcp::registry()`, the 66 meta-layer conversions, the choke point's switch, the 20 `clippy.toml` entries, the leaf allows of §2.4 and §2.6, the test-module allows of §2.7, the class-table file, T1 and the negative fixture (§2.2 A). None of these compiles without the others, so they are one commit. It is large, about 250 files counting the test-module allows, but mechanical, and the compiler and the lint list every site in it.
6. The S7a fix (§6, above), after its red row.

**Size** (from §3; the ± is a guess, not a measurement):

| Part | Files | Lines |
|---|---|---|
| Types, operations, `ScopedBackends::scoped_get`, `MetaMcp::registry`, forwarder | `scoped_backends.rs`, `meta_mcp/mod.rs` | +110 |
| Class table file | 1 new | +80 |
| 73 production reads, 2 escape closures | 27 + `events_wiring.rs`, `run.rs` | ~75 changed, +45 net |
| 7 cfg(test) reads + 47 test reads → `for_test()` | ~30 | ~54 changed |
| `clippy.toml` (20 entries); 55 leaf allows (§2.4, §2.6) | ~30 | +130 |
| Test-module allows (§2.7) | ~190 | +190 |
| Negative fixture crate and its script (§2.2 A) | 3 new | +120 |
| Router choke point (`backend_choke.rs`) and its 6 callers | 6 | +50 |
| T1 (a, b, d, e, f) and T2 (a, b, c) | 2 new | +300 |
| T4 | 1 new | +130 |
| FW1, C2, R3, S7a rows and fixture | 4–5 new, 1–2 fixture edits | +550 |
| S7a fix | `task_replay.rs` | +10 |
| Docs, inventory rows | 3–4 | +40 |
| **Total** | **~320 files** | **~+1,770 / −140** |

## 7. Risks, visibility, and the reads with no grant in hand

### 7.1 Visibility. No widening; every new or changed item

| Item | Visibility | Note |
|---|---|---|
| `Registry` | `pub(in crate::gateway)` | Field private to `scoped_backends.rs` |
| `Registry::new`, `scoped`, `get_for`, `all_for`, `membership_for`, `statuses_for`, `subscribe_started_for`, `nudge_catalogue_for` | `pub(in crate::gateway)` | |
| `MetaMcp::registry` | `pub(in crate::gateway)` | New, for the router choke point (§2.5) |
| `Registry::for_test` | `pub(in crate::gateway)`, `#[cfg(test)]` | |
| `Unscoped` (5 variants: Visibility, Discovery, Background, Admin, Lifecycle) | `pub(in crate::gateway)` | |
| `ScopedBackends::scoped_get` | `pub(in crate::gateway)` | Renamed from `get` (§2.3); the capability name is now owned |
| `router::backend_choke::{backend_for, backends_for}` | `pub(super)` (router) | New |
| `MetaMcp.backends` | `pub(super)`, unchanged | Type changes to `Registry` |
| `MetaMcp::events_backend_registry` | `pub(crate)` → **removed** | A narrowing |
| `events_wiring::install` | `pub(super)`, unchanged | Gains a `&Arc<BackendRegistry>` parameter |
| `target_account`, `fill_account_outcomes`, `live_refusal`, `mints_per_caller` | unchanged | Each gains a `&ScopedBackends` parameter (§7.2) |
| `clippy.toml` | config | 20 `disallowed-methods` entries: 18 `BackendRegistry` methods, 2 propagation APIs |
| `scripts/lint-fixtures/registry-ban/` | test fixture, not in the workspace | New (§2.2 A) |

- `BackendRegistry` and its `pub` methods are unchanged.
- `AppState.backends` (`pub`) and `ReloadContext.registry` (`pub` field) are unchanged; they are API surface.
  - A read through either one, anywhere in the crate, is a banned method call, so the lint closes the round-2 `reload_context().registry` finding without touching the field.
  - The lead ruled out the widening that wrapping `AppState.backends` would need.
- `construction.rs` keeps its constructors, which name `BackendRegistry`. They need no allow: the type is not banned, only its methods, and `new` and `Default` stay allowed (GPT r2).
- The surface check (`scripts/release/check_surface_inventory.py`) must still exit 0; `src/lib.rs` does not change.

### 7.2 Grantless helpers and public compatibility methods

v2 assumed every caller "holds a scope". GPT r2 found that several helpers get only a `CallerProof` or names, so a scope does not reach them by itself. v3 threads the caller's view in from the request entry points and never falls back to `Visibility`:

| Helper | Gets today | Change |
|---|---|---|
| `target_account(server, tool)` (`account_outcome.rs:36`) | names | `target_account(&ScopedBackends, server, tool)` |
| `fill_account_outcomes(targets, CallerProof, writes)` (`account_outcome.rs:55`) | `CallerProof` | takes `&ScopedBackends` too |
| `live_refusal((server, tool), CallerProof)` (`caller_verdict.rs:115`) | `CallerProof` | takes `&ScopedBackends` too |
| `mints_per_caller(server, tool)` (`admission_replay.rs:100`) | names | takes `&ScopedBackends` too |

- **Where the view comes from.** Each request entry point holds a `MetaMcpCallerContext` and builds it once: `let view = self.scoped(caller.scope().authorizer.backend_grant());`. The entry points are the `/mcp` `tools/call` dispatch, the stored-read entries (`refuse_stored`, `prepare_stored_read`, `prepare_repeated_call`), admission, and the task worker's dispatch.
- **Each helper's callers pass the view down.** The full caller list comes from the compiler once the parameter is added; there are 11 `target_account` callers today (§7.2 of v2).
- **A worker or background caller with no request context** is classed explicitly in the class table, never given a grant. None is known today.
- **`resolve_propagation_credential` and `resolve_propagation_headers`** (`invoke/propagation.rs:20,40`, both `pub`). Signatures unchanged. Both are banned in `clippy.toml`, with one leaf allow on the forwarding edge at `propagation.rs:26`; their read is `get_for(Unscoped::Discovery, server)`. See §2.6, which corrects the earlier zero baseline.
- **`resolve_caller_credential`** (`propagation.rs:151`) is `#[cfg(test)]` and switches to `for_test()`.

### 7.3 Other risks

- **Misclassification.** The compiler forces a class but cannot check it.
  - Mitigation: one seat review of the one class-table file, then T1 makes every later change a one-file diff.
  - Residual: a read merged once and never touched again rests on that one review.
- **Answers that change where a call-path read was reachable with an absent name.** `ScopedBackends::get` is `None` there. On gated paths no answer changes, and every PR-A row must stay green unchanged. A row that turns red has found a reachable site: it gets a row and a reported fix, never an `Unscoped` to silence it.
- **Merge churn.** Each per-submodule commit is small (§6). The type flip is mechanical, and the compiler and the lint list every site in it. The open lanes rebase per commit, in a window agreed with them.
- **S7a fixture.** S7a stays unresolved until its positive-witness integration row passes (§4.0). If the fixture cannot be built, S7a is reported as unresolved with the obstacle, not closed: fixture trouble does not show the touch is unreachable in production. The §6 filter still ships.
- **Coverage and inventory.** New non-test functions on the COV.3 paths get rows: `Registry::*`, `ScopedBackends::scoped_get`, `backend_choke::*`, and the S7a filter if it becomes a helper. `check_inventory_rows.py <base> HEAD` and `--all` must exit 0.
- **Not done here:** `authorize_backend`, listing and search decisions, MIK-8441's empty-grant behaviour, and MIK-8446.

## 8. Order of work

0. **Step 0: build the S7a fixture (§4.0) and run its positive witnesses:** the same actor id, and a held warm slot. Until those pass, S7a is unresolved.
1. **Rows first, with their evidence:**
   - FW1, C2 and R3 as guards, with M10, M23, M16 and the C2 mutant run against them;
   - S7a red.
2. **The commits of §6, 1 to 6,** each on the fast gate (fmt, clippy with `--all-features` and with `--no-default-features`, the touched modules).
   - T4 comes with commit 1, and M31 to M34 run there, not at the end (Kimi r2).
   - T2 comes with commit 4, with M20, M20b and M20c.
   - L, T1, the negative fixture and T4's router cell come with commit 5. M19, M19b, M19c, M19d, M19f, M19g, M19h and M35 run there.
   - The negative fixture's script runs in CI from commit 5; it is red if any marked line goes unflagged or an unmarked line is flagged.
3. **The S7a fix,** which turns S7a green.
4. **MIK-8447's gaps leave the pinned gap set** (`backend_oracle/gaps.rs`) as each gets its row, and the pin moves in the same commit.
5. **Mutants run in a scratch worktree** (anchor asserted once; VOID on a compile failure or an empty filter). The full suite runs in CI.

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

## 10. The v2 review (round 2), item by item

The round-2 findings shared one root cause: T1 and T2 were lexical scanners. v3 moves the ban into clippy (§2.1, evidence in §2.2) and keeps only small structural pins.

| Finding (seat) | v3 |
|---|---|
| HIGH: the `.registry` zero-pin misses a chained or bound access (Kimi, GPT) | Closed by the lint. Every read through `ReloadContext.registry` is a banned method call, whatever the binding (§2.2 A: chain, alias and inferred binding all flagged) |
| HIGH: new callers of `resolve_propagation_credential` change no key (GPT, Kimi) | T1(c) pins the production call sites of both propagation APIs and their forwarders at zero. Correction: `discovery_fetch.rs:367` is in a `#[cfg(test)]` fn (§7.2) |
| HIGH: T2 does not follow aliases or helper calls (GPT) | The lint bans every router read outside the choke point (§2.5). T2 shrinks to the allow pin and the structural order check (§4.2) |
| HIGH: the path filter treats `router/latest.rs` as a test file (GPT) | Test-ness comes from cfg ancestry only (§4.2); clippy itself works by cfg (§2.2 A) |
| MEDIUM: function-item bindings bypass T1 (GPT) | The lint flags the raw method at the path reference (§2.2 A). T1 fails on a function-item reference to an operation, so its class stays visible |
| MEDIUM: `MetaMcp::scoped` cannot borrow the capability name (GPT) | `ScopedBackends` holds an owned `Option<String>` (§2.3) |
| MEDIUM: helpers get only a `CallerProof` or names (GPT) | The view is threaded in from the entry points, with no Visibility fallback (§7.2) |
| MEDIUM: `construction.rs` needs the type (GPT) | The type is not banned, only its read methods; the constructors do not read (§7.1) |
| MEDIUM: the commit sequence does not compile (Kimi, GPT) | The type flip and its dependent conversions are one atomic commit (§6) |
| MEDIUM: T2 scans only the router, so a helper outside it can read `AppState.backends` (Kimi) | The lint is crate-wide; every such read outside an allowed item is red |
| LOW: the `for_test(` zero-pin contradicts the planned conversions (Kimi) | Dropped: the lint replaces the zero-pins |
| Improvement: pin `Registry::new` call sites (Kimi) | T1(d) |
| Improvement: run the T1/T4 mutants early (Kimi) | T4's mutants at commit 1; T1's when T1 exists, at commit 5 (§8) |
| Improvement: no byte-offset ordering (Kimi) | T2(b) is structural: `route` takes `&Envelope`, and `Envelope` is built only in `read_envelope` (§4.2) |
| Lead: S7a unresolved until the positive witness passes | §4.0, §7.3, §8 step 0 |

## 11. The v3 review (round 3), item by item

Both seats found the lint approach sound. v4 makes it complete by construction and pins what the lint cannot see.

| Finding (seat) | v4 |
|---|---|
| HIGH: a helper called before S4 can read through the router choke point (GPT) | T2(c) pins every production reference to `backend_for` and `backends_for`, function items included, by (file, fn). A new helper is a new key (§2.5, M20c) |
| HIGH: an allow on a fn or module admits later raw reads inside it (GPT; Kimi LOW) | Allows sit on one statement or expression (§2.4). T1(b) pins each allow's complete raw-call content, crate-wide, and pins the pre-existing clock and home allows at 0 registry calls. Inherited test-module allows are accepted and bounded to test code (§2.7) |
| HIGH: `remove` leaks membership through its `bool` (GPT) | All 18 methods but `new` and `Default` are banned (§2.1); lifecycle calls take a `Lifecycle` leaf allow |
| HIGH: the ban holds only for five inherent methods; traits, derives and new methods are unpinned (Kimi) | `BackendRegistry` has no derives and only `Default`. T1(e) pins the method, trait-impl and derive sets (§2.1, M19h) |
| HIGH: nothing pins the `clippy.toml` entries (Kimi) | T1(f) pins the marked MIK-8387 span byte for byte (§4.2, M19g) |
| HIGH: function-item references to the propagation APIs escape T1(c) (GPT) | Both APIs are in `clippy.toml`, which flags function items (§2.2 A, §2.6). T1(c) is retired |
| MEDIUM: v3's zero baseline for propagation is wrong (GPT) | Corrected: one production edge, `propagation.rs:26`, with the only allow (§2.6) |
| MEDIUM: T1's receiver grammar misses bound views (GPT, Kimi) | The scoped read is `scoped_get`; the receiver follows from the operation name. The receiver-type column is dropped (§2.3, §3.2, §4.2) |
| MEDIUM: `backend_for` has no capability input (Kimi) | Router grants can name the capability provider, so `backend_for` takes the provider name from `get_capabilities()`; T4's router cell pins it equal to `scoped_get` (§2.5, M35) |
| MEDIUM: §3.1 excludes tests by filename (Kimi) | §3.1 is only the class-table key; every pin uses cfg ancestry (§3.1, §4.2) |
| Improvement: commit the lint experiments as fixtures (GPT) | `scripts/lint-fixtures/registry-ban/` with `//~ disallowed` markers, run in CI (§2.2 A) |
| Improvement: allow reasons use the `Unscoped` names (Kimi) | Each reason starts with one of the five variant names; T1(b) checks the word (§2.4) |
| Improvement: the router reads a stored `Registry`, not a per-call wrapper (Kimi) | It reads `state.meta_mcp.registry()`, the `Registry` stored in `MetaMcp` inside `AppState`, over the same `Arc` as `AppState.backends` (§2.5) |
