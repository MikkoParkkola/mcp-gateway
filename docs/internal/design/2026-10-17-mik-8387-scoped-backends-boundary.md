# MIK-8387 PR-B: a compiler-enforced boundary between a caller and the backend registry

Status: design **v3**, for a third review before any code. v3 enforces the boundary with a clippy lint (§2.1, experiment in §2.2) instead of text scanners. Rounds 1 and 2 are answered in §9 and §10. Base: release line `19ca01f07` (PR #3907, which carries PR-A). Ticket: MIK-8387, criterion ORACLE.5. Gap ticket: MIK-8447. 

## 1. Problem

ORACLE.5, as the ticket states it: a backend outside a scoped key's scope must be indistinguishable from a missing one on every route and response shape, the record must keep the scope reason, and this must be "enforced by a type boundary: caller-request code reaches backends only through a caller-scoped view (`ScopedBackends`), so the compiler finds every lookup site; `authorize_backend`'s refusal stays for non-call readers."

PR-A made the behaviour hold on every route that has a row, at eight hand-picked sites (S0 to S7). Each asks `ScopedBackends::absence` / `absent_step` before it reads the registry. Nothing stops the next change from adding a ninth read that skips the question: the field is a plain `Arc<BackendRegistry>`, so `self.backends.get(name)` compiles anywhere in the meta layer.

Two facts show the risk is real:
- **The d1 hand inventory missed reads.** It missed 20 multi-line reads.
- **One read sat in the wrong class.** `prepare_stored_read_kind` (`task_replay.rs:92`) runs before the stored-read scope check. Its warm path touches a per-user slot (`task_replay.rs:221-223`) before the scope-aware `refused_without_catalogue` (`:244`). That is gap S7a in MIK-8447.

## 2. The boundary

### 2.1 Enforcement is a clippy lint, not a text scan (v3)

v1 and v2 enforced the boundary with text scanners (T1, T2). Round 2 showed a lexical scanner does not converge under adversarial review: a chained `.registry` access, a binding alias, a function-item binding (`let read = Registry::get_for`), and a path filter that treats `router/latest.rs` as a test file all slip through.

v3 moves the ban into the type checker. The repo already does this for the wall clock (MIK-8202) and the home directory (MIK-8001): `clippy.toml` lists `disallowed-methods`, sanctioned sites carry a scoped `#[allow]` with a reason, and CI runs `clippy --all-targets -D warnings` on both feature sets, so a violation is a red build. v3 adds the raw registry reads:

```toml
# clippy.toml, appended (MIK-8387 ORACLE.5)
{ path = "mcp_gateway::backend::registry::BackendRegistry::get",               reason = "read through Registry::scoped(..).get or Registry::get_for (MIK-8387)" },
{ path = "mcp_gateway::backend::registry::BackendRegistry::all",               reason = "read through Registry::all_for (MIK-8387)" },
{ path = "mcp_gateway::backend::registry::BackendRegistry::with_membership",   reason = "read through Registry::membership_for (MIK-8387)" },
{ path = "mcp_gateway::backend::registry::BackendRegistry::statuses",          reason = "read through Registry::statuses_for (MIK-8387)" },
{ path = "mcp_gateway::backend::registry::BackendRegistry::subscribe_started", reason = "read through Registry::subscribe_started_for (MIK-8387)" },
```

### 2.2 The experiment (Spark, 2026-10-17)

**A. A standalone crate, `exp`,** with a `BackendRegistry` type, `get` and `all` banned by path, and the type banned too. Run with `spark-cargo clippy --all-targets -- -D warnings`: rc 101. Clippy flagged every raw access shape:

| Case | Code | Result |
|---|---|---|
| Field chain | `c.registry.get("a")` | `use of a disallowed method …::get` |
| Chain through a call | `c.registry.as_ref().all()` | `…::all` |
| `use … as R` alias, typed binding | `let x: &R = &c.registry; x.get("a")` | method and type, both flagged |
| Function-item binding | `let f = reg::BackendRegistry::get; f(&c.registry, "a")` | flagged at the path reference |
| Fully qualified call | `reg::BackendRegistry::get(&c.registry, "a")` | flagged |
| Inferred binding, no type spelled anywhere | `let held = &c.registry; held.get("b")` | flagged |
| `#[cfg(test)]` code under `--all-targets` | `r.0.get("a")` in a `#[test]` | flagged (in the lib-test target) |
| A module under `#[allow(clippy::disallowed_methods, clippy::disallowed_types)]` | `self.0.get(n)` in the sanctioned `Registry` | silent, as intended |
| The sanctioned operation | `m.backends.get_for("a")` | silent |

Clippy resolves the method itself, so receiver aliasing, auto-deref through `Arc`, and a bound function item make no difference. That closes every escape round 2 found in the method half. Test-ness comes from cfg ancestry: clippy sees a `#[cfg(test)]` item only in the test target, and it checks it there too. No filename filter is involved.

**B. The real crate, at `19ca01f07`,** with the five entries above appended to the repo's `clippy.toml`. Run with `spark-cargo clippy --all-targets --all-features -- -D warnings`: rc 101, with no unresolved-path warning, so the canonical paths resolve.
- **Library target:** 105 violations.
  - By area: `gateway/meta_mcp` 65, `gateway/server` 13, `events` 9, `gateway/ui` 7, `gateway/router` 6, `config_reload` 3, `backend` 1 (the registry's own module), `gateway/streaming_session.rs` 1.
  - By method: `get` 70, `all` 31, `with_membership` 2, `subscribe_started` 1, `statuses` 1.
- **Including tests:** 280, across 137 files.

The lexical inventory of §3 (73 `self.backends` lines in meta_mcp) saw neither the 40 reads outside meta_mcp nor how many `get`s a multi-line chain holds. The compiler's list is the real one, and it is the list PR-B works from.

**The type ban is not adopted.** `BackendRegistry` is named in 240 files, most of them tests and fixtures, and a type ban would need an allow in every one. It adds nothing the method ban misses, because holding the type is harmless while every read through it is a banned method. The method ban plus `Registry`'s private field gives the property. One exception: `disallowed-types` would still catch a *new* raw handle stored in a struct, but that handle can do nothing without a banned method.

### 2.3 Types (in `src/gateway/meta_mcp/scoped_backends.rs`)

```rust
pub(in crate::gateway) struct Registry(Arc<BackendRegistry>);   // field private to this module

pub(in crate::gateway) enum Unscoped { Visibility, Discovery, Background, Admin }

impl Registry {
    pub(in crate::gateway) fn new(inner: Arc<BackendRegistry>) -> Self;
    /// Call-path view. The capability name is owned: `get_capabilities()`
    /// returns a temporary `Arc`, so the view cannot borrow from it (GPT r2).
    pub(in crate::gateway) fn scoped<'a>(&'a self, grant: BackendGrant<'a>,
                                         capability: Option<String>) -> ScopedBackends<'a>;
    pub(in crate::gateway) fn get_for(&self, why: Unscoped, name: &str) -> Option<Arc<Backend>>;
    pub(in crate::gateway) fn all_for(&self, why: Unscoped) -> Vec<Arc<Backend>>;
    pub(in crate::gateway) fn membership_for<R>(&self, why: Unscoped, read: impl FnOnce(u64) -> R) -> R;
    pub(in crate::gateway) fn statuses_for(&self, why: Unscoped) -> HashMap<String, BackendStatus>;
    pub(in crate::gateway) fn subscribe_started_for(&self, why: Unscoped) -> broadcast::Receiver<String>;
    #[cfg(test)] pub(in crate::gateway) fn for_test(&self) -> &Arc<BackendRegistry>;
}

pub(in crate::gateway) struct ScopedBackends<'a> {
    registry: &'a BackendRegistry,
    capability: Option<String>,   // owned (GPT r2)
    grant: BackendGrant<'a>,
}
impl ScopedBackends<'_> {
    pub(in crate::gateway) fn get(&self, name: &str) -> Option<Arc<Backend>>;   // new: None when absent
    // absence(), absent_step(): unchanged from PR-A
}
```

- `scoped_backends.rs` is the one meta-layer module with `#[allow(clippy::disallowed_methods)]`, with reason "the class-taking operations are the sanctioned reads (MIK-8387)".
- `MetaMcp::scoped(grant)` forwards `self.get_capabilities().map(|c| c.name.clone())`.
- `MetaMcp.backends` changes type from `pub(super) Arc<BackendRegistry>` to `pub(super) Registry`; `MetaMcp::new` keeps its signature.
- `nudge_catalogue` is not a read: it signals a catalogue change, which reveals nothing. It stays unbanned, and `admin.rs:317` calls it through `get_for(Unscoped::Admin, ..)`'s backend.

### 2.4 The sanctioned allows outside the meta layer (the 40 non-meta production violations)

Each takes a scoped `#[allow(clippy::disallowed_methods)]` on the narrowest item that holds the reads, with a reason naming its class:

| Area | Violations | Allow on | Reason (class) |
|---|---|---|---|
| `gateway/server` (startup, warmstart, background, tools_changed, support) | 13 | each fn | Lifecycle and Background: process startup and timers, no caller |
| `events` (upstream listener and session) | 9 | each fn | Background: event sources, no caller |
| `gateway/ui` (control-plane snapshot, backends pages) | 7 | each fn | Admin: authenticated operator UI |
| `gateway/router` | 6 | **one choke point** (§2.5) | the only router reads |
| `config_reload` | 3 | each fn | Lifecycle: reload registers and removes backends |
| `backend/registry.rs` | 1 | the registry's own internal call | defining module |
| `gateway/streaming_session.rs` | 1 | the fn | Background (session notifications); confirmed per site at implementation |

The allows themselves are the inventory. The scoped-allow pin (§4, T1) lists every `#[allow(clippy::disallowed_methods)]` that names MIK-8387, with its item, so adding one is a reviewed diff. That makes it a pin on attribute items: a token the compiler also sees, and one an alias cannot hide.

### 2.5 The router's one choke point

Every router read of `AppState.backends` goes through one function in `router/backend_choke.rs`, the only router item with the allow:

```rust
/// The router's only registry read. A caller-scoped read takes the grant;
/// a read with no caller names its class.
pub(super) fn backend_for(state: &AppState, grant: BackendGrant<'_>, name: &str) -> Option<Arc<Backend>>;
pub(super) fn backends_for(state: &AppState, why: Unscoped) -> Vec<Arc<Backend>>;
```

- The 6 router violations (`authorization.rs`, `view_judge.rs`, `handlers/health.rs`, `backend_handlers/direct_caller.rs` `route()`, `accounts.rs`) move to it.
- `route()`'s lookup becomes `backend_for(state, grant, name)`. Under a Scoped grant it returns `None` for an absent name, so the lookup cannot answer differently from S4 even if it ever ran before S4.
- `AppState.backends` stays a `pub` field, which is no widening. The lint stops a read through it anywhere in the crate except the choke point and the allowed items in §2.4.

## 3. Call sites that change, counted

### 3.1 The search

**v3:** the authoritative list is the compiler's (§2.2 B): 105 production violations. The lexical count below covers only `MetaMcp.backends` in `meta_mcp`. It is kept because the class table is keyed by it, and the 65 meta-layer lint sites map onto it, where one multi-line chain can hold two reads.

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

The table lands as one committed file, `src/gateway/meta_mcp/scoped_backends_classes.tsv`, with columns file, enclosing fn, operation (`scoped.get`, `get_for`, `all_for`, `membership_for`, `statuses_for`, `subscribe_started_for`), receiver type (`ScopedBackends` or `Registry`), class, count and reason (GPT r2). Each variant is documented in the file header. T1 reads the file, so the seat review of the classes is a review of one file, and every later class change is a one-file diff.

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
- **Status (v3, GPT r2):** S7a stays **unresolved** until its positive-witness integration row passes. The trace above shows the touch is reachable in production, through the key-server path. Fixture trouble would show only that the fixture cannot reach it, never that production cannot.
- **The fixture:** the per-user fixture `meta_mcp::slot_verdict_fixture` (identity-bound, with resolve and list counters) combined with two key-server-style callers for one subject: one scoped `[beta]` (or `*`), one scoped `[alpha]`. If the key-server harness cannot be combined with that fixture in one router, the fallback is a static scoped key plus the same `VerifiedIdentity` extension on the request. That gives the same (client, identity) pair the key-server path produces, and step 0 confirms the auth middleware leaves the extension in place.

### 4.1 Rows, with their colour on the tip

L (the lint) is red on the tip with 105 production violations; it turns green with the type flip. T1 and T4 name types and operations that do not exist on the tip, so on the tip they do not compile. They land in the same commit as the types, and the commit before it is their red evidence. T2 is green on the tip: it pins today's router reads. FW1, C2 and R3 pin behaviour PR-A shipped, so they are expected green; they are guards and mutant killers, and if one is red, that is a new defect. S7a is the one behavioural red row.

| Row | What it asserts | Tip | Kills |
|---|---|---|---|
| **L** the lint | `clippy.toml` bans the five raw read methods (§2.1). CI runs `clippy --all-targets -D warnings` with `--all-features` and with `--no-default-features`, so every raw read anywhere in the crate, through any alias, chain or function-item binding, test code included, is a red build unless it sits in an allowed item | the 105 production and 280 total violations are the red evidence (§2.2 B); green from the type-flip commit | M19: a raw `self.backends.get(..)`-style read added anywhere (does not compile). M19c: a helper returning the raw registry, then read (its read is banned) |
| **T1** class table and allow pin | Small, structural (§4.2). (a) The class-taking operation call sites, keyed by (file, enclosing fn, operation, receiver type, class) with counts, equal `scoped_backends_classes.tsv`. (b) Every `#[allow(clippy::disallowed_methods)]` item naming MIK-8387 equals a pinned list. (c) The production call sites of `resolve_propagation_credential`, `resolve_propagation_headers` and their forwarding helpers equal a pinned list, which is empty today (§7.2). (d) The call sites of `Registry::new` are only `MetaMcp`'s constructors (Kimi r2) | no compile | M19b: one Discovery `get_for` reclassed as Visibility, total unchanged. M19d: a new allowed item. M19e: a new production caller of `resolve_propagation_credential` |
| **T2** router choke point | (a) In `src/gateway/router`, the only item with `#[allow(clippy::disallowed_methods)]` is `backend_choke.rs`'s two fns; T1(b) pins it. (b) Order: in `backend_handler_inner`, `read_envelope` returns before `route` is called, asserted structurally: `route`'s only caller is that fn, and it is reached only on `read_envelope`'s `Ok` (§4.2). (c) `read_envelope` calls neither choke-point fn | green after the choke-point commit | M20: a `backend_for` call added in `read_envelope` before S4 (fails c). M20b: `route` called before `read_envelope` (fails b). A raw read anywhere else in the router does not compile (L) |
| **T4** view table | Registry `{alpha, beta}` plus capability `cap`. Grants `Scoped([alpha, ghost])`, `Scoped([alpha, cap])`, `Empty`, `Unscoped` (from `*` and from no client). Names alpha, beta, ghost, nosuch, cap. Each cell pins `get(name).is_some()`, `absence(name)`, and `absent_step(name, "t")` with and without a recorded `Withheld(Absent)`. The capability cells are built through `Registry::scoped(.., Some("cap"))` and through `MetaMcp::scoped`, which must agree | no compile | M31 (registration before scope), M32 (`Empty` as `Scoped([])`), M33 (`get` ignores the grant), M34 (`MetaMcp::scoped` passes `None` for the capability: `cap` turns `Unregistered`) |
| **FW1** response targets | A response-firewall rule keyed on target `X` and one keyed on the gateway's own target. Asserts the three cells are equal, **and** pins the verdict: the `X` rule applies to no cell, the gateway-target rule to all. Observed through the response firewall's own audit projection, the record of which rule fired, with no new seam | green | **M10, M23** (§5) |
| **C2** capability out of scope | Fixture with a capability provider outside the key's scope, against `nosuch`, on `/mcp` invoke: one answer, pinned | green | C2-mutant: S3's absent check moved below the capability arm (`gate.rs`) → `ToolNotFound` |
| **R3** stored-read reason | R2 (T0)'s `beta` cell emits the `audit_refusal` warning (tracing capture) naming -32003 and the scope; `ghost` emits none; answers equal under a failing log | green | M16: S7's `check_visible_policy` call removed |
| **S7a** warm and cold, excluded target | Fixture from §4.0. **Positive witnesses first:** the two callers resolve the same `stable_actor_id`, and the first one's call leaves a warm slot for it on `beta` (`holds_per_user_slot_for_test`). **Then the excluded read:** a `tasks/get` by the `[alpha]` caller of a task targeting `beta` must not touch the slot (slot age unchanged after `age_per_user_slot_for_test`). A cold variant, with the slot evicted first, asserts no custody read (the fixture's resolve counter is unchanged), no cold claim (`cold_lease_remaining` stays `None`) and no catalogue refresh (`beta`'s list counter is unchanged) | **red** | the §6 fix; mutant: the fix removed |

### 4.2 What is still a scan, and its grammar (v3)

The lint carries the ban. What remains textual is small, and it only pins what the lint cannot express: which class a sanctioned read claims, and where the allows are.
- **T1(a):** the call sites of the class-taking operations, the six names in §2.3, in non-test items. Each site gives (file, enclosing fn, operation, receiver type, class literal).
  - *Receiver type* is `ScopedBackends` when the call chains from `.scoped(`, otherwise `Registry`.
  - *Class literal* is the `Unscoped::X` argument. A call that does not spell `Unscoped::X` literally fails T1.
  - A function-item reference to an operation (`Registry::get_for` not followed by `(`) also fails T1 (GPT r2). It cannot launder a read past the lint, which bans only the raw methods, but it would hide its class.
- **T1(b) and T2(a):** every `#[allow(` whose list includes `clippy::disallowed_methods`, with the item it is attached to.
- **T1(c) and T1(d):** call sites of the named fns. These are what GPT and Kimi asked for.
- **Test-ness (GPT r2):** never a filename. An item is test-only when it, or an ancestor module, carries `#[cfg(test)]`. A file is test-only when its `mod` declaration in the parent carries `#[cfg(test)]`, followed up the module tree from `src/lib.rs`. So `router/latest.rs` is production.
- **Masking:** comments and string literals are masked before matching.
- **Enclosing fn:** the nearest enclosing `fn` item by brace depth, not indentation.
- **T2(b), order, done structurally:** `route` has exactly one caller in the crate, `backend_handler_inner`. In that fn, the only path to the `route(` call passes the `match read_envelope(..)` arm that binds `Ok(envelope)`, and `route` takes that `envelope` by reference. Since `route(state, &name, &caller, key, &envelope)` needs the value `read_envelope` returned, the type system already forces the order. T2(b) pins two facts. First, `route` takes `&Envelope`. Second, `Envelope { … }` struct literals in production items appear only in `read_envelope` (there is one today, `direct_caller.rs:324`). Its fields are `pub(super)`, so the pin is what keeps another constructor from appearing. It needs no byte offsets (Kimi r2).

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

**Commits (v3, corrected per GPT r2).** v2's sequence did not compile: its conversions called `Registry`-only operations while `MetaMcp.backends` was still an `Arc<BackendRegistry>`. v3 splits only what compiles alone:
1. **Types and operations, unused.** `Registry`, `Unscoped`, the operations, `ScopedBackends::get` and the owned capability name, with T4. `MetaMcp.backends` is unchanged. This compiles alone: nothing calls the new operations yet.
2. **Grant threading, no type change.** `fill_account_outcomes`, `live_refusal`, `mints_per_caller`, `target_account` and their callers take the caller's `ScopedBackends` from the request entry points (§7.2). They still read through the old field. This compiles alone, and the PR-A rows stay green.
3. **Escape closures.** `events_backend_registry` is deleted and wired from the startup `Arc`; `unfilled_outcome_read`'s argument becomes `cfg(test)`. Compiles alone.
4. **Router choke point** (`backend_choke.rs`) and its six reads, with T2. The router reads `AppState.backends`, not `MetaMcp`, so this compiles alone.
5. **The type flip, atomic.** `MetaMcp.backends: Registry`, all 65 meta-layer read conversions, the `clippy.toml` entries, the scoped allows of §2.4, `for_test()` in tests, the class-table file and T1. None of these compiles without the others, so they are one commit. It is large, about 30 files, but mechanical, and the compiler and the lint list every site in it.
6. The S7a fix (§6, above), after its red row.

**Size** (from §3; the ± is a guess, not a measurement):

| Part | Files | Lines |
|---|---|---|
| Types, operations, `ScopedBackends::get`, forwarder | `scoped_backends.rs`, `meta_mcp/mod.rs` | +110 |
| Class table file | 1 new | +80 |
| 73 production reads, 2 escape closures | 27 + `events_wiring.rs`, `run.rs` | ~75 changed, +45 net |
| 7 cfg(test) reads + 47 test reads → `for_test()` | ~30 | ~54 changed |
| `clippy.toml` entries; scoped allows in server, events, ui, config_reload, registry, streaming | ~20 | +60 |
| Router choke point (`backend_choke.rs`) and its 6 callers | 6 | +50 |
| T1 (class table, allow pin, propagation and `Registry::new` call-site pins) and T2 (choke point, order) | 2 new | +200 |
| T4 | 1 new | +130 |
| FW1, C2, R3, S7a rows and fixture | 4–5 new, 1–2 fixture edits | +550 |
| S7a fix | `task_replay.rs` | +10 |
| Docs, inventory rows | 3–4 | +40 |
| **Total** | **~95 files** | **~+1,260 / −140** |

## 7. Risks, visibility, and the reads with no grant in hand

### 7.1 Visibility. No widening; every new or changed item

| Item | Visibility | Note |
|---|---|---|
| `Registry` | `pub(in crate::gateway)` | Field private to `scoped_backends.rs` |
| `Registry::new`, `scoped`, `get_for`, `all_for`, `membership_for`, `statuses_for`, `subscribe_started_for` | `pub(in crate::gateway)` | |
| `Registry::for_test` | `pub(in crate::gateway)`, `#[cfg(test)]` | |
| `Unscoped` (4 variants) | `pub(in crate::gateway)` | |
| `ScopedBackends::get` | `pub(in crate::gateway)` | The capability name is now owned |
| `router::backend_choke::{backend_for, backends_for}` | `pub(super)` (router) | New |
| `MetaMcp.backends` | `pub(super)`, unchanged | Type changes to `Registry` |
| `MetaMcp::events_backend_registry` | `pub(crate)` → **removed** | A narrowing |
| `events_wiring::install` | `pub(super)`, unchanged | Gains a `&Arc<BackendRegistry>` parameter |
| `target_account`, `fill_account_outcomes`, `live_refusal`, `mints_per_caller` | unchanged | Each gains a `&ScopedBackends` parameter (§7.2) |
| `clippy.toml` | config | Five `disallowed-methods` entries |

- `BackendRegistry` and its `pub` methods are unchanged.
- `AppState.backends` (`pub`) and `ReloadContext.registry` (`pub` field) are unchanged; they are API surface.
  - A read through either one, anywhere in the crate, is a banned method call, so the lint closes the round-2 `reload_context().registry` finding without touching the field.
  - The lead ruled out the widening that wrapping `AppState.backends` would need.
- `construction.rs` keeps its constructors, which name `BackendRegistry`. They need no allow: the type is not banned, only its read methods, and the constructors do not read (GPT r2).
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
- **`resolve_propagation_credential` and `resolve_propagation_headers`** (`invoke/propagation.rs:20,40`, both `pub`, identity-only). Their signatures are unchanged, because they are public methods.
  - Correction to v2, from GPT r2: they have **no production caller**. `discovery_fetch.rs:367` sits in `seed_caller_slot_for_test`, which is `#[cfg(test)]`, and `resolve_propagation_headers` has none either.
  - Their read is `get_for(Unscoped::Discovery, server)`.
  - T1(c) pins their production call sites at **zero**, together with any forwarding helper, so the first production caller is a reviewed key (Kimi and GPT r2).
- **`resolve_caller_credential`** (`propagation.rs:151`) is `#[cfg(test)]` and switches to `for_test()`.

### 7.3 Other risks

- **Misclassification.** The compiler forces a class but cannot check it.
  - Mitigation: one seat review of the one class-table file, then T1 makes every later change a one-file diff.
  - Residual: a read merged once and never touched again rests on that one review.
- **Answers that change where a call-path read was reachable with an absent name.** `ScopedBackends::get` is `None` there. On gated paths no answer changes, and every PR-A row must stay green unchanged. A row that turns red has found a reachable site: it gets a row and a reported fix, never an `Unscoped` to silence it.
- **Merge churn.** Each per-submodule commit is small (§6). The final type flip is one line plus the compiler's verdict. The open lanes rebase per commit, in a window agreed with them.
- **S7a fixture.** S7a stays unresolved until its positive-witness integration row passes (§4.0). If the fixture cannot be built, S7a is reported as unresolved with the obstacle, not closed: fixture trouble does not show the touch is unreachable in production. The §6 filter still ships.
- **Coverage and inventory.** New non-test functions on the COV.3 paths get rows: `Registry::*`, `ScopedBackends::get`, and the S7a filter if it becomes a helper. `check_inventory_rows.py <base> HEAD` and `--all` must exit 0.
- **Not done here:** `authorize_backend`, listing and search decisions, MIK-8441's empty-grant behaviour, and MIK-8446.

## 8. Order of work

0. **Step 0: build the S7a fixture (§4.0) and run its positive witnesses:** the same actor id, and a held warm slot. Until those pass, S7a is unresolved.
1. **Rows first, with their evidence:**
   - FW1, C2 and R3 as guards, with M10, M23, M16 and the C2 mutant run against them;
   - S7a red.
2. **The commits of §6, 1 to 6,** each on the fast gate (fmt, clippy with `--all-features` and with `--no-default-features`, the touched modules).
   - T4 comes with commit 1, and M31 to M34 run there, not at the end (Kimi r2).
   - T2 comes with commit 4, with M20 and M20b.
   - L and T1 come with commit 5. M19, M19b, M19d and M19e run there.
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
