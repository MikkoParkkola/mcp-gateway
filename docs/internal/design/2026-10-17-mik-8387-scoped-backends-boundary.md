# MIK-8387 PR-B: a compiler-enforced boundary between a caller and the backend registry

Status: design, for review before any code. Base: release line `19ca01f07` (PR #3907, which carries PR-A). Author lane: impl-8387. Ticket: MIK-8387, criterion ORACLE.5. Gap ticket: MIK-8447.

## 1. Problem

ORACLE.5, as the ticket states it: a backend outside a scoped key's scope must be indistinguishable from a missing one on every route and response shape, the record must keep the scope reason, and this must be "enforced by a type boundary: caller-request code reaches backends only through a caller-scoped view (`ScopedBackends`), so the compiler finds every lookup site; `authorize_backend`'s refusal stays for non-call readers."

PR-A (in #3907) made the behaviour hold on every route that has a row. It did this at eight hand-picked sites (S0 to S7): each one asks `ScopedBackends::absence` / `absent_step` before it reads the registry. Nothing stops the next change from adding a ninth read that skips the question. The registry field is still a plain `Arc<BackendRegistry>`, so `self.backends.get(name)` compiles anywhere in the meta layer.

Two facts show the risk is real:

- **The hand inventory missed sites before.** The d1 design inventory used a one-line search and missed 20 multi-line `backends` + `.get(` reads (design d2 header).
- **PR-A found a site the design had in the wrong class.** `prepare_stored_read_kind` (`task_replay.rs:92`) runs before the stored-read scope check. Its warm path calls `touch_caller_slot` (`task_replay.rs:221-223`) before the scope-aware `refused_without_catalogue` (`:244`). That is gap S7a, open in MIK-8447.

What PR-B adds is the structural half: after it, a read that does not say which caller it serves, or why it needs none, does not compile.

## 2. The boundary

### 2.1 Types (all in `src/gateway/meta_mcp/scoped_backends.rs`, which PR-A created)

```rust
/// The meta layer's only handle on the registry. No `get`, no `all`.
pub(in crate::gateway) struct Registry(Arc<BackendRegistry>);

/// Why a read needs no caller. An enum, not a comment, so a reviewer sees the
/// class of every unscoped read in the diff, and a source test can pin them.
pub(in crate::gateway) enum Unscoped {
    Visibility,  // listings and the A3 visibility predicate; decide through authorize_backend / admits_backend
    Discovery,   // search, catalogue fill
    Background,  // timers, reapers, notifications not tied to one request
    Admin,       // operator-only tools (kill, revive, reload)
    Lifecycle,   // construction, registration, shutdown
}

impl Registry {
    pub(in crate::gateway) fn new(inner: Arc<BackendRegistry>) -> Self;
    /// Call-path reads: the caller's grant decides what exists.
    pub(in crate::gateway) fn scoped<'a>(&'a self, grant: BackendGrant<'a>) -> ScopedBackends<'a>;
    /// Every other read names its class.
    pub(in crate::gateway) fn unscoped(&self, why: Unscoped) -> &BackendRegistry;
    /// Tests reach the full registry without a class.
    #[cfg(test)]
    pub(in crate::gateway) fn for_test(&self) -> &Arc<BackendRegistry>;
}

impl ScopedBackends<'_> {
    /// New in PR-B. `None` for a name this caller's grant excludes, as for a
    /// missing one: Scoped -> None when absence(name) is Some; Empty -> None
    /// for every name; Unscoped -> the registry's answer.
    pub(in crate::gateway) fn get(&self, name: &str) -> Option<Arc<Backend>>;
    // absence() and absent_step() are unchanged from PR-A.
}
```

- `ScopedBackends` currently holds `&MetaMcp`. It changes to hold `&BackendRegistry` plus the capability name, so it can be built from a `Registry` alone.
- `MetaMcp::scoped(grant)` stays as a thin forwarder, so PR-A's eight call sites do not change.
- `MetaMcp.backends` (`meta_mcp/mod.rs:177`) changes type from `pub(super) Arc<BackendRegistry>` to `pub(super) Registry`. Its visibility does not change.
- `MetaMcp::new(Arc<BackendRegistry>)` keeps its signature and wraps the argument. The 69 context builders and every fixture that calls it do not change.
- `BackendRegistry` itself, and its `pub fn get` (`backend/registry.rs:510`, public API), do not change.

### 2.2 What becomes impossible to write

- `self.backends.get(name)`, `self.backends.all()` and `self.backends.with_membership(..)`: `Registry` has none of them. Every one of today's reads stops compiling, and each must choose one of two forms:
  - `self.backends.scoped(scope.authorizer.backend_grant()).get(name)`, a caller-scoped read;
  - `self.backends.unscoped(Unscoped::X).get(name)`, a read whose class is in the source.
- **Holding the raw `Arc` past construction.** `Registry`'s field is private to `scoped_backends.rs`, so no other module can reach the inner `Arc`. The one exception is the `#[cfg(test)]` accessor, which a release build cannot call.

### 2.3 What the compiler cannot do, and what covers it

- **Whether a declared class is right.** The compiler forces a class; it cannot judge it. Covered by **T1**, a source test that pins every `unscoped(Unscoped::X)` read by (file, enclosing fn, variant) with a count per key. A new unscoped read, a moved one, or a reclassified one fails T1 and goes to review. The class table is reviewed once in the seat round.
- **The router's `AppState.backends`** (`router/mod.rs:279`) is a `pub` field reachable through the doc-hidden `gateway::test_helpers`. Wrapping it would need a `pub` `Registry`, which is a visibility widening. The lead ruled no widening, so it stays. Covered by **T2**, a source test that pins the router's `state.backends` reads (classes V/N only) and fails on any new one.
- **Readers that decide through `may_invoke` / `tool_visible_to` rather than a lookup.** These are not lookups, so the type cannot see them. Only rows cover them, the same as today.

## 3. Call sites that change, counted

All counts are lines, at `19ca01f07`, from these searches (`-U` so a `self` and `.backends` split over two lines still count):

```
rg -U -c '\bself\s*\.\s*backends\b' src/gateway/meta_mcp --glob '!*test*'      # 73 lines in 29 files
rg -U -c '\b(meta|meta_mcp|fx\.meta|m)\s*\.\s*backends\b' src/gateway --glob '*test*'   # 47 lines in 26 files
rg -U -c '\bstate\s*\.\s*backends\b' src/gateway/router --glob '!*test*'        # 14 lines in 8 files
rg -l 'impl (super::)*(crate::gateway::meta_mcp::)?MetaMcp\b' src --glob '!*test*' | rg -v '^src/gateway/meta_mcp/'
                                                                              # router/accounts/offer.rs, 0 reads
```

**Production reads of `MetaMcp.backends` (73 lines, 29 files).** Each must pick `scoped(..)` or `unscoped(Unscoped::X)`. The compiler gives the exact list. The class shown here is provisional, from the d5 §2 inventory, and the seat round reviews the final table.

| File | Lines | Provisional class |
|---|---|---|
| `task_replay.rs` | 7 | scoped (stored reads, S7 and S7a); 1 is `#[cfg(test)]` |
| `invoke/gate.rs` | 7 | scoped (S2, S3, `fill_marks` / `filled_since` keep the membership read: Unscoped::Visibility) |
| `visible.rs`, `listing_view.rs`, `surfaced.rs`, `handlers.rs`, `audience.rs`, `task_confirmation.rs`, `visibility.rs` | 4, 2, 3, 2, 1, 1, 2 | Unscoped::Visibility |
| `discovery_fetch.rs`, `search.rs`, `spec_preview.rs` | 4, 3, 3 | Unscoped::Discovery |
| `upstream.rs`, `events_hook.rs` | 4, 1 | Unscoped::Background |
| `invoke/admin.rs` | 3 | Unscoped::Admin |
| `accessors.rs`, `direct_route.rs` | 1, 1 | Unscoped::Lifecycle |
| `resources.rs`, `protocol.rs` | 3, 3 | split: prompts/get is scoped (S5); resource owner lookup is Discovery (design out-of-scope row 29) |
| `invoke/caller_verdict.rs`, `invoke/propagation.rs`, `invoke/policy.rs`, `invoke/step_fingerprint.rs`, `invoke/chokepoint.rs`, `account_outcome.rs`, `account_direct_bridge.rs`, `admission_replay.rs`, `chain_receipt.rs`, `passthrough.rs` | 3, 2, 2, 1, 1, 3, 2, 1, 2, 1 | scoped (call path after the gate: an absent name never reaches them, and `get` returning `None` makes a bug fail closed) |

**Test reads (47 lines, 26 files).** These are test fixtures and rows that reach the registry through a `MetaMcp`. Each becomes `.backends.for_test()`, a mechanical edit with no class.

**Router `state.backends` (14 lines, 8 files).** Unchanged by the type, pinned by T2.
- Production: 7 lines. `authorization.rs` 3, `view_judge.rs` 1, `handlers/health.rs` 1, `backend_handlers/direct_caller.rs` 1 (`route()`, after S4), `accounts.rs` 1.
- Test fixtures without "test" in the file name: 7 lines. `oracle_parity_fixture.rs` 3, `direct_guards_fixture.rs` 3, `direct_guards_fixture_a2a.rs` 1.

## 4. Rows, written first

A row is red on the tip when it pins a defect PR-B fixes. T1, T2 and T4 name types that do not exist yet, so on the tip they fail to compile. They go in the same commit as the types, and the commit before it is the red evidence. FW1, C2 and R3 pin behaviour PR-A already shipped, so on the tip they are expected **green**. They are guards and mutant killers, not red rows, and if any is red that is a new defect found. S7a is the one behavioural red row.

| Row | What it asserts | Expected at tip | Kills |
|---|---|---|---|
| **T1** class table | Every `unscoped(Unscoped::X)` read in `src/gateway` outside tests is listed in a pinned table keyed by (file, enclosing fn, variant), with a count per key. Found by a source scan in the style of the repo's existing source-pinning tests | no compile (types absent) | M19: an `unscoped(Visibility)` read added inside `gate_answer` (a new key). M19b: one Discovery read reclassed as Visibility with the total unchanged |
| **T2** router reads | The router's non-test `state.backends` reads match the pinned list in §3: 7 lines, each with its class (V/N, or "after S4" for `route()`) | green on the tip; it pins today | M20: a `state.backends.get(name)` added in `direct_caller.rs` before S4 |
| **T4** view table | One table. Registry `{alpha, beta}` plus a capability provider `cap`. Grants: `Scoped([alpha, ghost])`, `Scoped([alpha, cap])`, `Empty`, `Unscoped`. Names: alpha, beta, ghost, nosuch, cap. Each cell pins `get(name).is_some()`, `absence(name)`, and `absent_step(name, "t")` with and without a recorded `Withheld(Absent)` | no compile (`get` absent) | M31 (registration judged before scope), M32 (`Empty` treated as `Scoped([])`), M33 (`get` ignores the grant) |
| **FW1** response targets | A response-firewall rule keyed on target `X` and one keyed on the gateway's own target. All three cells run under the same response targets: `without_withheld` (`response_security.rs:127-142`) reads S1's memo before S2, so it must drop `ghost` and `nosuch` exactly as it drops `beta`. Observed as the same firewall verdict and audit projection per cell | green (S1 memoizes all three) | **M10, M23** (§5) |
| **C2** capability out of scope | A fixture with a capability provider outside the key's scope, against `nosuch`, on `/mcp` invoke: one answer, pinned | green (S3 answers before the capability arm) | a mutant moving S3's check after the capability arm (`gate.rs`), which answers `ToolNotFound` |
| **R3** stored-read scope reason | R2 (T0)'s `beta` cell emits the `audit_refusal` warning (tracing capture) naming -32003 and the scope; `ghost` emits none; answers stay equal under a failing log | green (S7 calls `check_visible_policy` for an out-of-scope target) | M16: S7's emit removed |
| **S7a** warm slot touch | `beta` is a per-user backend whose caller principal holds a warm slot, warmed by a credential that had `beta` in scope. A `tasks/get` by a credential of the same principal whose grant excludes `beta` must not touch, claim or refresh `beta`'s slot: a slot-touch counter stays at 0 and the slot's last-used time is unchanged. Today `settle_caller_view` (`task_replay.rs:176-253`) touches it at `:221-223`, before the scope-aware `refused_without_catalogue` at `:244` | **red** | the fix in §6 (scoped targets only, before the pre-pass), and a mutant that removes it |

**S7a fixture, the one hard part.** The per-user fixture (`meta_mcp::slot_verdict_fixture`) binds by verified identity. The row needs one principal with two grants. There are two candidates:
- (a) A key-server bearer: two tokens for the same OIDC subject with different `backends` scopes, issued through the key-server harness (`key_server/oidc_harness_tests.rs` exchanges with `backends:a,b`).
- (b) An OIDC identity plus two static keys mapped to that identity, if the propagation principal is the identity rather than the key.

I will confirm which one `principal_for` (`task_replay.rs:202`) resolves before writing the row. If neither yields a shared principal across scopes, the touch is unreachable, and S7a closes as N/A with that trace (file:line).

## 5. The surviving mutants M10 and M23

PR-A's mutant run left these two alive:
- **M10** removes S1's `record_absent` (the memo write at the route stage, `chokepoint.rs`).
- **M23** keeps it only for `OutOfScope`.

Every PR-A row passed under both. The reason: on an all-absent call, S2 (`invisible_at_route`) records the absence again before anything acts, and mixed chains judge live at S2b′ and S3.

S1's memo matters only to the readers that run **between S1 and S2**:
- the route-stage caller verdicts (`dispatch_tools_call.rs`, the MIK-8356 per-user verdict, which mints nothing for an unregistered name either way);
- `without_withheld`, which filters the call's response targets and runs before S2.

- **Under M10,** no cell is recorded at S1. Since PR-A, S1 returns early for `beta` too, so the registered-backend arm that recorded `Withheld(Refused)` is never reached for an absent name. `without_withheld` then keeps target `X` for all three cells. The cells still agree with each other, so an equality check alone does not kill M10. What changes is the shared verdict: the rule keyed on `X` now fires, where on the tip all three targets are dropped to the gateway's own.
- **Under M23,** `beta` and `nosuch` (out of scope) are recorded and dropped, while `ghost` (unregistered, in scope) keeps target `X`.

**FW1 therefore asserts two things.** First, the three cells are equal. Second, the pinned verdict: the rule keyed on `X` does **not** apply to any cell, and the rule keyed on the gateway's own target does. The pin kills M10, because all three now match the `X` rule. The equality kills M23, because `ghost` differs. FW1's red evidence is these two mutants, run as in PR-A: a scratch worktree, the anchor asserted once, and VOID when nothing compiles or no test runs.

If FW1 cannot be written because no rule shape fires on the miss answer (the open question in MIK-8447), the fallback is a response-target probe. A `#[cfg(test)]` seam records the targets `without_withheld` returns, and the row asserts that for all three cells they are the gateway's own target, not `X`. That kills M10 (`X` kept everywhere) and M23 (`X` kept for `ghost`) without depending on firewall rule semantics.

## 6. The S7a fix, and the size

**S7a fix.** `prepare_stored_read_kind` (`task_replay.rs:92-146`) builds its target list from `stored.targets`. It drops every target for which `ScopedBackends::absence` is `Some` for the reading caller's grant, before `fill_account_outcomes`, `keep_permanent_refusal`, `settle_caller_view` and `settle_shared_view` see it. This applies to Scoped grants only. Empty and Unscoped grants change nothing, because `absence` is `None` for them, which keeps MIK-8441's empty-grant answers. The read itself is then answered by S7, as today. After PR-B this falls out of the type: those helpers read `self.backends`, and on this path the read becomes `scoped(..).get(..)`, which is `None` for an absent name. The explicit filter stays anyway, so the row does not depend on every helper having been converted.

**Size estimate** (from the counts in §3; ± is a guess, not a measurement):

| Part | Files | Lines |
|---|---|---|
| `Registry`, `Unscoped`, `ScopedBackends::get`, reshaping `ScopedBackends` to hold the registry | 1 (`scoped_backends.rs`) + `meta_mcp/mod.rs` | +80 |
| 73 production reads | 29 | ~73 changed, +40 net (some calls gain a line for the grant) |
| 47 test reads → `for_test()` | 26 | ~47 changed |
| T1 (class table plus scanner) and T2 (router pin) | 2 new test files | +250 |
| T4 view table | 1 new test file | +120 |
| FW1, C2, R3, S7a rows and fixtures (key-server or identity fixture for S7a) | 4–5 new test files, 1–2 fixture edits | +500 |
| S7a fix | `task_replay.rs` | +10 |
| Docs: changelog fragment, design status, inventory rows if the scan flags new functions | 3 | +30 |
| **Total** | **~65 files** | **~+1,050 / −120** |

Because of §7, the production half (types plus 73 reads) should be one commit with no behaviour change: the PR-A rows stay green, unchanged. The rows go in their own commits, each with its red evidence.

## 7. Risks

**API visibility. No widening; every new item:**

| Item | Visibility | Note |
|---|---|---|
| `Registry` | `pub(in crate::gateway)` | Its field is private to `scoped_backends.rs` |
| `Registry::new`, `scoped`, `unscoped` | `pub(in crate::gateway)` | |
| `Registry::for_test` | `pub(in crate::gateway)`, `#[cfg(test)]` | |
| `Unscoped` (5 variants) | `pub(in crate::gateway)` | |
| `ScopedBackends::get` | `pub(in crate::gateway)` | Same as its siblings from PR-A |
| `MetaMcp.backends` | `pub(super)`, unchanged | The type changes: `Arc<BackendRegistry>` → `Registry` |

- `BackendRegistry` and `BackendRegistry::get` (public API) are unchanged.
- `AppState.backends` is unchanged and stays `pub`. Wrapping it would need a `pub` doc-hidden `Registry`, which is the widening the lead ruled out. T2 covers it instead.
- The surface check (`scripts/release/check_surface_inventory.py`) must still exit 0; nothing in `src/lib.rs` changes.

**Misclassification.** The compiler forces a class but cannot check it. A call-path read declared `Unscoped::Visibility` would compile and skip the scope.
- Mitigation: the seat round reviews the full class table once. After that, T1 turns every later change to the table into a reviewed diff.
- Residual: the class of a read that is merged and never touched again rests on that one review.

**Answers change where a call-path read was reachable with an absent name.** `ScopedBackends::get` returns `None` for such a name, where today's `get` returns the backend. On a correctly gated path no absent name arrives, so no answer changes, and every PR-A row stays green as the check. If a row turns red, the site it names was reachable, which is a bug the type found: it gets a row and a reported fix, never an `Unscoped` to silence it.

**Merge churn.** The production half touches 29 meta-layer files. Every open lane editing `meta_mcp` will conflict, mechanically: each conflicting `self.backends.get` becomes `scoped(..)` or `unscoped(..)`.
- Mitigation: merge PR-B in a window agreed with the open lanes (design d5 §6). Rebase each lane after it; the compiler lists every site.

**Fixture risk for S7a.** If neither shared-principal fixture (§4) works, S7a closes N/A with the trace, and the explicit filter in §6 still ships, covered only by a unit-level row on `prepare_stored_read_kind`'s target list.

**Coverage and inventory.** New non-test functions on the COV.3 paths need inventory rows: `Registry::*`, `ScopedBackends::get`, and the S7a filter if it becomes a helper. `scripts/release/check_inventory_rows.py <base> HEAD` and `--all` must exit 0.

**Not done here.** No change to `authorize_backend`, to listing or search (the V class keeps deciding through `authorize_backend` / `admits_backend`), or to MIK-8441's empty-grant behaviour. MIK-8446 (the signing failure under a malformed nonce) stays separate.

## 8. Order of work

1. Rows first, each with its evidence, so the reviewers see the tests before the code:
   - FW1, C2 and R3 as guards, with M10, M23, M16 and the C2 mutant run against them;
   - T2 as a pin;
   - S7a red.
2. Types plus the 73 reads, one commit, no behaviour change, with T1 and T4. The seat round reviews the class table.
3. The S7a fix, which turns S7a green.
4. Fast gate on each iteration (fmt, clippy with `--all-features` and with `--no-default-features`, the touched modules). The full suite runs in CI. Mutants run in a scratch worktree.
5. Close MIK-8447's rows in the gap table (`backend_oracle/gaps.rs`): each gap that gets a row leaves the pinned set, and the pin moves in the same commit.
