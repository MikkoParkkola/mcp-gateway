# MIK-8387 PR-B: test plan

Status: test plan **v1**, for review as a test plan. Design: `2026-10-17-mik-8387-scoped-backends-boundary.md` v8 (`b87f83267`). Base: `19ca01f07`. Criterion: ORACLE.5.

## 0. What the review checks

Failure messages in backticks give each assertion's meaning; the exact text is fixed when the test is written, and the red run records it verbatim.

Every row below states **why it fails**, not only that it exists. Each row is one of three kinds:
- **Red on the tip.** It fails at `19ca01f07` (or at the commit before its subject lands) with the stated message, for the stated reason. The red run is recorded before the commit that turns it green.
- **Guard.** It is green on the tip by design, because PR-A already ships the behaviour. Its proof of strength is a named mutant: the mutant is applied in a scratch worktree, the row must fail with the stated message, and the mutant is reverted. A guard with no killing mutant is not a row.
- **Does not compile on the tip.** The row names a type or operation PR-B adds. Its red evidence is a named mutant run after the type lands; "does not compile" is never counted as red.

Mutants run in a scratch worktree, never in the worktree under review. The anchor of each scripted edit is asserted to match exactly once. A mutant run that fails to compile, or whose test filter matches no test, is VOID, not killed (`--list` count ≥ 1 per row).

## 1. The lint pass (L) and its self-test (SELF)

| Row | Where | Asserts | Red on the tip, and why | Kills |
|---|---|---|---|---|
| **L-all** | pre-push step, CI `check` job (lead) | `CLIPPY_CONF_DIR=scripts/lint/registry-ban cargo clippy --lib --bins --all-features -- -D warnings` exits 0 | At `19ca01f07` plus the dedicated config only: exit 101 with **127** `error: use of a disallowed method`, 126 on `BackendRegistry` methods and 1 on `resolve_propagation_credential` at `propagation.rs:26`, per-method counts as design §2.8 B2. Reason: every raw production read is still raw. Green at commit 5 | M19 (a raw `get` added to a production fn), M19c (a helper returning `&BackendRegistry`, then `.all()` on it), M19f (a `let f = MetaMcp::resolve_propagation_credential;` in production) |
| **L-nodef** | same | the same with `--no-default-features` | 114 errors in 53 files (§2.8 C2), same reason | as L-all, on code outside feature gates |
| **SELF** | `scripts/dev/check_registry_lint.sh --self-test` (new; mirrors `check_clock_lint.sh`) | In a scratch worktree of HEAD, a new production module `src/registry_lint_plants.rs` holds one plant per config entry (19), plus: an alias (`use .. as reg_get`), a function-item binding of a method and of each propagation API, a fully qualified call, a raw read inside a local `macro_rules!` body invoked from production, a raw read hoisted into a `let` with a classed leaf allow (must **not** fire), and a `#[cfg(test)]` module with a raw read (must **not** fire in this pass). Two clippy runs with the dedicated config, `--lib --all-features --message-format=json`, dev and `--release` (release plants: §4). Every `// PLANT` line is reported as `clippy::disallowed_methods` at its own line; no `// ALLOWED` or `// TESTONLY` line is; nothing outside the plant file is (clean control, once the conversions land); no "does not refer to a reachable function" warning; clippy's build completes. The checker is first proven on synthetic diagnostics, as in `check_clock_lint.sh` | Before commit 5 the script does not exist. Its red evidence is the four mutants in the next column, each giving the named failure line | **SELF-m1:** one entry deleted from the config → `plant <name> (src/registry_lint_plants.rs:<n>) was not reported`. **SELF-m2:** an entry's path misspelt → the unreachable-function warning fails the run. **SELF-m3:** the leaf allow widened to the plant fn's `#[allow]` → still green: SELF does not judge placement, T1(b) does (row T1b-m1). Listed so no one counts it as a kill. **SELF-m4:** `CLIPPY_CONF_DIR` not exported (the vacuous `spark-cargo` case) → every plant unreported |

`SELF` exists because clippy only warns when a `disallowed-methods` path does not resolve, so a renamed method would switch the ban off silently. That is the same reason MIK-8202 ships `check_clock_lint.sh`.

## 2. The pin scanner and its adversarial fixtures (SCAN)

T1 and T2 share one `syn` scanner, `src/gateway/meta_mcp/boundary_pins/scan.rs` (`#[cfg(test)]`). Its rules are design §4.2. It gets unit tests on synthetic source strings first, so a scanner bug fails a small named case instead of hiding inside a pin over the real tree (GPT v5).

**SCAN-TT, the truth table (GPT v7).** `cfg_status(predicate)` returns `False`, `True` or `Unknown`, with `test` = false and every other atom unknown. One table-driven test covers every operator over every operand state: `not` of each of the three; `all` and `any` over every pair of the three; nesting two deep; and the empty forms, `all()` = `True` and `any()` = `False`, as Rust defines them. An item is test-only only when its predicate, or an ancestor's, is `False`.

| Row | Snippet | Expected | The wrong scanner it catches |
|---|---|---|---|
| SCAN-1 | `#[cfg(test)] fn f() { r.get("a"); }` | test-only, skipped | (baseline) |
| SCAN-2 | `#[cfg(all(test, feature = "x"))] fn f() {..}` | test-only | (baseline) |
| SCAN-3 | `#[cfg(any(test, feature = "webui"))] fn f() {..}` | **production** | SCAN-m1, v5's "predicate mentions test" |
| SCAN-4 | `#[cfg(not(test))] fn f() {..}` | **production** | SCAN-m1 |
| SCAN-5 | `#[cfg(not(feature = "webui"))] fn f() {..}` | **production** | SCAN-m2, v6's "unknown atoms are true" (`not(true)` = false) |
| SCAN-6 | `#[cfg(any(not(test), windows))] mod m {..}` | production, nested | SCAN-m6, an evaluator that reads only the first operand |
| SCAN-7 | `#[cfg_attr(test, allow(clippy::disallowed_methods))] fn f() {..}` in production | T1(b) records it, in its `cfg_attr` form | SCAN-m3, a scanner that reads only `#[allow]` |
| SCAN-8 | `#[cfg_attr(feature = "x", allow(warnings))] fn f() {..}` | T1(b2) records a broad suppression | SCAN-m3 |
| SCAN-9 | `fn f() { #[allow(clippy::disallowed_methods, reason = "Admin: ..")] let s = r.statuses(); }` | T1(b): node kind statement, class `Admin`, contents `[statuses]` | (baseline) |
| SCAN-10 | as SCAN-9, with `r.all()` and a path `MetaMcp::resolve_propagation_credential` inside the one statement | contents `[all, resolve_propagation_credential]` | SCAN-m4, v5's "method calls of the 17 only" |
| SCAN-11 | `#[allow(clippy::disallowed_methods)] fn f() {..}`, a new fn-level allow | T1(b) **fails**: node kind fn | SCAN-m7, a scanner that accepts any node kind |
| SCAN-12 | `#[path = "x.rs"] mod m;` under a `src/main.rs` root | the module is walked | SCAN-m5, a scanner that walks `src/lib.rs` only |
| SCAN-13 | `let f = Registry::get_for;` | T1(a) **fails**: a non-call reference | (baseline) |
| SCAN-14 | `reg.all_for(why)` with `why` a variable | T1(a) **fails**: a non-literal class | (baseline) |

Each SCAN-m is applied to `scan.rs` in a scratch worktree and must fail exactly the rows named above, plus SCAN-TT for m2 and m6.

## 3. The pins over the real tree (T1, T2)

The pins live in `src/gateway/meta_mcp/boundary_pins/t1_tests.rs` and `src/gateway/router/backend_choke_pin_tests.rs`. Their pinned values sit beside them: `scoped_backends_classes.tsv` (T1a), `boundary_pins/allows.tsv` (T1b), and inline constants for the rest.

| Row | Asserts | Kind | Red evidence (mutant → failure message) |
|---|---|---|---|
| **T1a** | The class-taking operation sites, keyed by (file, fn, method line, op, class), equal `scoped_backends_classes.tsv`. The TSV is generated once from the second pass's JSON spans, then reviewed (design §3.1) | no compile on the tip | **M19b:** one site's `Unscoped::Visibility` → `Unscoped::Admin` gives `class changed at <file>:<line>: want Visibility, got Admin`. **M19b2:** a new `get_for(Unscoped::Admin, ..)` in a production fn gives `unpinned site <file>:<fn>` |
| **T1b** | Every production `disallowed_methods` allow, as (file, fn, node kind, reason class, banned names inside), equals `allows.tsv`. The existing clock and home allows are rows with contents `[]` | no compile | **M19d:** a second raw call inside an allowed statement gives `contents changed`. **T1b-m1:** an allow moved from the statement to its fn gives `node kind fn`. **T1b-m2:** a registry `get` added inside `clock.rs`'s inner allow gives `contents changed at src/clock.rs` |
| **T1b2** | No production `allow` or `expect` of `warnings`, `clippy::all` or `clippy::style`, conditional or not | **green on the tip** (none exist); guard | **T1b2-m1:** `#![allow(clippy::style)]` added to `gateway/ui/mod.rs` gives `broad suppression at src/gateway/ui/mod.rs` |
| **T1d** | The `Registry::new` call sites equal the pin | no compile | **T1d-m1:** a second `Registry::new` in `events_wiring.rs` gives `unpinned Registry::new` |
| **T1e** | `BackendRegistry` has: the method set, with each method's `cfg(test)` flag (17, plus `new`, plus the test-only `is_stopping`); trait impls `[Default]`; derives `[]`; every field private | **green on the tip**; guard | **M19h:** a new `pub fn peek(&self)` gives `method set changed`. **T1e-m2:** `#[derive(Debug)]` gives `derives changed`. **T1e-m3:** `pub backends:` gives `field backends is not private`. **T1e-m4:** `#[cfg(test)]` removed from `is_stopping` gives `is_stopping became production; add it to the config` |
| **T1f** | The dedicated config's `# MIK-8387 begin`..`end` span is byte-equal to the pin, with nothing outside the span; `pre-push.sh` exports `CLIPPY_CONF_DIR` naming `scripts/lint/registry-ban` | red on the tip: `config not found` | **M19g:** one entry deleted gives `span differs at line <n>`. **T1f-m2:** an entry added below the end marker gives `content outside the span`. **T1f-m3:** pre-push's path changed gives `pre-push does not name scripts/lint/registry-ban`. The workflow half of this pin lands with the lead's workflow commit |
| **T2a** | No `disallowed_methods` allow in production under `src/gateway/router` (read from T1b's inventory) | no compile | **T2a-m1:** an allowed raw `state.backends.get` in `accounts.rs` gives `router allow at src/gateway/router/accounts.rs` |
| **T2b** | In production, `Envelope { .. }` literals occur only in `read_envelope` (`direct_caller.rs:200`), and `route` (`direct_caller.rs:367`) takes `&Envelope` | **green on the tip**; guard | **M20b:** an `Envelope` literal built in the handler, so `route` can run before `read_envelope`, gives `Envelope literal outside read_envelope` |
| **T2c** | Every production reference to `backend_for`, calls and function items alike, keyed by (file, fn), equals the pin; `read_envelope` is not a key | no compile | **M20:** `backend_for` called in `read_envelope` before S4 gives `unpinned reference in read_envelope`. **M20c:** a helper called from `read_envelope` that calls `backend_for` gives `unpinned reference in <helper>` |

## 4. Release-only code (L-rel), replacing v7's T1(g)

| Row | Where | Asserts | Red evidence |
|---|---|---|---|
| **L-rel-all**, **L-rel-nodef** | CI `check` job only (lead) | the ban pass with `--release`, on both feature sets, exits 0 | On the tip: the same 127 and 114 errors as L, since today's release-only code reads no registry. Their strength comes from SELF's release run |
| **SELF-rel** | `check_registry_lint.sh --self-test`, release run | three plants fire: a `#[cfg(not(debug_assertions))] let` statement; a `#[cfg(any(not(debug_assertions), target_os = "macos"))]` fn; a release-gated invocation of the macro plant. Each also stays **unreported** in the dev run, which proves the dev passes cannot see it | **SELF-rel-m1:** the release run dropped from the script gives `plant release_stmt was not reported` |

## 5. Behavioural rows

| Row | Where | Asserts | Kind | Fails for this reason |
|---|---|---|---|---|
| **T4** view table | `src/gateway/meta_mcp/scoped_backends_view_tests.rs` | Registry `{alpha, beta}` plus capability `cap`. Grants: `Scoped([alpha, ghost])`, `Scoped([alpha, cap])`, `Empty`, `Unscoped` (both from `*` and from no client). Names: alpha, beta, ghost, nosuch, cap. Each cell pins `scoped_get(name).is_some()`, `absence(name)`, and `absent_step(name, "t")` with and without a recorded `Withheld(Absent)`. The capability cells are built both through `Registry::scoped(.., Some("cap"))` and through `MetaMcp::scoped`, and must agree. **Router cell:** `backend_for(state, grant, name)` equals `scoped_get` for every grant and name | no compile; the core table lands at commit 1, the router cell at commit 5 | **M31:** the registration check before the scope check gives `beta under Scoped([alpha, ghost]): want OutOfScope, got Unregistered`. **M32:** `Empty` treated as `Scoped([])` gives a differing `Empty` column. **M33:** `scoped_get` ignores the grant gives `beta: want None, got Some`. **M34:** `MetaMcp::scoped` passes `None` for the capability gives `cap: want Some, got None (Unregistered)`. **M35:** `backend_for` passes `None` for the capability gives `router cell cap differs from scoped_get` |
| **FW1** response targets | `src/gateway/router/oracle_parity_tests.rs` (beside PR-A's parity rows) | A response-firewall rule keyed on target `X`, and one keyed on the gateway's own target. The three cells are equal, **and** the verdict is pinned: the `X` rule applies to no cell, the gateway-target rule to all. Observed through the response firewall's own audit projection (which rule fired), with no new seam | **guard**, green on the tip | **M10** (S1's `record_absent` removed, `chokepoint.rs`): all three cells keep target `X`, so the cells agree but the pinned verdict fails: `rule X fired; want gateway-target rule only`. **M23** (that write kept only for `OutOfScope`): `ghost` keeps `X` while `beta` and `nosuch` drop it, so equality fails: `cells differ: ghost`. A surviving run is a failed row, not a skipped one |
| **C2** capability out of scope | `src/gateway/router/oracle_capability_tests.rs` | A fixture with a capability provider outside the key's scope, called with `nosuch` on `/mcp` invoke, gets one pinned answer | **guard** | **C2-m:** S3's absent check moved below the capability arm (`gate.rs`) gives a `ToolNotFound` answer where the pinned answer is expected: `C2 answer changed` |
| **R3** stored-read reason | `src/gateway/router/oracle_per_user_tests.rs` | R2 (T0)'s `beta` cell emits the `audit_refusal` warning (tracing capture) naming -32003 and the scope; `ghost` emits none; the answers are equal under a failing log | **guard** | **M16:** S7's `check_visible_policy` call removed gives `no audit_refusal warning for beta` |
| **S7a-0** step 0, the positive witnesses | `src/gateway/router/oracle_per_user_tests/excluded_target.rs` (new) | Two key-server-style callers for one OIDC subject, one scoped `[beta]` and one `[alpha]`, on `meta_mcp::slot_verdict_fixture`: both resolve the same `stable_actor_id`, and the `[beta]` caller's call leaves a warm slot on `beta` (`holds_per_user_slot_for_test`) | must be **green** before S7a counts | If it is red, the fixture cannot reach the touch, and S7a is reported **unresolved** with the obstacle, never closed (design §4.0) |
| **S7a-warm** | same file | After `age_per_user_slot_for_test`, a `tasks/get` by the `[alpha]` caller for a task targeting `beta` leaves the slot age unchanged | **red on the tip** | On the tip `settle_caller_view` reads the unscoped registry and touches `beta`'s slot, giving `slot age changed: the excluded target was touched` |
| **S7a-cold** | same file | With the slot evicted first: no custody read (the fixture's resolve counter is unchanged), no cold claim (`cold_lease_remaining` stays `None`), no catalogue refresh (`beta`'s list counter is unchanged) | **red on the tip** for each assertion reached | On the tip the cold path resolves and claims for `beta`, giving `resolve counter moved` (and the others, in order) |

**S7a's mutant (design v8 §6):** after commit 5, `settle_caller_view`'s `scoped_get` turned back into `get_for(Unscoped::Visibility)` must turn S7a-warm red with the message above. The reversions of other stored-read helpers are **not** S7a kills. Some are equivalent under this fixture (`settle_shared_view` returns early at `task_replay.rs:283`; `target_refused_without_catalogue` refuses through `may_invoke` at `:311`), and T1a's class pin covers them instead. If S7a is still red after commit 5, the §6 filter lands as commit 6, and its removal becomes a second mutant.

## 6. Order and the record

1. **Step 0:** S7a-0, green, or S7a is reported unresolved.
2. **Red first:** S7a-warm and S7a-cold run red on the tip. Their output is saved to the evidence file `docs/internal/evidence/mik-8387-prb-red.md` with the commit hash.
3. **Guards:** FW1, C2, R3, T1b2, T1e and T2b run green on the tip. Each one's mutants are run and must kill.
4. **Commits 1 to 5** (design §6). Each row's mutants run when its subject lands: T4 at commit 1; T2 at commit 4; SCAN, T1, L, SELF and the T4 router cell at commit 5. L's red is the base-commit run (127 / 114).
5. **Commit 6, only if needed** (the S7a filter).
6. **Mutant ledger:** one line per mutant, giving id, row, anchor, result (KILLED, SURVIVED or VOID) and the failure line. A SURVIVED or VOID mutant is fixed or reported, never dropped.
