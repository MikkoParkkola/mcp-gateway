# MIK-8387 PR-B: test plan

Status: test plan **v2**: v1 plus its test-plan review (§7). Design: `2026-10-17-mik-8387-scoped-backends-boundary.md` v8 (`b87f83267`). Base: `19ca01f07`. Criterion: ORACLE.5.

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
| **SELF** | `scripts/dev/check_registry_lint.sh --self-test` (new; mirrors `check_clock_lint.sh`) | In a scratch worktree of HEAD, a new production module `src/registry_lint_plants.rs` holds one plant per config entry (19), plus: an alias (`use .. as reg_get`), a function-item binding of a method and of each propagation API, a fully qualified call, a raw read inside a local `macro_rules!` body invoked from production, a raw read hoisted into a `let` with a classed leaf allow (must **not** fire), and a `#[cfg(test)]` module with a raw read (must **not** fire in this pass). Two clippy runs with the dedicated config, `--lib --all-features --message-format=json`, dev and `--release` (release plants: §4). Every `// PLANT` line is reported as `clippy::disallowed_methods` at its own line; no `// ALLOWED` or `// TESTONLY` line is; nothing outside the plant file is (clean control, once the conversions land); no "does not refer to a reachable function" warning; clippy's build completes. The checker is first proven on synthetic diagnostics, as in `check_clock_lint.sh` | Before commit 5 the script does not exist. Its red evidence is SELF-m1, m2 and m4, each giving the named failure line; SELF-m3 is listed only to mark what SELF does not judge | **SELF-m1:** one entry deleted from the config → `plant <name> (src/registry_lint_plants.rs:<n>) was not reported`. **SELF-m2:** an entry's path misspelt → the unreachable-function warning fails the run. **SELF-m3:** the leaf allow widened to the plant fn's `#[allow]` → still green: SELF does not judge placement, T1(b) does (row T1b-m1). Listed so no one counts it as a kill. **SELF-m4:** `CLIPPY_CONF_DIR` not exported (the vacuous `spark-cargo` case) → every plant unreported |

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
| SCAN-6 | `#[cfg(any(not(test), windows))] mod m {..}` | production, nested | (baseline; SCAN-m6 is killed by SCAN-3, whose first operand `test` is false) |
| SCAN-7 | `#[cfg_attr(test, allow(clippy::disallowed_methods))] fn f() {..}` in production | T1(b) records it, in its `cfg_attr` form | SCAN-m3, a scanner that reads only `#[allow]` |
| SCAN-8 | `#[cfg_attr(feature = "x", allow(warnings))] fn f() {..}` | T1(b2) records a broad suppression | SCAN-m3 |
| SCAN-9 | `fn f() { #[allow(clippy::disallowed_methods, reason = "Admin: ..")] let s = r.statuses(); }` | T1(b): node kind statement, class `Admin`, contents `[statuses]` | (baseline) |
| SCAN-10 | as SCAN-9, with `r.all()` and a path `MetaMcp::resolve_propagation_credential` inside the one statement | contents `[all, resolve_propagation_credential]` | SCAN-m4, v5's "method calls of the 17 only" |
| SCAN-11 | `#[allow(clippy::disallowed_methods)] fn f() {..}`, a new fn-level allow | T1(b) **fails**: node kind fn | SCAN-m7, a scanner that accepts any node kind |
| SCAN-12 | `#[path = "x.rs"] mod m;` under a `src/main.rs` root | the module is walked | SCAN-m5, a scanner that walks `src/lib.rs` only |
| SCAN-13 | `let f = Registry::get_for;` | T1(a) **fails**: a non-call reference | (baseline) |
| SCAN-14 | `reg.all_for(why)` with `why` a variable | T1(a) **fails**: a non-literal class | (baseline) |

| SCAN-15 | a `Cargo.toml` fixture naming `[[bin]] path = "src/bin/extra.rs"` that the root list does not walk | T1 **fails**: `unwalked target src/bin/extra.rs` | SCAN-m8, a scanner with a hard-coded root list |
| SCAN-16 | two `fn backend_for` definitions in the fixture tree | T1 **fails**: `second definition of backend_for` | SCAN-m9, a scanner that keys by name without counting definitions |
| SCAN-17 | `fn f() { #[expect(clippy::disallowed_methods, reason = "Admin: ..")] let s = r.statuses(); }` | T1(b) records it as an `expect` | SCAN-m3b, a scanner that reads only `allow` |
| SCAN-18 | `#[derive(Debug, Clone)] struct BackendRegistry { pub x: u8, y: u8 }` | T1(e) extraction: derives `[Debug, Clone]`, field `x` not private | SCAN-m10, a scanner that discards derives; SCAN-m11, one that ignores field visibility |

**Mutants for the baseline rows (GPT, Kimi):** SCAN-m12, a scanner that ignores cfg entirely (kills SCAN-1, SCAN-2); SCAN-m13, one that records no allow contents (kills SCAN-9); SCAN-m14, one that accepts function-item references (kills SCAN-13); SCAN-m15, one that accepts a variable class (kills SCAN-14). **SCAN-TT pins its own case count** (Kimi), so a dropped table line fails as `want <n> cases, got <n-1>`.

Each SCAN-m is applied to `scan.rs` in a scratch worktree and must fail exactly the rows named for it, plus SCAN-TT for m2.

## 3. The pins over the real tree (T1, T2)

The pins live in `src/gateway/meta_mcp/boundary_pins/t1_tests.rs` and `src/gateway/router/backend_choke_pin_tests.rs`. Their pinned values sit beside them: `scoped_backends_classes.tsv` (T1a), `boundary_pins/allows.tsv` (T1b), and inline constants for the rest.

| Row | Asserts | Kind | Red evidence (mutant → failure message) |
|---|---|---|---|
| **T1a** | The class-taking operation sites, keyed by (file, fn, method line, op, class), equal `scoped_backends_classes.tsv`. The TSV is generated once from the second pass's JSON spans, then reviewed (design §3.1) | no compile on the tip | **M19b:** one site's `Unscoped::Visibility` → `Unscoped::Admin` gives `class changed at <file>:<line>: want Visibility, got Admin`. **M19b2:** a new `get_for(Unscoped::Admin, ..)` in a production fn gives `unpinned site <file>:<fn>` |
| **T1b** | Every production `disallowed_methods` allow, as (file, fn, node kind, reason class, banned names inside), equals `allows.tsv`. The existing clock and home allows are rows with contents `[]` | no compile | **M19d:** a second raw call inside an allowed statement gives `contents changed`. **T1b-m1:** an allow moved from the statement to its fn gives `node kind fn`. **T1b-m2:** a registry `get` added inside `clock.rs`'s inner allow gives `contents changed at src/clock.rs` |
| **T1b2** | No production `allow` or `expect` of `warnings`, `clippy::all` or `clippy::style`, conditional or not | **green on the tip** (none exist); guard | **T1b2-m1:** `#![allow(clippy::style)]` added to `gateway/ui/mod.rs` gives `broad suppression at src/gateway/ui/mod.rs` |
| **T1d** | The `Registry::new` call sites equal the pin | no compile | **T1d-m1:** a second `Registry::new` in `events_wiring.rs` gives `unpinned Registry::new` |
| **T1e** | `BackendRegistry` has: the method set, with each method's `cfg(test)` flag (17, plus `new`, plus the test-only `is_stopping`); trait impls `[Default]`; derives `[]`; every field private | **green on the tip**; guard | **M19h:** a new `pub fn peek(&self)` gives `method set changed`. (v1's T1e-m2, `#[derive(Debug)]` on the real struct, is VOID: `Destinations` is not `Debug`, so it does not compile. Derive and field extraction are proven on SCAN-18 instead.) **T1e-m3:** `pub backends:` gives `field backends is not private`. **T1e-m4:** `#[cfg(test)]` removed from `is_stopping` gives `is_stopping became production; add it to the config` |
| **T1f** | The dedicated config's `# MIK-8387 begin`..`end` span is byte-equal to the pin, with nothing outside the span; `pre-push.sh` exports `CLIPPY_CONF_DIR` naming `scripts/lint/registry-ban` | red on the tip: `config not found` | **M19g:** one entry deleted gives `span differs at line <n>`. **T1f-m2:** an entry added below the end marker gives `content outside the span`. **T1f-m3:** pre-push's path changed gives `pre-push does not name scripts/lint/registry-ban`. The workflow half of this pin lands with the lead's workflow commit |
| **T2a** | No `disallowed_methods` allow in production under `src/gateway/router` (read from T1b's inventory) | no compile | **T2a-m1:** an allowed raw `state.backends.get` in `accounts.rs` gives `router allow at src/gateway/router/accounts.rs` |
| **T2b** | In production, `Envelope { .. }` literals occur only in `read_envelope` (`direct_caller.rs:200`), and `route` (`direct_caller.rs:367`) takes `&Envelope` | **green on the tip**; guard | **M20b:** an `Envelope` literal built in the handler, so `route` can run before `read_envelope`, gives `Envelope literal outside read_envelope` |
| **T2c** | Every production reference to `backend_for`, calls and function items alike, keyed by (file, fn), equals the pin; `read_envelope` is not a key | no compile | **M20:** `backend_for` called in `read_envelope` before S4 gives `unpinned reference in read_envelope`. **M20c:** a helper called from `read_envelope` that calls `backend_for` gives `unpinned reference in <helper>` |

## 4. Release-only code (L-rel), replacing v7's T1(g)

| Row | Where | Asserts | Red evidence |
|---|---|---|---|
| **L-rel-all**, **L-rel-nodef** | CI `check` job only (lead) | the ban pass with `--release`, on both feature sets, exits 0 | On the tip: the same 127 and 114 errors as L, since today's release-only code reads no registry. Their strength comes from SELF's release run |
| **SELF-rel** | `check_registry_lint.sh --self-test`, release run | three plants fire: a `#[cfg(not(debug_assertions))] let` statement; a `#[cfg(any(not(debug_assertions), target_os = "redox"))]` fn (an atom false on every host the self-test runs on, so the dev run cannot compile it on macOS or Linux; v1's `macos` was compiled in a macOS dev build); a release-gated invocation of the macro plant. Each also stays **unreported** in the dev run, which proves the dev passes cannot see it | **SELF-rel-m1:** the release run dropped from the script gives `plant release_stmt was not reported` |

## 5. Behavioural rows

| Row | Where | Asserts | Kind | Fails for this reason |
|---|---|---|---|---|
| **T4** view table | `src/gateway/meta_mcp/scoped_backends_view_tests.rs` | Registry `{alpha, beta}` plus capability `cap`. Grants: `Scoped([alpha, ghost])`, `Scoped([alpha, cap])`, `Empty`, `Unscoped` (both from `*` and from no client). Names: alpha, beta, ghost, nosuch, cap. Each cell pins `scoped_get(name).is_some()`, `absence(name)`, and `absent_step(name, "t")` with and without a recorded `Withheld(Absent)`. The capability cells are built both through `Registry::scoped(.., Some("cap"))` and through `MetaMcp::scoped`, and must agree. **Router cell (v2):** `backend_for` builds its view through one function, `backend_choke::view_for(state, grant) -> ScopedBackends` (`pub(super)`, added to the PR's visibility list). The cell asserts `view_for(state, g).absence(n)` equals `MetaMcp::scoped(g).absence(n)` for every grant and name. v1 compared lookup results, which are `None` for `cap` either way, because a capability provider has no registry entry | no compile; the core table lands at commit 1, the router cell at commit 5 | **M31:** the registration check before the scope check gives `nosuch under Scoped([alpha, ghost]): want OutOfScope, got Unregistered` (GPT: `beta` is registered, so it cannot show this). **M32:** `Empty` treated as `Scoped([])` gives a differing `Empty` column. **M33:** `scoped_get` ignores the grant gives `beta: want None, got Some`. **M34:** `MetaMcp::scoped` passes `None` for the capability gives `cap under Scoped([alpha, cap]): absence want None, got Some(Unregistered)`. **M35:** `view_for` passes `None` for the capability gives `router cell cap: absence want None, got Some(Unregistered)` |
| **T5** the `Registry` forwarders (COV.3) | `src/gateway/meta_mcp/scoped_backends_view_tests.rs` | On a registry `{alpha, beta}` with one status, one membership tick, one started subscription and one change feed: `get_for(_, "alpha")` is `Some` and `get_for(_, "nosuch")` is `None`; `all_for` yields `{alpha, beta}`; `membership_for` hands the closure the registry's membership counter; `statuses_for` equals the raw `statuses()`; `subscribe_started_for` receives a registration's start; `nudge_catalogue_for` reaches the change feed. The class argument changes no answer | no compile; lands at commit 1 | **T5-m1..m6:** each forwarder replaced by an empty answer (`None`, an empty `Vec` or map, a fresh receiver, a no-op), giving `get_for/all_for/.. forwarded nothing` |
| **FW1** response targets | `src/gateway/router/oracle_parity_tests.rs` (beside PR-A's parity rows) | A response-firewall rule keyed on target `X`, and one keyed on the gateway's own target. Both rules match the response content (a redact rule on a fixed marker the fixture's backend returns), so every cell writes a **non-empty** response audit row. The three cells are equal, **and** each row's `policy_targets` is pinned to exactly the gateway's own target, with `X` absent. v1 asked for a "which rule fired" field; the audit row has none, it records `policy_targets` and the aggregate action (GPT). Fallback ladder (design §5, Kimi): if `policy_targets` cannot separate the cells, use the verdict of a refusing rule keyed on `X`; a new `#[cfg(test)]` seam is the last resort and is reported as such | **guard**, green on the tip | **M10** (S1's `record_absent` removed, `chokepoint.rs`): all three cells keep target `X`, so the cells agree but the pin fails: `policy_targets contains X`. **M23** (that write kept only for `OutOfScope`): `ghost` keeps `X` while `beta` and `nosuch` drop it, so equality fails: `cells differ: ghost`. A surviving run is a failed row, not a skipped one |
| **C2** capability out of scope | `src/gateway/router/oracle_capability_tests.rs` | A fixture where the server named is a capability provider outside the key's scope, called with tool `nosuch` on `/mcp` invoke, gets one pinned not-found answer | **guard** | **C2-m:** S3's absent check moved below the capability arm (`gate.rs`) exposes the scope refusal instead, because `named_gate_answer` returns `None` with no capability-rule refusal (GPT): `C2 answer changed: got the scope refusal` |
| **R3** stored-read reason | `src/gateway/router/oracle_per_user_tests.rs` | R2 (T0)'s `beta` cell emits the `audit_refusal` warning (tracing capture) with its actual fields: `caller`, `server = beta`, `tool`, and the scope-refusal `reason` text (`authz.rs:281`). `ghost` emits none. The -32003 code is pinned separately, from the authorization result, since the warning carries no number. The answers are equal under a failing log | **guard** | **M16:** S7's `check_visible_policy` call removed gives `no audit_refusal warning for beta` |
| **S7a-0** step 0, the positive witnesses | `src/gateway/router/oracle_per_user_tests/excluded_target.rs` (new) | Two key-server-style callers for one OIDC subject, one scoped `[beta]` and one `[alpha]`, on `meta_mcp::slot_verdict_fixture`: both resolve the same `stable_actor_id`, and the `[beta]` caller's call leaves a warm slot on `beta` (`holds_per_user_slot_for_test`) | must be **green** before S7a counts | If it is red, the fixture cannot reach the touch, and S7a is reported **unresolved** with the obstacle, never closed (design §4.0) |
| **S7a-warm** | same file | After `age_per_user_slot_for_test`, a `tasks/get` by the `[alpha]` caller for a task targeting `beta` leaves the slot's **last-used instant** unchanged, the field the touch writes (`touch_caller_slot`, `task_replay.rs:221`) | **red on the tip** | On the tip `settle_caller_view` reads the unscoped registry and touches `beta`'s slot, giving `slot age changed: the excluded target was touched` |
| **S7a-cold** | same file | With the slot evicted first: no custody read (the fixture's resolve counter is unchanged), no cold claim (`cold_lease_remaining` stays `None`), no catalogue refresh (`beta`'s list counter is unchanged) | **guard**, green on the tip (GPT): account resolution skips refused targets (`task_replay.rs:136`), and `settle_caller_view` returns at `:245` before any claim or refresh | Each assertion gets its own mutant (Kimi). **S7a-c-m1:** the `target_refused_without_catalogue` filter at `:136` removed gives `resolve counter moved`. **S7a-c-m2:** the `refused_without_catalogue` return at `:245` removed gives `cold claim made: cold_lease_remaining is Some`. **S7a-c-m3:** with m2, the refresh also runs, giving `list counter moved`; m3 is m2 observed at the third assertion, run with the first two assertions disabled, so that each assertion's red is shown on its own |

**S7a's mutant (design v8 §6):** after commit 5, `settle_caller_view`'s `scoped_get` turned back into `get_for(Unscoped::Visibility)` must turn S7a-warm red with the message above. The reversions of other stored-read helpers are **not** S7a kills. Some are equivalent under this fixture (`settle_shared_view` returns early at `task_replay.rs:283`; `target_refused_without_catalogue` refuses through `may_invoke` at `:311`), and T1a's class pin covers them instead. If S7a is still red after commit 5, the §6 filter lands as commit 6, and its removal becomes a second mutant.

## 6. Order and the record

1. **Step 0:** S7a-0, green, or S7a is reported unresolved.
2. **Red first:** S7a-warm runs red on the tip (S7a-cold is a guard, v2). Their output is saved to the evidence file `docs/internal/evidence/mik-8387-prb-red.md` with the commit hash.
3. **Guards:** FW1, C2, R3, S7a-cold, T1b2, T1e and T2b run green on the tip. Each one's mutants are run and must kill.
4. **Commits 1 to 5** (design §6). Each row's mutants run when its subject lands: T4 and T5 at commit 1; T2 at commit 4; SCAN, T1, L, SELF and the T4 router cell at commit 5. L's red is the base-commit run (127 / 114).
5. **Commit 6, only if needed** (the S7a filter).
6. **Mutant ledger:** one line per mutant, giving id, row, anchor, result (KILLED, SURVIVED or VOID) and the failure line. A SURVIVED or VOID mutant is fixed or reported, never dropped.
7. **Gates the design requires, recorded per commit with exit status (GPT v1 review):**
   - every PR-A row, unchanged, green (design §7.3: a row that turns red has found a reachable site and gets a row and a reported fix);
   - `scripts/release/check_surface_inventory.py` exits 0;
   - `check_inventory_rows.py <base> HEAD` and `check_inventory_rows.py --all` exit 0;
   - the pre-push gate (`CARGO=spark-cargo scripts/dev/pre-push.sh`), exit 0, with its new registry-ban step. Until `spark-cargo` forwards `CLIPPY_CONF_DIR` (an operator decision), that step's self-test is red under `spark-cargo`; the step is then run with local `cargo` against the Spark mirror's result, and the run is recorded as such, never skipped.

## 7. The v1 test-plan review, item by item

Both seats: SHIP-WITH-FIXES (ledger `gpt-20261017T140243Z-35406`, `synthetic-20261017T140243Z-35407`). Source claims were checked before folding.

| Finding (seat) | Checked at source | v2 |
|---|---|---|
| FW1 needs a "which rule fired" field that does not exist; a clean response matches no rule (GPT) | **Right**: the response audit row carries `policy_targets` and an aggregate action (`response_tests/audit.rs`) | Rules that match, a non-empty row, `policy_targets` pinned; fallback ladder recorded (Kimi) |
| M35 is equivalent: `cap` has no registry entry, so lookups are `None` either way (GPT) | **Right** | Router cell compares `absence` through `view_for` |
| S7a-cold is green on the tip (GPT); only its first assertion would show red (Kimi) | **Right**: `task_replay.rs:136` and `:245` | S7a-cold is a guard, with one mutant per assertion |
| R3: the warning has no -32003 (GPT) | **Right**: `audit_refusal` (`authz.rs:281`) logs caller, server, tool, reason | Assert those fields; pin the code from the authorization result |
| T1e-m2 (`derive(Debug)`) is VOID (GPT) | **Right**: `Destinations` is not `Debug` | Moved to the synthetic SCAN-18 |
| SELF-rel's `macos` plant compiles in a macOS dev build (GPT) | **Right** | `target_os = "redox"`, false on every host used |
| No rows for the six forwarders (COV.3) (GPT) | **Right** | T5 with six mutants |
| PR-A regression, surface and inventory checks missing (GPT) | **Right**, design §7.3 requires them | §6 step 7 |
| No row for an unwalked target or a second definition (GPT; Kimi HIGH, MEDIUM) | **Right**, design §4.2 obliges both | SCAN-15, SCAN-16 |
| Baseline SCAN rows lack mutants (GPT, Kimi) | **Right** | SCAN-m12 to m15 |
| M31 cannot show on `beta` (GPT) | **Right**: `beta` is registered | Cell `nosuch` |
| SCAN-6 cannot kill a first-operand evaluator (GPT) | **Right**: its first operand is already true | m6 is killed by SCAN-3 |
| C2's mutant shows the scope refusal, not `ToolNotFound` (GPT) | Taken as stated; the red run records the actual answer | Row re-worded |
| SELF claims four killing mutants, but m3 stays green (Kimi) | **Right** | Wording fixed |
| No `expect` row (Kimi) | **Right** | SCAN-17 |
| S7a-warm should observe the last-used instant (GPT) | Taken | Row re-worded |
| SCAN-TT should pin its case count (Kimi) | Taken | §2 |

