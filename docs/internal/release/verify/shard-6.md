# Shard 6 verification — RELEASE-4.0.0-criteria-status.md lines 432-502

Method: read rows, check every file:line/symbol/SHA cited at source, classify as
MATCH / DRIFT (content correct, line number stale) / CONTRADICTION (source says
something different).

## Rows checked

| Row | Claim | Check | Verdict |
|---|---|---|---|
| GH475.VAL.8 | test `src/config/tests.rs:2019` | `sed -n '2010,2030p'` — doc comment `/// GH475.VAL.8` at 2019, `fn gh475_val_8_accepted_boundary_values_parse` at 2021, body accepts boundary values exactly as described | MATCH (near-exact) |
| GH475.OBS.1 | tests at invoke.rs `:4650`, `:4664`, `:4678`; symbol `mcp_error_budget_suppressed_total`; commit `5e0a8da2` | `rg -n` for the three fn names found them at **4854, 4868, 4882** (~204-line drift). Bodies match the described assertions exactly (`Some(1)` for the sole exclusion arm, `None` for Success/Failure arms). `git log --oneline -1 5e0a8da2` = `test(gh475): OBS.1 — pin the suppression counter's population...`; `git merge-base --is-ancestor 5e0a8da2 HEAD` = ancestor (on branch) | DRIFT, not contradiction |
| GH475.OBS.1 (ops.rs:258 exclusion) | `src/backend/ops.rs:258` out of population per ruling `0961b990` | not independently re-checked (out of primary scope of citation density); no contradicting evidence found | UNCHECKED (not flagged — no evidence against it) |
| GH475.OBS.2 | test invoke.rs `:4540`; commit `a8b1158f` | `rg -n rate_limited_exclusion_emits_a_debug_event` → actual line **4750** (~210-line drift). Body installs scoped tracing subscriber and asserts one `debug!` fires, matching description. `git log -1 a8b1158f` = `test(invoke): GH475.OBS.2 — capture the suppression debug event`; ancestor of HEAD confirmed | DRIFT, not contradiction |
| GH475.MIG.1 | test `src/commands/upgrade.rs:1163`, starts at stamp `3.9.0`, asserts config byte-identical | Actual fn `migration_4_0_0_advances_the_stamp_without_touching_the_config` starts at line **1169** (doc comment 1165); `write_stamp(..., "3.9.0")` at line 1174. Citation lands ~6-11 lines early, inside/adjacent to the correct test | DRIFT (minor) |
| GH475.MIG.2 | assertions at upgrade.rs `:1182`, `:1189` pin literal `"4.0.0"`; production reads at `:465`, `:522` stay version-agnostic; commit `98bef5d1` | `sed -n '1176,1200p'` shows first `assert_eq!(..., "4.0.0")` at ~1181-1183, second at ~1188-1190 — within 1-2 lines of cited. `:465` and `:522` are **exact** matches: both are `let current_str = env!("CARGO_PKG_VERSION");`. `git log -1 98bef5d1` = `test(upgrade): GH475.MIG.2 — pin migration stamp assertions to the literal 4.0.0`; ancestor confirmed | MATCH (near-exact) |
| GH475.MIG.3 | comparison direction pinned at upgrade.rs `:404` (`old_ver < ceiling`); test `upgrade_from_above_4_0_0_does_not_refire_the_notice` at `:1206`; commit `82d8490b` | `:404` is an **exact** match: `SemVer::parse(m.applies_below).is_some_and(|ceiling| self.old_ver < ceiling)`. Test fn at `:1206` is **exact** match. `git log -1 82d8490b` = `test(upgrade): GH475.MIG.3 — pin the comparison direction in applicable_migrations`; ancestor confirmed | MATCH (exact) |
| GH475.MIG.4 | test `:1148` (four items named) | doc comment at 1150, fn `notice_4_0_0_carries_all_four_items` at 1154 — content matches, ~2-6 line drift | DRIFT (minor) |
| GH475.MIG.4 | test `:1218` (every command notice tells operator to run exists) | Line 1218 in current source falls inside an **unrelated** test (`notice_only_upgrade_leaves_no_config_backup`, body). The actual fn `every_command_a_notice_prints_is_a_real_subcommand` is at line **1256** (doc comment 1245) — **38-line drift**. Content of the real test matches the claim (checks every notice-printed command against `clap`'s subcommand list) | DRIFT (large, but content confirmed correct at the true location — not a contradiction) |
| GH475.NOTICE.1 | integration test `tests/gh475_quiet_upgrade_still_warns.rs:3` runs built binary `--quiet` over 2.x data dir | Line 3 is the module doc comment describing exactly this scenario; `Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))` at line 24; `#[test]` at 39 calls `upgrade_from_2_x(&["--quiet"])`. Behavior matches | MATCH |
| Narrative (line 461-463) GH475.CFG.5 | "setters are at `:972` and `:977`, called from `server/mod.rs:615`" | `rg -n 'fn set_error_budget_config\|fn set_capability_budget_config'` → actual definitions at **1001** and **1006** (~29-line drift from the ledger's own citation). Caller line **exact**: `server/mod.rs:615` = `meta_mcp.set_error_budget_config(backend_budget);`, `:616` = `set_capability_budget_config(capability_budget)`. Substance (setters are called, not callerless) holds | DRIFT — ledger's own corrective citation has drifted from the source it corrects, but the correction itself remains true |

No row in 432-502 was found where the source contradicts the stated verdict or the substance of the
reasoning. Every citation with a discrepancy showed the same pattern: right symbol, right test body,
right commit, stale line number — consistent with the doc's own stated caveat (lines 54-60) that line
anchors drift as later commits insert lines above cited locations. None of the drifted citations in
this range fall inside the `continuation.rs`/MRTR scope that caveat names — this drift is from
**committed** history (later same-file commits), not the concurrent uncommitted MRTR session.

No VERDICT-RIGHT-REASONING-WRONG case found in this range.

## Second task — summary/totals recount

Stated (line 11): "146 criteria, 183 rows, 162 met or non-blocking, 21 blocking."

```
rg -c '^\| `?[A-Z][A-Za-z0-9]*-?[A-Za-z0-9]*\.[A-Z]+\.[0-9]' docs/requirements/RELEASE-4.0.0-criteria-status.md
→ 185   (pattern over-broad by ~2 vs. stated row count; not a clean re-derivation of "rows")

rg -c '\| yes \|$' docs/requirements/RELEASE-4.0.0-criteria-status.md   → 21   (blocking)
rg -c '\| no \|$'  docs/requirements/RELEASE-4.0.0-criteria-status.md   → 162  (non-blocking)
21 + 162 = 183  — MATCHES the stated row/blocking totals exactly.
```

The blocking-column recount (21 blocking, 162 non-blocking, 183 total) reproduces the stated numbers
exactly via an independent `rg` count, not by reading the summary line back to itself. This is
consistent with the file's own claim (lines 13-19) that `scripts/release/count-release-criteria.py
--check` mechanically recounts the blocking column and fails on disagreement — the number is not
hand-transcribed here. The "146 criteria" figure (distinct from "183 rows" because some criteria are
split into multiple clause rows) was not independently re-derived — clause-splitting makes a
criterion-level recount from row text alone unreliable without the same clause-grouping logic the
counting script uses — so it is reported as UNVERIFIED rather than confirmed or contradicted.

## Commands run (representative)

```
sed -n '432,502p' docs/requirements/RELEASE-4.0.0-criteria-status.md
sed -n '2010,2030p' src/config/tests.rs
rg -n "ignored_rate_limit_increments_the_suppressed_counter_exactly_once|success_outcome_does_not_increment_the_suppressed_counter|ordinary_failure_does_not_increment_the_suppressed_counter" src/gateway/meta_mcp/invoke.rs
rg -n "rate_limited_exclusion_emits_a_debug_event" src/gateway/meta_mcp/invoke.rs
rg -n "mcp_error_budget_suppressed_total" src/gateway/meta_mcp/invoke.rs
git log --oneline -1 5e0a8da2 && git merge-base --is-ancestor 5e0a8da2 HEAD
git log --oneline -1 a8b1158f && git merge-base --is-ancestor a8b1158f HEAD
sed -n '1155,1225p' src/commands/upgrade.rs
sed -n '460,470p;518,526p' src/commands/upgrade.rs
rg -n 'CARGO_PKG_VERSION' src/commands/upgrade.rs
git log --oneline -1 98bef5d1 && git merge-base --is-ancestor 98bef5d1 HEAD
sed -n '395,415p' src/commands/upgrade.rs
git log --oneline -1 82d8490b && git merge-base --is-ancestor 82d8490b HEAD
sed -n '1140,1260p' src/commands/upgrade.rs
cat tests/gh475_quiet_upgrade_still_warns.rs | head -60
rg -n "fn set_error_budget_config|fn set_capability_budget_config" src/gateway/meta_mcp/mod.rs
rg -n "set_error_budget_config|set_capability_budget_config" src/gateway/server/mod.rs
rg -c '^\| (MIK-|GH)' docs/requirements/RELEASE-4.0.0-criteria-status.md
rg -c '\| yes \|$' / '\| no \|$' docs/requirements/RELEASE-4.0.0-criteria-status.md
git status --porcelain -- src/commands/upgrade.rs src/gateway/meta_mcp/invoke.rs src/gateway/meta_mcp/mod.rs src/gateway/server/mod.rs src/config/tests.rs
```

`git status --porcelain` on all five source files touched by this shard's citations returned empty —
confirming (per the parent task's note) that the drift found here is from **committed** history, not
the concurrent uncommitted `continuation.rs` MRTR churn the doc's own caveat (lines 54-60) warns about.
