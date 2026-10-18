# CI shard design: macOS check, Windows check, Tests (draft for review)

Branch `ci/mik-NEW-shard-os-tests` from `origin/docs/ranking-1-release-line` @ 9df6385fe. No code yet.

## Measured baseline (PR 3930, run 39127109418, 0 min queue, every rust-cache "No cache found")

| Job | deps | crate + test targets compile | clippy | test run | total |
|---|---|---|---|---|---|
| macOS check (macos-latest: 3 M1 cores, 7 GB) | 1.3 min | **38.4 min** | - | 28 min | 68 min |
| Windows check (windows-2025: 4 cores, 16 GB) | (in compile) | 14.3 min | 5.4 min | 29.5 min (+9 s privileged rows) | 51 min |
| Tests (ubuntu-latest: 4 cores, 16 GB) | 0.9 min | 4.3 min | - | 22 min | 27 min |

Source: step timestamps from `gh api .../jobs/{id}`; the cargo `Finished` lines in `gh run view --job --log`.
Test-binary spans (Linux / macOS / Windows): lib unittests (12,291 tests) take 565 / 790 / 1091 s. The
largest integration binaries are `f24_tools_changed_delivery` (1 test, ~200 s, the floor for any shard),
`mik_7479_mrtr7b_ledger` (62-93 s) and `mik_7212` (69 s). There are 221 test binaries, 14,543 passed tests and 42 ignored.
macOS: the `(lib test)` eh_frame linker warning comes 6 s before `Finished`, so the lib-test target is the long pole.
Specs come from docs.github.com "GitHub-hosted runners" (public repos). macOS memory pressure is an
**inference (I)**, not yet measured.

**Conclusion: compile dominates macOS. Sharding the test run alone cannot get macOS under ~45 min.**
Compile-once (`cargo nextest archive`) leaves 38 min on the critical path, and the archive is roughly 217
statically linked test binaries, multiple GB per OS. Restoring the cache saves about 1 min of deps only.
So the plan does not use an archive.

## Revision 2: route choice (review round 1 folded)

Two routes. **Recommended: B.**

**A, nextest partitions.** `scripts/ci/check-pick-then-bind.py:169-183` fails the build when any workflow (or
`.config/nextest.toml`) says `nextest` while `src/test_ports.rs` lacks the `nextest-reviewed` marker.
That is correct, because `reserved_port()` (`src/test_ports.rs:42-52`) is only unique within one process: it starts
at a pid-derived offset, keeps a per-process counter, and releases its probe socket before returning. Under
process-per-test, two processes can each return the same "free" port.
So A's **step one is a separate small PR**: make `test_ports` concurrency-safe and mark it `nextest-reviewed`.
- Either: bind-and-hold. The caller receives the listener, or a lock file / OS-held reservation keyed by port,
  so the port cannot be handed out twice across processes.
- Or: a per-process random start plus retry on `AddrInUse` at the use site.
- That PR has its own red test: two child processes call `reserved_port()` concurrently N times with zero duplicates.
  On today's code it must go red.
- It also unblocks nextest on the local Spark gate later.
- nextest is installed pinned by SHA (`taiki-e/install-action@<sha>` with a pinned `tool: cargo-nextest@<ver>`), like every other action.

**B, shard by test target with plain `cargo test` (no nextest, no port change).** Each shard is its own VM,
so no two test processes share a host; within a shard the process model is today's.
- **Lib split:** libtest filter vs `--skip` on the same substring is an exact complement by construction.
  `gateway::` is 5,350 of the 12,291 lib tests (44 %, from the PR 3930 log).
  - Lib A: `cargo test --all-features --lib -- gateway:: <skips>`
  - Lib B: `cargo test --all-features --lib -- --skip gateway:: <skips>`
- **Integration split:** cargo `--test` takes Unix globs; `'[a-l]*'` and `'[!a-l]*'` are exact complements.
  First letters of the 217 targets: a-l is 74 files, the rest is 143 (93 of them `m*`). Rebalance the class from the per-binary times.
  - Int A: `cargo test --all-features --no-fail-fast --bins --test '[a-l]*' -- <skips>`
  - Int B: `cargo test --all-features --no-fail-fast --test '[!a-l]*' -- <skips>`, then (Linux/macOS only)
    `cargo test --all-features --no-fail-fast --doc` and `cargo build --all-features --examples`
  - Lib shards also carry `--no-fail-fast` (several lib binaries: `--lib` is one, but the flag is uniform).
- **Compile splits too:** lib shards build only the lib-test target; integration shards build the lib (non-test),
  the bins and their own tests. That is the only lever on macOS's 38 min compile.

**Why B:**
- Cheaper: no port rewrite, no new tool, no 12k-process spawn cost on Windows, and `--skip` keeps its substring meaning.
- Safer: the process model is unchanged, so P0b only has to show parity, not a new concurrency model.
- Costs: manual balance, and a guard (below) that each OS's shard set reproduces its original targets exactly.

The test_ports PR stays worth doing for the Spark gate, but off this critical path.
**Lead decision:** B, or A with the test_ports PR first.

## Plan

**Stage 0: probes (throwaway draft PR, no merge). Route B chosen (MIK-8482).**
- P0-glob (seconds, first): `cargo test --all-features --test '[a-l]*' --no-run` and `'[!a-l]*'`, with the
  `Executable` lines captured from each, checked against `cargo metadata` test targets. Pass = both sets non-empty,
  disjoint, and their union equals every `kind: test` target. Cargo documents glob support for `--test`
  (doc.rust-lang.org/cargo/commands/cargo-test.html, target selection). This step is the test that `[!..]` negation works.
- P0a, macOS:
  - First, cold and isolated: `cargo test --all-features --lib --no-run --timings` in a fresh job, deps only from the cache.
    This is the lib-test compile wall that the Lib shards inherit.
  - Then the full `--no-run --timings`, sampling `vm_stat`, `sysctl vm.swapusage` and peak rustc RSS every 30 s.
  - Repeat with `CARGO_BUILD_JOBS=2`, and once on `macos-15-intel`. Upload `cargo-timing.html`.
  - If the lib-test target alone takes more than ~25 min to compile, no target split meets the threshold.
    Only a runner change or shrinking that target would.
- P0b, Linux, Windows **and macOS**, 5 runs each at one SHA. It runs the route-B shard commands, with each OS job's
  real exclusions:
  - Linux and macOS: `--skip a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result --skip mik_7479_full_burst` (ci.yml:596, :613).
  - Windows: `--skip mik_7479_full_burst` (ci.yml:533).
  - Baselines are recorded **per shard and per step**, on all three OSes at the probe SHA: the suite step,
    doctests, UPGRADING (Linux), and the privileged rows (Windows). Parity is checked per selection, never as one sum:
    - the suite-step shards sum to the unsharded suite step;
    - each auxiliary step is compared with its own unsharded value.
    This avoids double counting.
  - Pass = 0 failures in all 5 runs, and per-selection counts equal to the unsharded run each time
    (Linux suite reference from PR 3930: 14,543 passed, 42 ignored).
  - Output: the per-shard selected-count table (the floors for Stage 1) and per-shard wall times.
  - If route A is chosen, the same probe runs `cargo nextest` with the same exclusions as a filterset, after the
    test_ports PR has merged. It also measures cross-binary overlap (f24, mik_7479, mik_7212, admission cap,
    gateway spawns) and Windows spawn cost.

**Stage 1 (route B; times from PR 3930 per-binary spans, I until P0b).**
- `windows-clippy` ("Windows clippy") is a new parallel job. It saves 5.4 min. The `Windows check` aggregate `needs:` it,
  and it joins the gating sets in `test_docs_only_gating.py` / `test_throwaway_routing.py` like every shard.
- Tests: 4 shards on ubuntu-latest, each 1 + ≤5 compile + about 5-7 min run, so **~13 min**.
  The UPGRADING step needs `--bin mcp-gateway` and `--test upgrading_summary_rows`, so it runs in Linux Int B.
- Windows: 4 shards. The lib shards take about 14 + 9 min; integration about 12 + 7. Expected **~24 min (I)**.
  Each shard compiles for itself, so no archive and no new handoff. Doctests stay out on Windows, as today (`--tests`).
  The privileged rows (`--lib --ignored win_privileged::`) run in Windows Lib A, after its suite, with `!cancelled()`.
  Every Windows shard runs "Allow symlink creation" before its suite, because the W-T6 no-follow rows can land in any shard.
  "The debug exe starts" runs in Windows Int A, which builds `--bins`, right after that shard's build.

**Stage 2: macOS, target-filtered (not compile-minimal); threshold set after P0a.**
- **macOS Lib A / Lib B** (the lib split above) each compile the lib-test target and run half of the 790 s.
- **macOS Int A** runs `--bins` plus `[a-l]*`.
- **macOS Int B** runs `[!a-l]*`, plus `cargo test --doc --all-features` (39 s today), plus `cargo build --examples --all-features`.
  The examples build keeps `examples/validator_demo.rs` compiling, which the current default target set covers.
- **macOS Lib A** also runs `check_macos_exclusions.py`.
- Lib shards inherit the lib-test compile wall. If P0a shows that target alone takes more than ~25 min, the fallbacks are:
  - M1: cap `CARGO_BUILD_JOBS` when memory pressure is confirmed.
  - M3: Intel runner, which needs an operator decision because it loses arm64 coverage.
- 4 macOS jobs per PR against the cap of 5 shared by every PR in flight: a second PR queues its macOS work.
  Merging Int A into Int B gives 3 jobs if queueing dominates.
- **Calibrated projection** (published in the Stage 0 report, before Stage 2 is built):
  macOS wall = max over shards of (deps ~1.3 + that shard's P0a compile + its P0b run).
  The 3-job variant is used when either holds:
  - queue time for macOS shards exceeds 5 min on 2 of the 3 threshold runs; or
  - the projected Int A + Int B merged wall stays ≤ 30 min.

## Required names kept (exact) and the aggregate rule

Main protection requires `Tests` and `Windows check` (plus build, Clippy, Helm x2 and Secret-leak). The release line has no
GitHub-required checks (`required_status_checks` absent), so local merge tooling reads the names.
Job keys `test`, `windows-check` and `macos-check` and names `Tests`, `Windows check` and `macOS check` become the **aggregates**.
`docker-build` `needs: test` is unchanged.

**Shard names** (exact-match safe):
- `Linux shard 1/4..4/4`, `Windows shard 1/4..4/4` and `Windows clippy`: none of them contains `Tests`.
- `macOS shard 1/4..4/4`. `.git/lead-mon/guarded_merge.sh:14-15` excludes macOS only by EXACT `$1!="macOS check"`.
  So the macOS shards would be waited on, and counted as failures, without the `macos` flag.
- The plan changes both awk filters to `$1 !~ /^macOS /`, with a self-test: fixture `gh pr checks` output in which a
  pending or failing `macOS shard 2/4` neither blocks nor fails without `macos`, and does both with it. The same fixture
  asserts that the `macOS check` aggregate behaves exactly as today in both flag modes.
- The script lives outside the repo, so its change ships alongside this one (lead-mon owner) and lands before the first sharded PR.
- An exact-match guard (new, in `test_docs_only_gating.py`) pins the three aggregate names and asserts that no shard name equals one of them.

**Aggregate rule:**
- The aggregate `if:` is `always()` plus the original job's own skip guards: the throwaway inverse and the release-line post-merge push.
  It is never bare `always()`. Every new shard job carries both guards too, and joins the gating sets.
- The body fails unless every needed job's `result == 'success'`, so a skipped or cancelled shard is red.
- **Completeness is by construction, plus a guard.** Lib filter vs `--skip` on the same pattern, and the glob class
  `[x]` vs `[!x]`, are exact complements. A new static check (in `test_workflow_wiring_mutations.py`) asserts three things:
  each OS's shard matrix forms complement pairs; the union of target flags equals the original command's targets
  (Linux/macOS: lib, bins, tests, doc, examples; Windows: `--tests`); and every shard repeats that OS's exact skip list.
- Every shard also fails if libtest reports `running 0 tests` across all its binaries. That catches a broken filter, not imbalance.
- **Per-shard selected-count floor (muse r2 HIGH).** Each shard step sums libtest's `running N tests` lines and fails
  when N is below that shard's floor. Floors are written as literals in the matrix (`floor:`), seeded from the P0b
  minimum. A PR that deletes tests lowers the floor in the same diff, where review sees it. No artifact and no handoff.
  Each shard also writes passed/ignored to the step summary.

**Aggregate mutation cases (test plan):** an evaluator over the aggregate's `if:` plus body, fed synthetic `needs` results.
- one shard `failure` → red
- one shard `skipped` → red
- one shard `cancelled` → red
- a mixed matrix (3 success, 1 failure) → red
- all success → green
- the throwaway-PR event → aggregate skipped, and the `Tests (throwaway)` job unaffected
- the release-line post-merge push → aggregate skipped
- `windows-clippy` failed with all Windows shards green → `Windows check` red

## Guards that parse these jobs (edited in the same PR)
- `scripts/ci/test_docs_only_gating.py`: lists test/windows-check/macos-check, and windows-check must not need Tests.
- `scripts/release/check_macos_exclusions.py:380`: reads `--skip` inside `macos-check`. It moves to the macOS shard job,
  and must ignore the `--skip gateway::` complement filter. Otherwise that filter reads as a macOS exclusion.
- `scripts/ci/check-pick-then-bind.py:169`: untouched under route B (no `nextest` in workflows); under route A, the test_ports PR first.
- `scripts/release/test_windows_job_scope.py`: rewritten to read the `windows-shards` matrix. It asserts:
  - the shards are exactly {Lib A, Lib B, Int A, Int B};
  - Lib A/Lib B are `--lib -- gateway::` / `--lib -- --skip gateway::`, and Int A/Int B are `--bins --test '[a-l]*'` / `--test '[!a-l]*'`;
  - every shard has `--all-features --no-fail-fast` and exactly one `--skip mik_7479_full_burst`, with no other skip;
  - the union of shard targets equals `--tests`.
- `scripts/release/test_check_tag_manifest.py:2840`: the `cargo test --all-features --tests` single-command match becomes
  a check over the `windows-shards` steps. Every shard's skip list is exactly `["mik_7479_full_burst"]`, and no skip is a
  substring of `ac_mrtr_7b_every_call_reaches_one_terminal_frame`, so the per-PR burst property still runs on Windows.
  :2866 is unchanged (no new handoff).
- `test_throwaway_routing.py` requires the inverse guard on every new job. `check-hosted-runners.sh` accepts literal labels / `matrix.os` only.
- `test_workflow_wiring_mutations.py` anchors on name + runs-on.

## Failure modes
- Flaky shard: re-run only that shard (`gh run rerun --job`), then re-run the aggregate. No automatic retries
  (a retry would hide flakes, and MIK-8222 forbids timing-window tests).
- Concurrency (I, Pro plan ≈ 40 jobs / 5 macOS): route B adds 10 jobs per PR (4 Linux, 4 Windows plus clippy,
  and 4 macOS replacing 1). 4 PRs in flight will queue. The 4 macOS jobs per PR take 4 of the 5 shared macOS slots,
  so a 2nd concurrent PR queues its macOS work; the 3-job variant is in Stage 2. The measured threshold includes queue time.
- Cache: repo cache is at 10.9 GB, over the 10 GB cap. This deliberately departs from the brief's per-shard keys:
  matrix shards share one rust-cache key, so no new entries are added. Cold deps cost only ~1 min anyway.
- Concurrency group and cancel-in-progress are unchanged. `git grep` over all `*.yml/*.py/*.sh` finds no other workflow
  that references these jobs by key or name: feature-combos.yml:72 and mutants.yml:134 are comments only, and nothing
  reads check-runs by name. coverage-probe, mutants, mrtr7b and packaged-suite are unaffected.
  `test_windows_job_scope.py` grades Windows coverage from the job text, so it must follow the tests into the shards.
- Cost: standard hosted runners are free on a public repo. Spark is not used.

## Pass/fail thresholds (3 consecutive non-docs PR runs, push to last required check green, queue included)
- Tests ≤ 16 min, Windows check ≤ 30 min, macOS check ≤ 30 min after Stage 2 (provisional until P0a; fail = > 40).
  The brief suggested ≤ 25 for macOS. Here it is ≤ 30 because compile alone is 38 min today, and whether a split
  can bring it under 25 depends on P0a.
- 0 new failures relative to the libtest baseline. Per-PR test count equals the baseline count.

Not in scope: `Release tooling unit tests` (13 min) is 9.3 min of `test_workflow_wiring_mutations.py`.
That job becomes the Linux critical path after Stage 1 and is a separate follow-up.
