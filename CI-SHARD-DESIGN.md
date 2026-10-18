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

## Plan

**Stage 0: probes (throwaway draft PR, no merge).**
- P0a, macOS: run `cargo test --all-features --no-run --timings`, sampling `vm_stat`, `sysctl vm.swapusage`
  and peak rustc RSS every 30 s. Repeat with `CARGO_BUILD_JOBS=2`, and once on `macos-15-intel` (4 cores, 14 GB).
  Upload `cargo-timing.html`. Decides M1 vs M2 vs M3 below.
  If the lib-test target alone takes more than ~25 min to compile, no target split meets the threshold.
  Only a runner change or shrinking that target would.
- P0b, Linux **and Windows**: run `cargo nextest run --all-features --no-fail-fast` unsharded at one SHA, 3 times each.
  Pass = 0 new failures and counts equal to the libtest totals each time. This tests two changes:
  process-per-test isolation (35 in-process statics, shared HOME, fixed paths), and **cross-binary overlap**.
  libtest runs one binary at a time; nextest overlaps f24, mik_7479, mik_7212, the admission-cap test and the
  gateway-spawn tests for the first time. Windows also measures the cost of spawning 12k processes, and whether `target/`
  needs the Defender exclusion that `RUNNER_TEMP` already has. Fallback if overlap breaks: nextest `test-groups`
  (max-threads=1) for the heavy binaries, never retries.

**Stage 1: low-risk, fixed thresholds.**
- Windows clippy moves to its own job, `windows-clippy` (name: "Windows clippy"), which runs in parallel. Saves 5.4 min.
- Tests: 3 shards on ubuntu-latest (`cargo nextest run --partition hash:i/3`). Each shard compiles for itself;
  Linux compile is 5 min, so a handoff archive would cost more than it saves. Expected about 1 + 5 + 22/3 + spawn overhead = **~14-15 min**.
- Windows: 3 shards, each compiling for itself (14 min). Expected 1 + 14 + 30/3 + ~2 (spawn overhead, I until P0b) =
  **~27 min (I)**, against 51 today. The archive route has about the same wall time (14 + upload/download + 10) but holds
  fewer runner-minutes (~50 vs ~72). Review question: concurrency vs a multi-GB handoff that the
  `test_check_tag_manifest.py` handoff inventory has to learn.
- Doctests stay on Linux and macOS, because nextest does not run them: `cargo test --doc --all-features` in shard 1.
  The UPGRADING step and the macOS-exclusions check stay in one shard. The Windows privileged rows
  (`win_privileged::`, ignored tests, libtest) stay in Windows shard 1.

**Stage 2: macOS, threshold set after P0a.**
- M1: if memory pressure is confirmed, cap `CARGO_BUILD_JOBS` and/or split the compile by target set.
  `lib` shards (`--lib --partition hash:i/2`) compile only the lib-test target. One `integration` shard
  (`--test '*' --bins`) compiles the lib plus 217 binaries. That is 3 jobs, and none of them compiles everything.
- M2: if it is CPU or linker bound, the same target split without the job cap.
- M3: Intel runner. It loses arm64 test coverage, the arm64 Homebrew/release target, so it needs an operator decision.

## Required names kept (exact) and the aggregate rule

Main protection requires `Tests` and `Windows check` (plus build, Clippy, Helm x2 and Secret-leak). The release line has no
GitHub-required checks (`required_status_checks` absent), so local merge tooling reads the names.
Job keys `test`, `windows-check` and `macos-check` and names `Tests`, `Windows check` and `macOS check` become the **aggregates**.
`docker-build` `needs: test` is unchanged. Shards are named `Tests shard i/3`, `Windows tests i/3` and `macOS tests i/N`.

The aggregate `if:` uses `always()` plus the original job's own skip guards: the throwaway inverse and the release-line post-merge push.
It is never bare `always()`. The body fails unless every needed job's `result == 'success'`, so a skipped or cancelled shard is red.
Each shard runs with `--no-tests=fail`. Hash partitions of one deterministic listing sum to the total by construction,
so no count artifact is needed (and no handoff is created). Shard 1 also checks that full list minus filtered list
equals exactly the expected skip set, so a filterset that drops too much goes red.
Skips become a filterset: `-E 'not test(/a_real_sdk_job_outlives_.../) and not test(/mik_7479_full_burst/)'`.
That is substring semantics, the same as `--skip`.

## Guards that parse these jobs (edited in the same PR)
- `scripts/ci/test_docs_only_gating.py`: lists test/windows-check/macos-check, and windows-check must not need Tests.
- `scripts/release/check_macos_exclusions.py:380`: reads `--skip` inside `macos-check`. It moves to the shard filterset.
- `scripts/release/test_windows_job_scope.py`: exact `cargo test --all-features --tests --no-fail-fast` in windows-check.
- `scripts/release/test_check_tag_manifest.py:2840`: the same for Windows. :2866 sets artifact handoff retention = HANDOFF_RETENTION_DAYS.
- `test_throwaway_routing.py` requires the inverse guard on every new job. `check-hosted-runners.sh` accepts literal labels / `matrix.os` only.
- `test_workflow_wiring_mutations.py` anchors on name + runs-on.

## Failure modes
- Flaky shard: re-run only that shard (`gh run rerun --job`), then re-run the aggregate. nextest `retries` stays 0
  (a retry would hide flakes, and MIK-8222 forbids timing-window tests).
- Concurrency (I, Pro plan ≈ 40 jobs / 5 macOS): this adds ~6 long jobs per PR. 4 PRs in flight will queue.
  macOS: M1 is 3 jobs per PR against a cap of 5 shared by every PR in flight, so a 2nd concurrent PR queues
  its macOS work. Choosing M1 means accepting that, or using 2 jobs. The measured threshold includes queue time.
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
