# MIK-8481: pin the Linux CI registry-ban step's `CLIPPY_CONF_DIR`

Status: design v3 (after two design seats and two PACKED.1 review seats).
Test-only. Refs MIK-8481, family boundary-pins (MIK-8387).

## Problem

`t1f_the_ban_config_and_its_wiring_are_pinned`
(`src/gateway/meta_mcp/boundary_pins/allow_pins.rs`) pins the registry-ban
clippy config and asserts `scripts/dev/pre-push.sh` exports
`CLIPPY_CONF_DIR="$REPO_ROOT/scripts/lint/registry-ban"`. It does not read the
Linux CI workflow. Dropping or redirecting `CLIPPY_CONF_DIR` in the CI step
`Registry ban (MIK-8387)` leaves the pin green, and that step is the required
Linux check; pre-push is the weaker wiring (under `spark-cargo` it is vacuous
until the variable is forwarded). MIK-8387 design 4.2 requires both to name the
directory.

## Change

1. `t1f` reads the Linux CI workflow and calls one shared assertion,
   `assert_ci_registry_ban_conf_dir(text)`, which panics unless the step named
   exactly `Registry ban (MIK-8387)` sets `CLIPPY_CONF_DIR` to
   `${{ github.workspace }}/scripts/lint/registry-ban` in its own `env`
   mapping.
2. The workflow is parsed with the repo's adapter,
   `crate::yaml::from_str::<crate::yaml::Value>` (MIK-8425), then walked as
   `jobs.*.steps[]`. No parser is named in the test, so
   `no_new_file_names_a_yaml_parser_directly` stays green, and quoting,
   comments, blank lines and key order are the parser's concern, not a line
   scanner's. Exactly one step with that name must exist anywhere under `jobs`:
   zero (renamed or removed) and two or more both fail.
3. The value must match exactly, and only the step's own `env` counts: the
   variable in another step's `env`, or only inside a `run:` script, fails.

## Falsifiers (AC CLIPPIN.2)

The falsifiers call the same `assert_ci_registry_ban_conf_dir` that `t1f` calls
(one shared path, so a refactor that detaches `t1f` from it is a test failure,
not a silent pass), on an in-memory fixture of the two CI steps written with
the workflow's own indentation (so they also run in the packaged crate); the
checked-in workflow itself is checked by `t1f` and by
`the_checked_in_workflow_satisfies_the_pin`, and no workflow file is edited.
Keeping the fixture equal to the real step is MIK-8502 (DRIFT.1). Each is a
`catch_unwind` test that must panic for the stated reason, and the
unmodified text must not:

- delete the `CLIPPY_CONF_DIR` line of the step;
- comment it out;
- redirect it (`scripts/lint/registry-ban` -> `scripts/lint/other`);
- rename the step (`Registry ban (MIK-8387)` -> `Registry ban`);
- duplicate the step;
- move the `env:` block to the next step;
- keep the variable only inside a `run:` script.

## Packaged crate (AC CLIPPIN.3)

`Cargo.toml` `include` ships only the release workflow; the CI workflow,
`scripts/dev/pre-push.sh` and `scripts/lint/registry-ban/clippy.toml` are not in
the published crate (and the ruling is not to add repo tooling to it). The
PR-time packaged job only compiles (`--no-run`); the post-merge
`packaged-suite` runs the tests from the unpacked crate, where the existing
`t1f` would panic on the missing config.

PACKED.1 (PR #3949) added the helper; this PR moves it to a shared module,
`boundary_pins/packaged.rs`, with `repo_file(rel) -> Option<String>`:

- file readable: `Some(text)`;
- file not found and the crate is packaged: `None`, and `t1f` skips its whole
  file-dependent block with a printed note;
- any other read error, or a missing file in a checkout: panic, so deleting or
  renaming a pinned file, or pointing it at an unreadable path, cannot pass
  vacuously. (Seat residual: PACKED.1 skipped on any error.)

"Packaged" is `Cargo.toml.orig` present and no `.git` beside it (cargo writes
the marker into every packaged crate and an unpacked crate has no `.git`; a
checkout has one, a file in a worktree). Seat residual: a stray `Cargo.toml.orig`
in a checkout is therefore not mistaken for a packaged crate, and a test,
`no_stray_cargo_toml_orig_in_a_checkout`, fails on it with a message instead of
letting it pass silently.

`t1f` uses it for all three reads (config, pre-push, CI workflow). In the
packaged crate the config span comparison and both wiring assertions are
skipped together (the span is extracted from the missing config, so it cannot
run there); only compilation of the embedded snapshot is verified. A companion
test, `pinned_repo_files_are_read_in_a_checkout`, asserts that outside a
packaged crate all three files are present, so the pin cannot pass vacuously
in both modes.

## PACKED.2: a PR-time guard against the whole class

The packaged job at pull-request time only compiles, so any test that joins a
literal onto the crate root and reads a file `Cargo.toml` `include` leaves out
fails only after merge. `boundary_pins/shipped_reads.rs` closes that at PR
time. Per Rust file under `src/`, `tests/` and `benches/`: a file that mentions
`CARGO_MANIFEST_DIR` and does not go through `repo_file` / `read_or_skip` may
not contain a string literal that names an existing file, or an existing path
with a directory part, that is not shipped (`include` entry, glob, `dir/**`, or
a directory with something shipped under it). On today's tree this finds nothing
(measured before writing it: the only two offenders were `t1f`'s, now routed
through the helper), so there is no allowlist.

Limits, accepted: a literal is not proof of a read, and a path built at run time
(`format!`, `concat!`) is not seen; the guarded failure is the plain
`root.join("literal")` read. A file that reaches the crate root only through
another module's helper (it never spells `CARGO_MANIFEST_DIR`) is not scanned:
widening the trigger to `crate_root()`-style calls was measured and finds one
file, `tests/mik_8425_yaml_baseline_trees.rs`, which walks whole directory trees
and was green in the packaged run, so it needs its own look, not an allowlist
row. A literal handed to the helper through a `const` is not seen as covered.
The exemption of `packaged.rs` compares slash-form paths and normalises
Windows backslashes first. The guard is checkout-only (it asks whether files
exist). Falsifiers, on a scratch root: an unshipped file and an unshipped path
with a directory part are flagged; the helper exempts a file; a shipped file, a
directory with a shipped file under it, a name that is not a path and a path
that does not exist are not flagged; a file that never mentions the crate root is
not scanned. On the real tree, a scratch test file reading an unshipped file
turns the guard red (run once, not committed).

## Follow-up tickets (review items not folded here)

- MIK-8501: PACKED.2 scan coverage (crate-root helper callers, const-bound
  helper arguments, `include_str!` / `concat!` / backslash literals, and the
  decision on `tests/mik_8425_yaml_baseline_trees.rs`).
- MIK-8502: drift lanes (fixture equals the real step, one source for the
  vacuity guard's file list, one-line `include` array).
- MIK-8503: the pinned step must be able to fail (`continue-on-error`, `if:`)
  and sit in the required Linux job; assert the checked-in workflow once.

Declined, with reasons: replacing the helper by an early return in `t1f` (the
CI pin and the guard both use the helper); dropping the checkout vacuity guard
(asked for, and it is the only proof the skip was not taken in a checkout).

## MIK-8449: the Windows pass (same mechanism)

The registry ban lives in a dedicated clippy config, read only when
`CLIPPY_CONF_DIR` names it. Pre-push and the Linux step run it; the Windows
job runs `cargo clippy --all-targets --all-features` with the repo
`clippy.toml`, which does not carry the ban. So an unannotated raw registry
call under `#[cfg(windows)]` (code no other job compiles) is not linted.

- One step is added to the `windows-clippy` job, `Registry ban, Windows
  (MIK-8449)`: `CLIPPY_CONF_DIR` set to the same directory, `cargo clippy
  --lib --bins` on both feature sets, `-D warnings`, debug profile (the cfg
  tree is the same in release; the Linux step also runs release, which adds
  nothing for cfg coverage). Each native command's exit status is checked
  explicitly, because PowerShell would otherwise report only the last one.
- The pin from this ticket covers it: `assert_ci_registry_ban_conf_dir` now
  requires both steps, each exactly once with its own `env`. For the Windows
  step it also requires the job to be `windows-clippy` and one
  `exit $LASTEXITCODE` guard per `cargo` command (without them a failure of the
  first command is lost to the second). The falsifiers run against each step
  (delete, comment out, redirect, rename, duplicate, move, run-only), and
  further ones remove the Windows step, drop either guard, and move the step to
  another job.
- A review asked whether cargo's reuse of compiled artifacts from the ordinary
  clippy step could hide a banned call from this step. Observed, not derived:
  on the plant tree the ordinary step (same features, repo config) was green
  and this step then reported the call, so the first command re-lints under
  the ban config. The proof below is that evidence.
- Windows proof (COV.2), which Linux cannot give: a scratch branch with
  `#[cfg(windows)] fn plant(r: &BackendRegistry) { let _ = r.get("x"); }` in a
  production module of the library must turn the `Windows clippy` job red in
  this step; the same tree without the plant is the control and is green. The
  job is skipped for head branches named `throwaway/*`, so the scratch branch
  must not use that prefix. Never merged. (A plant in a file the binary crate
  also compiles fails the ordinary step at compile time instead and proves
  nothing; the first attempt did exactly that.)
- Not decided here: whether the ban pass should also run `--release` on
  Windows (no cfg difference), and the `--all-targets` test code (the ban
  config exempts test modules by design).

## Not changed

No product code and no `Cargo.toml`. The MIK-8481 PRs touch no workflow file;
MIK-8449 adds the one Windows step described above and nothing else there.

## Rollback

Revert the commit.
