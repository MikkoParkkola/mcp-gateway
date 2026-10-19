// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8481: the Linux CI step `Registry ban (MIK-8387)` names the dedicated
//! registry-ban clippy config directory, pinned next to `t1f`'s pre-push
//! assertion. The assertion is one function; `t1f` calls it on the checked-in
//! workflow, and every falsifier below calls it on a mutated in-memory copy of
//! the same step, so a mutation that turns a falsifier red is one `t1f` would
//! catch too, and the falsifiers run in the packaged crate as well.

use super::packaged::repo_file;
use crate::yaml::Value;

/// The CI step this pin reads.
const STEP: &str = "Registry ban (MIK-8387)";
/// What the step's `CLIPPY_CONF_DIR` must be.
const CONF_DIR: &str = "${{ github.workspace }}/scripts/lint/registry-ban";

/// The checked-in CI workflow, or `None` in a packaged crate (which does not
/// ship it).
pub(super) fn checked_in_workflow() -> Option<String> {
    repo_file(".github/workflows/ci.yml")
}

/// Panics unless exactly one step named [`STEP`] exists under `jobs` and its
/// own `env` sets `CLIPPY_CONF_DIR` to [`CONF_DIR`]. The workflow is parsed
/// with the repo's adapter, so quoting, comments and key order are the
/// parser's concern.
pub(super) fn assert_ci_registry_ban_conf_dir(workflow: &str) {
    let doc: Value = crate::yaml::from_str(workflow).expect("the CI workflow parses");
    let jobs = doc
        .get("jobs")
        .and_then(Value::as_mapping)
        .expect("the CI workflow has jobs");
    let mut found = Vec::new();
    for (job, def) in jobs {
        let Some(steps) = def.get("steps").and_then(Value::as_sequence) else {
            continue;
        };
        for step in steps {
            if step.get("name").and_then(Value::as_str) == Some(STEP) {
                found.push((job.as_str().unwrap_or("?").to_owned(), step));
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected exactly one CI step named {STEP:?}, found {}",
        found.len()
    );
    let (job, step) = &found[0];
    let conf = step
        .get("env")
        .and_then(|env| env.get("CLIPPY_CONF_DIR"))
        .and_then(Value::as_str);
    assert_eq!(
        conf,
        Some(CONF_DIR),
        "CLIPPY_CONF_DIR in the env of the {STEP:?} step of job {job}"
    );
}

/// The two steps as the workflow writes them (same indentation).
const FIXTURE: &str = "name: CI
jobs:
  clippy:
    runs-on: ubuntu-latest
    steps:
      - name: Registry ban (MIK-8387)
        env:
          CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban
        run: |
          cargo clippy --lib --bins --all-features -- -D warnings
      - name: The registry lint still bites (MIK-8387)
        run: scripts/dev/check_registry_lint.sh --self-test
";
const STEP_HEAD: &str = "      - name: Registry ban (MIK-8387)\n";
const NEXT_HEAD: &str = "      - name: The registry lint still bites (MIK-8387)\n";
const ENV_BLOCK: &str =
    "        env:\n          CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban\n";

/// `text` with `from` replaced by `to` exactly once; a mutation that changes
/// nothing would make its falsifier vacuous, so it fails the test instead.
fn mutate(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "mutation site: {from:?}");
    text.replacen(from, to, 1)
}

/// The panic message of the assertion on `text`; the test fails if it holds.
fn panic_message(label: &str, text: &str) -> String {
    let text = text.to_owned();
    let caught = std::panic::catch_unwind(move || assert_ci_registry_ban_conf_dir(&text));
    let payload = caught.expect_err(&format!("falsifier {label} left the pin green"));
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default()
}

/// Red, and for the stated reason (not an unrelated panic).
fn must_panic(label: &str, text: &str, reason: &str) {
    let message = panic_message(label, text);
    assert!(
        message.contains(reason),
        "falsifier {label} panicked for another reason: {message}"
    );
}

#[test]
fn the_fixture_satisfies_the_pin() {
    assert_ci_registry_ban_conf_dir(FIXTURE);
}

/// `t1f` runs this on the checked-in workflow too, but a failure here names the
/// file; skipped in a packaged crate, which does not ship it.
#[test]
fn the_checked_in_workflow_satisfies_the_pin() {
    let Some(text) = checked_in_workflow() else {
        return;
    };
    assert_ci_registry_ban_conf_dir(&text);
}

const NO_ENV: &str = "CLIPPY_CONF_DIR in the env of the";

#[test]
fn deleting_the_variable_turns_the_pin_red() {
    must_panic("delete", &mutate(FIXTURE, ENV_BLOCK, ""), NO_ENV);
}

#[test]
fn commenting_the_variable_out_turns_the_pin_red() {
    let from = "          CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban\n";
    let to = "          # CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban\n";
    must_panic("comment", &mutate(FIXTURE, from, to), NO_ENV);
}

#[test]
fn redirecting_the_variable_turns_the_pin_red() {
    let from = "CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban";
    let to = "CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/other";
    must_panic("redirect", &mutate(FIXTURE, from, to), NO_ENV);
}

#[test]
fn renaming_the_step_turns_the_pin_red() {
    let renamed = mutate(FIXTURE, STEP_HEAD, "      - name: Registry ban\n");
    must_panic("rename", &renamed, "found 0");
}

#[test]
fn duplicating_the_step_turns_the_pin_red() {
    let start = FIXTURE.find(STEP_HEAD).expect("the step");
    let end = FIXTURE.find(NEXT_HEAD).expect("the next step");
    let step = FIXTURE[start..end].to_owned();
    let duplicated = mutate(FIXTURE, NEXT_HEAD, &format!("{step}{NEXT_HEAD}"));
    must_panic("duplicate", &duplicated, "found 2");
}

/// The variable in the next step's env does not count for this step: the named
/// step itself has no env, so the failure is the missing one, not a match on
/// the wrong step.
#[test]
fn moving_the_variable_to_the_next_step_turns_the_pin_red() {
    let without = mutate(FIXTURE, ENV_BLOCK, "");
    let moved = mutate(&without, NEXT_HEAD, &format!("{NEXT_HEAD}{ENV_BLOCK}"));
    assert_eq!(moved.matches("CLIPPY_CONF_DIR").count(), 1, "still present");
    must_panic("move", &moved, NO_ENV);
}

/// The name appearing only inside a `run:` script is not an env entry.
#[test]
fn a_variable_only_in_the_run_script_turns_the_pin_red() {
    let without = mutate(FIXTURE, ENV_BLOCK, "");
    let from = "          cargo clippy --lib --bins --all-features -- -D warnings\n";
    let to = "          export CLIPPY_CONF_DIR=${{ github.workspace }}/scripts/lint/registry-ban\n          cargo clippy --lib --bins --all-features -- -D warnings\n";
    let run_only = mutate(&without, from, to);
    assert!(run_only.contains("export CLIPPY_CONF_DIR"), "still present");
    must_panic("run-only", &run_only, NO_ENV);
}
