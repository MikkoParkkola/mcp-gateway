// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8481: the Linux CI step `Registry ban (MIK-8387)` names the dedicated
//! registry-ban clippy config directory, pinned next to `t1f`'s pre-push
//! assertion. The assertion is one function; `t1f` and every falsifier below
//! call it, so a mutation that turns a falsifier red turns `t1f` red too.

use super::packaged::repo_file;
use crate::yaml::Value;

/// The CI step this pin reads.
pub(super) const STEP: &str = "Registry ban (MIK-8387)";
/// What the step's `CLIPPY_CONF_DIR` must be.
pub(super) const CONF_DIR: &str = "${{ github.workspace }}/scripts/lint/registry-ban";
/// Path of the CI workflow, relative to the crate root.
pub(super) const CI_WORKFLOW: &str = ".github/workflows/ci.yml";

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

fn real_workflow() -> Option<String> {
    repo_file(CI_WORKFLOW)
}

/// The step as written, from its `- name:` line up to the next step's.
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

fn must_panic(label: &str, text: &str) {
    let text = text.to_owned();
    let caught = std::panic::catch_unwind(move || assert_ci_registry_ban_conf_dir(&text));
    assert!(caught.is_err(), "falsifier {label} left the pin green");
}

#[test]
fn the_checked_in_workflow_satisfies_the_pin() {
    let Some(text) = real_workflow() else { return };
    assert_ci_registry_ban_conf_dir(&text);
}

#[test]
fn deleting_the_variable_turns_the_pin_red() {
    let Some(text) = real_workflow() else { return };
    must_panic("delete", &mutate(&text, ENV_BLOCK, ""));
}

#[test]
fn commenting_the_variable_out_turns_the_pin_red() {
    let Some(text) = real_workflow() else { return };
    let from = "          CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban\n";
    let to = "          # CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban\n";
    must_panic("comment", &mutate(&text, from, to));
}

#[test]
fn redirecting_the_variable_turns_the_pin_red() {
    let Some(text) = real_workflow() else { return };
    let from = "CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban";
    let to = "CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/other";
    must_panic("redirect", &mutate(&text, from, to));
}

#[test]
fn renaming_the_step_turns_the_pin_red() {
    let Some(text) = real_workflow() else { return };
    must_panic(
        "rename",
        &mutate(&text, STEP_HEAD, "      - name: Registry ban\n"),
    );
}

#[test]
fn duplicating_the_step_turns_the_pin_red() {
    let Some(text) = real_workflow() else { return };
    let start = text.find(STEP_HEAD).expect("the step");
    let end = text.find(NEXT_HEAD).expect("the next step");
    let step = text[start..end].to_owned();
    must_panic(
        "duplicate",
        &mutate(&text, NEXT_HEAD, &format!("{step}{NEXT_HEAD}")),
    );
}

#[test]
fn moving_the_variable_to_the_next_step_turns_the_pin_red() {
    let Some(text) = real_workflow() else { return };
    let without = mutate(&text, ENV_BLOCK, "");
    let moved = mutate(&without, NEXT_HEAD, &format!("{NEXT_HEAD}{ENV_BLOCK}"));
    must_panic("move", &moved);
}

#[test]
fn a_variable_only_in_the_run_script_turns_the_pin_red() {
    let Some(text) = real_workflow() else { return };
    let without = mutate(&text, ENV_BLOCK, "");
    let from = "          cargo clippy --lib --bins --all-features -- -D warnings\n";
    let to = "          export CLIPPY_CONF_DIR=${{ github.workspace }}/scripts/lint/registry-ban\n          cargo clippy --lib --bins --all-features -- -D warnings\n";
    must_panic("run-only", &mutate(&without, from, to));
}
