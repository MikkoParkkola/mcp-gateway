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

/// What the pin requires of one CI step.
struct Expect {
    /// The step's `name`.
    name: &'static str,
    /// The job that must hold it, when the job is part of the guarantee.
    job: Option<&'static str>,
    /// Whether its `run` script chains several native commands, so every one
    /// needs its own exit-status guard (PowerShell reports only the last).
    guarded: bool,
}

/// The CI steps this pin reads: the Linux registry-ban step (MIK-8387) and the
/// Windows one (MIK-8449), which lints the `cfg(windows)` code no other job
/// compiles.
const STEPS: [Expect; 2] = [
    Expect {
        name: "Registry ban (MIK-8387)",
        job: None,
        guarded: false,
    },
    Expect {
        name: "Registry ban, Windows (MIK-8449)",
        job: Some("windows-clippy"),
        guarded: true,
    },
];
/// What each step's `CLIPPY_CONF_DIR` must be.
const CONF_DIR: &str = "${{ github.workspace }}/scripts/lint/registry-ban";

/// The checked-in CI workflow, or `None` in a packaged crate (which does not
/// ship it).
pub(super) fn checked_in_workflow() -> Option<String> {
    repo_file(".github/workflows/ci.yml")
}

/// Panics unless, for each of [`STEPS`], exactly one step of that name exists
/// under `jobs`, its own `env` sets `CLIPPY_CONF_DIR` to [`CONF_DIR`], it sits
/// in the job the table names, and a chained script guards every native
/// command's exit status. The workflow is parsed with the repo's adapter, so
/// quoting, comments and key order are the parser's concern.
pub(super) fn assert_ci_registry_ban_conf_dir(workflow: &str) {
    let doc: Value = crate::yaml::from_str(workflow).expect("the CI workflow parses");
    let jobs = doc
        .get("jobs")
        .and_then(Value::as_mapping)
        .expect("the CI workflow has jobs");
    for expect in STEPS {
        let name = expect.name;
        let mut found = Vec::new();
        for (job, def) in jobs {
            let Some(steps) = def.get("steps").and_then(Value::as_sequence) else {
                continue;
            };
            for step in steps {
                if step.get("name").and_then(Value::as_str) == Some(name) {
                    found.push((job.as_str().unwrap_or("?").to_owned(), step));
                }
            }
        }
        assert_eq!(
            found.len(),
            1,
            "expected exactly one CI step named {name:?}, found {}",
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
            "CLIPPY_CONF_DIR in the env of the {name:?} step of job {job}"
        );
        if let Some(want) = expect.job {
            assert_eq!(job, want, "the job holding the {name:?} step");
        }
        if expect.guarded {
            let run = step.get("run").and_then(Value::as_str).unwrap_or_default();
            let commands = run
                .lines()
                .filter(|l| l.trim_start().starts_with("cargo "))
                .count();
            let guards = run.matches("exit $LASTEXITCODE").count();
            assert!(
                commands >= 1 && guards == commands,
                "exit-status guards in the {name:?} step: {guards} guards for {commands} cargo commands"
            );
        }
    }
}

/// The two registry-ban steps, each in its own job, as the workflow writes
/// them (same indentation).
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
  windows-clippy:
    runs-on: windows-2025
    steps:
      - name: Registry ban, Windows (MIK-8449)
        env:
          CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban
        run: |
          cargo clippy --lib --bins --all-features -- -D warnings
          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
          cargo clippy --lib --bins --no-default-features -- -D warnings
          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
";
const GUARD: &str = "          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n";
const ENV_LINE: &str =
    "          CLIPPY_CONF_DIR: ${{ github.workspace }}/scripts/lint/registry-ban\n";
const LINUX_HEAD: &str = "      - name: Registry ban (MIK-8387)\n";
const WINDOWS_HEAD: &str = "      - name: Registry ban, Windows (MIK-8449)\n";
const NEXT_HEAD: &str = "      - name: The registry lint still bites (MIK-8387)\n";

/// A step's head and its env block, the unit every mutation edits.
fn with_env(head: &str) -> String {
    format!("{head}        env:\n{ENV_LINE}")
}

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

/// Both steps, each by its own head, so a mutation on one cannot be masked by
/// the other and each step is pinned by the same set of falsifiers.
fn each_step() -> [(&'static str, &'static str); 2] {
    [("linux", LINUX_HEAD), ("windows", WINDOWS_HEAD)]
}

#[test]
fn deleting_the_variable_turns_the_pin_red() {
    for (label, head) in each_step() {
        must_panic(label, &mutate(FIXTURE, &with_env(head), head), NO_ENV);
    }
}

#[test]
fn commenting_the_variable_out_turns_the_pin_red() {
    for (label, head) in each_step() {
        let to =
            with_env(head).replace(ENV_LINE, &format!("          # {}", ENV_LINE.trim_start()));
        must_panic(label, &mutate(FIXTURE, &with_env(head), &to), NO_ENV);
    }
}

#[test]
fn redirecting_the_variable_turns_the_pin_red() {
    for (label, head) in each_step() {
        let to = with_env(head).replace("scripts/lint/registry-ban", "scripts/lint/other");
        must_panic(label, &mutate(FIXTURE, &with_env(head), &to), NO_ENV);
    }
}

#[test]
fn renaming_a_step_turns_the_pin_red() {
    for (label, head) in each_step() {
        let renamed = mutate(FIXTURE, head, "      - name: Registry ban\n");
        must_panic(label, &renamed, "found 0");
    }
}

#[test]
fn duplicating_a_step_turns_the_pin_red() {
    for (label, head) in each_step() {
        let block = with_env(head);
        let duplicated = mutate(FIXTURE, &block, &format!("{block}        run: x\n{block}"));
        must_panic(label, &duplicated, "found 2");
    }
}

/// The variable in another step's env does not count for this step: the named
/// step itself has no env, so the failure is the missing one, not a match on
/// the wrong step.
#[test]
fn moving_the_variable_to_another_step_turns_the_pin_red() {
    for (label, head) in each_step() {
        let gone = mutate(FIXTURE, &with_env(head), head);
        let moved = mutate(
            &gone,
            NEXT_HEAD,
            &format!("{NEXT_HEAD}        env:\n{ENV_LINE}"),
        );
        assert_eq!(
            moved.matches("CLIPPY_CONF_DIR").count(),
            2,
            "moved, not lost"
        );
        must_panic(label, &moved, NO_ENV);
    }
}

/// The name appearing only inside a `run:` script is not an env entry.
#[test]
fn a_variable_only_in_the_run_script_turns_the_pin_red() {
    for (label, head) in each_step() {
        let without = mutate(FIXTURE, &with_env(head), head);
        let run = format!("{head}        run: |\n");
        let to = format!(
            "{run}          export CLIPPY_CONF_DIR=${{{{ github.workspace }}}}/scripts/lint/registry-ban\n"
        );
        let run_only = mutate(&without, &run, &to);
        assert!(run_only.contains("export CLIPPY_CONF_DIR"), "still present");
        must_panic(label, &run_only, NO_ENV);
    }
}

/// The Windows step is required, not optional: removing it leaves the Linux
/// step green on its own, and the pin still goes red.
#[test]
fn removing_the_windows_step_turns_the_pin_red() {
    let start = FIXTURE.find(WINDOWS_HEAD).expect("the windows step");
    let removed = format!(
        "{}{}",
        &FIXTURE[..start],
        "      - name: other\n        run: x\n"
    );
    must_panic("windows removed", &removed, "found 0");
}

/// PowerShell reports only the last native command's status, so a missing
/// guard after the first `cargo` lets its failure pass: dropping either guard,
/// or both, turns the pin red.
#[test]
fn a_missing_exit_guard_in_the_windows_step_turns_the_pin_red() {
    assert_eq!(
        FIXTURE.matches(GUARD).count(),
        2,
        "two guards in the fixture"
    );
    // the first guard only
    let first = FIXTURE.find(GUARD).expect("first guard");
    let without_first = format!("{}{}", &FIXTURE[..first], &FIXTURE[first + GUARD.len()..]);
    must_panic("first guard", &without_first, "exit-status guards");
    // both
    let without_both = FIXTURE.replace(GUARD, "");
    must_panic("both guards", &without_both, "exit-status guards");
}

/// The step must sit in the gated `windows-clippy` job: the same step in
/// another job is not the Windows lint.
#[test]
fn the_windows_step_in_another_job_turns_the_pin_red() {
    let moved = mutate(FIXTURE, "  windows-clippy:\n", "  somewhere-else:\n");
    must_panic("job", &moved, "the job holding the");
}
