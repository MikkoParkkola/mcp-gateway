// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R3 (HOME.3): the unused-route and journal rows pass while another
//! holder sits on the vault lock their home would use.
//!
//! The contended lock is a stand-in. On the shared Spark host, holding the real
//! `<home>/.mcp-gateway-secrets.lock` would fail every other lane's run that
//! still resolves the real home. So each child gets a job-private platform home
//! P (HOME and USERPROFILE), and this row holds `P/.mcp-gateway-secrets.lock`
//! through the vault's own primitive. Every row here is ignored by default and
//! runs in the R3 Spark job, with filtered rows only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const OVERRIDE: &str = "MCP_GATEWAY_TEST_HOME_DIR";
const XDG: &str = "XDG_CONFIG_HOME";
const DATA_VAR: &str = "MCP_GATEWAY_CONFIG_DIR";
const LOCK_NAME: &str = ".mcp-gateway-secrets.lock";
const FILTERS: [&str; 2] = [
    "gateway::ui::settings::unused_route_tests::",
    "config_persistence::journal::",
];

/// The tests that failed in the red run against the held lock (the expected
/// set E, recorded by name in the red record: 12, all in the unused-route
/// module; no journal row touches the vault lock), each with the text its
/// failure printed when the held lock caused it: the label and the observed
/// value, both required (observed in the control run,
/// observe-control.log): a save answering 500, a delete answering 409, or an
/// index left empty by the failed save.
const E: &[(&str, &[&str])] = &[
    (
        "gateway::ui::settings::unused_route_tests::delete_is_audited",
        &["the save did not complete", "left: 500"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::delete_refuses_capability_named",
        &["the save did not complete", "left: 500"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::delete_refuses_env_named",
        &["the save did not complete", "left: 500"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::delete_refuses_hard_linked_entry_behind_symlinked_config",
        &["the save did not complete", "left: 500"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::delete_refuses_named_after_listing",
        &["the save did not complete", "left: 500"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::delete_route_refuses_pending_write",
        &["the save did not complete", "left: 500"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::delete_route_removes_entry",
        &["the save did not complete", "left: 500"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::delete_route_unlisted",
        &["left: 409", "right: 404"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::failed_commit_entry_listed",
        &["one indexed entry", "left: 0"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::locks_released_after_refusals",
        &["the save did not complete", "left: 500"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::routes_need_admin",
        &["the save did not complete", "left: 500"],
    ),
    (
        "gateway::ui::settings::unused_route_tests::unused_listed_with_write_time",
        &["the save did not complete", "left: 500"],
    ),
];

/// Which home a variant's children resolve.
#[derive(Clone, Copy, Debug)]
enum Variant {
    /// The env `test_binary()` sets: the parent's home, under a harness the
    /// harness home.
    Harness,
    /// The three variables removed: only the cfg(test) fallback stands between
    /// the child and P, as in a bare run.
    Fallback,
    /// The override pointed at P on purpose: the children must hit the held
    /// lock. This proves the holder really contends.
    Control,
}

fn child(platform: &Path, tmp: &Path, variant: Variant) -> Command {
    let mut cmd = crate::test_home::test_binary();
    cmd.env("HOME", platform).env("USERPROFILE", platform);
    for key in ["TMPDIR", "TMP", "TEMP"] {
        cmd.env(key, tmp);
    }
    match variant {
        Variant::Harness => {}
        Variant::Fallback => {
            cmd.env_remove(OVERRIDE)
                .env_remove(XDG)
                .env_remove(DATA_VAR);
        }
        Variant::Control => {
            cmd.env(OVERRIDE, platform)
                .env_remove(XDG)
                .env_remove(DATA_VAR);
        }
    }
    cmd
}

/// The home and vault lock a variant's children resolve, from the witness.
fn witness(platform: &Path, tmp: &Path, variant: Variant) -> BTreeMap<String, String> {
    let mut cmd = child(platform, tmp, variant);
    cmd.args([
        "--exact",
        "secret_store::tests::r3b_witness_child",
        "--ignored",
        "--nocapture",
    ])
    .env("MCP_GW_TEST_R3B_WITNESS", "1");
    let out = cmd.output().expect("spawn the witness");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "witness failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("r3b witness child ok"),
        "witness ran no case:\n{stdout}\n{stderr}"
    );
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("PROBE "))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// What the filtered runs of the suite reported, by test name.
#[derive(Debug, Default)]
struct Suite {
    passed: BTreeSet<String>,
    failed: BTreeSet<String>,
    /// Each failed test's captured output (libtest's `---- name stdout ----`
    /// section), so a failure can be traced to its cause.
    sections: BTreeMap<String, String>,
    /// Per filter: the exit code and the completed summary line, if any. A
    /// run that aborted (a crash, a timeout) prints no summary.
    runs: Vec<(&'static str, Option<i32>, Option<String>)>,
}

fn suite(platform: &Path, tmp: &Path, variant: Variant) -> Suite {
    let mut seen = Suite::default();
    for filter in FILTERS {
        let mut cmd = child(platform, tmp, variant);
        cmd.arg(filter);
        let out = cmd.output().expect("spawn the suite");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let summary = stdout
            .lines()
            .rev()
            .find(|line| line.starts_with("test result: "))
            .map(str::to_owned);
        seen.runs.push((filter, out.status.code(), summary));
        for section in stdout.split("\n---- ").skip(1) {
            if let Some((name, body)) = section.split_once(" stdout ----\n") {
                seen.sections.insert(name.to_owned(), body.to_owned());
            }
        }
        let mut selected = 0;
        for line in stdout.lines() {
            let Some(rest) = line.strip_prefix("test ") else {
                continue;
            };
            if let Some(name) = rest.strip_suffix(" ... ok") {
                seen.passed.insert(name.to_owned());
                selected += 1;
            } else if let Some(name) = rest.strip_suffix(" ... FAILED") {
                seen.failed.insert(name.to_owned());
                selected += 1;
            }
        }
        assert!(
            selected > 0,
            "{variant:?}: {filter} selected no test:\n{stdout}"
        );
    }
    // Printed in every run, so a red or control run records E by name and
    // shows why each failed.
    for name in &seen.failed {
        println!("R3B {variant:?} FAILED {name}");
        if let Some(body) = seen.sections.get(name) {
            for line in body.lines().filter(|line| !line.trim().is_empty()).take(6) {
                println!("R3B {variant:?} WHY {name}: {line}");
            }
        }
    }
    seen
}

/// Holds `P/.mcp-gateway-secrets.lock` through the vault's own primitive
/// (`lock_file_blocking`, the call `secret_store::save::take_lock` makes).
fn hold(lock: &Path) -> crate::fs_lock::ExclusiveFileLock {
    let held = crate::config_persistence::lock::lock_file_blocking(
        lock,
        "the R3b holder",
        Instant::now() + Duration::from_secs(30),
    )
    .expect("hold the stand-in lock");
    assert_busy(lock);
    held
}

/// A second taker is refused: the holder really holds the lock. A passed
/// deadline still makes one attempt (`poll_blocking` tries before it waits).
fn assert_busy(lock: &Path) {
    let second =
        crate::config_persistence::lock::lock_file_blocking(lock, "a second taker", Instant::now());
    assert!(
        matches!(
            second,
            Err(crate::config_persistence::lock::NotLocked::Busy)
        ),
        "the stand-in lock must be held"
    );
}

/// R3b for one variant: the suite runs while P's lock is held. Afterwards, the
/// witness shows which home the children resolved.
/// Whether a filtered run completed: exit 0 with a passing summary, or, when
/// `failures_allowed`, exit 101 with a failing one. An abort prints neither.
fn completed(code: Option<i32>, summary: Option<&str>, failures_allowed: bool) -> bool {
    match code {
        Some(0) => summary.is_some_and(|s| s.starts_with("test result: ok.")),
        Some(101) if failures_allowed => {
            summary.is_some_and(|s| s.starts_with("test result: FAILED."))
        }
        _ => false,
    }
}

/// What is wrong with a variant's runs, empty when it proves what it should.
/// The green variants need every run complete and passing, with every name in
/// E among the passes. The control needs every run complete, every name in E
/// failed, and each failure's section showing all of that test's markers.
fn judge(variant: Variant, seen: &Suite) -> Vec<String> {
    let mut problems = Vec::new();
    let control = matches!(variant, Variant::Control);
    for (filter, code, summary) in &seen.runs {
        if !completed(*code, summary.as_deref(), control) {
            problems.push(format!("{filter} did not complete: {code:?} {summary:?}"));
        }
    }
    for (name, markers) in E {
        if control {
            let Some(section) = seen.sections.get(*name) else {
                problems.push(format!("{name} did not fail against the held lock"));
                continue;
            };
            for marker in *markers {
                if !section.contains(marker) {
                    problems.push(format!("{name} failed without the held lock's {marker:?}"));
                }
            }
        } else if !seen.passed.contains(*name) {
            problems.push(format!("{name} did not pass"));
        }
    }
    if !control && !seen.failed.is_empty() {
        problems.push(format!("failed: {:?}", seen.failed));
    }
    problems
}

fn r3b(variant: Variant) {
    let platform = tempfile::tempdir().expect("stand-in home P");
    let tmp = tempfile::tempdir().expect("tmp");
    let lock = platform.path().join(LOCK_NAME);
    let held = hold(&lock);
    let seen = suite(platform.path(), tmp.path(), variant);
    let resolved = witness(platform.path(), tmp.path(), variant);
    assert_busy(&lock);
    drop(held);
    let home = PathBuf::from(&resolved["HOME"]);
    match variant {
        Variant::Harness => {
            // Judged against what the harness injected, not this process's own lookup.
            let injected = PathBuf::from(
                std::env::var_os(OVERRIDE)
                    .expect("the harness variant runs under the harness injection"),
            );
            assert_eq!(home, injected, "the children share the harness home");
        }
        Variant::Fallback => assert!(
            home.starts_with(tmp.path()),
            "a fallback in the row's tmp: {home:?}"
        ),
        Variant::Control => {
            assert_eq!(home, platform.path());
            assert_eq!(
                PathBuf::from(&resolved["LOCK"]),
                lock,
                "the control takes the held lock"
            );
        }
    }
    let problems = judge(variant, &seen);
    assert!(problems.is_empty(), "{variant:?}: {problems:#?}\n{seen:?}");
}

#[test]
#[ignore = "R3b: the Spark contention job"]
fn r3b_harness_children_pass_while_the_stand_in_lock_is_held() {
    r3b(Variant::Harness);
}

#[test]
#[ignore = "R3b: the Spark contention job"]
fn r3b_fallback_children_pass_while_the_stand_in_lock_is_held() {
    r3b(Variant::Fallback);
}

#[test]
#[ignore = "R3b: the Spark contention job"]
fn r3b_control_children_pointed_at_the_held_lock_fail() {
    r3b(Variant::Control);
}

/// R3a (HOME.3, m4): under spark-cargo the lib tests resolve the home the
/// harness exports, a fresh dir beside the mirror. Ignored by default: only a
/// harness run sets the variable.
#[test]
#[ignore = "R3a: run with --ignored --exact under spark-cargo"]
fn home_isolation_harness_probe() {
    let injected = PathBuf::from(
        std::env::var_os(OVERRIDE)
            .expect("no harness injection: MCP_GATEWAY_TEST_HOME_DIR is unset"),
    );
    assert_eq!(crate::home_dir::home_dir(), Some(injected.clone()));
    let parts: Vec<String> = injected
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        parts.last().map(String::as_str),
        Some("home"),
        "{injected:?}"
    );
    assert!(
        parts.iter().rev().skip(1).any(|part| part == "mirrors"),
        "a home beside the mirror: {injected:?}"
    );
}

/// A control Suite in which every name in E failed with all its markers.
fn control_suite() -> Suite {
    let mut seen = Suite::default();
    for (name, markers) in E {
        seen.failed.insert((*name).to_owned());
        seen.sections.insert((*name).to_owned(), markers.join("\n"));
    }
    seen.runs = vec![
        (
            FILTERS[0],
            Some(101),
            Some("test result: FAILED. 0 passed; 12 failed".to_owned()),
        ),
        (
            FILTERS[1],
            Some(0),
            Some("test result: ok. 9 passed; 0 failed".to_owned()),
        ),
    ];
    seen
}

/// A green Suite in which every name in E passed.
fn green_suite() -> Suite {
    Suite {
        passed: E.iter().map(|(name, _)| (*name).to_owned()).collect(),
        runs: FILTERS
            .iter()
            .map(|filter| {
                (
                    *filter,
                    Some(0),
                    Some("test result: ok. 12 passed; 0 failed".to_owned()),
                )
            })
            .collect(),
        ..Suite::default()
    }
}

/// The judge's own rows: each check refuses the case it exists for, and the
/// well-formed runs pass (both sides).
#[test]
fn r3b_judge_refuses_aborted_runs_and_unrelated_failures() {
    assert_eq!(
        judge(Variant::Control, &control_suite()),
        Vec::<String>::new()
    );
    assert_eq!(
        judge(Variant::Harness, &green_suite()),
        Vec::<String>::new()
    );

    let mut stray_failure = green_suite();
    stray_failure
        .failed
        .insert("gateway::ui::settings::unused_route_tests::other".to_owned());
    assert_eq!(
        judge(Variant::Fallback, &stray_failure).len(),
        1,
        "a failure the summaries did not show still fails a green variant"
    );
    let mut aborted = green_suite();
    aborted.runs[0].1 = None;
    assert_eq!(
        judge(Variant::Fallback, &aborted).len(),
        1,
        "a run killed by a signal"
    );
    let mut no_summary = green_suite();
    no_summary.runs[1].2 = None;
    assert_eq!(
        judge(Variant::Harness, &no_summary).len(),
        1,
        "a run with no summary"
    );
    let mut failing_green = green_suite();
    failing_green.runs[0] = (
        FILTERS[0],
        Some(101),
        Some("test result: FAILED.".to_owned()),
    );
    assert_eq!(
        judge(Variant::Harness, &failing_green).len(),
        1,
        "101 is no pass for green"
    );

    let (name, markers) = E[8];
    assert_eq!(markers, ["one indexed entry", "left: 0"]);
    let mut wrong_count = control_suite();
    wrong_count
        .sections
        .insert(name.to_owned(), "one indexed entry\n  left: 2".to_owned());
    assert_eq!(
        judge(Variant::Control, &wrong_count),
        vec![format!("{name} failed without the held lock's \"left: 0\"")],
        "the label alone is not the lock's failure"
    );
    let mut missing = control_suite();
    missing.sections.remove(E[0].0);
    assert_eq!(
        judge(Variant::Control, &missing).len(),
        1,
        "an E name that did not fail"
    );
    let mut aborted_control = control_suite();
    aborted_control.runs[0].1 = Some(137);
    assert_eq!(
        judge(Variant::Control, &aborted_control).len(),
        1,
        "a killed control run"
    );
}
