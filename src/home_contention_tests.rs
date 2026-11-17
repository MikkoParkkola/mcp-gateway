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
/// module; no journal row touches the vault lock). Each must pass in every green
/// variant and fail in the control.
const E: &[&str] = &[
    "gateway::ui::settings::unused_route_tests::delete_is_audited",
    "gateway::ui::settings::unused_route_tests::delete_refuses_capability_named",
    "gateway::ui::settings::unused_route_tests::delete_refuses_env_named",
    "gateway::ui::settings::unused_route_tests::delete_refuses_hard_linked_entry_behind_symlinked_config",
    "gateway::ui::settings::unused_route_tests::delete_refuses_named_after_listing",
    "gateway::ui::settings::unused_route_tests::delete_route_refuses_pending_write",
    "gateway::ui::settings::unused_route_tests::delete_route_removes_entry",
    "gateway::ui::settings::unused_route_tests::delete_route_unlisted",
    "gateway::ui::settings::unused_route_tests::failed_commit_entry_listed",
    "gateway::ui::settings::unused_route_tests::locks_released_after_refusals",
    "gateway::ui::settings::unused_route_tests::routes_need_admin",
    "gateway::ui::settings::unused_route_tests::unused_listed_with_write_time",
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

/// What one filtered run of the suite reported, by test name.
#[derive(Debug, Default)]
struct Suite {
    passed: BTreeSet<String>,
    failed: BTreeSet<String>,
}

fn suite(platform: &Path, tmp: &Path, variant: Variant) -> Suite {
    let mut seen = Suite::default();
    for filter in FILTERS {
        let mut cmd = child(platform, tmp, variant);
        cmd.arg(filter);
        let out = cmd.output().expect("spawn the suite");
        let stdout = String::from_utf8_lossy(&out.stdout);
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
    // Printed in every run, so the red run records E by name.
    for name in &seen.failed {
        println!("R3B {variant:?} FAILED {name}");
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
        Variant::Harness => assert_eq!(
            Some(home),
            crate::home_dir::home_dir(),
            "the children share the parent's home"
        ),
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
    let expected: BTreeSet<String> = E.iter().map(|name| (*name).to_owned()).collect();
    match variant {
        Variant::Control => assert!(
            expected.is_subset(&seen.failed),
            "the control must fail every name in E against the held lock: {seen:?}"
        ),
        Variant::Harness | Variant::Fallback => {
            assert!(
                expected.is_subset(&seen.passed),
                "{variant:?}: E must pass: {seen:?}"
            );
            assert!(
                seen.failed.is_empty(),
                "{variant:?} failed: {:?}",
                seen.failed
            );
        }
    }
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
