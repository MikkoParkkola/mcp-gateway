// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7964: a relative `MCP_GATEWAY_CONFIG_DIR` still hands a backend an
//! absolute npm cache, so a child started in its own `cwd` installs into the
//! directory the gateway recorded, not into one relative to itself.
//!
//! The setting has to be in the gateway process's own environment, and putting
//! it there in-process needs `unsafe` (`std::env::set_var`). So, like
//! `stdio_windows_env_tests.rs`, the test re-runs this binary with it set, from
//! a scratch working directory, and the nested run makes the assertions.

use std::collections::HashMap;

use crate::transport::{assigned_package_cache_dir, isolated_package_manager_env};

const SCENARIO_ENV: &str = "MCP_GATEWAY_TEST_RELATIVE_STATE_SCENARIO";
const SCENARIO: &str = "transport::stdio::cache_abs_tests::relative_state_dir_scenario";
const RELATIVE_STATE: &str = "relative-state";
const NESTED_RUN_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

#[tokio::test]
async fn a_relative_state_dir_assigns_an_absolute_cache() {
    let scratch = tempfile::tempdir().expect("scratch working directory");
    let mut nested = tokio::process::Command::new(std::env::current_exe().expect("test binary"));
    nested
        .args(["--exact", SCENARIO, "--nocapture"])
        .env(SCENARIO_ENV, "1")
        .env("MCP_GATEWAY_CONFIG_DIR", RELATIVE_STATE)
        .current_dir(scratch.path())
        .kill_on_drop(true);
    let output = tokio::time::timeout(NESTED_RUN_LIMIT, nested.output())
        .await
        .expect("the scenario finished within the limit")
        .expect("run the relative-state scenario");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(SCENARIO),
        "the nested filter did not run the scenario; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "relative-state scenario failed; stdout={stdout:?} stderr={stderr:?}"
    );
}

#[test]
fn relative_state_dir_scenario() {
    if std::env::var_os(SCENARIO_ENV).is_none() {
        return;
    }
    let cwd = std::env::current_dir().expect("the scenario's working directory");
    let expected = cwd.join(RELATIVE_STATE).join("pkg-cache");

    // ABS.1: the state directory itself is absolute, resolved against the
    // gateway's own working directory.
    let state = crate::config_persistence::gateway_data_dir();
    assert!(state.is_absolute(), "state dir {state:?} is relative");
    assert_eq!(state, cwd.join(RELATIVE_STATE));

    // ABS.2: the path the repair records is the path the child is handed,
    // byte for byte, wherever the child's own `cwd` is.
    let assigned = assigned_package_cache_dir("thing", "npx -y pkg", &HashMap::new())
        .expect("npx gets an assigned cache");
    assert!(
        assigned.is_absolute(),
        "assigned cache {assigned:?} is relative"
    );
    assert!(
        assigned.starts_with(&expected),
        "assigned cache {assigned:?} is not under {expected:?}"
    );
    let env = isolated_package_manager_env("thing", "npx -y pkg", HashMap::new());
    assert_eq!(
        env["npm_config_cache"],
        assigned.to_string_lossy(),
        "the child is handed the recorded path"
    );
}

const BLOCKED_SCENARIO_ENV: &str = "MCP_GATEWAY_TEST_BLOCKED_STATE_SCENARIO";
const BLOCKED_SCENARIO: &str = "transport::stdio::cache_abs_tests::blocked_state_dir_scenario";

/// MIK-8831.REL.5: a state dir the cache cannot be created in hands no runner
/// a cache, so the backend starts on its shared default instead of failing to
/// install. A path through a regular file fails for every user, root included,
/// where a read-only mode would not.
#[tokio::test]
async fn a_cache_dir_that_cannot_be_created_is_assigned_to_no_runner() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    let blocker = scratch.path().join("blocker");
    std::fs::write(&blocker, b"").expect("a regular file in the state path");
    let mut nested = tokio::process::Command::new(std::env::current_exe().expect("test binary"));
    nested
        .args(["--exact", BLOCKED_SCENARIO, "--nocapture"])
        .env(BLOCKED_SCENARIO_ENV, "1")
        .env("MCP_GATEWAY_CONFIG_DIR", blocker.join("state"))
        .kill_on_drop(true);
    let output = tokio::time::timeout(NESTED_RUN_LIMIT, nested.output())
        .await
        .expect("the scenario finished within the limit")
        .expect("run the blocked-state scenario");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "blocked-state scenario failed; stdout={stdout:?} stderr={stderr:?}"
    );
}

#[test]
fn blocked_state_dir_scenario() {
    if std::env::var_os(BLOCKED_SCENARIO_ENV).is_none() {
        return;
    }
    for (command, var) in [
        ("npx -y pkg", "npm_config_cache"),
        ("bunx pkg", "BUN_INSTALL_CACHE_DIR"),
    ] {
        let env = isolated_package_manager_env("thing", command, HashMap::new());
        assert!(
            !env.contains_key(var),
            "{command} was handed {var}={:?}, a cache it cannot create",
            env.get(var)
        );
    }
    assert_eq!(
        assigned_package_cache_dir("thing", "npx -y pkg", &HashMap::new()),
        None,
        "the repair records a cache the child was never handed"
    );
}
