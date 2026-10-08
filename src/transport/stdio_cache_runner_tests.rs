// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8147: every package manager's cache variable, from one assignment.
//!
//! A runner decodes its environment as UTF-8 (npm through Node, pnpm through
//! Rust's `env::var`), so a cache path that is not UTF-8 cannot be handed to
//! any of them in a form it will use: such a path is assigned to no runner.
//! And the operator names a setting only in a spelling that runner's own
//! reader reads.
//!
//! The data-directory scenarios need the gateway's own environment, which only
//! `unsafe` can set in-process, so they re-run this binary with it set, as
//! `stdio_cache_abs_tests.rs` does.

use std::collections::HashMap;
use std::ffi::OsString;

use crate::transport::{assigned_package_cache_dir, isolated_package_manager_env};

/// Each runner, the command that selects it, and the variables it reads.
const RUNNERS: [(&str, &[&str]); 5] = [
    ("npm exec pkg", &["npm_config_cache"]),
    ("npx -y pkg", &["npm_config_cache"]),
    ("bunx pkg", &["BUN_INSTALL_CACHE_DIR"]),
    ("yarn dlx pkg", &["YARN_CACHE_FOLDER"]),
    (
        "pnpm dlx pkg",
        &["pnpm_config_store_dir", "npm_config_store_dir"],
    ),
];

const NESTED_RUN_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);
const SCENARIO_ENV: &str = "MCP_GATEWAY_TEST_CACHE_RUNNER_SCENARIO";
const MODULE: &str = "transport::stdio::cache_runner_tests::";

/// Run one `*_scenario` test of this file in a fresh copy of the test binary,
/// with `set` in its environment and `removed` taken out of it.
async fn run_nested(
    scenario: &str,
    set: &[(&str, OsString)],
    removed: &[&str],
    cwd: &std::path::Path,
) {
    let filter = format!("{MODULE}{scenario}");
    let mut nested = tokio::process::Command::new(std::env::current_exe().expect("test binary"));
    nested
        .args(["--exact", &filter, "--nocapture"])
        .env(SCENARIO_ENV, scenario)
        .current_dir(cwd)
        .kill_on_drop(true);
    for (key, value) in set {
        nested.env(key, value);
    }
    for key in removed {
        nested.env_remove(key);
    }
    let output = tokio::time::timeout(NESTED_RUN_LIMIT, nested.output())
        .await
        .expect("the scenario finished within the limit")
        .expect("run the scenario");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(&filter),
        "the nested filter did not run {filter}; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{scenario} failed; stdout={stdout:?} stderr={stderr:?}"
    );
}

/// Whether this process is the nested run of `scenario`.
fn is_nested(scenario: &str) -> bool {
    std::env::var_os(SCENARIO_ENV).is_some_and(|running| running == scenario)
}

/// MIK-8147 D3: a key suppresses the injected variable only when that
/// variable's runner reads it. npm folds `_` to `-` after its prefix; pnpm
/// reads exactly `PNPM_CONFIG_<SUFFIX>` and `pnpm_config_<lower>`.
#[test]
fn the_operator_names_a_setting_only_in_a_spelling_its_runner_reads() {
    // (command, operator key, injected variable, still injected)
    let rows = [
        ("npx -y pkg", "NPM_CONFIG_CACHE", "npm_config_cache", false),
        ("npx -y pkg", "npm_config_cache", "npm_config_cache", false),
        ("npx -y pkg", "npm-config-cache", "npm_config_cache", true),
        (
            "pnpm dlx pkg",
            "npm_config_store-dir",
            "npm_config_store_dir",
            false,
        ),
        (
            "pnpm dlx pkg",
            "npm_config_store-dir",
            "pnpm_config_store_dir",
            true,
        ),
        (
            "pnpm dlx pkg",
            "PNPM_CONFIG_STORE_DIR",
            "pnpm_config_store_dir",
            false,
        ),
        (
            "pnpm dlx pkg",
            "pnpm_config_store_dir",
            "pnpm_config_store_dir",
            false,
        ),
        (
            "pnpm dlx pkg",
            "Pnpm_Config_Store_Dir",
            "pnpm_config_store_dir",
            !cfg!(windows),
        ),
        (
            "pnpm dlx pkg",
            "pnpm_config_store-dir",
            "pnpm_config_store_dir",
            true,
        ),
        // Bun reads its key verbatim.
        (
            "bunx pkg",
            "bun_install_cache_dir",
            "BUN_INSTALL_CACHE_DIR",
            !cfg!(windows),
        ),
        // Yarn 1 and Berry both fold `yarn_` keys: case and separators.
        (
            "yarn dlx pkg",
            "YARN_CACHE__FOLDER",
            "YARN_CACHE_FOLDER",
            false,
        ),
        (
            "yarn dlx pkg",
            "yarn_cache-folder",
            "YARN_CACHE_FOLDER",
            false,
        ),
        (
            "yarn dlx pkg",
            "YARN_CACHEFOLDER",
            "YARN_CACHE_FOLDER",
            true,
        ),
        (
            "yarn dlx pkg",
            "YARN_CACHE.FOLDER",
            "YARN_CACHE_FOLDER",
            false,
        ),
        (
            "yarn dlx pkg",
            "YARN_CACHE FOLDER",
            "YARN_CACHE_FOLDER",
            false,
        ),
    ];
    for (command, key, var, injected) in rows {
        let operator = HashMap::from([(key.to_owned(), "/operator/cache".to_owned())]);
        let env = isolated_package_manager_env("thing", command, operator);
        // The gateway's value, not the operator's (which `var` may itself be).
        let written = env.get(var).is_some_and(|value| value != "/operator/cache");
        assert_eq!(
            written, injected,
            "{command}: operator key {key:?} vs injected {var:?}: {env:?}"
        );
    }
}

/// A path under the scratch directory whose last component holds byte 0xE9,
/// which is not UTF-8 on its own.
#[cfg(unix)]
fn non_utf8_under(dir: &std::path::Path) -> OsString {
    use std::os::unix::ffi::OsStrExt;
    let mut path = dir.as_os_str().to_owned();
    path.push("/st");
    path.push(std::ffi::OsStr::from_bytes(&[0xE9]));
    path.push("te");
    path
}

/// MIK-8147 D2 (T1): with a home whose path is not UTF-8, no runner is handed
/// a cache path and the repair has nothing to clear.
#[cfg(unix)]
#[tokio::test]
async fn a_non_utf8_cache_is_assigned_to_no_runner() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    let home = non_utf8_under(scratch.path());
    run_nested(
        "non_utf8_home_scenario",
        &[("MCP_GATEWAY_TEST_HOME_DIR", home)],
        &["MCP_GATEWAY_CONFIG_DIR"],
        scratch.path(),
    )
    .await;
}

#[cfg(unix)]
#[test]
fn non_utf8_home_scenario() {
    if !is_nested("non_utf8_home_scenario") {
        return;
    }
    let data = crate::config_persistence::gateway_data_dir();
    assert!(
        data.to_str().is_none(),
        "the scenario's data dir {data:?} is UTF-8; the setup did not reach it"
    );
    assert_no_runner_is_assigned_a_cache();
}

/// MIK-8147 D2 (T1): npm expands `${VAR}` in a config value, so a data dir
/// holding `${` names another directory to npm and is assigned to no runner.
#[tokio::test]
async fn a_cache_path_npm_would_expand_is_assigned_to_no_runner() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    run_nested(
        "interpolated_home_scenario",
        &[(
            "MCP_GATEWAY_TEST_HOME_DIR",
            scratch.path().join("${HOME}").into_os_string(),
        )],
        &["MCP_GATEWAY_CONFIG_DIR"],
        scratch.path(),
    )
    .await;
}

#[test]
fn interpolated_home_scenario() {
    if !is_nested("interpolated_home_scenario") {
        return;
    }
    let data = crate::config_persistence::gateway_data_dir();
    assert!(
        data.to_string_lossy().contains("${"),
        "the scenario's data dir {data:?} holds no `${{`; the setup did not reach it"
    );
    assert_no_runner_is_assigned_a_cache();
}

/// No runner is handed a cache variable and the repair records nothing.
fn assert_no_runner_is_assigned_a_cache() {
    for (command, vars) in RUNNERS {
        let env = isolated_package_manager_env("thing", command, HashMap::new());
        for var in vars {
            assert!(
                !env.contains_key(*var),
                "{command} was handed {var}={:?}, a path it cannot use",
                env[*var]
            );
        }
        assert_eq!(
            assigned_package_cache_dir("thing", command, &HashMap::new()),
            None,
            "{command}: a cache the child was never handed is recorded for repair"
        );
    }
}

/// MIK-8147 (T2, guard): under a relative config dir every runner is handed
/// its absolute cache, the one the repair would record.
#[tokio::test]
async fn every_runner_gets_its_exact_absolute_cache() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    run_nested(
        "relative_config_dir_scenario",
        &[("MCP_GATEWAY_CONFIG_DIR", OsString::from("relative-state"))],
        &[],
        scratch.path(),
    )
    .await;
}

#[test]
fn relative_config_dir_scenario() {
    if !is_nested("relative_config_dir_scenario") {
        return;
    }
    let root = std::env::current_dir()
        .expect("the scenario's working directory")
        .join("relative-state")
        .join("pkg-cache");
    // The one directory every runner is handed: the path the repair records.
    let exact = assigned_package_cache_dir("thing", "npx -y pkg", &HashMap::new())
        .expect("npm's cache is recorded for repair");
    assert!(
        exact.is_absolute() && exact.parent() == Some(root.as_path()),
        "the recorded cache {exact:?} is not an absolute directory in {root:?}"
    );
    for (command, vars) in RUNNERS {
        let env = isolated_package_manager_env("thing", command, HashMap::new());
        for var in vars {
            assert_eq!(
                std::path::Path::new(&env[*var]),
                exact,
                "{command}: {var} is not the recorded cache"
            );
        }
    }
}

/// MIK-8147 D5 (T4): a config dir that is not UTF-8 is the gateway's data
/// dir, not silently replaced by the default under the home directory.
#[cfg(unix)]
#[tokio::test]
async fn a_non_utf8_config_dir_is_used_not_dropped() {
    let scratch = tempfile::tempdir().expect("scratch directory");
    let configured = non_utf8_under(scratch.path());
    run_nested(
        "non_utf8_config_dir_scenario",
        &[
            ("MCP_GATEWAY_CONFIG_DIR", configured.clone()),
            ("MCP_GATEWAY_TEST_CONFIGURED_DIR", configured),
        ],
        &[],
        scratch.path(),
    )
    .await;
}

#[cfg(unix)]
#[test]
fn non_utf8_config_dir_scenario() {
    if !is_nested("non_utf8_config_dir_scenario") {
        return;
    }
    let configured =
        std::env::var_os("MCP_GATEWAY_TEST_CONFIGURED_DIR").expect("the configured dir");
    assert_eq!(
        crate::config_persistence::gateway_data_dir().as_os_str(),
        configured.as_os_str(),
        "the operator's directory was dropped"
    );
}

/// MIK-8147 D3b (T5): Yarn Berry's global cache ignores `cacheFolder`, so a
/// yarn backend also gets the global cache turned off, unless the operator
/// set it in any spelling Berry reads.
#[test]
fn a_yarn_backend_turns_off_berrys_global_cache() {
    let env = isolated_package_manager_env("thing", "yarn dlx pkg", HashMap::new());
    assert_eq!(
        env.get("YARN_ENABLE_GLOBAL_CACHE").map(String::as_str),
        Some("false"),
        "{env:?}"
    );
    for key in [
        "YARN_ENABLE_GLOBAL_CACHE",
        "yarn_enable-global-cache",
        "YARN_ENABLE-GLOBAL-CACHE",
        "YARN_ENABLE GLOBAL CACHE",
    ] {
        let operator = HashMap::from([(key.to_owned(), "true".to_owned())]);
        let env = isolated_package_manager_env("thing", "yarn dlx pkg", operator);
        assert_eq!(env.get(key).map(String::as_str), Some("true"), "{key}");
        assert!(
            key == "YARN_ENABLE_GLOBAL_CACHE" || !env.contains_key("YARN_ENABLE_GLOBAL_CACHE"),
            "{key}: the operator's choice is overridden: {env:?}"
        );
    }
    // An operator's own folder is ignored by Berry too while the global cache
    // is on, so the switch is still turned off.
    let operator = HashMap::from([("YARN_CACHE_FOLDER".to_owned(), "/mine".to_owned())]);
    let env = isolated_package_manager_env("thing", "yarn dlx pkg", operator);
    assert_eq!(env["YARN_CACHE_FOLDER"], "/mine");
    assert_eq!(
        env.get("YARN_ENABLE_GLOBAL_CACHE").map(String::as_str),
        Some("false"),
        "{env:?}"
    );
    let other = isolated_package_manager_env("thing", "npx -y pkg", HashMap::new());
    assert!(!other.contains_key("YARN_ENABLE_GLOBAL_CACHE"), "{other:?}");
}
