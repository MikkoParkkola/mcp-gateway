// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Windows half of the stdio child-environment contract (#525).
//!
//! `configure_child_environment` clears a backend's environment and re-injects
//! `PATH`, `HOME`, `TMPDIR` and, on Windows only, a fixed allowlist. Both
//! halves are pinned here: every allowlisted key the gateway holds reaches the
//! child with the same value (#522 was a missing `APPDATA`), and nothing else
//! reaches it -- not a secret in the gateway's environment, and not a key
//! added to the production allowlist without being added to this test.
//!
//! The secret has to be in the gateway process's own environment, and putting
//! it there in-process needs `unsafe` (`std::env::set_var`). So, like the unix
//! scenario in `stdio_tests.rs`, the test re-runs this binary with the secret
//! set, and that run spawns the backend. The backend is this binary again,
//! reduced to printing its environment, so no shell adds variables of its own
//! to what is being measured.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::process::Stdio;

use crate::transport::stdio::configure_child_environment;

const SCENARIO_ENV: &str = "MCP_GATEWAY_TEST_WINDOWS_ENV_SCENARIO";
const DUMP_ENV: &str = "MCP_GATEWAY_TEST_WINDOWS_ENV_DUMP";
const PARENT_SECRET_ENV: &str = "MCP_GATEWAY_TEST_WINDOWS_PARENT_SECRET";
const PARENT_SECRET: &str = "dummy-windows-parent-secret-must-not-reach-backend";
const DUMP_PREFIX: &str = "MCPGW_CHILD_ENV=";
const SCENARIO: &str = "transport::stdio::tests::windows_env::windows_child_environment_scenario";
const DUMP: &str = "transport::stdio::tests::windows_env::windows_child_environment_dump";

/// The keys `configure_child_environment` passes through on Windows, written
/// out here rather than shared with the production list: a key added there
/// must fail this test until someone decides it belongs in both.
const WINDOWS_ALLOWLIST: [&str; 8] = [
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
];
/// Set on every platform, from the parent or a fallback.
const ALWAYS_SET: [&str; 3] = ["PATH", "HOME", "TMPDIR"];
/// An allowlisted key the backend's own `env:` overrides.
// Not APPDATA: that is the key #522 lost, so it must be checked as a pass-through.
const OVERRIDDEN_KEY: &str = "TEMP";
const OVERRIDE_VALUE: &str = r"C:\mcp-gateway-test\backend-configured-temp";

/// Bounds each nested run, so a hung child is a red test rather than a CI job
/// that sits until its own timeout.
const NESTED_RUN_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

#[tokio::test]
async fn windows_backend_receives_the_allowlist_and_nothing_else() {
    let mut nested = tokio::process::Command::new(std::env::current_exe().expect("test binary"));
    nested
        .args(["--exact", SCENARIO, "--nocapture"])
        .env(SCENARIO_ENV, "1")
        .env(PARENT_SECRET_ENV, PARENT_SECRET)
        .kill_on_drop(true);
    // Above the inner run's own limit, so a hung backend fails the inner run.
    let output = tokio::time::timeout(NESTED_RUN_LIMIT * 2, nested.output())
        .await
        .expect("the scenario finished within the limit")
        .expect("run the Windows child-environment scenario");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(SCENARIO),
        "the nested filter did not run the scenario; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("1 passed"),
        "the nested run did not pass exactly the scenario; stdout={stdout:?}"
    );
    assert!(
        output.status.success(),
        "Windows child-environment scenario failed; stdout={stdout:?} stderr={stderr:?}"
    );
}

#[tokio::test]
async fn windows_child_environment_scenario() {
    if std::env::var_os(SCENARIO_ENV).is_none() {
        return;
    }
    assert_eq!(
        std::env::var(PARENT_SECRET_ENV).as_deref(),
        Ok(PARENT_SECRET),
        "the scenario must start with the parent secret in its own environment"
    );
    let parent_value = std::env::var(OVERRIDDEN_KEY)
        .unwrap_or_else(|_| panic!("premise: the runner defines {OVERRIDDEN_KEY}"));
    assert_ne!(
        parent_value, OVERRIDE_VALUE,
        "the override must be observable"
    );

    let mut cmd = tokio::process::Command::new(std::env::current_exe().expect("test binary"));
    cmd.args(["--exact", DUMP, "--nocapture"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_child_environment(
        &mut cmd,
        &HashMap::from([
            (DUMP_ENV.to_string(), "1".to_string()),
            (OVERRIDDEN_KEY.to_string(), OVERRIDE_VALUE.to_string()),
        ]),
    );
    let output = tokio::time::timeout(NESTED_RUN_LIMIT, cmd.output())
        .await
        .expect("the backend stand-in finished within the limit")
        .expect("spawn the backend stand-in");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let child: BTreeMap<String, String> = stdout
        .lines()
        .find_map(|line| line.strip_prefix(DUMP_PREFIX))
        .map(|json| serde_json::from_str(json).expect("environment dump is JSON"))
        .unwrap_or_else(|| panic!("the backend printed no environment; stdout={stdout:?}"));
    assert!(
        output.status.success(),
        "the backend stand-in failed; stdout={stdout:?}"
    );

    // Negative half: nothing reaches the child that is not named here.
    assert!(
        !child.contains_key(PARENT_SECRET_ENV) && !child.values().any(|v| v == PARENT_SECRET),
        "a secret in the gateway's environment reached the backend: {child:?}"
    );
    let permitted: BTreeSet<&str> = ALWAYS_SET
        .iter()
        .chain(WINDOWS_ALLOWLIST.iter())
        .chain([DUMP_ENV].iter())
        .copied()
        .collect();
    let unexpected: Vec<&String> = child
        .keys()
        .filter(|key| !permitted.contains(key.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "the backend received keys outside the allowlist: {unexpected:?}"
    );

    // Positive half: every allowlisted key arrives with the gateway's value.
    // Each is a premise too: a runner that stopped defining one would
    // otherwise stop proving it without saying so.
    for key in WINDOWS_ALLOWLIST
        .iter()
        .filter(|key| **key != OVERRIDDEN_KEY)
    {
        let value =
            std::env::var_os(key).unwrap_or_else(|| panic!("premise: the runner defines {key}"));
        assert_eq!(
            child.get(*key).map(String::as_str),
            Some(value.to_string_lossy().as_ref()),
            "{key} did not reach the backend with the gateway's value"
        );
    }
    assert_eq!(
        child.get("PATH").map(String::as_str),
        Some(
            std::env::var("PATH")
                .expect("premise: the runner defines PATH")
                .as_str()
        ),
        "PATH did not reach the backend with the gateway's value"
    );
    // HOME and TMPDIR come from the parent when it has them, and otherwise
    // from the same fallbacks production uses.
    let home = std::env::var_os("HOME")
        .or_else(|| dirs::home_dir().map(std::path::PathBuf::into_os_string))
        .expect("a home directory");
    let tmpdir =
        std::env::var_os("TMPDIR").unwrap_or_else(|| std::env::temp_dir().into_os_string());
    for (key, value) in [("HOME", home), ("TMPDIR", tmpdir)] {
        assert_eq!(
            child.get(key).map(String::as_str),
            Some(value.to_string_lossy().as_ref()),
            "{key} did not reach the backend with the value production chose"
        );
    }

    // The backend's own `env:` wins over an allowlisted default.
    assert_eq!(
        child.get(OVERRIDDEN_KEY).map(String::as_str),
        Some(OVERRIDE_VALUE),
        "backend env: must override the allowlisted {OVERRIDDEN_KEY}"
    );
}

/// The backend stand-in: prints its environment and exits.
///
/// Keys are upper-cased because Windows names are case-insensitive (`Path`
/// and `PATH` are one variable). Names starting with `=` are skipped: those
/// are the per-drive working-directory entries (`=C:`) a process keeps for
/// itself, not state it was given.
#[test]
fn windows_child_environment_dump() {
    if std::env::var_os(DUMP_ENV).is_none() {
        return;
    }
    let env: BTreeMap<String, String> = std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().to_uppercase(),
                v.to_string_lossy().into_owned(),
            )
        })
        .filter(|(k, _)| !k.starts_with('='))
        .collect();
    println!(
        "{DUMP_PREFIX}{}",
        serde_json::to_string(&env).expect("serialise environment")
    );
}
