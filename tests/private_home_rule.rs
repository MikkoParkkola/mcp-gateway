// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The private-home rule (`require_private_home!()`): which envs it refuses,
//! which it accepts, and the child protocol and env helpers its rows rely on.
//! Every row here runs its case in a child of this binary, so the parent's own
//! env never decides the outcome.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/private_home.rs"]
#[macro_use]
mod private_home;
// Only the Windows rows can skip (R9: a volume with 8.3 names off).
#[cfg(windows)]
#[path = "common/required.rs"]
mod required;
#[path = "../src/test_source_files.rs"]
mod test_source_files;

use private_home::{Expect, fresh_private_dir, literal_env_command, run_row_child};
use std::path::Path;
use std::process::Command;

#[path = "private_home_rule/guard.rs"]
mod guard;
#[path = "private_home_rule/refusals.rs"]
mod refusals;

/// The rule's only caller outside the wrapped tests: run as a child by every
/// R row, with that row's env.
#[test]
#[ignore = "run by the R rows as a child, with their env"]
fn private_home_probe() {
    require_private_home!();
}

/// The fix line every refusal ends with.
const FIX: &str = "MCP_GATEWAY_TEST_HOME_DIR=$(mktemp -d)";

/// Run the probe in a child built from `command` and expect `expect`.
fn probe(command: Command, expect: &Expect, keep: Vec<tempfile::TempDir>) {
    let _kept = run_row_child(command, "private_home_probe", true, expect, keep);
}

/// The literal env with the override set to `home`.
fn with_override(home: &Path) -> Command {
    let mut command = literal_env_command();
    command.env("MCP_GATEWAY_TEST_HOME_DIR", home); // spawn-check: not the gateway: the probe child, this test binary
    command
}

/// R0a: a private override with the config and data variables unset is accepted.
#[test]
fn r0a_a_private_override_alone_is_accepted() {
    let home = fresh_private_dir();
    probe(with_override(home.path()), &Expect::Pass, vec![home]);
}

/// R0b: the harness shape, both variables exactly under the override and not
/// created yet, is accepted.
#[test]
fn r0b_the_harness_shape_is_accepted() {
    let home = fresh_private_dir();
    let mut command = with_override(home.path());
    command
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("MCP_GATEWAY_CONFIG_DIR", home.path().join(".mcp-gateway"));
    probe(command, &Expect::Pass, vec![home]);
}

/// The env a built command carries: every explicit set as `Some`, every
/// removal as `None`.
fn explicit_env(command: &Command) -> std::collections::BTreeMap<String, Option<String>> {
    command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

/// The literal env T2 and T7 run in: a planted inherited `MCP_GATEWAY_*` pair
/// to be removed, nothing else of the gateway's.
fn golden_child() -> Command {
    let mut command = literal_env_command();
    command
        .env("MCP_GATEWAY_FOO", "x")
        .env("MCP_GATEWAY_CONFIG_DIR", "y");
    command
}

/// What every isolated command removes, sets whatever its home (the heartbeat
/// opt-out, docs/PRIVACY.md), and passes through, given the child's env.
fn removals_and_switch(expected: &mut std::collections::BTreeMap<String, Option<String>>) {
    expected.insert("MCP_GATEWAY_FOO".into(), None);
    expected.insert("MCP_GATEWAY_CONFIG_DIR".into(), None);
    expected.insert("DO_NOT_TRACK".into(), Some("1".into()));
    if let Ok(mutant) = std::env::var("MCP_GATEWAY_MUTANT") {
        expected.insert("MCP_GATEWAY_MUTANT".into(), Some(mutant));
    }
}

fn s(path: &Path) -> Option<String> {
    path.to_str().map(str::to_owned)
}

/// T2: `isolated_with_env_home` puts the override at A and every platform-home
/// variable at B, removes inherited gateway variables, and sets nothing else.
#[test]
fn t2_isolated_with_env_home_maps_two_homes() {
    if private_home::is_row_child("t2_isolated_with_env_home_maps_two_homes") {
        let a = Path::new("/never-created/a");
        let b = Path::new("/never-created/b");
        let built = gateway_bin::isolated_with_env_home(
            Command::new("never-run"),
            a,
            b,
            gateway_bin::Inherit::Environment,
        );
        let mut expected = std::collections::BTreeMap::from([
            ("HOME".to_string(), s(b)),
            ("USERPROFILE".to_string(), s(b)),
            ("APPDATA".to_string(), s(&b.join("AppData").join("Roaming"))),
            (
                "LOCALAPPDATA".to_string(),
                s(&b.join("AppData").join("Local")),
            ),
            ("MCP_GATEWAY_TEST_HOME_DIR".to_string(), s(a)),
            (
                "MCP_GATEWAY_SECRETS__STORE".to_string(),
                Some("files".to_string()),
            ),
            ("XDG_CONFIG_HOME".to_string(), s(&a.join(".config"))),
            (
                "XDG_DATA_HOME".to_string(),
                s(&a.join(".local").join("share")),
            ),
            (
                "XDG_STATE_HOME".to_string(),
                s(&a.join(".local").join("state")),
            ),
        ]);
        removals_and_switch(&mut expected);
        assert_eq!(explicit_env(&built), expected);
        return;
    }
    let _ = run_row_child(
        golden_child(),
        "t2_isolated_with_env_home_maps_two_homes",
        false,
        &Expect::Pass,
        Vec::new(),
    );
}

/// T7: the existing `command()` and `command_with_env_home()` keep today's env.
#[test]
fn t7_existing_gateway_bin_envs_are_unchanged() {
    if private_home::is_row_child("t7_existing_gateway_bin_envs_are_unchanged") {
        let home = Path::new("/never-created/home");
        let env_home = Path::new("/never-created/env-home");
        let mut expected = std::collections::BTreeMap::from([
            ("HOME".to_string(), s(home)),
            ("USERPROFILE".to_string(), s(home)),
            (
                "APPDATA".to_string(),
                s(&home.join("AppData").join("Roaming")),
            ),
            (
                "LOCALAPPDATA".to_string(),
                s(&home.join("AppData").join("Local")),
            ),
            ("MCP_GATEWAY_TEST_HOME_DIR".to_string(), s(home)),
            (
                "MCP_GATEWAY_SECRETS__STORE".to_string(),
                Some("files".to_string()),
            ),
            ("XDG_CONFIG_HOME".to_string(), s(&home.join(".config"))),
            (
                "XDG_DATA_HOME".to_string(),
                s(&home.join(".local").join("share")),
            ),
            (
                "XDG_STATE_HOME".to_string(),
                s(&home.join(".local").join("state")),
            ),
        ]);
        removals_and_switch(&mut expected);
        let plain = gateway_bin::command(home, gateway_bin::Inherit::Environment);
        assert_eq!(explicit_env(&plain), expected, "command()");
        expected.insert("HOME".into(), s(env_home));
        expected.insert("USERPROFILE".into(), s(env_home));
        let split =
            gateway_bin::command_with_env_home(home, env_home, gateway_bin::Inherit::Environment);
        assert_eq!(explicit_env(&split), expected, "command_with_env_home()");
        return;
    }
    let _ = run_row_child(
        golden_child(),
        "t7_existing_gateway_bin_envs_are_unchanged",
        false,
        &Expect::Pass,
        Vec::new(),
    );
}

/// The mutant switch reaches a grandchild that only its grandparent was given.
#[test]
fn the_mutant_switch_reaches_a_grandchild() {
    const ME: &str = "the_mutant_switch_reaches_a_grandchild";
    if private_home::is_row_child(ME) {
        // The child: spawn the grandchild without supplying the switch.
        let seen = std::env::var("MCP_GATEWAY_MUTANT").expect("the child has the switch");
        let mut command = literal_env_command();
        command.env("MCP_GW_EXPECT_MUTANT", &seen);
        let _ = run_row_child(
            command,
            "mutant_switch_grandchild",
            true,
            &Expect::Pass,
            Vec::new(),
        );
        return;
    }
    let mut command = literal_env_command();
    if std::env::var_os("MCP_GATEWAY_MUTANT").is_none() {
        command.env("MCP_GATEWAY_MUTANT", "pass-through-probe");
    }
    let _ = run_row_child(command, ME, false, &Expect::Pass, Vec::new());
}

/// The grandchild of the row above: it sees exactly the switch its parent had.
#[test]
#[ignore = "run by the_mutant_switch_reaches_a_grandchild as a grandchild"]
fn mutant_switch_grandchild() {
    let expected = std::env::var("MCP_GW_EXPECT_MUTANT").expect("the expected switch");
    assert_eq!(std::env::var("MCP_GATEWAY_MUTANT").ok(), Some(expected));
}
