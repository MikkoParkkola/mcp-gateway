// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R1a, R1b and R2: the home a test process resolves, seen from
//! child processes whose environment each row sets. Every child gets its own
//! temp dir, owned by the parent row, so a fallback it creates is removed with
//! that dir and never reaches the Linux leftover check.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const CASE: &str = "MCP_GW_TEST_HOME_PROBE_CASE";
const PREFIX: &str = "mcp-gateway-test-home-";
const OVERRIDE: &str = "MCP_GATEWAY_TEST_HOME_DIR";
const XDG: &str = "XDG_CONFIG_HOME";
const DATA_VAR: &str = "MCP_GATEWAY_CONFIG_DIR";

/// Points every temp-dir lookup of the child at `tmp`.
fn private_tmp(cmd: &mut Command, tmp: &Path) {
    for key in ["TMPDIR", "TMP", "TEMP"] {
        cmd.env(key, tmp);
    }
}

/// Runs a child, requires success and its ok marker (printed only after the
/// child's own assertions), and returns its `PROBE KEY=value` lines.
fn run(mut cmd: Command, row: &str) -> BTreeMap<String, String> {
    let out = cmd.output().expect("spawn the child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{row} child failed:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("{row} child ok")),
        "{row} child ran no case:\n{stdout}\n{stderr}"
    );
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("PROBE "))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// The fallback homes in `tmp`, sorted.
fn fallbacks(tmp: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(tmp)
        .expect("read the child's tmp")
        .map(|entry| entry.expect("tmp entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(PREFIX))
        })
        .collect();
    found.sort();
    found
}

fn args(child: &str) -> [String; 4] {
    [
        "--exact".to_owned(),
        format!("home_dir::probe_tests::{child}"),
        "--ignored".to_owned(),
        "--nocapture".to_owned(),
    ]
}

fn case_is(name: &str) -> bool {
    std::env::var(CASE).as_deref() == Ok(name)
}

/// R1a's spawner. On unix the child runs under `umask 022`, because a host's
/// own umask 077 would make an unpermissioned dir look owner-only (m7). The
/// row's variables go on after [`crate::test_home::child_env`], so they win.
fn spawn_r1a_child(tmp: &Path, xdg: &Path, data: &Path) -> Command {
    #[cfg(unix)]
    let mut cmd = {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("umask 022; exec \"$0\" \"$@\"")
            .arg(std::env::current_exe().expect("the running test binary"))
            .args(args("r1a_child"));
        cmd
    };
    #[cfg(not(unix))]
    let mut cmd = {
        let mut cmd = crate::test_home::test_binary();
        cmd.args(args("r1a_child"));
        cmd
    };
    cmd.envs(crate::test_home::child_env())
        .env_remove(OVERRIDE)
        .env(XDG, xdg)
        .env(DATA_VAR, data)
        .env(CASE, "r1a");
    private_tmp(&mut cmd, tmp);
    cmd
}

/// R1a (HOME.1): with the override absent, each test process resolves its own
/// fresh private home under its temp dir. Inherited XDG and data-dir values
/// (sentinels S1, S2) are ignored, and on unix the home is owner-only.
#[test]
fn r1a_without_the_override_each_process_gets_its_own_private_home() {
    let tmp = tempfile::tempdir().expect("tmp");
    let s1 = tempfile::tempdir().expect("xdg sentinel");
    let s2 = tempfile::tempdir().expect("data sentinel");
    let one = run(spawn_r1a_child(tmp.path(), s1.path(), s2.path()), "r1a");
    let two = run(spawn_r1a_child(tmp.path(), s1.path(), s2.path()), "r1a");
    let account_home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    for seen in [&one, &two] {
        let home = PathBuf::from(&seen["HOME"]);
        assert_eq!(seen["HOME"], seen["HOME2"], "one home for every call");
        assert_eq!(
            home.parent(),
            Some(tmp.path()),
            "a fallback under the child's tmp: {seen:?}"
        );
        let name = home
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        assert!(name.starts_with(PREFIX), "the fallback prefix: {name}");
        assert_ne!(
            Some(home.as_os_str()),
            account_home.as_deref(),
            "not the account home"
        );
        #[cfg(not(target_os = "macos"))]
        {
            let config = PathBuf::from(&seen["CONFIG"]);
            assert_eq!(config, home.join(".config"));
            assert_ne!(config, s1.path());
        }
        let data = PathBuf::from(&seen["DATA"]);
        assert_eq!(data, home.join(".mcp-gateway"));
        assert_ne!(data, s2.path());
        #[cfg(unix)]
        {
            assert_eq!(seen["MODE"], "700", "the fallback is owner-only");
            let control = u32::from_str_radix(&seen["CONTROL"], 8).expect("control mode");
            assert_ne!(
                control & 0o077,
                0,
                "premise: umask 022 lets a plain dir be shared"
            );
        }
    }
    assert_ne!(one["HOME"], two["HOME"], "one fallback per process");
    let mut both = vec![PathBuf::from(&one["HOME"]), PathBuf::from(&two["HOME"])];
    both.sort();
    assert_eq!(fallbacks(tmp.path()), both);
}

#[test]
#[ignore = "run by r1a_without_the_override_each_process_gets_its_own_private_home"]
fn r1a_child() {
    if !case_is("r1a") {
        return;
    }
    let home = super::home_dir().expect("a home");
    println!("PROBE HOME={}", home.display());
    println!(
        "PROBE HOME2={}",
        super::home_dir().expect("a home").display()
    );
    #[cfg(not(target_os = "macos"))]
    println!(
        "PROBE CONFIG={}",
        super::config_dir().expect("a config dir").display()
    );
    println!(
        "PROBE DATA={}",
        crate::config_persistence::gateway_data_dir().display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode =
            |path: &Path| std::fs::metadata(path).expect("mode").permissions().mode() & 0o777;
        println!("PROBE MODE={:o}", mode(&home));
        let control = tempfile::tempdir().expect("control dir");
        println!("PROBE CONTROL={:o}", mode(control.path()));
    }
    println!("r1a child ok");
}

/// R1b (H3, HOME.2): with the override present, the child resolves exactly it,
/// an explicit XDG and data dir win under it, and no wrapper builds a fallback
/// (m9a-c). In the Spark `cargo test --release` row this is red on today's
/// code, where release compiles the override out (m3).
#[test]
fn r1b_with_the_override_the_child_resolves_it_and_builds_no_fallback() {
    let tmp = tempfile::tempdir().expect("tmp");
    let home = tempfile::tempdir().expect("override home");
    let xdg = tempfile::tempdir().expect("xdg");
    let data = tempfile::tempdir().expect("data dir");
    let mut cmd = crate::test_home::test_binary();
    cmd.args(args("r1b_child"))
        .env(OVERRIDE, home.path())
        .env(XDG, xdg.path())
        .env(DATA_VAR, data.path())
        .env(CASE, "r1b");
    private_tmp(&mut cmd, tmp.path());
    let seen = run(cmd, "r1b");
    let resolved = PathBuf::from(&seen["HOME"]);
    assert_eq!(resolved, home.path());
    assert_ne!(
        Some(resolved),
        super::home_dir(),
        "not the parent's own home"
    );
    #[cfg(not(target_os = "macos"))]
    assert_eq!(PathBuf::from(&seen["CONFIG"]), xdg.path());
    let resolved_data = PathBuf::from(&seen["DATA"]);
    assert_eq!(resolved_data, data.path());
    assert_ne!(resolved_data, home.path().join(".mcp-gateway"));
    assert_eq!(
        PathBuf::from(&seen["TMPSEEN"]),
        tmp.path(),
        "the child listed its own tmp"
    );
    assert_eq!(seen["FALLBACKS"], "0", "no fallback under the override");
}

#[test]
#[ignore = "run by r1b_with_the_override_the_child_resolves_it_and_builds_no_fallback"]
fn r1b_child() {
    if !case_is("r1b") {
        return;
    }
    println!(
        "PROBE HOME={}",
        super::home_dir().expect("a home").display()
    );
    #[cfg(not(target_os = "macos"))]
    println!(
        "PROBE CONFIG={}",
        super::config_dir().expect("a config dir").display()
    );
    println!(
        "PROBE DATA={}",
        crate::config_persistence::gateway_data_dir().display()
    );
    // Counted after all three lookups, so an eager fallback in any wrapper shows.
    let tmp = std::env::temp_dir();
    println!("PROBE TMPSEEN={}", tmp.display());
    println!("PROBE FALLBACKS={}", fallbacks(&tmp).len());
    println!("r1b child ok");
}

/// R2 (HOME.2): a test-binary child shares its parent's home through
/// `test_binary()`, and a test's own override after it still wins. It runs two
/// levels deep, so the parent's harness override cannot decide it (m6).
#[test]
fn r2_a_spawned_test_binary_shares_its_parents_home() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut cmd = crate::test_home::test_binary();
    cmd.args(args("r2_a_child"))
        .env_remove(OVERRIDE)
        .env_remove(XDG)
        .env_remove(DATA_VAR)
        .env(CASE, "r2a");
    private_tmp(&mut cmd, tmp.path());
    run(cmd, "r2a");
}

#[test]
#[ignore = "run by r2_a_spawned_test_binary_shares_its_parents_home"]
fn r2_a_child() {
    if !case_is("r2a") {
        return;
    }
    let own = super::home_dir().expect("a home");
    let tmp = std::env::temp_dir();
    let mut shared = crate::test_home::test_binary();
    shared.args(args("r2_b_child")).env(CASE, "r2b");
    let seen = run(shared, "r2b");
    assert_eq!(
        PathBuf::from(&seen["HOME"]),
        own,
        "the child shares the parent's home"
    );
    assert_eq!(
        fallbacks(&tmp),
        vec![own.clone()],
        "and builds no fallback of its own"
    );
    // Not a fallback name, so the count above is unaffected.
    let explicit = tempfile::tempdir().expect("explicit home");
    let mut overridden = crate::test_home::test_binary();
    overridden
        .args(args("r2_b_child"))
        .env(OVERRIDE, explicit.path())
        .env(CASE, "r2b");
    let seen = run(overridden, "r2b");
    let resolved = PathBuf::from(&seen["HOME"]);
    assert_eq!(resolved, explicit.path(), "the test's own override wins");
    assert_ne!(resolved, own);
    println!("r2a child ok");
}

#[test]
#[ignore = "run by r2_a_child"]
fn r2_b_child() {
    if !case_is("r2b") {
        return;
    }
    println!(
        "PROBE HOME={}",
        super::home_dir().expect("a home").display()
    );
    println!("r2b child ok");
}
