// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The home a test process shares with the test-binary children it spawns.
//!
//! A child started without the parent's home would resolve a fallback of its
//! own and lose the parent's vault and data directory, so every spawn of the
//! running test binary goes through [`test_binary`]. A spawn that must wrap the
//! binary in a shell applies [`child_env`] itself.

use std::ffi::OsString;
use std::process::Command;

/// The variables that give a child the parent's resolved home: the override,
/// and the config and data directories beneath it.
pub(crate) fn child_env() -> Vec<(&'static str, OsString)> {
    let home = crate::home_dir::home_dir().expect("a test process always has a home");
    vec![
        ("MCP_GATEWAY_TEST_HOME_DIR", home.clone().into_os_string()),
        ("XDG_CONFIG_HOME", home.join(".config").into_os_string()),
        (
            "MCP_GATEWAY_CONFIG_DIR",
            home.join(".mcp-gateway").into_os_string(),
        ),
    ]
}

/// The running test binary with [`child_env`] applied. A test's own `.env()`
/// or `.env_remove()` after this still wins. A tokio site takes
/// `tokio::process::Command::from(test_binary())`.
pub(crate) fn test_binary() -> Command {
    let mut command = Command::new(std::env::current_exe().expect("the running test binary"));
    command.envs(child_env());
    command
}

/// The call the scan looks for, built so this file's own text never matches it.
const CALL: &str = concat!("current_", "exe()");
/// The calls the clear check looks for, built the same way.
const CLEAR: &str = concat!(".env_", "clear()");
/// The bare call, so an imported `test_binary()` counts as well as the path form.
const BINARY: &str = concat!("test_", "binary()");
const RESTORE: &str = concat!("child_", "env()");

/// Every `(file, enclosing fn)` that calls [`CALL`] in `text`, skipping comment
/// lines. The enclosing fn is the nearest `fn name` at or above the call.
fn spawn_sites(rel: &str, text: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut sites = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        if !line.contains(CALL) || line.trim_start().starts_with("//") {
            continue;
        }
        let name = lines[..=at]
            .iter()
            .rev()
            .find_map(|above| fn_name(above))
            .unwrap_or_default();
        sites.push((rel.to_owned(), name));
    }
    sites
}

/// The name in a line declaring a fn, if it declares one.
fn fn_name(line: &str) -> Option<String> {
    let rest = line.split("fn ").nth(1)?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty() && !line.trim_start().starts_with("//")).then_some(name)
}

/// The text of fn `name` in `text`: from its declaration to the next fn
/// declared at the same or a shallower indent.
fn fn_body<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
    let lines: Vec<&str> = text.lines().collect();
    let indent = |line: &str| line.len() - line.trim_start().len();
    let Some(start) = lines
        .iter()
        .position(|line| fn_name(line).as_deref() == Some(name))
    else {
        return Vec::new();
    };
    let end = lines[start + 1..]
        .iter()
        .position(|line| fn_name(line).is_some() && indent(line) <= indent(lines[start]))
        .map_or(lines.len(), |offset| start + 1 + offset);
    lines[start..end].to_vec()
}

/// Every `(file, enclosing fn)` that starts the test binary and then clears
/// its environment without giving the parent's home back after the clear.
fn cleared_without_home(rel: &str, text: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        if !line.contains(CLEAR) || line.trim_start().starts_with("//") {
            continue;
        }
        let Some(name) = lines[..=at].iter().rev().find_map(|above| fn_name(above)) else {
            continue;
        };
        let body = fn_body(text, &name);
        if !body.iter().any(|line| line.contains(BINARY)) {
            continue;
        }
        // Every clear must be restored before the next clear or the fn's end;
        // a commented-out restore does not count.
        let mut pending = false;
        let mut lost = false;
        for line in body {
            // Code only: a restore inside a trailing comment does not count.
            let code = line.split("//").next().unwrap_or_default();
            let mut segments = code.split(CLEAR);
            if segments
                .next()
                .is_some_and(|before| before.contains(RESTORE))
            {
                pending = false;
            }
            // Each segment follows one clear, so two clears on a line are two.
            for after in segments {
                lost |= pending;
                pending = !after.contains(RESTORE);
            }
        }
        if (lost || pending)
            && !found
                .iter()
                .any(|(file, fn_name)| file == rel && *fn_name == name)
        {
            found.push((rel.to_owned(), name));
        }
    }
    found
}

/// R2.3: the running test binary is started only through
/// [`test_binary`], except at the listed sites that wrap it in a shell and
/// apply [`child_env`] themselves, and at the production uses (the gateway starting itself).
#[cfg(tp3)]
#[test]
fn every_test_binary_spawn_goes_through_test_binary() {
    const OWN: (&str, &str) = ("src/test_home.rs", "test_binary");
    const SHELL_WRAPPED: [(&str, &str); 6] = [
        ("src/file_mode_inherit_tests.rs", "in_child"),
        (
            "src/identity_propagation/audit_fail_closed_tests.rs",
            "mint_write_failure_is_fail_closed",
        ),
        (
            "src/gateway/meta_mcp/invoke/identity_propagation_enforcement_tests/resolution.rs",
            "mint_audit_write_failure_returns_generic_error_no_leak",
        ),
        (
            "src/gateway/router/backend_handlers/tests.rs",
            "mint_write_failure_is_fail_closed",
        ),
        ("src/home_dir_probe_tests.rs", "spawn_r1a_child"),
        // umask 022 for the spend history's mode rows.
        (
            "src/gateway/server/spend_history_save_tests.rs",
            "under_umask_022",
        ),
    ];
    const PRODUCTION: [(&str, &str); 3] = [
        // The sandbox's helper is the gateway's own binary, found in one place.
        ("src/preview_sandbox/mod.rs", "gateway"),
        ("src/gateway/server/window_saver.rs", "start_window_saver"),
        // Reads the running file for the restart notice's start command; spawns nothing.
        ("src/gateway/ui/restart_confirm.rs", "restart_advice"),
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    crate::test_source_files::rust_files(&root.join("src"), &mut files);
    let mut texts = std::collections::BTreeMap::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .expect("under the crate")
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        texts.insert(rel, std::fs::read_to_string(&path).expect("read source"));
    }
    for named in [
        "src/test_home.rs",
        "src/file_mode_inherit_tests.rs",
        "src/discovery/non_client_tests.rs",
        "src/transport/stdio_cache_abs_tests.rs",
    ] {
        assert!(texts.contains_key(named), "the scan read {named}");
    }
    // Counted per site, so a second call inside a listed fn is not hidden.
    let mut found = std::collections::BTreeMap::<(String, String), usize>::new();
    for site in texts.iter().flat_map(|(rel, text)| spawn_sites(rel, text)) {
        *found.entry(site).or_default() += 1;
    }
    let expected: std::collections::BTreeMap<(String, String), usize> = std::iter::once(OWN)
        .chain(SHELL_WRAPPED)
        .chain(PRODUCTION)
        .map(|(file, name)| ((file.to_owned(), name.to_owned()), 1))
        .collect();
    let unrouted: Vec<_> = found
        .iter()
        .filter(|(site, count)| expected.get(*site) != Some(*count))
        .collect();
    assert_eq!(
        unrouted,
        Vec::<(&(String, String), &usize)>::new(),
        "start the test binary through test_home::test_binary()"
    );
    assert_eq!(
        found, expected,
        "a listed site no longer calls it: update the list"
    );
    let cleared: Vec<_> = texts
        .iter()
        .flat_map(|(rel, text)| cleared_without_home(rel, text))
        .collect();
    assert_eq!(
        cleared,
        Vec::<(String, String)>::new(),
        "an env_clear() after test_binary() drops the parent's home: apply child_env() after it"
    );
    for (file, name) in SHELL_WRAPPED {
        let body = fn_body(&texts[file], name);
        assert!(
            body.iter().any(|line| line.contains(RESTORE)),
            "{file}::{name} wraps the test binary and must apply child_env()"
        );
    }
    for (file, name) in PRODUCTION {
        let kept = crate::test_source_text::production_text(&texts[file]);
        assert!(
            spawn_sites(file, &kept).contains(&(file.to_owned(), name.to_owned())),
            "{file}::{name} is listed as production but compiles only under test"
        );
    }
}

/// The scan finds a planted call and names its fn (A3: it can fail).
#[cfg(tp3)]
#[test]
fn the_spawn_scan_finds_a_planted_call() {
    let planted =
        format!("fn planted() {{\n    let c = Command::new(std::env::{CALL}.unwrap());\n}}\n");
    assert_eq!(
        spawn_sites("src/x_tests.rs", &planted),
        vec![("src/x_tests.rs".to_owned(), "planted".to_owned())]
    );
    let twice = format!("fn twice() {{\n    a(std::env::{CALL});\n    b(std::env::{CALL});\n}}\n");
    assert_eq!(
        spawn_sites("src/x_tests.rs", &twice).len(),
        2,
        "each call counts"
    );
    let cleared =
        format!("fn hermetic() {{\n    let mut c = crate::{BINARY};\n    c{CLEAR};\n}}\n");
    assert_eq!(
        cleared_without_home("src/x_tests.rs", &cleared),
        vec![("src/x_tests.rs".to_owned(), "hermetic".to_owned())]
    );
    let restored = format!(
        "fn hermetic() {{\n    let mut c = crate::{BINARY};\n    c{CLEAR};\n    c.envs(crate::test_home::{RESTORE});\n}}\n"
    );
    assert_eq!(
        cleared_without_home("src/x_tests.rs", &restored),
        Vec::new()
    );
    let twice_cleared = format!(
        "fn hermetic() {{\n    let mut c = crate::{BINARY};\n    c{CLEAR};\n    c.envs(crate::test_home::{RESTORE});\n    c{CLEAR};\n}}\n"
    );
    assert_eq!(
        cleared_without_home("src/x_tests.rs", &twice_cleared).len(),
        1,
        "a second clear"
    );
    let commented_restore = format!(
        "fn hermetic() {{\n    let mut c = crate::{BINARY};\n    c{CLEAR};\n    // c.envs(crate::test_home::{RESTORE});\n}}\n"
    );
    assert_eq!(
        cleared_without_home("src/x_tests.rs", &commented_restore).len(),
        1,
        "a commented restore"
    );
    let same_line = format!(
        "fn hermetic() {{\n    let mut c = crate::{BINARY};\n    c{CLEAR}.envs(crate::test_home::{RESTORE});\n}}\n"
    );
    assert_eq!(
        cleared_without_home("src/x_tests.rs", &same_line),
        Vec::new(),
        "restored on the same line"
    );
    let imported = format!("fn hermetic() {{\n    let mut c = {BINARY};\n    c{CLEAR};\n}}\n");
    assert_eq!(
        cleared_without_home("src/x_tests.rs", &imported).len(),
        1,
        "an imported test_binary()"
    );
    let inline_comment = format!(
        "fn hermetic() {{\n    let mut c = crate::{BINARY};\n    c{CLEAR}; // c.envs(crate::test_home::{RESTORE});\n}}\n"
    );
    assert_eq!(
        cleared_without_home("src/x_tests.rs", &inline_comment).len(),
        1,
        "a restore in a trailing comment"
    );
    let two_on_a_line = format!(
        "fn hermetic() {{\n    let mut c = crate::{BINARY};\n    c{CLEAR}.envs(crate::test_home::{RESTORE}){CLEAR};\n}}\n"
    );
    assert_eq!(
        cleared_without_home("src/x_tests.rs", &two_on_a_line).len(),
        1,
        "a second clear on the same line"
    );
    let commented = format!("// std::env::{CALL}\n");
    assert_eq!(spawn_sites("src/x_tests.rs", &commented), Vec::new());
}
