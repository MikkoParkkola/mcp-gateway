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
///
/// Red-stage stub: empty.
pub(crate) fn child_env() -> Vec<(&'static str, OsString)> {
    Vec::new()
}

/// The running test binary with [`child_env`] applied. A test's own `.env()`
/// or `.env_remove()` after this still wins.
///
/// Red-stage stub: the environment is not applied.
pub(crate) fn test_binary() -> Command {
    Command::new(std::env::current_exe().expect("the running test binary"))
}

/// The call the scan looks for, built so this file's own text never matches it.
const CALL: &str = concat!("current_", "exe()");

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

fn rust_files(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// R2.3: the running test binary is started only through
/// [`test_binary`], except at the listed sites that wrap it in a shell and
/// apply [`child_env`] themselves, and at two production uses.
#[test]
fn every_test_binary_spawn_goes_through_test_binary() {
    const OWN: (&str, &str) = ("src/test_home.rs", "test_binary");
    const SHELL_WRAPPED: [(&str, &str); 5] = [
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
    ];
    const PRODUCTION: [(&str, &str); 2] = [
        ("src/preview_sandbox/mod.rs", "start"),
        ("src/gateway/server/window_saver.rs", "start_window_saver"),
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
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
    let found: std::collections::BTreeSet<(String, String)> = texts
        .iter()
        .flat_map(|(rel, text)| spawn_sites(rel, text))
        .collect();
    let expected: std::collections::BTreeSet<(String, String)> = std::iter::once(OWN)
        .chain(SHELL_WRAPPED)
        .chain(PRODUCTION)
        .map(|(file, name)| (file.to_owned(), name.to_owned()))
        .collect();
    assert_eq!(
        found.difference(&expected).collect::<Vec<_>>(),
        Vec::<&(String, String)>::new(),
        "start the test binary through test_home::test_binary()"
    );
    assert_eq!(
        found, expected,
        "a listed site no longer calls it: update the list"
    );
    for (file, name) in SHELL_WRAPPED {
        let body = fn_body(&texts[file], name);
        assert!(
            body.iter().any(|line| line.contains("child_env()")),
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
#[test]
fn the_spawn_scan_finds_a_planted_call() {
    let planted =
        format!("fn planted() {{\n    let c = Command::new(std::env::{CALL}.unwrap());\n}}\n");
    assert_eq!(
        spawn_sites("src/x_tests.rs", &planted),
        vec![("src/x_tests.rs".to_owned(), "planted".to_owned())]
    );
    let commented = format!("// std::env::{CALL}\n");
    assert_eq!(spawn_sites("src/x_tests.rs", &commented), Vec::new());
}
