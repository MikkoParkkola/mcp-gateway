// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! This binary's private-home rows: its routing row (T3-T5), T1 (discovery reads
//! only the private home) and T6 (config routing without XDG).

use crate::{gateway_bin, private_home};
use mcp_gateway::discovery::AutoDiscovery;

/// T3-T5: this binary's gateway home routes to the test-home override.
#[test]
fn private_home_routes_to_the_override() {
    private_home::assert_routes_to_the_override(
        module_path!(),
        "private_home_routes_to_the_override",
    );
}

/// One planted source: its name, its path relative to a home, and its file content.
type Int1Source = (&'static str, String, fn(&str) -> String);

/// The sources T1 plants, as literal paths per OS (relative to a home) and the
/// file content for a server named `<n>` with the command `<n>`. One server
/// per source, each with a unique name and command, so de-duplication cannot
/// merge them. Parsers in `src/discovery/config_scanner.rs`: `parse_claude_config`
/// :275, `parse_vscode_config` :303, `parse_zed_config` :454,
/// `parse_continue_config` :504, `scan_mcp_config_dir` :191.
fn int1_sources() -> Vec<Int1Source> {
    let mcp_servers: fn(&str) -> String =
        |n| format!(r#"{{"mcpServers":{{"{n}":{{"command":"{n}"}}}}}}"#);
    let vscode: fn(&str) -> String =
        |n| format!(r#"{{"mcp":{{"servers":{{"{n}":{{"command":"{n}"}}}}}}}}"#);
    let continue_: fn(&str) -> String =
        |n| format!(r#"{{"mcpServers":[{{"name":"{n}","command":"{n}"}}]}}"#);
    let zed: fn(&str) -> String =
        |n| format!(r#"{{"context_servers":{{"{n}":{{"command":"{n}"}}}}}}"#);
    let app = if cfg!(target_os = "macos") {
        "Library/Application Support"
    } else if cfg!(windows) {
        "AppData/Roaming"
    } else {
        ".config"
    };
    let zed_path = if cfg!(windows) {
        ".config/Zed/settings.json"
    } else {
        ".config/zed/settings.json"
    };
    vec![
        ("claude-code", ".claude.json".into(), mcp_servers),
        ("cursor-mcp", ".cursor/mcp.json".into(), mcp_servers),
        ("continue", ".continue/config.json".into(), continue_),
        ("codex", ".codex/config.json".into(), mcp_servers),
        (
            "claude-desktop",
            format!("{app}/Claude/claude_desktop_config.json"),
            mcp_servers,
        ),
        (
            "windsurf",
            format!("{app}/Windsurf/windsurf_config.json"),
            mcp_servers,
        ),
        ("vscode", format!("{app}/Code/User/settings.json"), vscode),
        ("cursor", format!("{app}/Cursor/User/settings.json"), vscode),
        ("zed", zed_path.into(), zed),
        (
            "mcp-config",
            ".config/mcp/PLACEHOLDER.json".into(),
            mcp_servers,
        ),
    ]
}

/// Plant every source under `home` for the name prefix `prefix`; returns the
/// files written, with their bytes.
fn int1_plant(home: &std::path::Path, prefix: &str) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    int1_sources()
        .into_iter()
        .map(|(source, rel, content)| {
            let name = format!("{prefix}-{source}");
            let rel = rel.replace("PLACEHOLDER", &name);
            let path = home.join(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("source dir");
            let bytes = content(&name).into_bytes();
            std::fs::write(&path, &bytes).expect("source file");
            (path, bytes)
        })
        .collect()
}

/// T1 (INT.1): discovery reads only the private home. Canaries are
/// planted in a decoy real home (HOME, USERPROFILE, APPDATA), never the
/// developer's own dirs; private entries in the override home must all be
/// listed and no canary may be. On Windows `dirs` ignores USERPROFILE, so the
/// canary negative proves nothing about the decoy there; the preflight and the
/// private entries are the routing evidence.
#[test]
fn int1_discovery_reads_only_the_private_home() {
    const ME: &str = "int1_discovery_reads_only_the_private_home";
    if private_home::is_row_child(ME) {
        let a = std::path::PathBuf::from(
            std::env::var_os("MCP_GATEWAY_TEST_HOME_DIR").expect("the override"),
        );
        let b = std::path::PathBuf::from(std::env::var_os("HOME").expect("the decoy home"));
        // Preflight: nothing is written or scanned unless every routing check holds.
        // The parent's own fixture paths come in variables the helper under test
        // never sets, so a helper that left HOME or the override wrong is caught here.
        for (var, dir) in [("MCP_GW_T1_A", &a), ("MCP_GW_T1_B", &b)] {
            let given =
                std::path::PathBuf::from(std::env::var_os(var).expect("the parent's fixture"));
            assert_eq!(
                private_home::canonical(dir),
                private_home::canonical(&given),
                "{var}: the child's home is not the fixture its parent made"
            );
        }
        let temp = private_home::canonical(&std::env::temp_dir());
        for dir in [&a, &b] {
            let canonical = private_home::canonical(dir);
            assert!(
                canonical.starts_with(&temp) && canonical != temp,
                "{} is not a private temp dir",
                dir.display()
            );
        }
        let data = mcp_gateway::config_persistence::gateway_data_dir();
        assert_eq!(
            private_home::canonical_leaf(&data),
            private_home::canonical(&a).join(".mcp-gateway")
        );
        #[cfg(not(target_os = "macos"))]
        {
            let config = mcp_gateway::gateway::test_helpers::config_dir().expect("a config dir");
            assert_eq!(
                private_home::canonical_leaf(&config),
                private_home::canonical(&a).join(".config")
            );
        }
        let pid = std::process::id();
        let canaries = int1_plant(&b, &format!("canary-{pid}"));
        let _private = int1_plant(&a, &format!("private-{pid}"));
        let found = tokio::runtime::Runtime::new()
            .expect("a runtime")
            .block_on(AutoDiscovery::new().discover_all())
            .expect("discovery runs");
        // Each private entry exactly once, counted before any set can hide a duplicate.
        for (source, _, _) in int1_sources() {
            let name = format!("private-{pid}-{source}");
            let seen = found.iter().filter(|server| server.name == name).count();
            assert_eq!(seen, 1, "{name} discovered {seen} times");
        }
        let names: std::collections::BTreeSet<String> =
            found.iter().map(|server| server.name.clone()).collect();
        let private: std::collections::BTreeSet<String> = names
            .iter()
            .filter(|name| name.starts_with(&format!("private-{pid}-")))
            .cloned()
            .collect();
        let expected: std::collections::BTreeSet<String> = int1_sources()
            .iter()
            .map(|(source, _, _)| format!("private-{pid}-{source}"))
            .collect();
        assert_eq!(
            private, expected,
            "every private source is listed, exactly once"
        );
        let leaked: Vec<&String> = names
            .iter()
            .filter(|name| name.starts_with(&format!("canary-{pid}")))
            .collect();
        assert!(
            leaked.is_empty(),
            "decoy-home canaries were read: {leaked:?} (on Windows this negative proves nothing about the decoy: dirs ignores USERPROFILE)"
        );
        for (path, bytes) in canaries {
            assert_eq!(
                std::fs::read(&path).expect("canary readable"),
                bytes,
                "{} changed",
                path.display()
            );
        }
        return;
    }
    let a = private_home::fresh_private_dir();
    let b = private_home::fresh_private_dir();
    let mut command = gateway_bin::isolated_with_env_home(
        std::process::Command::new(std::env::current_exe().expect("the test binary")),
        a.path(),
        b.path(),
        gateway_bin::Inherit::Environment,
    );
    command
        .env("MCP_GW_T1_A", a.path())
        .env("MCP_GW_T1_B", b.path());
    let _kept = private_home::run_row_child(
        command,
        &private_home::test_path(module_path!(), ME),
        false,
        &private_home::Expect::Pass,
        vec![a, b],
    );
}

/// T6: with `XDG_CONFIG_HOME` removed, the config dir still routes to
/// the override, so a lookup that ignored the override cannot hide behind an
/// explicit XDG value.
#[cfg(not(target_os = "macos"))]
#[test]
fn t6_config_routes_to_the_override_without_xdg() {
    const ME: &str = "t6_config_routes_to_the_override_without_xdg";
    if private_home::is_row_child(ME) {
        assert!(
            std::env::var_os("XDG_CONFIG_HOME").is_none(),
            "premise: XDG_CONFIG_HOME is removed"
        );
        let a = std::path::PathBuf::from(
            std::env::var_os("MCP_GATEWAY_TEST_HOME_DIR").expect("the override"),
        );
        let config = mcp_gateway::gateway::test_helpers::config_dir().expect("a config dir");
        assert_eq!(
            private_home::canonical_leaf(&config),
            private_home::canonical(&a).join(".config")
        );
        return;
    }
    let a = private_home::fresh_private_dir();
    let b = private_home::fresh_private_dir();
    let mut command = gateway_bin::isolated_with_env_home(
        std::process::Command::new(std::env::current_exe().expect("the test binary")),
        a.path(),
        b.path(),
        gateway_bin::Inherit::Environment,
    );
    command.env_remove("XDG_CONFIG_HOME");
    let _kept = private_home::run_row_child(
        command,
        &private_home::test_path(module_path!(), ME),
        false,
        &private_home::Expect::Pass,
        vec![a, b],
    );
}
