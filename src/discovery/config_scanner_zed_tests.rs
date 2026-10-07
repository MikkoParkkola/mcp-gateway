// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1811: Zed `context_servers` entries in the shapes Zed itself writes
//! (zed-industries/zed @ 1a28cff4, `crates/settings_content/src/project.rs:517-615`),
//! and Zed's settings location (`crates/paths/src/paths.rs:133-152`).

use std::path::Path;

use serde_json::json;

use super::*;

fn parse(entry: &serde_json::Value) -> Option<DiscoveredServer> {
    ConfigScanner::parse_zed_server("srv", entry, Path::new("/zed/settings.json"))
}

#[test]
fn a_flat_stdio_entry_imports_as_stdio() {
    let entry = json!({"command": "npx", "args": ["-y", "some-server"], "env": {"K": "v"}});
    let server = parse(&entry).expect("Zed's stdio shape must import");
    assert_eq!(server.source, DiscoverySource::Zed);
    match server.transport {
        TransportConfig::Stdio { command, .. } => assert_eq!(command, "npx -y some-server"),
        other => panic!("expected stdio, got {other:?}"),
    }
}

#[test]
fn a_url_entry_imports_as_http() {
    let entry =
        json!({"url": "https://mcp.example.test/mcp", "headers": {"Authorization": "Bearer x"}});
    let server = parse(&entry).expect("Zed's HTTP shape must import");
    assert_eq!(server.source, DiscoverySource::Zed);
    match server.transport {
        TransportConfig::Http { http_url, .. } => {
            assert_eq!(http_url, "https://mcp.example.test/mcp");
        }
        other => panic!("expected HTTP, got {other:?}"),
    }
}

#[test]
fn an_extension_entry_is_not_imported() {
    let entry = json!({"source": "extension", "enabled": true, "settings": {}});
    assert!(parse(&entry).is_none());
}

#[test]
fn a_nested_command_object_is_not_a_zed_shape() {
    // Zed's settings have no `command.path` object, so it is not imported.
    let entry = json!({"command": {"path": "npx", "args": ["x"]}});
    assert!(parse(&entry).is_none());
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the oracle is the platform answer, independent of the routed lookup"
)]
fn zed_config_path_matches_zed_config_dir() {
    let path = ConfigScanner::zed_config_path().expect("home dir");
    if cfg!(target_os = "macos") {
        assert!(
            path.ends_with(".config/zed/settings.json"),
            "{}",
            path.display()
        );
    } else if cfg!(target_os = "linux") {
        assert_eq!(path, dirs::config_dir().unwrap().join("zed/settings.json"));
    } else {
        assert_eq!(path, dirs::config_dir().unwrap().join("Zed/settings.json"));
    }
}
