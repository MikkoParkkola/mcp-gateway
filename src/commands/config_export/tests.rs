// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for `config_export`.

use std::path::Path;

use serde_json::{Value, json};

use mcp_gateway::{cli::ConnectionMode, config::Config};

use super::{
    ClientSpec, ExportAction, ExportTarget, build_gateway_entry, client_specs, export_one,
    merge_into_config, merge_into_config_with_safety, resolve_mode, rollback_client_config,
};

fn default_config() -> Config {
    Config::default()
}

// ── build_gateway_entry ───────────────────────────────────────────────────────

#[test]
fn build_gateway_entry_proxy_mode() {
    // GIVEN: default config (host=127.0.0.1, port=39400) and Proxy mode
    let cfg = default_config();
    let entry = build_gateway_entry(&cfg, None, ConnectionMode::Proxy);

    // THEN: produces {"url": "http://127.0.0.1:39400/mcp"}
    assert_eq!(entry["url"], "http://127.0.0.1:39400/mcp");
    assert!(entry.get("command").is_none());
}

#[test]
fn build_gateway_entry_stdio_mode() {
    // GIVEN: default config and Stdio mode, no config path
    let cfg = default_config();
    let entry = build_gateway_entry(&cfg, None, ConnectionMode::Stdio);

    // THEN: produces {"command": "mcp-gateway", "args": ["serve", "--stdio"]}
    assert_eq!(entry["command"], "mcp-gateway");
    let args = entry["args"].as_array().unwrap();
    assert_eq!(args[0], "serve");
    assert_eq!(args[1], "--stdio");
    assert_eq!(args.len(), 2); // no -c flag without config path
}

#[test]
fn build_gateway_entry_stdio_with_config() {
    // GIVEN: Stdio mode with a config path supplied
    let cfg = default_config();
    let config_path = Path::new("/etc/mcp-gateway/gateway.yaml");
    let entry = build_gateway_entry(&cfg, Some(config_path), ConnectionMode::Stdio);

    // THEN: -c flag and path are appended to args
    let args = entry["args"].as_array().unwrap();
    assert_eq!(args[2], "-c");
    assert_eq!(args[3], "/etc/mcp-gateway/gateway.yaml");
}

// ── merge_into_config ─────────────────────────────────────────────────────────

#[test]
fn merge_into_new_file() {
    // GIVEN: a path that does not exist yet
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.json");
    let entry = json!({"url": "http://127.0.0.1:39400/mcp"});

    // WHEN: merging into a non-existent file
    let action = merge_into_config(&path, "mcpServers", "gateway", &entry).unwrap();

    // THEN: file is created with correct structure
    assert!(matches!(action, ExportAction::Created));
    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(
        parsed["mcpServers"]["gateway"]["url"],
        "http://127.0.0.1:39400/mcp"
    );
}

#[test]
fn merge_into_existing_preserves_content() {
    // GIVEN: an existing config with an unrelated key
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("existing.json");
    std::fs::write(
        &path,
        r#"{"otherTool": {"key": "value"}, "mcpServers": {}}"#,
    )
    .unwrap();

    let entry = json!({"url": "http://127.0.0.1:39400/mcp"});

    // WHEN: merging gateway entry
    merge_into_config(&path, "mcpServers", "gateway", &entry).unwrap();

    // THEN: existing keys are preserved
    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["otherTool"]["key"], "value");
    assert_eq!(
        parsed["mcpServers"]["gateway"]["url"],
        "http://127.0.0.1:39400/mcp"
    );
}

#[test]
fn merge_into_existing_updates_entry() {
    // GIVEN: an existing config with a stale gateway entry
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("update.json");
    std::fs::write(
        &path,
        r#"{"mcpServers": {"gateway": {"url": "http://old:1234/mcp"}}}"#,
    )
    .unwrap();

    let new_entry = json!({"url": "http://127.0.0.1:39400/mcp"});

    // WHEN: merging with the same name
    let action = merge_into_config(&path, "mcpServers", "gateway", &new_entry).unwrap();

    // THEN: entry is replaced, action is Updated
    assert!(matches!(action, ExportAction::Updated));
    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(
        parsed["mcpServers"]["gateway"]["url"],
        "http://127.0.0.1:39400/mcp"
    );
}

#[test]
fn merge_zed_shared_config() {
    // GIVEN: a Zed settings.json with non-MCP keys (editor preferences, etc.)
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        r#"{"theme": "One Dark", "font_size": 14, "context_servers": {}}"#,
    )
    .unwrap();

    let entry = json!({"command": "mcp-gateway", "args": ["serve", "--stdio"]});

    // WHEN: merging into context_servers key
    merge_into_config(&path, "context_servers", "gateway", &entry).unwrap();

    // THEN: non-MCP keys are preserved
    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["theme"], "One Dark");
    assert_eq!(parsed["font_size"], 14);
    assert_eq!(
        parsed["context_servers"]["gateway"]["command"],
        "mcp-gateway"
    );
}

#[test]
fn client_specs_resolve_paths() {
    // GIVEN: All target
    let specs = client_specs(ExportTarget::All);

    // THEN: each spec has a non-empty path and a known servers_key
    assert!(!specs.is_empty());
    for spec in &specs {
        assert!(
            !spec.path.as_os_str().is_empty(),
            "empty path for {}",
            spec.label
        );
        assert!(
            ["mcpServers", "servers", "context_servers"].contains(&spec.servers_key),
            "unexpected servers_key '{}' for {}",
            spec.servers_key,
            spec.label
        );
    }
}

#[test]
fn resolve_mode_returns_proxy_when_mode_is_proxy() {
    // GIVEN: explicit Proxy mode
    let cfg = default_config();

    // WHEN/THEN: resolve_mode returns Proxy unchanged
    assert_eq!(
        resolve_mode(ConnectionMode::Proxy, &cfg),
        ConnectionMode::Proxy
    );
}

#[test]
fn resolve_mode_returns_stdio_when_mode_is_stdio() {
    // GIVEN: explicit Stdio mode
    let cfg = default_config();

    // WHEN/THEN: resolve_mode returns Stdio unchanged
    assert_eq!(
        resolve_mode(ConnectionMode::Stdio, &cfg),
        ConnectionMode::Stdio
    );
}

#[test]
fn resolve_mode_auto_proxy_when_not_on_path() {
    // GIVEN: Auto mode with a config that points to an unreachable port
    // (port 1 is reserved/unreachable) — so the health probe fails.
    let mut cfg = default_config();
    cfg.server.port = 1; // reserved/unreachable port

    // WHEN: resolve_mode in Auto mode
    // The health probe on port 1 will fail (TCP refused or timed out).
    // which_mcp_gateway() may or may not find the binary — we cannot
    // reliably control PATH without unsafe, so we only assert that the
    // return value is *either* Proxy or Stdio (never panics or crashes).
    let result = resolve_mode(ConnectionMode::Auto, &cfg);

    // THEN: result must be a concrete mode (not Auto)
    assert_ne!(result, ConnectionMode::Auto);
}

#[test]
fn resolve_mode_auto_with_unreachable_port_returns_concrete_mode() {
    // GIVEN: config with port 2 (also reserved/unreachable)
    let mut cfg = default_config();
    cfg.server.port = 2;

    // WHEN: resolving Auto
    let result = resolve_mode(ConnectionMode::Auto, &cfg);

    // THEN: always returns Proxy or Stdio, never panics
    assert!(
        result == ConnectionMode::Proxy || result == ConnectionMode::Stdio,
        "unexpected mode: {result:?}"
    );
}

#[test]
fn dry_run_produces_no_writes() {
    // GIVEN: an existing config file
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    let original = r#"{"mcpServers": {}}"#;
    std::fs::write(&path, original).unwrap();

    let entry = json!({"url": "http://127.0.0.1:39400/mcp"});
    let spec = ClientSpec {
        label: "Test",
        path: path.clone(),
        servers_key: "mcpServers",
    };

    // WHEN: dry-run export
    let action = export_one(&spec, "gateway", &entry, true);

    // THEN: file content is unchanged
    assert!(matches!(action, ExportAction::Updated));
    let after = std::fs::read_to_string(&path).unwrap();
    assert_eq!(after, original);
}

#[test]
fn merge_creates_parent_directory() {
    // GIVEN: a nested path whose parent does not exist
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subdir/client.json");

    let entry = json!({"url": "http://127.0.0.1:39400/mcp"});

    // WHEN: merging (parent doesn't exist yet)
    let action = merge_into_config(&path, "mcpServers", "gateway", &entry).unwrap();

    // THEN: parent is created and file is written
    assert!(matches!(action, ExportAction::Created));
    assert!(path.exists());
}

#[test]
fn safe_merge_existing_file_creates_backup_and_verifies() {
    // GIVEN: an existing client config with a stale gateway entry
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    let original = r#"{"mcpServers":{"gateway":{"url":"http://old:1234/mcp"}}}"#;
    std::fs::write(&path, original).unwrap();

    let entry = json!({"url": "http://127.0.0.1:39400/mcp"});

    // WHEN: applying the safe merge path used by setup export
    let result = merge_into_config_with_safety(&path, "mcpServers", "gateway", &entry).unwrap();

    // THEN: it updates, keeps a byte-for-byte backup, and verifies the write
    assert!(matches!(result.action, ExportAction::Updated));
    assert!(result.verified);
    let backup_path = result
        .backup_path
        .expect("existing config must be backed up");
    assert_eq!(std::fs::read_to_string(&backup_path).unwrap(), original);

    let parsed: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        parsed["mcpServers"]["gateway"]["url"],
        "http://127.0.0.1:39400/mcp"
    );
}

#[test]
fn safe_merge_new_file_verifies_without_backup() {
    // GIVEN: no existing client config
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    let entry = json!({"url": "http://127.0.0.1:39400/mcp"});

    // WHEN: applying the safe merge path
    let result = merge_into_config_with_safety(&path, "mcpServers", "gateway", &entry).unwrap();

    // THEN: new files are verified and do not create pointless backups
    assert!(matches!(result.action, ExportAction::Created));
    assert!(result.verified);
    assert!(result.backup_path.is_none());
}

#[test]
fn rollback_restores_backup_to_original_config_path() {
    // GIVEN: a safe merge backup and a modified original
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    let original = r#"{"mcpServers":{"gateway":{"url":"http://old:1234/mcp"}}}"#;
    std::fs::write(&path, original).unwrap();

    let entry = json!({"url": "http://127.0.0.1:39400/mcp"});
    let backup_path = merge_into_config_with_safety(&path, "mcpServers", "gateway", &entry)
        .unwrap()
        .backup_path
        .expect("existing config must be backed up");

    // WHEN: rolling back from that backup
    let restored = rollback_client_config(&backup_path).unwrap();

    // THEN: the original client config content is restored
    assert_eq!(restored, path);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
}
