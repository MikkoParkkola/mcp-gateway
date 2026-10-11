// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8365: SIEM export verifies with the transparency key, so a key that
//! did not resolve (log off, key left empty) disables export rather than pass
//! a signed log's entries on hash-only.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use crate::config::Config;

const VAR: &str = "MCP_GW_8365_EXPORT_KEY";
const KEY: &str = "tlog-8365-export-key-0123456789abcdefghij";

fn write_0600(path: &Path, body: &str) {
    std::fs::write(path, body).expect("write fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// Export on, the log off, its key `env:VAR`, and an env file holding `env_body`.
fn load(dir: &Path, env_body: &str) -> (Config, std::path::PathBuf) {
    let env = dir.join("gateway.env");
    write_0600(&env, env_body);
    let path = dir.join("gateway.yaml");
    write_0600(
        &path,
        &format!(
            "env_files:\n  - \"{}\"\nsecurity:\n  transparency_log:\n    enabled: false\n    \
             path: \"{}\"\n    shared_secret: \"env:{VAR}\"\ncontrol_plane:\n  store_dir: \"{}\"\n  \
             export:\n    enabled: true\n    sink_path: \"{}\"\n",
            env.display(),
            dir.join("invocation.jsonl").display(),
            dir.join("cp").display(),
            dir.join("sink.ndjson").display(),
        ),
    );
    (
        Config::load(Some(&path)).expect("a disabled log loads"),
        path,
    )
}

fn export_starts(config: &Config, path: &Path) -> bool {
    let (tx, rx) = tokio::sync::broadcast::channel(1);
    let base = super::super::control_plane_store::control_plane_base(config, Some(path));
    let status = super::spawn_export_task(config, &base, rx);
    let _ = tx.send(());
    status.is_some()
}

#[tokio::test]
async fn siem_export_refuses_a_key_that_did_not_resolve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, path) = load(dir.path(), "MCP_GW_8365_OTHER=1\n");
    assert!(
        !export_starts(&config, &path),
        "export ran with an unresolved key"
    );
}

/// Control: the same config with the key resolvable starts export.
#[tokio::test]
async fn siem_export_starts_with_a_resolved_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, path) = load(dir.path(), &format!("{VAR}={KEY}\n"));
    assert!(export_starts(&config, &path), "export did not start");
}
