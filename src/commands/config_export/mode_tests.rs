// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F18 W4: a client config `config export` rewrites holds other servers'
//! secrets, so it is written 0600, and the tightening is announced once.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use serde_json::json;

use super::{
    merge_into_config, merge_into_config_with_safety, rollback_client_config, tightening_notice,
};

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn write_mode(path: &Path, body: &str, mode: u32) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn config_export_merge_writes_0600() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    write_mode(
        &path,
        r#"{"mcpServers":{"other":{"env":{"T":"s"}}}}"#,
        0o644,
    );
    merge_into_config(
        &path,
        "mcpServers",
        "gateway",
        &json!({"url": "http://x/mcp"}),
    )
    .unwrap();
    assert_eq!(mode(&path), 0o600);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("other") && text.contains("gateway"), "{text}");
}

#[test]
fn config_export_rollback_writes_0600() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    write_mode(&path, r#"{"mcpServers":{}}"#, 0o644);
    let backup =
        merge_into_config_with_safety(&path, "mcpServers", "gateway", &json!({"url": "u"}))
            .unwrap()
            .backup_path
            .expect("backup");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    rollback_client_config(&backup).unwrap();
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn config_export_rollback_refuses_non_utf8_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    write_mode(&path, r#"{"mcpServers":{}}"#, 0o600);
    let backup =
        merge_into_config_with_safety(&path, "mcpServers", "gateway", &json!({"url": "u"}))
            .unwrap()
            .backup_path
            .expect("backup");
    std::fs::write(&backup, [0xff, 0xfe]).unwrap();
    let before = std::fs::read(&path).unwrap();
    let err = rollback_client_config(&backup).expect_err("a non-UTF-8 backup is refused");
    assert!(err.contains("UTF-8"), "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing restored");
}

#[test]
fn config_export_tightening_prints_notice() {
    let path = Path::new("/home/u/.config/client.json");
    let line = tightening_notice(path, Some(0o644)).expect("a 0644 file is tightened");
    assert!(
        line.contains("/home/u/.config/client.json") && line.contains("0644"),
        "{line}"
    );
    assert_eq!(tightening_notice(path, Some(0o600)), None, "already 0600");
    assert_eq!(tightening_notice(path, None), None, "did not exist");
}
