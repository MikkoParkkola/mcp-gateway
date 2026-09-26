// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F18 I4: a control-plane collection other users can change is refused, and a
//! missing one is still an empty collection.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;

use mcp_gateway::control_plane::{ControlPlaneStore, FileControlPlaneStore, StoreError};
use mcp_gateway::security::{TransparencyLogConfig, TransparencyLogger};

fn store(dir: &Path) -> FileControlPlaneStore {
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir.join("audit.jsonl").to_string_lossy().to_string(),
        key_id: "gov".to_string(),
        shared_secret: "governance-secret-at-least-32-bytes-long!".to_string(),
        ..TransparencyLogConfig::default()
    });
    let audit = Arc::new(TransparencyLogger::open(cfg).expect("open governance log"));
    FileControlPlaneStore::open(dir.join("store"), audit).expect("open store")
}

#[test]
fn control_plane_world_writable_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path());
    let grants = dir.path().join("store").join("grants.json");
    std::fs::write(&grants, r#"{"schema_version":1,"generation":0,"items":[]}"#).unwrap();
    std::fs::set_permissions(&grants, std::fs::Permissions::from_mode(0o666)).unwrap();
    match store.list_grants() {
        Err(StoreError::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
            assert!(e.to_string().contains("control-plane file"), "{e}");
        }
        other => panic!("a world-writable collection must be refused: {other:?}"),
    }
}

#[test]
fn control_plane_missing_file_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    assert!(store(dir.path()).list_policies().unwrap().is_empty());
}

#[test]
fn control_plane_readable_collection_loads() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path());
    let grants = dir.path().join("store").join("grants.json");
    std::fs::write(&grants, r#"{"schema_version":1,"generation":0,"items":[]}"#).unwrap();
    std::fs::set_permissions(&grants, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        store
            .list_grants()
            .expect("a 0644 collection loads")
            .is_empty()
    );
}
