// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A pin-mismatch record names the capability its file was trusted as, and
//! is cleared only while it still describes what is on disk.

use std::sync::Arc;

use tempfile::TempDir;

use crate::capability::hash::{compute_capability_hash, rewrite_with_pin};
use crate::capability::{CapabilityBackend, CapabilityExecutor};

const BODY: &str = r"
name: rugtest
description: Initially legit
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1
";

/// A backend that has loaded one pinned file, and that file's path and text.
async fn loaded() -> (TempDir, CapabilityBackend, std::path::PathBuf, String) {
    let dir = TempDir::new().unwrap();
    let pinned = rewrite_with_pin(BODY, &compute_capability_hash(BODY));
    let path = dir.path().join("rugtest.yaml");
    std::fs::write(&path, &pinned).unwrap();
    let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
    backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    assert!(backend.has_capability("rugtest"));
    (dir, backend, path, pinned)
}

#[tokio::test]
async fn a_renamed_change_is_recorded_and_unloaded_under_the_trusted_name() {
    let (_dir, backend, path, pinned) = loaded().await;
    std::fs::write(&path, pinned.replace("name: rugtest", "name: evil")).unwrap();

    let detected = backend.detect_rug_pulls().await;

    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].loaded_as.as_deref(), Some("rugtest"));
    assert!(
        !backend.has_capability("rugtest"),
        "the loaded version must go, whatever name the changed bytes claim"
    );
}

#[tokio::test]
async fn a_file_never_loaded_records_no_trusted_name() {
    let dir = TempDir::new().unwrap();
    let pinned = rewrite_with_pin(BODY, &compute_capability_hash(BODY));
    let path = dir.path().join("rugtest.yaml");
    std::fs::write(&path, pinned.replace("Initially legit", "Changed")).unwrap();
    let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
    backend.register_directories(&[dir.path().to_str().unwrap().to_string()]);

    let detected = backend.detect_rug_pulls().await;

    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].loaded_as, None);
}

#[tokio::test]
async fn a_record_is_cleared_only_while_its_hash_is_current() {
    let (_dir, backend, path, pinned) = loaded().await;
    std::fs::write(&path, pinned.replace("Initially legit", "First change")).unwrap();
    let first = backend.detect_rug_pulls().await.remove(0);
    std::fs::write(&path, pinned.replace("Initially legit", "Second change")).unwrap();
    let second = backend.detect_rug_pulls().await.remove(0);
    assert_ne!(first.actual, second.actual);
    let file = path.display().to_string();

    assert!(
        !backend.clear_rug_pull_if(&file, &first.actual),
        "a stale reconcile must not drop the newer mismatch"
    );
    assert_eq!(backend.rug_pull_records().len(), 1);
    assert!(backend.clear_rug_pull_if(&file, &second.actual));
    assert!(backend.rug_pull_records().is_empty());
}
