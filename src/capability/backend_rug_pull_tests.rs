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

/// Log text written while the guard lives, through the text layer the
/// gateway runs with.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn a_changed_name_cannot_forge_a_log_line() {
    use tracing_subscriber::layer::SubscriberExt as _;
    // Without a second dispatcher a callsite first hit by a parallel test on
    // a thread with no subscriber is cached off, and this capture misses it.
    crate::test_log_capture::keep_interest_open();

    let (_dir, backend, path, pinned) = loaded().await;
    let forged = "name: \"evil\\n2026-10-28T12:00:00Z  WARN forged line\\u001b[2K\"";
    std::fs::write(&path, pinned.replace("name: rugtest", forged)).unwrap();
    let logs = Captured::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(logs.clone()),
    );
    let guard = tracing::subscriber::set_default(subscriber);

    let detected = backend.detect_rug_pulls().await;
    drop(guard);

    assert_eq!(detected.len(), 1, "the change is detected");
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("RUG-PULL DETECTED"), "{text}");
    assert_eq!(text.lines().count(), 1, "one warning, one line: {text:?}");
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(
        text.contains("rugtest"),
        "the trusted name is logged: {text}"
    );
}

/// A changed file that declares another capability's pin is still only
/// itself: the declared pin is the changed bytes' claim, not a trust anchor.
#[tokio::test]
async fn a_change_declaring_another_files_pin_never_acts_on_that_capability() {
    let (dir, backend, path, pinned) = loaded().await;
    let other_body = BODY.replace("name: rugtest", "name: bystander");
    let other_pin = compute_capability_hash(&other_body);
    std::fs::write(
        dir.path().join("bystander.yaml"),
        rewrite_with_pin(&other_body, &other_pin),
    )
    .unwrap();
    backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    assert!(backend.has_capability("bystander"));

    let own_pin = compute_capability_hash(BODY);
    let forged = pinned
        .replace(&own_pin, &other_pin)
        .replace("Initially legit", "Changed");
    std::fs::write(&path, forged).unwrap();

    let detected = backend.detect_rug_pulls().await;

    assert_eq!(detected.len(), 1, "{detected:?}");
    assert_ne!(detected[0].loaded_as.as_deref(), Some("bystander"));
    assert!(
        backend.has_capability("bystander"),
        "another file's capability stays loaded"
    );
    assert_eq!(detected[0].loaded_as.as_deref(), Some("rugtest"));
}

/// A file never loaded that names a loaded capability unloads nothing: its
/// declared name is the changed bytes' claim.
#[tokio::test]
async fn a_never_loaded_file_cannot_unload_the_capability_it_names() {
    let (dir, backend, _path, _pinned) = loaded().await;
    let stranger = rewrite_with_pin(BODY, &compute_capability_hash(BODY))
        .replace("Initially legit", "Not what was pinned");
    std::fs::write(dir.path().join("stranger.yaml"), stranger).unwrap();

    let detected = backend.detect_rug_pulls().await;

    let stranger_record = detected
        .iter()
        .find(|record| record.file.ends_with("stranger.yaml"))
        .expect("the stranger's mismatch is recorded");
    assert_eq!(stranger_record.loaded_as, None);
    assert!(
        backend.has_capability("rugtest"),
        "the capability the stranger names stays loaded"
    );
}

/// An admin re-pinning the changed bytes resolves the change, though the
/// pin recorded at detection was the old one.
#[cfg(feature = "webui")]
#[tokio::test]
async fn a_re_pinned_change_clears_its_record() {
    let (_dir, backend, path, _pinned) = loaded().await;
    let changed = BODY.replace("Initially legit", "Changed and reviewed");
    std::fs::write(
        &path,
        rewrite_with_pin(&changed, &compute_capability_hash(BODY)),
    )
    .unwrap();
    assert_eq!(backend.detect_rug_pulls().await.len(), 1);

    std::fs::write(
        &path,
        rewrite_with_pin(&changed, &compute_capability_hash(&changed)),
    )
    .unwrap();
    let mismatches = backend.current_mismatches();

    assert!(mismatches.changes.is_empty(), "{:?}", mismatches.changes);
    assert!(!mismatches.incomplete);
    assert!(
        backend.rug_pull_records().is_empty(),
        "the record is cleared"
    );
}

/// A changed file that cannot be read is not resolved: its record stays and
/// the reconcile says it is incomplete.
#[cfg(all(unix, feature = "webui"))]
#[tokio::test]
async fn an_unreadable_change_keeps_its_record() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_dir, backend, path, pinned) = loaded().await;
    std::fs::write(&path, pinned.replace("Initially legit", "Changed")).unwrap();
    assert_eq!(backend.detect_rug_pulls().await.len(), 1);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mismatches = backend.current_mismatches();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert!(mismatches.incomplete);
    assert_eq!(backend.rug_pull_records().len(), 1, "the record stays");
}

/// A file never admitted that holds the same name as an admitted one gets no
/// trusted name: trust follows the admitted file, not the name.
#[tokio::test]
async fn a_never_admitted_file_sharing_a_name_is_not_trusted() {
    let (dir, backend, _path, pinned) = loaded().await;
    let twin = dir.path().join("twin.yaml");
    std::fs::write(&twin, pinned.replace("Initially legit", "Changed")).unwrap();

    let detected = backend.detect_rug_pulls().await;

    let record = detected
        .iter()
        .find(|record| record.file.ends_with("twin.yaml"))
        .expect("the twin's mismatch is recorded");
    assert_eq!(
        record.loaded_as, None,
        "the admitted file's name is not the twin's"
    );
    assert!(backend.has_capability("rugtest"));
}

/// A refused file's earlier record keeps its name for display only: once
/// another file is admitted under that name, a further change to the refused
/// file leaves the newcomer loaded.
#[tokio::test]
async fn a_refused_files_old_name_never_unloads_its_successor() {
    let (dir, backend, path, pinned) = loaded().await;
    std::fs::write(&path, pinned.replace("Initially legit", "Changed")).unwrap();
    assert_eq!(backend.detect_rug_pulls().await.len(), 1);
    let successor = BODY.replace("Initially legit", "The successor");
    std::fs::write(
        dir.path().join("successor.yaml"),
        rewrite_with_pin(&successor, &compute_capability_hash(&successor)),
    )
    .unwrap();
    backend.reload().await.unwrap();
    assert!(
        backend.has_capability("rugtest"),
        "the successor is admitted"
    );

    std::fs::write(&path, pinned.replace("Initially legit", "Changed again")).unwrap();
    let detected = backend.detect_rug_pulls().await;

    assert_eq!(detected.len(), 1, "{detected:?}");
    assert_eq!(detected[0].loaded_as.as_deref(), Some("rugtest"));
    assert!(
        backend.has_capability("rugtest"),
        "the successor stays loaded"
    );
}

/// Garbled bytes, or a pin that is not a string, resolve nothing: the record
/// stays and the reconcile is incomplete.
#[cfg(feature = "webui")]
#[tokio::test]
async fn garbled_bytes_keep_the_record() {
    for garbled in ["name: [unclosed\n", "name: rugtest\nsha256: [1, 2]\n"] {
        let (_dir, backend, path, pinned) = loaded().await;
        std::fs::write(&path, pinned.replace("Initially legit", "Changed")).unwrap();
        assert_eq!(backend.detect_rug_pulls().await.len(), 1);
        std::fs::write(&path, garbled).unwrap();

        let mismatches = backend.current_mismatches();

        assert!(mismatches.incomplete, "{garbled:?}");
        assert_eq!(backend.rug_pull_records().len(), 1, "{garbled:?}");
    }
}

/// A pin key spelled with a tag reads as no key, but names a pin: the
/// record stays.
#[cfg(feature = "webui")]
#[tokio::test]
async fn a_tagged_pin_key_keeps_the_record() {
    let (_dir, backend, path, pinned) = loaded().await;
    std::fs::write(&path, pinned.replace("Initially legit", "Changed")).unwrap();
    assert_eq!(backend.detect_rug_pulls().await.len(), 1);
    std::fs::write(
        &path,
        BODY.replace("name: rugtest", "name: rugtest\n!tag sha256: [1, 2]"),
    )
    .unwrap();

    let mismatches = backend.current_mismatches();

    assert!(mismatches.incomplete);
    assert_eq!(backend.rug_pull_records().len(), 1);
}
