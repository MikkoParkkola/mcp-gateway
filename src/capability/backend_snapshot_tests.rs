// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Snapshot rows. Expected ids are `config_revision` over literal parts built
//! here, never a revision read back from the backend. A step that takes the
//! catalogue lock is bounded by 30s. Nothing sleeps to open a window.
//!
//! The capability publish stores nothing. Rows that read the snapshot name
//! the assertion in the message.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::CapabilityBackend;
use crate::capability::CapabilityExecutor;
use crate::config::Config;
use crate::config_reload::LiveConfig;
use crate::config_reload::revision::{
    AppliedInputs, CapabilityPart, PartDigest, RawInputs, config_revision, part_digest,
};

const YAML: &[u8] = b"server:\n  port: 1\n";
const RELOADED: &[u8] = b"server:\n  port: 2\n";

fn key() -> [u8; 32] {
    crate::gateway::record_principal::test_record_key().config_revision_key()
}

/// The id of the fixed gateway bytes with `part` and nothing else.
fn id_of(part: &CapabilityPart<PartDigest>) -> String {
    revision_of(YAML, part)
}

/// The id of `yaml` with `part` and nothing else. Built from those literals.
fn revision_of(yaml: &[u8], part: &CapabilityPart<PartDigest>) -> String {
    config_revision(
        &key(),
        &AppliedInputs {
            gateway_yaml: part_digest(&key(), yaml),
            capabilities: part.clone(),
            ..AppliedInputs::default()
        },
    )
}

fn yaml_bytes(name: &str, description: &str) -> Vec<u8> {
    format!(
        "name: {name}\ndescription: {description}\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.com\n      path: /{name}\n"
    )
    .into_bytes()
}

fn root_of(dir: &tempfile::TempDir) -> String {
    dir.path()
        .to_str()
        .expect("the temp path is utf-8")
        .to_owned()
}

fn write_at(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("the capability file writes");
}

fn keyed() -> Arc<CapabilityBackend> {
    Arc::new(
        CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()))
            .with_revision_key(key()),
    )
}

fn admitting() -> Arc<CapabilityBackend> {
    let registry = Arc::new(crate::identity_propagation::AccountStrategyRegistry::default());
    Arc::new(
        CapabilityBackend::new(
            "caps",
            Arc::new(CapabilityExecutor::new().with_account_strategies(registry)),
        )
        .with_revision_key(key()),
    )
}

async fn wait<T>(work: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(Duration::from_secs(30), work).await {
        Ok(value) => value,
        Err(_) => panic!("hung past 30s"),
    }
}

/// The snapshot, off this thread. A lock the stub does not take yet still
/// fails at 30s rather than hanging the runtime.
fn snapshot(backend: &Arc<CapabilityBackend>) -> CapabilityPart<PartDigest> {
    let backend = Arc::clone(backend);
    let (done, wait) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let part = backend.capability_snapshot();
        let _ = done.send(part);
    });
    match wait.recv_timeout(Duration::from_secs(30)) {
        Ok(part) => {
            worker.join().expect("the snapshot panicked");
            part
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past 30s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(
                worker
                    .join()
                    .expect_err("the snapshot ended without reporting"),
            );
        }
    }
}

fn loaded(path: String, bytes: &[u8]) -> CapabilityPart<PartDigest> {
    CapabilityPart::Loaded(vec![(path, part_digest(&key(), bytes))])
}

/// A step that takes the publish locks. A deadlock fails at 30s.
fn within_30s(step: impl FnOnce() + Send + 'static) {
    let (done, wait) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        step();
        let _ = done.send(());
    });
    match wait.recv_timeout(Duration::from_secs(30)) {
        Ok(()) => worker.join().expect("the step panicked"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past 30s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(worker.join().expect_err("the step ended without reporting"));
        }
    }
}

fn published_id(live: &LiveConfig) -> String {
    live.applied_now()
        .published
        .expect("a revision is published")
        .revision
        .clone()
}

/// A capability file's bytes change and a reload runs: the snapshot's id
/// equals a fresh load of the new bytes, and it is not the previous id.
#[tokio::test]
async fn p1_changed_bytes_reload_to_the_new_id() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = root_of(&dir);
    let previous = yaml_bytes("alpha", "one");
    let changed = yaml_bytes("alpha", "two");
    write_at(&dir.path().join("alpha.yaml"), &previous);
    let backend = keyed();
    wait(backend.load_from_directory(&root))
        .await
        .expect("the first load");
    write_at(&dir.path().join("alpha.yaml"), &changed);
    wait(backend.reload()).await.expect("the reload");

    let after = snapshot(&backend);
    let expected = loaded(format!("{root}/alpha.yaml"), &changed);
    let prior = loaded(format!("{root}/alpha.yaml"), &previous);
    assert_eq!(
        id_of(&after),
        id_of(&expected),
        "equals the id of a fresh load of the new bytes"
    );
    assert_ne!(id_of(&after), id_of(&prior), "the snapshot's id changes");
}

/// Identical bytes reloaded keep the id. A file added, then removed, names
/// a new id and then the original.
#[tokio::test]
async fn p2_identical_bytes_keep_the_id_and_membership_rounds_trip() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = root_of(&dir);
    let alpha = yaml_bytes("alpha", "same");
    let beta = yaml_bytes("beta", "added");
    write_at(&dir.path().join("alpha.yaml"), &alpha);
    let backend = keyed();
    wait(backend.load_from_directory(&root))
        .await
        .expect("the first load");
    wait(backend.reload()).await.expect("the identical reload");

    let reloaded = snapshot(&backend);
    let one = loaded(format!("{root}/alpha.yaml"), &alpha);
    assert_eq!(
        id_of(&reloaded),
        id_of(&one),
        "identical bytes reloaded keep the id"
    );

    write_at(&dir.path().join("beta.yaml"), &beta);
    wait(backend.reload())
        .await
        .expect("the reload that adds a file");
    let added = snapshot(&backend);
    let two = CapabilityPart::Loaded(vec![
        (format!("{root}/alpha.yaml"), part_digest(&key(), &alpha)),
        (format!("{root}/beta.yaml"), part_digest(&key(), &beta)),
    ]);
    assert_eq!(id_of(&added), id_of(&two), "a file added names a new id");

    std::fs::remove_file(dir.path().join("beta.yaml")).expect("the added file is removed");
    wait(backend.reload())
        .await
        .expect("the reload that removes a file");
    let removed = snapshot(&backend);
    assert_eq!(
        id_of(&removed),
        id_of(&one),
        "a file removed restores the original id"
    );
}

/// A gateway.yaml reload keeps the capability part and its sequence. A
/// following capability reload changes the snapshot id.
///
/// The part is not seeded through `with_applied`: `set_capabilities` is what
/// publishes it, and that stub stores nothing. The capability reload compares
/// the snapshot. Publish points, which would move the published revision, are
/// the next slice.
#[tokio::test]
async fn p3_yaml_reload_keeps_the_part_and_seq_until_a_capability_reload() {
    let part = CapabilityPart::Loaded(vec![("caps/a.yaml".to_owned(), part_digest(&key(), b"v1"))]);
    let live = Arc::new(
        LiveConfig::new(Config::default())
            .with_revision_key(key())
            .with_applied(RawInputs {
                gateway_yaml: YAML.to_vec(),
                capabilities: CapabilityPart::NotLoaded,
                ..RawInputs::default()
            }),
    );
    let generation = Arc::new(
        live.prepare(Config::default(), &crate::config::EnvOverlay::none())
            .expect("the reloaded config prepares"),
    );
    let step = Arc::clone(&live);
    let published_part = part.clone();
    within_30s(move || {
        step.set_capabilities(4, published_part);
        step.set_applied(
            generation,
            RawInputs {
                gateway_yaml: RELOADED.to_vec(),
                capabilities: CapabilityPart::NotLoaded,
                ..RawInputs::default()
            },
            &[],
        );
    });

    assert_eq!(
        published_id(&live),
        revision_of(RELOADED, &part),
        "a gateway.yaml reload keeps the capability part"
    );
    assert_eq!(
        live.capability_seq(),
        4,
        "a gateway.yaml reload keeps the capability seq"
    );

    let dir = tempfile::tempdir().expect("a temp dir");
    let root = root_of(&dir);
    let before = yaml_bytes("alpha", "before");
    let after = yaml_bytes("alpha", "after");
    write_at(&dir.path().join("alpha.yaml"), &before);
    let backend = keyed();
    wait(backend.load_from_directory(&root))
        .await
        .expect("the capability load");
    let prior = id_of(&snapshot(&backend));
    write_at(&dir.path().join("alpha.yaml"), &after);
    wait(backend.reload()).await.expect("the capability reload");
    let changed = snapshot(&backend);
    let expected = loaded(format!("{root}/alpha.yaml"), &after);
    assert_ne!(
        id_of(&changed),
        prior,
        "a following capability reload changes the id"
    );
    assert_eq!(
        id_of(&changed),
        id_of(&expected),
        "the changed id is a fresh load of the new bytes"
    );
}

/// A scan over two directories: one snapshot afterwards covers both.
#[tokio::test]
async fn s1_a_scan_of_two_directories_is_one_part() {
    let first = tempfile::tempdir().expect("a temp dir");
    let second = tempfile::tempdir().expect("a temp dir");
    let root_a = root_of(&first);
    let root_b = root_of(&second);
    let alpha = yaml_bytes("alpha", "from the first directory");
    let beta = yaml_bytes("beta", "from the second directory");
    write_at(&first.path().join("alpha.yaml"), &alpha);
    write_at(&second.path().join("beta.yaml"), &beta);
    let backend = keyed();
    wait(backend.load_from_directory(&root_a))
        .await
        .expect("the first directory loads");
    wait(backend.load_from_directory(&root_b))
        .await
        .expect("the second directory loads");
    wait(backend.detect_rug_pulls()).await;

    let part = snapshot(&backend);
    let expected = CapabilityPart::Loaded(vec![
        (format!("{root_a}/alpha.yaml"), part_digest(&key(), &alpha)),
        (format!("{root_b}/beta.yaml"), part_digest(&key(), &beta)),
    ]);
    assert_eq!(
        id_of(&part),
        id_of(&expected),
        "the snapshot after the scan is one part covering both directories"
    );
}

/// Admission refuses one file. Rug-pull detection unloads another. Neither
/// is in the part: its id equals a load of the file that stayed.
///
/// The fault named here is a snapshot taken before `detect_rug_pulls`: that
/// part would still name the pinned file. This snapshot is taken after it.
#[tokio::test]
async fn s2_refused_and_rug_pulled_capabilities_are_absent() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = root_of(&dir);
    let kept = yaml_bytes("kept", "served");
    let refused = {
        let mut bytes = yaml_bytes("refused", "not admitted");
        bytes.extend_from_slice(b"auth:\n  account: missing\n");
        bytes
    };
    let trusted_body = String::from_utf8(yaml_bytes("trusted", "stable")).expect("utf-8");
    let trusted = crate::capability::rewrite_with_pin(
        &trusted_body,
        &crate::capability::compute_capability_hash(&trusted_body),
    )
    .into_bytes();
    write_at(&dir.path().join("kept.yaml"), &kept);
    write_at(&dir.path().join("refused.yaml"), &refused);
    write_at(&dir.path().join("trusted.yaml"), &trusted);
    let backend = admitting();
    wait(backend.load_from_directory(&root))
        .await
        .expect("the directory loads");
    assert!(!backend.has_capability("refused"), "admission refused it");
    assert!(
        backend.has_capability("kept") && backend.has_capability("trusted"),
        "the other two are served"
    );

    let tampered = std::fs::read_to_string(dir.path().join("trusted.yaml"))
        .expect("the pinned file reads")
        .replace("stable", "tampered");
    write_at(&dir.path().join("trusted.yaml"), tampered.as_bytes());
    let found = wait(backend.detect_rug_pulls()).await;
    assert!(!found.is_empty(), "the pin mismatch was detected");
    assert!(
        !backend.has_capability("trusted"),
        "rug-pull detection unloaded it"
    );
    assert!(backend.has_capability("kept"), "the other file stays");

    let part = snapshot(&backend);
    let expected = loaded(format!("{root}/kept.yaml"), &kept);
    assert_eq!(
        id_of(&part),
        id_of(&expected),
        "a refused capability and a rug-pulled one are absent"
    );
}

/// Two directories hold the same capability name. A reload serves both files,
/// and both are in the part.
#[tokio::test]
async fn s3_the_same_name_in_two_directories_keeps_both_files() {
    let first = tempfile::tempdir().expect("a temp dir");
    let second = tempfile::tempdir().expect("a temp dir");
    let root_a = root_of(&first);
    let root_b = root_of(&second);
    let left = yaml_bytes("shared", "left");
    let right = yaml_bytes("shared", "right");
    write_at(&first.path().join("shared.yaml"), &left);
    write_at(&second.path().join("shared.yaml"), &right);
    let backend = keyed();
    backend.register_directories(&[root_a.clone(), root_b.clone()]);
    wait(backend.reload()).await.expect("the reload");
    assert_eq!(backend.len(), 2, "both files are served");

    let part = snapshot(&backend);
    let expected = CapabilityPart::Loaded(vec![
        (format!("{root_a}/shared.yaml"), part_digest(&key(), &left)),
        (format!("{root_b}/shared.yaml"), part_digest(&key(), &right)),
    ]);
    assert_eq!(id_of(&part), id_of(&expected), "both files are in the part");
}

/// Restores a mode of 000 so the temp directory can remove the path. Unix
/// only: the S4 rows deny access through the mode bits.
#[cfg(unix)]
struct ModeGuard(std::path::PathBuf);

#[cfg(unix)]
impl ModeGuard {
    /// Clears the mode and checks the premise: a process that can still read
    /// the path (one running as root) would make the row prove nothing.
    fn deny(path: &Path) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0))
            .expect("the mode can be cleared");
        let guard = Self(path.to_path_buf());
        let readable = if path.is_dir() {
            std::fs::read_dir(path).is_ok()
        } else {
            std::fs::read(path).is_ok()
        };
        assert!(!readable, "the premise: {} cannot be read", path.display());
        guard
    }
}

#[cfg(unix)]
impl Drop for ModeGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn s4_reload_unreadable_directory_is_partial() {
    let root = tempfile::tempdir().expect("a temp dir");
    let good = root.path().join("good");
    let bad = root.path().join("bad");
    std::fs::create_dir(&good).expect("the readable directory");
    std::fs::create_dir(&bad).expect("the unreadable directory");
    let alpha = yaml_bytes("alpha", "served");
    write_at(&good.join("alpha.yaml"), &alpha);
    let _mode = ModeGuard::deny(&bad);
    let good = good.to_str().expect("utf-8").to_owned();
    let backend = keyed();
    backend.register_directories(&[good.clone(), bad.to_str().expect("utf-8").to_owned()]);
    wait(backend.reload()).await.expect("the reload");
    let part = snapshot(&backend);
    // Partial over the files installed: the readable directory's one file.
    let expected = CapabilityPart::Partial(vec![(
        format!("{good}/alpha.yaml"),
        part_digest(&key(), &alpha),
    )]);
    assert_eq!(
        id_of(&part),
        id_of(&expected),
        "reload: an unreadable directory makes the part Partial"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn s4_reload_unreadable_file_is_partial() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let alpha = yaml_bytes("alpha", "served");
    write_at(&dir.path().join("alpha.yaml"), &alpha);
    write_at(
        &dir.path().join("secret.yaml"),
        &yaml_bytes("secret", "hidden"),
    );
    let _mode = ModeGuard::deny(&dir.path().join("secret.yaml"));
    let backend = keyed();
    let root = root_of(&dir);
    backend.register_directories(std::slice::from_ref(&root));
    wait(backend.reload()).await.expect("the reload");
    let part = snapshot(&backend);
    let expected = CapabilityPart::Partial(vec![(
        format!("{root}/alpha.yaml"),
        part_digest(&key(), &alpha),
    )]);
    assert_eq!(
        id_of(&part),
        id_of(&expected),
        "reload: an unreadable file in a readable directory makes the part Partial"
    );
}
