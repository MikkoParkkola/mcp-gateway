// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S4 on the two startup paths. An unreadable directory, and separately one
//! unreadable file in a readable directory, make the capability part Partial.
//!
//! The HTTP scan runs in the background: this waits until it reports
//! complete, yielding, and gives up at 30s. Nothing sleeps.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::Gateway;
use super::warmstart::{WarmStartMode, WarmerGuard};
use crate::capability::{CapabilityBackend, CapabilityWatcher};
use crate::config::Config;
use crate::config_reload::LiveConfig;
use crate::config_reload::refusals::ReloadReporting;
use crate::config_reload::revision::{
    AppliedInputs, CapabilityPart, PartDigest, config_revision, part_digest,
};
use crate::gateway::webhooks::WebhookRegistry;

fn yaml_bytes(name: &str) -> String {
    format!(
        "name: {name}\ndescription: served\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.com\n      path: /{name}\n"
    )
}

fn write_good(dir: &Path, name: &str) {
    std::fs::write(dir.join(format!("{name}.yaml")), yaml_bytes(name))
        .expect("the capability file writes");
}

/// Restores a mode of 000 so the temp directory can remove the path.
struct ModeGuard(PathBuf);

impl ModeGuard {
    /// Clears the mode and checks the premise: a process that can still read
    /// the path (one running as root) would make the row prove nothing.
    fn deny(path: &Path) -> Self {
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

/// The id of `part` alone, under `key`. Built from literals in each row.
fn id_of(key: &[u8; 32], part: &CapabilityPart<PartDigest>) -> String {
    config_revision(
        key,
        &AppliedInputs {
            capabilities: part.clone(),
            ..AppliedInputs::default()
        },
    )
}

/// Partial over the one file installed: `alpha` in `dir`, as configured.
fn alpha_only(key: &[u8; 32], dir: &str) -> CapabilityPart<PartDigest> {
    CapabilityPart::Partial(vec![(
        format!("{dir}/alpha.yaml"),
        part_digest(key, yaml_bytes("alpha").as_bytes()),
    )])
}

impl Drop for ModeGuard {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

struct HttpScan {
    backend: Arc<CapabilityBackend>,
    key: [u8; 32],
    // Held: dropping the sender closes the scan's shutdown subscription.
    _shutdown: tokio::sync::broadcast::Sender<()>,
    _watcher: Option<CapabilityWatcher>,
}

async fn http_scan(dirs: &[PathBuf]) -> HttpScan {
    let mut config = Config::default();
    config.capabilities.enabled = true;
    config.capabilities.directories = dirs.iter().map(|dir| dir.display().to_string()).collect();
    let gateway = Gateway::new(config).await.expect("the gateway builds");
    let meta = gateway
        .build_meta_mcp()
        .await
        .expect("the meta-mcp builds")
        .meta_mcp;
    let webhooks = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        gateway.config.webhooks.clone(),
    )));
    let (shutdown, _) = tokio::sync::broadcast::channel(4);
    let watcher = gateway
        .start_capability_watcher(&meta, &webhooks, &shutdown)
        .await
        .expect("the capability step starts");
    let backend = meta.get_capabilities().expect("the catalogue is installed");
    // As run does after this step, once LiveConfig is built and before the bind.
    backend.attach_revision(Arc::new(LiveConfig::new(gateway.config.clone())));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !backend.initial_scan_complete() {
        if tokio::time::Instant::now() >= deadline {
            panic!("hung past 30s");
        }
        tokio::task::yield_now().await;
    }
    HttpScan {
        backend,
        key: meta.record_key().config_revision_key(),
        _shutdown: shutdown,
        _watcher: watcher,
    }
}

async fn stdio_catalogue(dirs: &[String]) -> (Arc<CapabilityBackend>, [u8; 32]) {
    let mut config = Config::default();
    config.capabilities.enabled = true;
    config.capabilities.directories = dirs.to_vec();
    let gateway = Gateway::new(config).await.expect("the gateway builds");
    let meta = gateway
        .build_meta_mcp()
        .await
        .expect("the meta-mcp builds")
        .meta_mcp;
    let warmer = WarmerGuard::new(&gateway.backends, WarmStartMode::Stdio, None);
    let live = Arc::new(LiveConfig::new(gateway.config.clone()));
    match tokio::time::timeout(
        Duration::from_secs(30),
        gateway.install_stdio_startup_catalogue(
            &meta,
            &live,
            None,
            &warmer,
            ReloadReporting::default(),
        ),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("stdio startup refused: {error}"),
        Err(_) => panic!("hung past 30s"),
    }
    let backend = meta.get_capabilities().expect("the catalogue is installed");
    (backend, meta.record_key().config_revision_key())
}

fn display(path: &Path) -> String {
    path.to_str().expect("the temp path is utf-8").to_owned()
}

/// Off the runtime thread: a catalogue lock the stub does not take yet still
/// fails at 30s instead of stalling the workers the scan is running on.
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
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => std::panic::resume_unwind(
            worker
                .join()
                .expect_err("the snapshot ended without reporting"),
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s4_http_scan_unreadable_directory_is_partial() {
    let root = tempfile::tempdir().expect("a temp dir");
    let good = root.path().join("good");
    let bad = root.path().join("bad");
    std::fs::create_dir(&good).expect("the readable directory");
    std::fs::create_dir(&bad).expect("the unreadable directory");
    write_good(&good, "alpha");
    let _mode = ModeGuard::deny(&bad);
    let configured = display(&good);
    let scan = http_scan(&[good, bad]).await;
    let part = snapshot(&scan.backend);
    assert_eq!(
        id_of(&scan.key, &part),
        id_of(&scan.key, &alpha_only(&scan.key, &configured)),
        "HTTP scan: an unreadable directory makes the part Partial"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s4_http_scan_unreadable_file_is_partial() {
    let dir = tempfile::tempdir().expect("a temp dir");
    write_good(dir.path(), "alpha");
    write_good(dir.path(), "secret");
    let _mode = ModeGuard::deny(&dir.path().join("secret.yaml"));
    let scan = http_scan(&[dir.path().to_path_buf()]).await;
    let part = snapshot(&scan.backend);
    assert_eq!(
        id_of(&scan.key, &part),
        id_of(&scan.key, &alpha_only(&scan.key, &display(dir.path()))),
        "HTTP scan: an unreadable file in a readable directory makes the part Partial"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn s4_stdio_startup_unreadable_directory_is_partial() {
    let root = tempfile::tempdir().expect("a temp dir");
    let good = root.path().join("good");
    let bad = root.path().join("bad");
    std::fs::create_dir(&good).expect("the readable directory");
    std::fs::create_dir(&bad).expect("the unreadable directory");
    write_good(&good, "alpha");
    let _mode = ModeGuard::deny(&bad);
    let (backend, key) = stdio_catalogue(&[display(&good), display(&bad)]).await;
    let part = snapshot(&backend);
    assert_eq!(
        id_of(&key, &part),
        id_of(&key, &alpha_only(&key, &display(&good))),
        "stdio startup: an unreadable directory makes the part Partial"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn s4_stdio_startup_unreadable_file_is_partial() {
    let dir = tempfile::tempdir().expect("a temp dir");
    write_good(dir.path(), "alpha");
    write_good(dir.path(), "secret");
    let _mode = ModeGuard::deny(&dir.path().join("secret.yaml"));
    let (backend, key) = stdio_catalogue(&[display(dir.path())]).await;
    let part = snapshot(&backend);
    assert_eq!(
        id_of(&key, &part),
        id_of(&key, &alpha_only(&key, &display(dir.path()))),
        "stdio startup: an unreadable file in a readable directory makes the part Partial"
    );
}
