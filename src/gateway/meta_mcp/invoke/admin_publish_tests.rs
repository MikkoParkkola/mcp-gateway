// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! P4, L2, and a reload with no directories. Expected ids are
//! `config_revision` over a literal part built here.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::backend::BackendRegistry;
use crate::capability::op_gate::{self, Gate, Step};
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config_reload::revision::{
    AppliedInputs, CapabilityPart, PartDigest, config_revision, part_digest,
};
use crate::gateway::meta_mcp::MetaMcp;

fn key() -> [u8; 32] {
    crate::gateway::record_principal::test_record_key().config_revision_key()
}

/// The id of `part` alone. Built from that literal, not from a snapshot.
fn id_of(part: &CapabilityPart<PartDigest>) -> String {
    config_revision(
        &key(),
        &AppliedInputs {
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

fn loaded(path: &str, bytes: &[u8]) -> CapabilityPart<PartDigest> {
    CapabilityPart::Loaded(vec![(path.to_string(), part_digest(&key(), bytes))])
}

fn part_ids(delivered: &[(u64, CapabilityPart<PartDigest>)]) -> Vec<String> {
    delivered.iter().map(|(_, part)| id_of(part)).collect()
}

async fn within_30s<T>(work: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(Duration::from_secs(30), work).await {
        Ok(value) => value,
        Err(elapsed) => panic!("hung past 30s: {elapsed}"),
    }
}

fn backend_in(root: &str) -> (Arc<CapabilityBackend>, Arc<MetaMcp>) {
    let backend = Arc::new(
        CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()))
            .with_revision_key(key()),
    );
    let paths = [root.to_string()];
    backend.register_directories(&paths);
    let meta = Arc::new(MetaMcp::new(Arc::new(BackendRegistry::new())));
    meta.set_capabilities(Arc::clone(&backend));
    (backend, meta)
}

/// The admin tool reload and the watcher reload each deliver one part after
/// the swap, equal to a fresh load of the new bytes.
#[tokio::test]
async fn p4_admin_and_watcher_reload_deliver_after_the_swap() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = root_of(&dir);
    let path = format!("{root}/alpha.yaml");
    let original = yaml_bytes("alpha", "one");
    let admin_bytes = yaml_bytes("alpha", "admin");
    let watcher_bytes = yaml_bytes("alpha", "watcher");
    write_at(&dir.path().join("alpha.yaml"), &original);
    let (backend, meta) = backend_in(&root);
    within_30s(backend.load_from_directory(&root))
        .await
        .expect("the first load");

    write_at(&dir.path().join("alpha.yaml"), &admin_bytes);
    within_30s(meta.reload_capabilities())
        .await
        .expect("the admin reload");
    let admin_ids = part_ids(&backend.delivered_revisions());

    // The watcher's reload is this sequence. Its publish is the one inside
    // `reload`, not a second call at the spawn.
    write_at(&dir.path().join("alpha.yaml"), &watcher_bytes);
    within_30s(backend.detect_rug_pulls()).await;
    within_30s(backend.reload())
        .await
        .expect("the watcher reload");
    let all = part_ids(&backend.delivered_revisions());
    let watcher_ids = all[admin_ids.len()..].to_vec();

    assert_eq!(
        admin_ids,
        vec![id_of(&loaded(&path, &admin_bytes))],
        "admin reload publishes after the swap, of a fresh load of the new bytes; publish moved before replace_all"
    );
    assert_eq!(
        watcher_ids,
        vec![id_of(&loaded(&path, &watcher_bytes))],
        "watcher reload publishes after the swap, of a fresh load of the new bytes; publish moved before replace_all"
    );
}

fn wait_arrived(arrived: &std::sync::mpsc::Receiver<()>) {
    match arrived.recv_timeout(Duration::from_secs(30)) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past 30s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the step ended before it arrived");
        }
    }
}

fn let_go(slot: &mut Option<std::sync::mpsc::SyncSender<()>>) {
    if let Some(tx) = slot.take() {
        let _ = tx.send(());
    }
}

/// Sends any release the row has not sent yet, so a failing assertion does
/// not then sit until a held step panics.
struct Releases {
    watcher_load: Option<std::sync::mpsc::SyncSender<()>>,
    watcher_swap: Option<std::sync::mpsc::SyncSender<()>>,
    watcher_publish: Option<std::sync::mpsc::SyncSender<()>>,
    admin_acquire: Option<std::sync::mpsc::SyncSender<()>>,
    admin_load: Option<std::sync::mpsc::SyncSender<()>>,
    admin_swap: Option<std::sync::mpsc::SyncSender<()>>,
    admin_publish: Option<std::sync::mpsc::SyncSender<()>>,
}

impl Drop for Releases {
    fn drop(&mut self) {
        let_go(&mut self.watcher_load);
        let_go(&mut self.watcher_swap);
        let_go(&mut self.watcher_publish);
        let_go(&mut self.admin_acquire);
        let_go(&mut self.admin_load);
        let_go(&mut self.admin_swap);
        let_go(&mut self.admin_publish);
    }
}

fn spawn_gated(
    gates: Vec<Gate>,
    run: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // The reload polls on this thread, so the gate it reaches is this one.
        op_gate::arm(gates);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        runtime.block_on(run);
    })
}

/// A watcher reload and an admin reload, each held at its load, at the swap,
/// and between the unlock and the publish. The admin reload is also held at
/// Acquire, before it takes the operation lock, while the watcher still holds
/// that lock. The second waits for the first, the admin's load is after the
/// watcher's publish, and the last delivery names the catalogue installed last.
#[test]
fn l2_watcher_and_admin_reloads_are_ordered() {
    // The arrival log is process-wide. This row is the one that reads it.
    op_gate::clear_arrivals();
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = root_of(&dir);
    let path = format!("{root}/alpha.yaml");
    let watcher_bytes = yaml_bytes("alpha", "watcher");
    let admin_bytes = yaml_bytes("alpha", "admin");
    let (backend, meta) = backend_in(&root);

    // The watcher does not arm Acquire: that reach is not a held step, and
    // an ungated reach is not recorded. The admin's Acquire is the proof
    // that its path still takes the lock.
    let (watcher_load, watcher_load_arrived, watcher_load_release) = Gate::open(Step::Load);
    let (watcher_swap, watcher_swap_arrived, watcher_swap_release) = Gate::open(Step::Swap);
    let (watcher_publish, watcher_publish_arrived, watcher_publish_release) =
        Gate::open(Step::BeforePublish);
    let (admin_acquire, admin_acquire_arrived, admin_acquire_release) = Gate::open(Step::Acquire);
    let (admin_load, admin_load_arrived, admin_load_release) = Gate::open(Step::Load);
    let (admin_swap, admin_swap_arrived, admin_swap_release) = Gate::open(Step::Swap);
    let (admin_publish, admin_publish_arrived, admin_publish_release) =
        Gate::open(Step::BeforePublish);

    let watcher = {
        let backend = Arc::clone(&backend);
        spawn_gated(
            vec![watcher_load, watcher_swap, watcher_publish],
            async move {
                backend.detect_rug_pulls().await;
                backend.reload().await.expect("the watcher reload");
            },
        )
    };
    let admin = {
        let meta = Arc::clone(&meta);
        spawn_gated(
            vec![admin_acquire, admin_load, admin_swap, admin_publish],
            async move {
                meta.reload_capabilities().await.expect("the admin reload");
            },
        )
    };

    let mut releases = Releases {
        watcher_load: Some(watcher_load_release),
        watcher_swap: Some(watcher_swap_release),
        watcher_publish: Some(watcher_publish_release),
        admin_acquire: Some(admin_acquire_release),
        admin_load: Some(admin_load_release),
        admin_swap: Some(admin_swap_release),
        admin_publish: Some(admin_publish_release),
    };

    // The watcher is inside its load, so it already holds the operation lock.
    // Acquire is before that lock: releasing the admin here lets it try the
    // lock while the watcher still holds it and is still parked at its load.
    // Skipping the lock lets the admin reach its load before this release.
    wait_arrived(&watcher_load_arrived);
    let second_waited = backend.operation_lock_held();
    wait_arrived(&admin_acquire_arrived);
    let_go(&mut releases.admin_acquire);
    write_at(&dir.path().join("alpha.yaml"), &watcher_bytes);
    let_go(&mut releases.watcher_load);

    wait_arrived(&watcher_swap_arrived);
    let_go(&mut releases.watcher_swap);
    wait_arrived(&watcher_publish_arrived);
    let_go(&mut releases.watcher_publish);

    // The watcher's catalogue lock is gone, and so is its operation lock
    // once `reload` returns. Only then can the admin reload reach its load.
    wait_arrived(&admin_load_arrived);
    write_at(&dir.path().join("alpha.yaml"), &admin_bytes);
    let_go(&mut releases.admin_load);
    wait_arrived(&admin_swap_arrived);
    let_go(&mut releases.admin_swap);
    wait_arrived(&admin_publish_arrived);
    let_go(&mut releases.admin_publish);

    watcher.join().expect("the watcher reload panicked");
    admin.join().expect("the admin reload panicked");
    drop(releases);

    assert!(
        second_waited,
        "the second waits for the first: the operation lock dropped, or the snapshot/seq taken outside the catalogue write lock"
    );
    let last = backend
        .delivered_revisions()
        .last()
        .map(|(_, part)| id_of(part));
    let installed_last = id_of(&loaded(&path, &admin_bytes));
    assert_eq!(
        last.as_deref(),
        Some(installed_last.as_str()),
        "the last delivery names the catalogue installed last"
    );
    // First Load and first BeforePublish are the watcher's: its load is
    // released, and its publish is reached, before the admin can pass the
    // lock. The admin's load is the second Load. A path that skips the lock
    // reaches that load before any BeforePublish.
    let arrivals = op_gate::arrivals();
    let first_before = arrivals
        .iter()
        .position(|step| *step == Step::BeforePublish)
        .expect("the watcher reached BeforePublish");
    let second_load = arrivals
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == Step::Load)
        .nth(1)
        .map(|(index, _)| index)
        .expect("the admin reached Load");
    assert!(
        second_load > first_before,
        "the admin load comes after the watcher publish: the admin path skipped the operation lock"
    );
}

/// A reload with no configured directories installs an empty catalogue and a
/// fresh empty coverage set. A partial left by an earlier operation does not
/// survive it.
#[tokio::test]
async fn reload_with_no_directories_replaces_a_stale_partial_with_an_empty_loaded_part() {
    let backend = Arc::new(
        CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()))
            .with_revision_key(key()),
    );
    backend.begin_incremental_coverage();
    backend.note_unreadable("missing");
    let stale = backend.capability_snapshot();
    assert!(
        matches!(stale, CapabilityPart::Partial(entries) if entries.is_empty()),
        "an earlier operation left an empty partial catalogue"
    );

    within_30s(backend.reload())
        .await
        .expect("the reload with no directories");

    let installed = backend.capability_snapshot();
    assert!(
        matches!(installed, CapabilityPart::Loaded(entries) if entries.is_empty()),
        "a reload with no directories stores an empty loaded part; a stale partial survived it"
    );
}
