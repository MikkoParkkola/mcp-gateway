// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grant-change records through the reload paths (MIK-7570.AUDIT.4, cells
//! T2c, T2d, T2e, T6, T6b, T10a). Auditor harness in `grant_audit_tests.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::grant_audit::{GrantAuditFault, GrantAuditor, STATE_FILE};
use super::grant_audit_tests::{FlakyStore, add, row, upsert};
use super::{ConfigWatcher, IdentityGrantSink, LiveConfig, ReloadContext, ReloadTrigger};
use crate::backend::BackendRegistry;
use crate::config::{Config, EnvOverlay, LiveEnv, ResolvedEnvFiles};
use crate::control_plane::GrantChangeVerb as V;
use crate::identity_grants::LocalIdentityGrantStore;
use crate::identity_grants::journal::{GrantChange, Hooks, apply_change, apply_change_with};

struct Reload {
    _dir: tempfile::TempDir,
    grants: std::path::PathBuf,
    state_dir: std::path::PathBuf,
    store: Arc<FlakyStore>,
    live: Arc<parking_lot::RwLock<LocalIdentityGrantStore>>,
    epoch: Arc<AtomicU64>,
    sink: Arc<IdentityGrantSink>,
    auditor: Arc<GrantAuditor>,
}

impl Reload {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let grants = dir.path().join("grants.yaml");
        let state_dir = dir.path().join("store");
        std::fs::create_dir_all(&state_dir).unwrap();
        let store = Arc::new(FlakyStore::default());
        let live = Arc::new(parking_lot::RwLock::new(LocalIdentityGrantStore::default()));
        let epoch = Arc::new(AtomicU64::new(0));
        let auditor = Arc::new(GrantAuditor::new(store.clone(), &state_dir, &grants));
        let sink = Arc::new(
            IdentityGrantSink::new(live.clone(), epoch.clone(), grants.clone())
                .with_auditor(auditor.clone()),
        );
        Self {
            _dir: dir,
            grants,
            state_dir,
            store,
            live,
            epoch,
            sink,
            auditor,
        }
    }

    fn ctx(&self) -> ReloadContext {
        ReloadContext::new(
            self.grants.clone(),
            Arc::new(LiveConfig::new(Config::default())),
            Arc::new(BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(300),
        )
        .expect("the registry pairs with the config")
        .with_identity_grant_sink(self.sink.clone())
    }

    async fn reload(&self) -> Result<String, String> {
        self.ctx()
            .reload_identity_grants()
            .await
            .expect("a sink is wired")
    }

    async fn cli(&self, change: GrantChange) {
        apply_change(&self.grants, true, change).await.unwrap();
    }

    fn verbs(&self) -> Vec<(V, String)> {
        self.store
            .events()
            .into_iter()
            .map(|e| {
                assert_eq!(e.actor_id, "unknown", "{e:?}");
                (e.grant_change.expect("grant record").verb, e.target_id)
            })
            .collect()
    }

    fn live_ids(&self) -> Vec<String> {
        self.live
            .read()
            .values()
            .map(|g| g.grant_id.clone())
            .collect()
    }
}

/// T2d: an identical-content `--replace` leaves the rows unchanged, and the
/// reload still records it.
#[tokio::test]
async fn t2d_identical_replace_is_recorded() {
    let r = Reload::new();
    r.cli(add(row("g1", "r"))).await;
    r.reload().await.unwrap();
    r.cli(upsert(row("g1", "r"), true)).await;
    let outcome = r.reload().await.unwrap();
    assert!(outcome.contains("unchanged"), "{outcome}");
    assert_eq!(
        r.verbs(),
        vec![(V::Add, "g1".into()), (V::Replace, "g1".into())]
    );
    assert!(outcome.contains("grant records: 1 written"), "{outcome}");
}

/// T2e: a parse refusal keeps the live set and leaves the journal pending;
/// the fixed file's reload records the entry once.
#[tokio::test]
async fn t2e_parse_refusal_keeps_the_entry_pending() {
    let r = Reload::new();
    r.cli(add(row("g1", "r"))).await;
    r.cli(add(row("g2", "r"))).await;
    r.reload().await.unwrap();
    assert_eq!(r.live_ids(), vec!["g1".to_string(), "g2".to_string()]);
    r.cli(add(row("g3", "r"))).await;
    let good = std::fs::read(&r.grants).unwrap();
    std::fs::write(&r.grants, b"grants: [not a grant\n").unwrap();
    assert!(r.reload().await.is_err());
    assert_eq!(r.live_ids(), vec!["g1".to_string(), "g2".to_string()]);
    assert_eq!(r.verbs().len(), 2, "{:?}", r.verbs());
    std::fs::write(&r.grants, good).unwrap();
    r.reload().await.unwrap();
    let got = r.verbs();
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(got[2], (V::Add, "g3".into()));
}

/// T6: an append that fails after the publish keeps the change in force and
/// says UNRECORDED; the publish is observed before the failing append.
#[tokio::test]
async fn t6_failed_append_keeps_the_change_and_says_unrecorded() {
    let r = Reload::new();
    r.store.watch_epoch.set(r.epoch.clone()).unwrap();
    r.cli(add(row("g1", "r"))).await;
    r.store.fail_from.store(1, Ordering::SeqCst);
    let outcome = r
        .reload()
        .await
        .expect("an applied reload is not a refusal");
    assert!(outcome.contains("UNRECORDED"), "{outcome}");
    assert_eq!(r.live_ids(), vec!["g1".to_string()]);
    assert_eq!(r.epoch.load(Ordering::SeqCst), 1);
    assert_eq!(
        r.store.epoch_at_failure.load(Ordering::SeqCst),
        2,
        "the failing append saw epoch 1: publish came first"
    );
}

/// T6b: a plan that cannot be written refuses the reload and keeps the live set.
#[tokio::test]
async fn t6b_unwritable_plan_refuses_the_reload() {
    let r = Reload::new();
    // A directory where the state file goes: the atomic write cannot land
    // (not chmod: CI runs as root).
    std::fs::create_dir_all(r.state_dir.join(STATE_FILE).join("x")).unwrap();
    r.cli(add(row("g1", "r"))).await;
    let refused = r.reload().await.expect_err("the change must be refused");
    assert!(
        refused.contains("audit plan could not be written"),
        "{refused}"
    );
    assert!(r.live_ids().is_empty());
    assert_eq!(r.epoch.load(Ordering::SeqCst), 0);
    assert!(r.verbs().is_empty());
}

/// T10a: a CLI change held between its file write and its append makes the
/// reload busy with no record; after it completes, exactly one `add`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t10a_reload_waits_for_the_cli_append() {
    let r = Reload::new();
    let (written_tx, written_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let hooks = Hooks {
        after_grant_write: Some(Box::new(move || {
            written_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
        })),
        ..Hooks::default()
    };
    let grants = r.grants.clone();
    let cli = tokio::spawn(async move {
        apply_change_with(&grants, true, add(row("g1", "r")), None, &hooks).await
    });
    tokio::task::spawn_blocking(move || written_rx.recv().unwrap())
        .await
        .unwrap();

    let busy = r.reload().await.expect_err("the journal lock is held");
    assert!(busy.contains("busy") && busy.contains("retry"), "{busy}");
    assert!(r.verbs().is_empty(), "{:?}", r.verbs());

    release_tx.send(()).unwrap();
    cli.await.unwrap().unwrap();
    r.reload().await.unwrap();
    assert_eq!(r.verbs(), vec![(V::Add, "g1".into())]);
}

/// T2c: a watcher-driven reload records the CLI change.
#[tokio::test]
async fn t2c_watcher_reload_records_the_change() {
    let r = Reload::new();
    let config_path = r.grants.with_file_name("gateway.yaml");
    crate::gateway::test_helpers::write_config_fixture(&config_path, &Config::default()).unwrap();
    r.cli(add(row("g1", "r"))).await;

    let (event_tx, event_rx) = tokio::sync::mpsc::channel(4);
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    ConfigWatcher::spawn_reload_task(
        config_path,
        Arc::new(LiveConfig::new(Config::default())),
        Arc::new(BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
        Arc::new(LiveEnv::new(
            Arc::new(EnvOverlay::none()),
            ResolvedEnvFiles::default(),
        )),
        Some(r.sink.clone()),
        None,
        event_rx,
        shutdown_rx,
        Arc::new(super::env_poll::EnvReloadCounts::default()),
    );
    event_tx.send(ReloadTrigger::ConfigFile).await.unwrap();
    // The task debounces on a std `Instant`: poll real time.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while r.verbs().is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = shutdown_tx.send(());
    assert_eq!(r.verbs(), vec![(V::Add, "g1".into())]);
}

/// T6b (plan write): the state file reads fine but the plan write fails; the
/// reload is refused and publishes nothing.
#[tokio::test]
async fn t6b_failed_plan_write_refuses_the_reload() {
    let r = Reload::new();
    r.cli(add(row("g1", "r"))).await;
    r.reload().await.unwrap();
    r.cli(add(row("g2", "r"))).await;
    *r.auditor.fault.lock() = Some(GrantAuditFault::PlanWrite);
    let refused = r.reload().await.expect_err("the change must be refused");
    assert!(
        refused.contains("audit plan could not be written"),
        "{refused}"
    );
    assert_eq!(r.live_ids(), vec!["g1".to_string()]);
    assert_eq!(r.epoch.load(Ordering::SeqCst), 1);
    assert_eq!(r.verbs().len(), 1);
}

/// Review fix: a torn append that split a multibyte character is one torn
/// line, not an unreadable journal: the next CLI change is still recorded.
#[tokio::test]
async fn torn_multibyte_line_does_not_block_later_entries() {
    use std::io::Write as _;
    let r = Reload::new();
    r.cli(add(row("g1", "r"))).await;
    let journal = crate::identity_grants::journal::journal_path(&r.grants);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&journal)
        .unwrap();
    file.write_all(b"{\"grant_id\":\"\xe2\x82").unwrap();
    drop(file);
    r.cli(add(row("g2", "r"))).await;
    r.reload().await.unwrap();
    let got = r.verbs();
    assert!(got.contains(&(V::Add, "g2".into())), "{got:?}");
    assert!(
        got.iter()
            .any(|v| v.0 == V::Indeterminate && v.1 == "journal-torn-line"),
        "{got:?}"
    );
}
