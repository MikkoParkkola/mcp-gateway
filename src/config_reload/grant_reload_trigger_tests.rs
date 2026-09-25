// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7537 — grant-reload cells that need `config_reload` internals.
//!
//! Cells from `docs/internal/design/2026-09-22-live-identity-grant-reload.md`
//! §3 and §D4 that must reach the grants lock or the watcher's private reload
//! task: T6 and T10b (the busy refusal) and W (the watcher entry point).
//!
//! T10 IS NOT A SEPARATE CELL, and that is a finding rather than an omission.
//! Its interleaving — trigger A reads, trigger B reads and publishes, A
//! publishes its older snapshot — cannot be constructed while one mutex spans
//! read through publish: B cannot read until A has published. What remains
//! observable is what a held lock does to the second trigger, which is T10b.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::Utc;

use super::{ConfigWatcher, IdentityGrantSink, LiveConfig, ReloadContext, ReloadTrigger};
use crate::backend::BackendRegistry;
use crate::config::{Config, EnvOverlay, LiveEnv, ResolvedEnvFiles};
use crate::identity_grants::{
    CapabilityExposure, GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantRequest,
    LocalIdentityGrantStore,
};

type Store = Arc<parking_lot::RwLock<LocalIdentityGrantStore>>;

fn grant(grant_id: &str, subject: &str, capability: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::new("https://idp".to_string(), subject.to_string(), None),
        agent: GrantAgent::Any,
        capability: capability.to_string(),
        tool: None,
        scope: GrantScope::Read,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "fixture".to_string(),
        reason: "grant-reload trigger cell".to_string(),
    }
}

fn revoked(mut row: IdentityGrant) -> IdentityGrant {
    row.revoked_at = Some(Utc::now() - chrono::Duration::seconds(1));
    row
}

fn write_grants(path: &std::path::Path, rows: &[IdentityGrant]) {
    let file = serde_json::json!({
        "schema_version": crate::identity_grants::IDENTITY_GRANTS_FILE_SCHEMA_VERSION,
        "grants": rows,
    });
    std::fs::write(path, serde_json::to_vec_pretty(&file).expect("serialize")).expect("write");
}

fn allows(store: &Store, subject: &str, capability: &str) -> bool {
    let subject = GrantSubject::new("https://idp".to_string(), subject.to_string(), None);
    store
        .read()
        .evaluate(&IdentityGrantRequest {
            identity: Some(subject.clone()),
            agent_id: None,
            capability: capability.to_string(),
            tool: None,
            scope: GrantScope::Read,
            exposure: CapabilityExposure::Personal,
            owner: Some(subject),
            now: Utc::now(),
        })
        .allowed
}

/// A live store holding alice/cal and bob/mail, and a sink over it that
/// reloads from `grants_path`.
fn live_store(grants_path: &std::path::Path) -> (Store, Arc<AtomicU64>, Arc<IdentityGrantSink>) {
    let store: Store = Arc::new(parking_lot::RwLock::new(
        LocalIdentityGrantStore::from_grants([
            grant("g1", "alice", "cal"),
            grant("g2", "bob", "mail"),
        ]),
    ));
    let epoch = Arc::new(AtomicU64::new(0));
    let sink = Arc::new(IdentityGrantSink::new(
        Arc::clone(&store),
        Arc::clone(&epoch),
        grants_path.to_path_buf(),
    ));
    (store, epoch, sink)
}

fn ctx(sink: Arc<IdentityGrantSink>) -> ReloadContext {
    ReloadContext::new(
        sink.path.clone(),
        Arc::new(LiveConfig::new(Config::default())),
        Arc::new(BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    )
    .with_identity_grant_sink(sink)
}

/// Bounds a reload that would otherwise wait forever on a held lock, so the
/// pre-fix code fails the cell instead of hanging CI.
async fn reload_bounded(ctx: &ReloadContext) -> Option<Result<String, String>> {
    tokio::time::timeout(Duration::from_secs(60), ctx.reload_identity_grants())
        .await
        .expect("a held grants lock must yield a busy refusal, not an unbounded wait")
}

// T6 (busy half) — goes red when a retryable refusal reads like a broken file,
// sending the operator to inspect a grants file that is perfectly fine.
#[tokio::test(start_paused = true)]
async fn t6_a_busy_refusal_is_distinguishable_from_a_parse_refusal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    write_grants(&path, &[revoked(grant("g1", "alice", "cal"))]);
    let (_store, _epoch, sink) = live_store(&path);
    let ctx = ctx(Arc::clone(&sink));

    let _held = sink.lock.lock().await;
    let busy = reload_bounded(&ctx)
        .await
        .expect("a wired sink reports")
        .expect_err("T6: a reload behind a held grants lock must not report success");

    assert!(
        busy.contains("busy") && busy.contains("retry"),
        "T6: the busy refusal must say it is busy and retryable: {busy}"
    );
    assert!(
        !busy.contains("not reloaded from"),
        "T6: the busy refusal must not reuse the unreadable-file wording: {busy}"
    );
}

// T10b — goes red when a busy refusal is not inert: it must change nothing,
// and the retry must then apply.
#[tokio::test(start_paused = true)]
async fn t10b_a_busy_refusal_publishes_nothing_and_the_retry_applies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    write_grants(
        &path,
        &[
            revoked(grant("g1", "alice", "cal")),
            grant("g2", "bob", "mail"),
        ],
    );
    let (store, epoch, sink) = live_store(&path);
    let ctx = ctx(Arc::clone(&sink));
    let rows_before: Vec<_> = store.read().values().cloned().collect();
    let epoch_before = epoch.load(Ordering::Acquire);

    let held = sink.lock.lock().await;
    let outcome = reload_bounded(&ctx).await.expect("a wired sink reports");
    assert!(outcome.is_err(), "T10b: busy must refuse: {outcome:?}");
    assert_eq!(
        store.read().values().cloned().collect::<Vec<_>>(),
        rows_before,
        "T10b: a busy refusal must not publish"
    );
    assert_eq!(
        epoch.load(Ordering::Acquire),
        epoch_before,
        "T10b: a busy refusal must not flush every caller's cache"
    );
    assert!(allows(&store, "alice", "cal"), "T10b: nothing applied yet");

    drop(held);
    // Unbounded on purpose: the lock is free, and under paused time an outer
    // timeout can auto-advance past a file read still on the blocking pool.
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reports")
        .expect("T10b: the retry against the same file must apply");
    assert!(
        !allows(&store, "alice", "cal"),
        "T10b: the retried revocation must deny"
    );
    assert!(
        allows(&store, "bob", "mail"),
        "T10b: an unrelated grant must still allow"
    );
}

// W — goes red when an AUTOMATIC config reload leaves a revoked grant in
// force. The watcher builds its own `ReloadContext` rather than sharing the
// one the meta-tool and admin UI hold (§D4); a grant sink wired only into the
// shared one makes every watcher-driven reload skip grants while the CLI tells
// the operator the next reload applies them. Driven through the watcher's own
// reload task, not through `reload_outcome`, because the gap is the wiring.
#[tokio::test]
async fn w_a_watcher_driven_config_reload_applies_a_revocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("gateway.yaml");
    crate::config_persistence::write_config(&config_path, &Config::default())
        .expect("write config");
    let grants_path = dir.path().join("grants.json");
    let (store, _epoch, sink) = live_store(&grants_path);

    // PREMISE: the grant allows before the revocation reaches the file.
    assert!(
        allows(&store, "alice", "cal"),
        "W premise: alice is allowed"
    );
    write_grants(
        &grants_path,
        &[
            revoked(grant("g1", "alice", "cal")),
            grant("g2", "bob", "mail"),
        ],
    );

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
        Some(sink),
        event_rx,
        shutdown_rx,
    );
    event_tx
        .send(ReloadTrigger::ConfigFile)
        .await
        .expect("the reload task is listening");

    // The task debounces on a std `Instant`, so paused tokio time cannot skip
    // it; poll real time well past the 500 ms debounce.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while allows(&store, "alice", "cal") && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = shutdown_tx.send(());

    assert!(
        !allows(&store, "alice", "cal"),
        "W: a watcher-driven config reload must apply the revocation on disk"
    );
    assert!(
        allows(&store, "bob", "mail"),
        "W: an unrelated grant must still allow after the watcher reload"
    );
}

/// F11b — a pin of UPGRADING §27: a hot reload of a file holding a 3.x bare
/// `exact` row is refused, publishes nothing, and the live grants still apply.
#[tokio::test]
async fn a_bare_exact_row_reload_keeps_the_previous_grants() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let mut row = serde_json::to_value(revoked(grant("g1", "alice", "cal"))).expect("row");
    row["agent"] = serde_json::json!({"exact": "runner"});
    let file = serde_json::json!({
        "schema_version": crate::identity_grants::IDENTITY_GRANTS_FILE_SCHEMA_VERSION,
        "grants": [row],
    });
    std::fs::write(&path, file.to_string()).expect("write");
    let (store, epoch, sink) = live_store(&path);
    let ctx = ctx(sink);

    let refusal = reload_bounded(&ctx)
        .await
        .expect("a wired sink reports")
        .expect_err("F11b: a bare exact row must not reload");

    assert!(refusal.contains("g1"), "{refusal}");
    assert_eq!(epoch.load(Ordering::Acquire), 0, "nothing was published");
    assert!(
        allows(&store, "alice", "cal"),
        "the live grant still applies"
    );
    assert!(allows(&store, "bob", "mail"));
}
