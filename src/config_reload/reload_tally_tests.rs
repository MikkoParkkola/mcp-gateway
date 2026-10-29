// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The reload tally: every attempt has exactly one outcome, whichever entry
//! point made it, and the contexts of one gateway share one tally.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::backend::BackendRegistry;
use crate::config::{Config, FailsafeConfig};
use crate::config_reload::refusals::ReloadReporting;
use crate::config_reload::reload_tally::{ReloadResult, ReloadTally};
use crate::config_reload::{LiveConfig, ReloadContext};

fn write_config(path: &Path, text: &str) {
    crate::gateway::test_helpers::write_owner_only(path, text).expect("config written owner-only");
}

fn valid_yaml() -> String {
    crate::yaml::to_string(&Config::default()).expect("default config serializes")
}

/// A context on `path` reporting into `reporting`.
fn context(path: PathBuf, reporting: &ReloadReporting) -> ReloadContext {
    ReloadContext::new(
        path,
        Arc::new(LiveConfig::new(Config::default())),
        Arc::new(BackendRegistry::new()),
        FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
    .with_reporting(reporting.clone())
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_config(&path, &valid_yaml());
    (dir, path)
}

#[test]
fn a_fresh_tally_has_no_attempts_and_no_last() {
    let counts = ReloadTally::default().snapshot();
    assert_eq!((counts.attempts, counts.applied), (0, 0));
    assert!(counts.last.is_none());
}

#[test]
fn each_outcome_counts_one_attempt_and_only_applied_counts_applied() {
    let tally = ReloadTally::default();
    tally.applied();
    tally.refused();
    tally.skipped();
    let counts = tally.snapshot();
    assert_eq!((counts.attempts, counts.applied), (3, 1));
    assert_eq!(counts.last.map(|l| l.outcome), Some(ReloadResult::Skipped));
}

#[tokio::test]
async fn a_watcher_style_reload_is_counted_once_as_applied() {
    let (_dir, path) = fixture();
    let reporting = ReloadReporting::default();
    let ctx = context(path, &reporting);
    ctx.reload_outcome().await.expect("applied");
    let counts = ctx.reload_tally().snapshot();
    assert_eq!((counts.attempts, counts.applied), (1, 1));
}

#[tokio::test]
async fn an_admin_write_is_counted_once_as_applied() {
    let (_dir, path) = fixture();
    let ctx = context(path.clone(), &ReloadReporting::default());
    ctx.mutate_and_reload_outcome(&path, |_config: &mut Config| Ok::<(), ()>(()))
        .await
        .expect("written and reloaded");
    let counts = ctx.reload_tally().snapshot();
    assert_eq!((counts.attempts, counts.applied), (1, 1));
}

#[tokio::test]
async fn a_reload_paid_after_lock_recovery_is_counted_once() {
    let (_dir, path) = fixture();
    let ctx = context(path.clone(), &ReloadReporting::default());
    ctx.pay_owed_reload(
        crate::config_persistence::journal::Recovered::RolledBack,
        &path,
    )
    .await;
    let counts = ctx.reload_tally().snapshot();
    assert_eq!((counts.attempts, counts.applied), (1, 1));
}

#[tokio::test]
async fn a_refused_reload_is_counted_once_as_refused() {
    let (_dir, path) = fixture();
    let ctx = context(path.clone(), &ReloadReporting::default());
    write_config(&path, "backends: [this is not a map");
    assert!(ctx.reload_outcome().await.is_err());
    let counts = ctx.reload_tally().snapshot();
    assert_eq!((counts.attempts, counts.applied), (1, 0));
    assert_eq!(counts.last.map(|l| l.outcome), Some(ReloadResult::Refused));
}

#[tokio::test]
async fn a_lock_skip_is_counted_once_as_skipped() {
    let (_dir, path) = fixture();
    let ctx = context(path, &ReloadReporting::default());
    ctx.note_refused_lock();
    let counts = ctx.reload_tally().snapshot();
    assert_eq!((counts.attempts, counts.applied), (1, 0));
    assert_eq!(counts.last.map(|l| l.outcome), Some(ReloadResult::Skipped));
}

#[tokio::test]
async fn contexts_sharing_reporting_share_one_tally() {
    let (_dir, path) = fixture();
    let reporting = ReloadReporting::default();
    let watcher = context(path.clone(), &reporting);
    let admin = context(path, &reporting);
    watcher.reload_outcome().await.expect("applied");
    admin.reload_outcome().await.expect("applied");
    assert_eq!(admin.reload_tally().snapshot().attempts, 2);
    assert_eq!(watcher.reload_tally().snapshot().applied, 2);
}

/// Real contention: another holder has the reload lock and the write gives up
/// at once (a zero wait, not a short timer), so the write is skipped, tallied
/// once, and changes nothing.
#[tokio::test]
async fn a_write_that_cannot_get_the_reload_lock_is_counted_once_as_skipped() {
    let (_dir, path) = fixture();
    let ctx = context(path.clone(), &ReloadReporting::default());
    #[allow(
        clippy::disallowed_methods,
        reason = "Lifecycle: the test plays the other holder of the reload lock"
    )]
    let held = ctx.registry.lock_reload().await;
    let before = ctx.reload_tally().snapshot().attempts;
    let result = ctx
        .mutate_and_reload_outcome_within(&path, Duration::ZERO, |_config: &mut Config| {
            Ok::<(), ()>(())
        })
        .await;
    drop(held);
    assert!(result.is_err(), "the write must be refused as busy");
    let counts = ctx.reload_tally().snapshot();
    assert_eq!(counts.attempts, before + 1);
    assert_eq!(counts.applied, 0);
    assert_eq!(counts.last.map(|l| l.outcome), Some(ReloadResult::Skipped));
}

/// A forced `lock_config` failure: another writer holds the config lock and
/// the whole-config write gives up at once, so exactly one `skipped` is
/// tallied and nothing is written.
#[tokio::test]
async fn a_whole_config_write_that_cannot_lock_the_config_is_counted_once_as_skipped() {
    let (_dir, path) = fixture();
    let ctx = context(path.clone(), &ReloadReporting::default());
    let held = crate::config_persistence::lock::lock_config(
        &path,
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .await
    .expect("the test plays the other holder of the config lock");
    let before = ctx.reload_tally().snapshot().attempts;
    let result = ctx
        .write_and_reload_outcome_within(&path, Duration::ZERO, &Config::default())
        .await;
    drop(held);
    assert!(result.is_err(), "the write must be refused as busy");
    let counts = ctx.reload_tally().snapshot();
    assert_eq!((counts.attempts, counts.applied), (before + 1, 0));
    assert_eq!(counts.last.map(|l| l.outcome), Some(ReloadResult::Skipped));
}
