// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8042: every `gateway.yaml` writer loads, edits and writes under one
//! cross-process lock, a `.gateway.yaml.lock` sidecar next to the file. A
//! writer that cannot take it in time writes nothing (`Busy`), and a writer
//! that cannot take it at all writes nothing either: never an unlocked write.

use std::{sync::Arc, time::Duration};

use super::*;
use crate::config::Config;
use crate::config_persistence::CommentLoss;
use crate::fs_lock::ExclusiveFileLock;
use crate::gateway::test_helpers::write_owner_only;

const START: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

/// A config file in its own directory, and the path of its lock sidecar.
fn config() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write config");
    let lock = dir.path().join(".gateway.yaml.lock");
    (dir, path, lock)
}

fn add_b(config: &mut Config) -> Result<(), String> {
    let backend = config.backends["a"].clone();
    config.backends.insert("b".to_string(), backend);
    Ok(())
}

/// What a write returned, for an assertion message (`ConfigMutation` has no
/// `Debug`).
fn outcome<T, E, X: std::fmt::Debug>(result: &Result<ConfigMutation<T, E>, X>) -> String {
    match result {
        Ok(ConfigMutation::Applied(..)) => "applied".to_string(),
        Ok(ConfigMutation::Rejected(_)) => "rejected".to_string(),
        Err(e) => format!("{e:?}"),
    }
}

/// R1: another process holds the lock, so the admin write waits out its
/// bound and reports `Busy` with the file untouched.
#[tokio::test]
async fn a_gateway_write_waits_for_the_lock_and_reports_busy() {
    let (_dir, path, lock) = config();
    let running = Config::load(Some(&path)).expect("config loads");
    let ctx = ReloadContext::new(
        path.clone(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    let held = ExclusiveFileLock::acquire(&lock).expect("the test holds the lock");

    let result = ctx
        .mutate_and_reload_outcome_within(&path, Duration::from_millis(300), add_b)
        .await;

    assert!(
        matches!(result, Err(ConfigWriteError::Busy)),
        "a write under another writer's lock must report Busy: {}",
        outcome(&result)
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), START);
    drop(held);
}

/// R1b: the same without a live gateway (the CLI's async path).
#[tokio::test]
async fn a_write_without_a_gateway_also_waits_for_the_lock() {
    let (_dir, path, lock) = config();
    let held = ExclusiveFileLock::acquire(&lock).expect("the test holds the lock");

    let result = mutate_config_and_reload_with(&path, None, CommentLoss::Refuse, add_b).await;

    assert!(
        matches!(result, Err(MutateError::Write(ConfigWriteError::Busy))),
        "a write under another writer's lock must report Busy: {}",
        outcome(&result)
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), START);
    drop(held);
}

/// R4: a directory where the sidecar goes means the lock cannot be taken;
/// the write is refused rather than made unlocked.
#[tokio::test]
async fn a_lock_that_cannot_be_taken_refuses_the_write() {
    let (_dir, path, lock) = config();
    std::fs::create_dir(&lock).expect("a directory in the sidecar's place");

    let result = mutate_config_and_reload_with(&path, None, CommentLoss::Refuse, add_b).await;

    assert!(
        matches!(&result, Err(MutateError::Write(ConfigWriteError::Failed(m))) if m.contains("lock")),
        "an untakeable lock must refuse the write, naming the lock: {}",
        outcome(&result)
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), START);
}
