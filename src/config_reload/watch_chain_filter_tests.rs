// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which events wake the rewatch task (MIK-8013). Each wake re-resolves the
//! config's whole link chain, so a write beside the config that cannot move
//! the chain must not cost one.
//!
//! Linux-only, as the other real-watcher rows (W-L9).

use std::path::Path;
use std::time::Duration;

use super::tests::real_watcher::{Harness, start};

/// Wait until the task has handled every wake it was sent: the count stops
/// moving for half a second.
async fn settled_wakes(h: &Harness) -> usize {
    let mut seen = h.wakes();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = h.wakes();
        if now == seen {
            return now;
        }
        seen = now;
    }
}

fn plain_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("root");
    let cfg = root.path().join("gateway.yaml");
    std::fs::write(&cfg, "a: 1\n").expect("config");
    (root, cfg)
}

/// MIK-8013.WATCH.2: 1000 files written beside the config run no chain
/// re-resolution. The config edit after them is the barrier: notify delivers
/// events in order, so once its reload arrives every earlier event was seen.
#[tokio::test]
async fn watch2_unrelated_files_beside_the_config_resolve_nothing() {
    let (root, cfg) = plain_config();
    let mut h = start(&cfg);
    h.wait_wakes_above(0).await;
    h.drain_idle().await;
    let before = settled_wakes(&h).await;

    write_unrelated(root.path(), 1000);
    std::fs::write(&cfg, "a: 2\n").unwrap();
    assert!(h.triggered_within(10).await, "the config edit reloads");
    let resolves = settled_wakes(&h).await - before;

    // The edit itself is up to two events (truncate, write); the 1000 files
    // add none.
    assert!(
        resolves <= 2,
        "{resolves} chain re-resolutions for 1000 unrelated files and one edit"
    );
    let _ = h.shutdown.send(());
}

fn write_unrelated(dir: &Path, count: usize) {
    for i in 0..count {
        std::fs::write(dir.join(format!("perf-{i}.data")), "x").unwrap();
    }
}

/// MIK-8013.WATCH.3: an atomic rename onto the config (write a temporary
/// file, rename it over the config) still reloads.
#[tokio::test]
async fn watch3_an_atomic_rename_onto_the_config_reloads() {
    let (root, cfg) = plain_config();
    let mut h = start(&cfg);
    h.wait_wakes_above(0).await;
    h.drain_idle().await;

    let tmp = root.path().join(".gateway.yaml.tmp");
    std::fs::write(&tmp, "a: 2\n").unwrap();
    std::fs::rename(&tmp, &cfg).unwrap();
    assert!(h.triggered_within(10).await, "the rename reloads");
    let _ = h.shutdown.send(());
}
