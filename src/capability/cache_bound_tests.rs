// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8661 T1 (PR4.6): the capability response cache is bounded, whichever
//! constructor built the executor. Before PR-4 it kept every entry whose key
//! was never read again, for the executor's whole life.
//!
//! The stores are sequential: the bound is pinned, not its exactness under
//! concurrent writers, which may briefly exceed it (lead ruling D4).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::capability::executor::CapabilityExecutor;
use crate::gateway::gateway_writes::WriteRecord;

/// The capability cache's bound (the Meta-MCP cache's default).
const CAP: usize = 10_000;

fn store(executor: &CapabilityExecutor, key: &str) {
    executor.cache.set_payload(
        key,
        json!({"ok": true}),
        (None, WriteRecord::default()),
        Duration::from_secs(60),
    );
}

fn cached(executor: &CapabilityExecutor, key: &str) -> bool {
    executor.cache.get_read(key).is_some()
}

fn entries(executor: &CapabilityExecutor) -> usize {
    executor.cache.stats().size
}

/// Store `k0`, then `CAP` more distinct keys: the cache holds `CAP`, the oldest
/// is gone and the newest is kept. "Oldest" is by insertion `Instant`, which no
/// test can inject, so the 20 ms sleep (past Windows' ~15.6 ms tick) makes `k0`
/// strictly older than every later key; ties among the later keys do not matter.
fn assert_bounded(executor: &CapabilityExecutor) {
    store(executor, "k0");
    std::thread::sleep(Duration::from_millis(20));
    for i in 1..=CAP {
        store(executor, &format!("k{i}"));
    }
    assert_eq!(
        entries(executor),
        CAP,
        "the cache holds at most CAP entries"
    );
    assert!(!cached(executor, "k0"), "the oldest entry was evicted");
    assert!(
        cached(executor, &format!("k{CAP}")),
        "the newest entry is kept"
    );
}

#[test]
fn the_default_executor_bounds_its_response_cache() {
    assert_bounded(&CapabilityExecutor::new());
}

#[test]
fn an_executor_with_token_storage_bounds_its_response_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage =
        Arc::new(crate::oauth::TokenStorage::new(dir.path().to_path_buf()).expect("storage"));
    assert_bounded(&CapabilityExecutor::with_token_storage(storage));
}
