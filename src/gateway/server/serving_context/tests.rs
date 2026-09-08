// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real builder lifecycle tests. HTTP/stdio I/O shutdown tests remain separate.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::HttpServeContext;
use crate::config::Config;
use crate::gateway::server::build_meta_mcp_for_test;

const T: u64 = 1_000;
use crate::gateway::server::test_support::{isolated_child, observed_without_time_advance};

#[tokio::test(start_paused = true)]
async fn expiry_builder_uses_one_trusted_clock_for_continuation_state() {
    let name = concat!(
        module_path!(),
        "::expiry_builder_uses_one_trusted_clock_for_continuation_state"
    )
    .split_once("::")
    .expect("crate-qualified test name")
    .1;
    if isolated_child(name) {
        return;
    }
    let epoch = Arc::new(AtomicU64::new(T));
    let clock = Arc::clone(&epoch);
    let owner = build_meta_mcp_for_test(
        Config::default(),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .await
    .expect("production builder");
    let state = owner.meta().continuation();
    for expected in [T, T + 60, T - 100] {
        epoch.store(expected, Ordering::SeqCst);
        assert_eq!(
            state.now(),
            expected,
            "production state ignored builder clock"
        );
    }
    println!("COMPLETED {name}");
}

#[tokio::test(start_paused = true)]
async fn expiry_builder_owner_starts_cleanup_of_the_actual_invoke_state() {
    let name = concat!(
        module_path!(),
        "::expiry_builder_owner_starts_cleanup_of_the_actual_invoke_state"
    )
    .split_once("::")
    .expect("crate-qualified test name")
    .1;
    if isolated_child(name) {
        return;
    }
    let epoch = Arc::new(AtomicU64::new(T));
    let clock = Arc::clone(&epoch);
    let owner = build_meta_mcp_for_test(
        Config::default(),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .await
    .expect("production builder");
    let context = HttpServeContext { owner };
    let state = context.owner.meta().continuation();
    let expired = state
        .in_flight()
        .hold("expiry-builder", T + 1, T)
        .await
        .unwrap();
    let live = state
        .in_flight()
        .hold("expiry-builder", T + 100, T)
        .await
        .unwrap();
    // Let the actual builder-spawned worker install its interval, without clock travel.
    tokio::task::yield_now().await;
    epoch.store(T + 2, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(1)).await;
    let removed = observed_without_time_advance(async {
        loop {
            if !state.in_flight().snapshot().await.contains_key(&expired) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        removed,
        Some(()),
        "actual builder did not start idle cleanup"
    );
    let raw = state.in_flight().snapshot().await;
    assert_eq!(raw.len(), 1);
    assert_eq!(raw.get(&live), Some(&(T + 100)));
    println!("COMPLETED {name}");
}

#[tokio::test(start_paused = true)]
async fn expiry_builder_owner_drop_stops_scans_even_with_a_live_meta_clone() {
    let name = concat!(
        module_path!(),
        "::expiry_builder_owner_drop_stops_scans_even_with_a_live_meta_clone"
    )
    .split_once("::")
    .expect("crate-qualified test name")
    .1;
    if isolated_child(name) {
        return;
    }
    let epoch = Arc::new(AtomicU64::new(T));
    let calls = Arc::new(AtomicU64::new(0));
    let clock = Arc::clone(&epoch);
    let count = Arc::clone(&calls);
    let owner = build_meta_mcp_for_test(
        Config::default(),
        Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            clock.load(Ordering::SeqCst)
        }),
    )
    .await
    .expect("production builder");
    let context = HttpServeContext { owner };
    let meta = Arc::clone(context.owner.meta());
    let state = meta.continuation();
    let held = state
        .in_flight()
        .hold("expiry-builder-stop", T + 1, T)
        .await
        .unwrap();
    tokio::task::yield_now().await;
    for _ in 0..2 {
        let before = calls.load(Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            observed_without_time_advance(async {
                while calls.load(Ordering::SeqCst) == before {
                    tokio::task::yield_now().await;
                }
            })
            .await,
            Some(()),
            "worker must repeat scans before drop is tested"
        );
    }
    assert_eq!(
        state.in_flight().snapshot().await.get(&held),
        Some(&(T + 1))
    );
    drop(context);
    tokio::task::yield_now().await;
    epoch.store(T + 2, Ordering::SeqCst);
    let after = calls.load(Ordering::SeqCst);
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            after,
            "dropped serving owner left worker running"
        );
    }
    let raw = state.in_flight().snapshot().await;
    assert_eq!(raw.len(), 1);
    assert_eq!(raw.get(&held), Some(&(T + 1)));
    println!("COMPLETED {name}");
}
