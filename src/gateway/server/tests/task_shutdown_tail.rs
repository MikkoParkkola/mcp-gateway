// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7844: the tail of task shutdown (the expiry join and the store close) is
//! bounded, the store is not closed under a worker that outlived its cancel,
//! and a task cannot start after a clean drain.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use serde_json::Value;

use super::super::task_runtime::{self, ShutdownBudget};
use super::owner2_stdio_tasks::{dispatch, fixture_on, held_backend, modern_call, reopen};
use crate::config::Config;
use crate::gateway::task_service::execution::CancelOutcome;

const BOUND: Duration = Duration::from_secs(10);

fn store_config(store: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.tasks.store_dir = store.display().to_string();
    config
}

fn task_id(answer: &Value) -> Option<&str> {
    answer.pointer("/result/taskId").and_then(Value::as_str)
}

/// SHUTDOWN.1. A store write stalled inside its commit holds the store close.
/// Shutdown still returns inside its budget, so backend teardown is not held
/// behind it; the stalled write finishes afterwards. Mutant: the expiry join
/// and the close are not under the `close` bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_store_write_does_not_hold_shutdown_past_its_budget() {
    let (url, _arrived, _release) = held_backend().await;
    let mut fixture = fixture_on((url, Arc::new(AtomicUsize::new(0))), None).await;
    let expiry = fixture.expiry.take().expect("the fixture's expiry sweep");

    let (entered, entered_rx) = tokio::sync::oneshot::channel::<()>();
    let entered = std::sync::Mutex::new(Some(entered));
    let (go, go_rx) = std::sync::mpsc::channel::<()>();
    let go_rx = std::sync::Mutex::new(go_rx);
    fixture
        .tasks
        .executor
        .barrier_on_publication(Arc::new(move || {
            if let Some(entered) = entered.lock().expect("unpoisoned").take() {
                let _ = entered.send(());
            }
            let _ = go_rx
                .lock()
                .expect("unpoisoned")
                .recv_timeout(Duration::from_secs(30));
        }))
        .await;

    let fixture = Arc::new(fixture);
    let create = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { dispatch(&fixture, modern_call(1, "held", "stalled", true)).await }
    });
    tokio::time::timeout(BOUND, entered_rx)
        .await
        .expect("the create reaches its commit")
        .expect("the hook fired");

    let shutdown = tokio::time::timeout(
        Duration::from_secs(5),
        task_runtime::shutdown(
            expiry,
            &fixture.tasks.executor,
            &fixture.tasks.service,
            ShutdownBudget {
                drain: Duration::from_millis(200),
                cancel: Duration::from_millis(200),
                close: Duration::from_millis(500),
            },
        ),
    )
    .await;
    let _ = go.send(());
    let _ = create.await;

    assert!(
        shutdown.is_ok(),
        "shutdown must return inside its budget while a store write is stalled"
    );
}

/// SHUTDOWN.2. A worker that did not end inside the cancel budget still holds
/// the store, so the store is retained, not closed under it: its lease is
/// still taken. A drain that ended cleanly closes it. Mutant: the store closes
/// anyway.
#[tokio::test]
async fn an_incomplete_cancel_keeps_the_store_open_and_a_complete_one_closes_it() {
    for (stopped, closed) in [(false, false), (true, true)] {
        let (url, _arrived, _release) = held_backend().await;
        let mut fixture = fixture_on((url, Arc::new(AtomicUsize::new(0))), None).await;
        let expiry = fixture.expiry.take().expect("the fixture's expiry sweep");

        task_runtime::settle_store(
            expiry,
            &fixture.tasks.service,
            Duration::from_secs(2),
            Some(&CancelOutcome {
                cancelled: 1,
                stopped,
            }),
        )
        .await;

        assert_eq!(
            reopen(&store_config(fixture.store.path())).await.is_ok(),
            closed,
            "a cancel that stopped = {stopped}: the store's lease is free only when it closed"
        );
    }
}

/// SHUTDOWN.3. A sealed executor refuses a new task and writes no row. Mutant:
/// admission ignores the seal.
#[tokio::test]
async fn a_sealed_executor_refuses_a_task_start() {
    let (url, _arrived, _release) = held_backend().await;
    let fixture = fixture_on((url, Arc::new(AtomicUsize::new(0))), None).await;
    fixture.tasks.executor.seal();

    let late = dispatch(&fixture, modern_call(1, "held", "late", true)).await;

    assert!(task_id(&late).is_none(), "a late start is refused: {late}");
}

/// SHUTDOWN.3 through the helper both transports call: a clean drain seals the
/// executor before the store closes. Mutant: shutdown never seals.
#[tokio::test]
async fn a_clean_drain_seals_the_executor() {
    let (url, _arrived, _release) = held_backend().await;
    let mut fixture = fixture_on((url, Arc::new(AtomicUsize::new(0))), None).await;
    let expiry = fixture.expiry.take().expect("the fixture's expiry sweep");

    let cancelled = task_runtime::shutdown(
        expiry,
        &fixture.tasks.executor,
        &fixture.tasks.service,
        ShutdownBudget::within(Duration::from_secs(10), Duration::from_secs(1)),
    )
    .await;

    assert_eq!(
        cancelled, None,
        "nothing was running, so the drain is clean"
    );
    assert!(fixture.tasks.executor.is_sealed());
}

/// The window is split three ways and never overdrawn. Mutant: `close` takes
/// the whole reserve.
#[test]
fn the_three_phases_fit_inside_the_window() {
    for (window, timeout) in [(10, 30), (40, 1), (30, 30), (5, 5)] {
        let window = Duration::from_secs(window);
        let budget = ShutdownBudget::within(window, Duration::from_secs(timeout));
        assert!(
            budget.drain + budget.cancel + budget.close <= window,
            "{budget:?} overdraws {window:?}"
        );
        assert!(budget.close > Duration::ZERO, "{budget:?}");
    }
}
