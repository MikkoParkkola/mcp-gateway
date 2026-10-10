// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7839.CANCEL.3 (C0): a worker sealed while it is parked takes no further
//! step when it wakes. tokio-util's `run_until_cancelled_owned` polls the
//! worker before the token, so the old spawn ran one more step, which on a
//! real worker can be the backend dispatch.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::{StoreLimits, open_runtime};

#[tokio::test]
async fn a_sealed_worker_takes_no_step_when_it_wakes() {
    let dir = tempfile::tempdir().expect("store root");
    let subscriptions = Arc::new(SubscriptionRegistry::new(
        DEFAULT_MAX_LISTENERS,
        crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
    ));
    let (service, executor) = open_runtime(
        &dir.path().join("tasks"),
        1,
        StoreLimits::default(),
        subscriptions,
    )
    .await
    .expect("the store opens");
    let wake = Arc::new(tokio::sync::Notify::new());
    let stepped = Arc::new(AtomicBool::new(false));
    let (woken, step) = (Arc::clone(&wake), Arc::clone(&stepped));
    executor
        .spawn_worker(async move {
            woken.notified().await;
            step.store(true, Ordering::SeqCst);
        })
        .await
        .expect("no slot is open, so nothing to append");
    // Current-thread runtime: one yield lets the worker register on the Notify.
    tokio::task::yield_now().await;

    // Sealed and woken in the same window, as a session dropped while its
    // runtime sat idle and later resumed would leave it.
    executor.seal();
    wake.notify_one();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(
        !stepped.load(Ordering::SeqCst),
        "a sealed worker took one more step after waking"
    );
    service.shutdown().await.expect("custody is released");
}
