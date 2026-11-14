// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! G12: the expiry sweep and the task-store gate. A sweep that reaches the
//! gate while a restart checkpoint holds the store does nothing and records no
//! failure; the next tick covers it. Written before the gate's behaviour.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::execution::TaskExecutor;
use crate::gateway::task_service::store::gate::seams::GateSeams;
use crate::gateway::task_service::{CreateOutcome, StoreLimits, Task, TaskOptions, TaskService};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};

const OWNER: &str = "verified-owner";
const BACKEND: &str = "peer";

async fn within<T>(row: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(Duration::from_secs(30), future).await {
        Ok(value) => value,
        Err(_) => panic!("{row}: did not finish in time"),
    }
}

struct Fixture {
    service: Arc<TaskService>,
    executor: Arc<TaskExecutor>,
}

async fn fixture() -> Fixture {
    let dir = Arc::new(tempfile::tempdir().expect("a fixture store root"));
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = Arc::new(
        TaskService::open(&dir.path().join("tasks"), StoreLimits::default(), admission)
            .await
            .expect("the fixture store opens"),
    );
    service.store.keep_test_dir(Arc::clone(&dir));
    let executor = TaskExecutor::new(
        Arc::clone(&service),
        Arc::new(SubscriptionRegistry::new(
            DEFAULT_MAX_LISTENERS,
            crate::gateway::test_helpers::auth_state(
                &crate::config::AuthConfig::default(),
                crate::gateway::record_principal::TEST_RECORD_KEY,
            ),
        )),
        1,
    );
    Fixture { service, executor }
}

/// A cancelled task, so its row ages out at its TTL. Returns its id.
async fn expiring_row(f: &Fixture, key: &str) -> String {
    let (operation, representation) = (json!({"backend": BACKEND, "tool": "echo"}), json!({}));
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let task = Task::create_at(
        "echo",
        crate::clock::utc_now().expect("the test host's clock reads after 1970"),
        TaskOptions {
            ttl_ms: Some(1_000),
            poll_interval_ms: Some(1_000),
        },
    );
    let request = Request {
        principal: OWNER,
        key,
        operation: &operation,
        representation: &representation,
        mode: Mode::Task,
    };
    let created = f
        .service
        .create(request, &task, BACKEND, move || {
            workers.try_acquire_owned().ok()
        })
        .await
        .expect("the fixture store accepts a create");
    let CreateOutcome::Created { task, slot } = created else {
        panic!("the fixture row must originate in a real committed task");
    };
    drop(slot);
    let id = task.task.id().to_owned();
    f.executor
        .cancel(OWNER, &id, task.revision)
        .await
        .expect("the fixture task cancels");
    id
}

/// Move the store's clock a day ahead, past every fixture row's TTL.
fn age_out(f: &Fixture) {
    let later = crate::clock::utc_now().expect("the clock reads") + chrono::Duration::days(1);
    f.service.store.set_clock_for_test(Some(later));
}

fn present(f: &Fixture, id: &str) -> bool {
    f.service.get(OWNER, id).is_ok()
}

fn pause(f: &Fixture) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let gate = f.service.store.gate_for_test();
    gate.pause(1, deadline, deadline + Duration::from_secs(30));
}

// G12: a tick that starts while the store is paused touches nothing and is
// no failure; the first tick after resume sweeps.
#[tokio::test(flavor = "current_thread")]
async fn a_paused_tick_sweeps_nothing_and_fails_nothing() {
    let f = fixture().await;
    let id = expiring_row(&f, "g12-start").await;
    age_out(&f);
    pause(&f);
    let tick = within("G12 paused tick", f.executor.expiry_pass_for_test()).await;
    assert!(tick.is_ok(), "a paused tick is no failure: {tick:?}");
    assert!(
        present(&f, &id),
        "nothing expired while the store was paused"
    );
    f.service.store.gate_for_test().resume();
    let tick = within("G12 next tick", f.executor.expiry_pass_for_test()).await;
    assert!(tick.is_ok());
    assert!(
        !present(&f, &id),
        "the next tick after resume swept the row"
    );
}

// G12: a pause that lands between two gated sweep calls of one tick stops the
// tick cleanly: the first deletion stands, the second waits for the next tick,
// and the tick is no failure.
#[tokio::test(flavor = "current_thread")]
async fn a_pause_mid_tick_stops_the_tick_cleanly() {
    let f = fixture().await;
    let first = expiring_row(&f, "g12-a").await;
    let second = expiring_row(&f, "g12-b").await;
    age_out(&f);
    let gate = f.service.store.gate_for_test();
    let hold = GateSeams::arm(&gate.seams().at_decision);
    let tick = tokio::spawn({
        let executor = Arc::clone(&f.executor);
        async move { executor.expiry_pass_for_test().await }
    });
    within("G12 first decision", hold.reached()).await;
    pause(&f);
    hold.release();
    within("G12 second decision", hold.reached()).await;
    hold.release();
    let outcome = within("G12 tick", tick).await.expect("the tick task");
    assert!(
        outcome.is_ok(),
        "a tick stopped by a pause is no failure: {outcome:?}"
    );
    let swept = [&first, &second]
        .iter()
        .filter(|id| !present(&f, id))
        .count();
    assert_eq!(
        swept, 1,
        "the deletion before the pause stands; the other waits"
    );
}
