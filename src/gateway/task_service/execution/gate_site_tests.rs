// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! G13, executor-level sites: the callers of the two shared store methods
//! each hand the gate their own class (the route's cancel External; a worker
//! settle, recovery and an input round's close Internal; the expiry sweep's
//! close Sweep) and obey its answer after the commit edge. Plus the two
//! end-to-end rows: after the commit edge the route's cancel is refused as a
//! store-unavailable answer, and a worker settle still lands. Written before
//! the gate's behaviour: the skeleton records nothing and refuses nothing.

use std::sync::Arc;

use serde_json::json;

use crate::gateway::gateway_writes::WriteRecord;
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::execution::{CommitFailure, TaskExecutor, TransitionWrite};
use crate::gateway::task_service::record::{ErrorAuthor, InputRound, Provenance};
use crate::gateway::task_service::store::gate::{Kind, TaskGate};
use crate::gateway::task_service::{
    CreateOutcome, ServiceError, StoreLimits, Task, TaskOptions, TaskService,
};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};
use crate::protocol::mrtr::InputRequired;
use crate::protocol::tasks::TaskTransition;

const OWNER: &str = "verified-owner";
const BACKEND: &str = "peer";
const ABSENT: &str = "no-such-task";

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

/// A live task owned by OWNER: its id and revision.
async fn live_row(f: &Fixture, key: &str) -> (String, u64) {
    let (operation, representation) = (json!({"backend": BACKEND, "tool": "echo"}), json!({}));
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let task = Task::create_at(
        "echo",
        crate::clock::utc_now().expect("the test host's clock reads after 1970"),
        TaskOptions {
            ttl_ms: Some(86_400_000),
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
    (task.task.id().to_owned(), task.revision)
}

fn gate(f: &Fixture) -> TaskGate {
    f.service.store.gate_for_test()
}

fn to_terminal(gate: &TaskGate) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    gate.pause(1, deadline, deadline + std::time::Duration::from_secs(30));
    gate.certify(1);
    gate.commit();
}

fn digest(f: &Fixture) -> String {
    f.service
        .owner(OWNER)
        .expect("the fixture owner hashes")
        .as_digest()
        .to_owned()
}

fn settle<'a>(id: &'a str, revision: u64) -> TransitionWrite<'a> {
    TransitionWrite::Settle {
        principal: OWNER,
        id,
        revision,
        event: TaskTransition::Cancel,
        targets: Provenance::default(),
        author: ErrorAuthor::Gateway,
        writes: WriteRecord::default(),
    }
}

// G13: the route's cancel asks for External and is refused after the commit
// edge; a worker settle, recovery and an input round's close ask for Internal
// and are admitted after it (the same answer as when open).
#[tokio::test(flavor = "current_thread")]
async fn every_shared_method_caller_asks_for_its_class_and_obeys_the_gate() {
    let f = fixture().await;
    let digest = digest(&f);
    let now = crate::clock::utc_now().expect("the clock reads");
    let route_cancel = TransitionWrite::Cancel {
        principal: OWNER,
        id: ABSENT,
        revision: 1,
    };
    let open = f.executor.commit_transition(route_cancel).await;
    assert_eq!(
        gate(&f).seams().take_admits(),
        vec![Kind::External],
        "route cancel"
    );
    assert!(open.is_err(), "the absent task is not cancelled");

    let calls: [(&str, Kind); 3] = [
        ("worker settle", Kind::Internal),
        ("recovery", Kind::Internal),
        ("input round close", Kind::Internal),
    ];
    let mut opens = Vec::new();
    for (name, kind) in calls {
        let outcome = match name {
            "worker settle" => format!(
                "{:?}",
                f.executor.commit_transition(settle(ABSENT, 1)).await
            ),
            "recovery" => {
                let recover = TransitionWrite::Recover {
                    owner_digest: &digest,
                    id: ABSENT,
                    revision: 1,
                    event: TaskTransition::Cancel,
                    author: ErrorAuthor::Gateway,
                    writes: WriteRecord::default(),
                };
                format!("{:?}", f.executor.commit_transition(recover).await)
            }
            _ => format!(
                "{:?}",
                f.executor
                    .close_round(&digest, ABSENT, 1, "closed".to_owned(), now)
                    .await
            ),
        };
        assert_eq!(gate(&f).seams().take_admits(), vec![kind], "{name}");
        opens.push((name, outcome));
    }

    to_terminal(&gate(&f));
    let route_cancel = TransitionWrite::Cancel {
        principal: OWNER,
        id: ABSENT,
        revision: 1,
    };
    let refused = f.executor.commit_transition(route_cancel).await;
    assert!(
        matches!(
            refused,
            Err(CommitFailure::Service(ServiceError::Unavailable))
        ),
        "after commit the route's cancel is refused as store-unavailable: {refused:?}"
    );
    for (name, open) in opens {
        let terminal = match name {
            "worker settle" => format!(
                "{:?}",
                f.executor.commit_transition(settle(ABSENT, 1)).await
            ),
            "recovery" => {
                let recover = TransitionWrite::Recover {
                    owner_digest: &digest,
                    id: ABSENT,
                    revision: 1,
                    event: TaskTransition::Cancel,
                    author: ErrorAuthor::Gateway,
                    writes: WriteRecord::default(),
                };
                format!("{:?}", f.executor.commit_transition(recover).await)
            }
            _ => format!(
                "{:?}",
                f.executor
                    .close_round(&digest, ABSENT, 1, "closed".to_owned(), now)
                    .await
            ),
        };
        assert_eq!(
            terminal, open,
            "{name}: admitted after commit, as when open"
        );
    }
}

// G13: the expiry sweep closes an expired input round as a Sweep, and after
// the commit edge it skips it: the round stays open and the tick is no failure.
#[tokio::test(flavor = "current_thread")]
async fn the_sweep_closes_rounds_as_a_sweep_and_skips_after_commit() {
    for terminal in [false, true] {
        let f = fixture().await;
        let (id, revision) = live_row(&f, if terminal { "g13-sweep-t" } else { "g13-sweep" }).await;
        let requested = InputRequired {
            requests: vec![(
                "q".to_owned(),
                json!({ "method": "elicitation/create", "params": {} }),
            )],
            request_state: None,
        };
        let round = InputRound {
            request_state: Some("state".to_owned()),
            tool: "gateway_invoke".to_owned(),
            arguments: json!({}),
            accepted_inputs: serde_json::Map::new(),
            continuation_deadline: Some(1),
            surfaced_server: None,
        };
        let now = crate::clock::utc_now().expect("the clock reads");
        f.service
            .store
            .require_input(&digest(&f), &id, revision, requested, round, now)
            .await
            .expect("the round opens");
        let _ = gate(&f).seams().take_admits();
        if terminal {
            to_terminal(&gate(&f));
        }
        let tick = f.executor.expiry_pass_for_test().await;
        assert!(tick.is_ok(), "the tick is no failure: {tick:?}");
        let (open_round, _) = f.service.store.input_round_for_test(&id);
        if terminal {
            assert!(
                open_round.is_some(),
                "after commit the sweep skipped the close"
            );
        } else {
            assert_eq!(
                gate(&f).seams().take_admits(),
                vec![Kind::Sweep],
                "the close is a Sweep"
            );
            assert!(open_round.is_none(), "the expired round was closed");
        }
    }
}

// End to end, after the commit edge: the route's own cancel call on a live
// task answers store-unavailable (the route maps every non-absence error to
// its existing store-unavailable reply, task_route.rs), and a worker settle on
// another live task still lands.
#[tokio::test(flavor = "current_thread")]
async fn after_commit_a_route_cancel_is_unavailable_and_a_worker_settle_lands() {
    let f = fixture().await;
    let (cancel_id, cancel_rev) = live_row(&f, "g13-e2e-cancel").await;
    let (settle_id, settle_rev) = live_row(&f, "g13-e2e-settle").await;
    to_terminal(&gate(&f));
    let refused = f.executor.cancel(OWNER, &cancel_id, cancel_rev).await;
    assert!(
        matches!(refused, Err(ServiceError::Unavailable)),
        "the route's cancel is store-unavailable after commit: {refused:?}"
    );
    assert!(
        f.service.get(OWNER, &cancel_id).is_ok(),
        "the refused task is untouched"
    );
    let settled = f
        .executor
        .commit_transition(settle(&settle_id, settle_rev))
        .await;
    assert!(
        settled.is_ok(),
        "a worker settle lands after commit: {settled:?}"
    );
}
