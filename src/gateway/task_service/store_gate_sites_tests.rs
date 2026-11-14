// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! G13, store-level sites: every task-store mutation asks the gate for the
//! class its callers have, and obeys the gate's answer. Each site is called on
//! an absent task (admission comes before the blocking body), once with the
//! gate open, where the recorded class is checked, and once after the commit
//! edge, where an External site must be refused, an Internal one admitted
//! (the same answer as when open) and a Sweep skipped. Written before the
//! gate's behaviour: the skeleton records nothing and refuses nothing.

use futures::future::BoxFuture;
use serde_json::{Map, json};

use super::gate::{Kind, TaskGate};
use super::{CancelHold, StoreError, StoreLimits, TaskStore};
use crate::gateway::task_service::record::{InputRound, PreparedTask, UpstreamRecord};
use crate::protocol::mrtr::InputRequired;
use crate::protocol::tasks::{Task, TaskOptions, TaskTransition};

const OWNER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ABSENT: &str = "no-such-task";

type Out = BoxFuture<'static, Result<(), StoreError>>;
type Call = fn(TaskStore) -> Out;

fn at() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-09-07T00:00:05Z")
        .expect("a fixed instant")
        .with_timezone(&chrono::Utc)
}

fn task() -> Task {
    Task::create_at(
        "private-tool",
        at(),
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    )
}

fn upstream() -> UpstreamRecord {
    UpstreamRecord {
        handle: "handle".into(),
        backend: "orders".into(),
        tool: "create".into(),
        arguments: json!({"sku": "x"}),
        operation_digest: "digest".to_owned(),
        secret_fingerprint: Some("none".to_owned()),
    }
}

fn round() -> InputRound {
    InputRound {
        request_state: Some("state".to_owned()),
        tool: "gateway_invoke".to_owned(),
        arguments: json!({}),
        accepted_inputs: Map::new(),
        continuation_deadline: None,
        surfaced_server: None,
    }
}

/// Every single-class site, with the class it must ask for. The two shared
/// methods take their class from the caller: their rows are the executor's.
fn sites() -> Vec<(&'static str, Kind, Call)> {
    let mut sites: Vec<(&'static str, Kind, Call)> = Vec::new();
    sites.push(("create", Kind::External, |s| -> Out {
        Box::pin(async move {
            s.create(PreparedTask::for_test(&task(), OWNER, 7))
                .await
                .map(drop)
        })
    }));
    sites.push(("provide_input", Kind::External, |s| -> Out {
        Box::pin(async move {
            s.provide_input(OWNER, ABSENT, Map::new(), || None, at())
                .await
                .map(drop)
        })
    }));
    sites.push(("mark_dispatched", Kind::Internal, |s| -> Out {
        Box::pin(async move { s.mark_dispatched(OWNER, ABSENT, 1).await })
    }));
    sites.push(("mark_upstream", Kind::Internal, |s| -> Out {
        Box::pin(async move {
            s.mark_upstream(OWNER, ABSENT, 1, (upstream(), Vec::new()))
                .await
        })
    }));
    sites.push(("require_input", Kind::Internal, |s| -> Out {
        Box::pin(async move {
            let requested = InputRequired {
                requests: Vec::new(),
                request_state: None,
            };
            s.require_input(OWNER, ABSENT, 1, requested, round(), at())
                .await
                .map(drop)
        })
    }));
    sites.push(("add_targets", Kind::Internal, |s| -> Out {
        Box::pin(async move {
            s.add_targets(OWNER, ABSENT, 1, (Vec::new(), Vec::new()))
                .await
        })
    }));
    sites.push(("claim_upstream_cancel", Kind::Internal, |s| -> Out {
        Box::pin(async move { s.claim_upstream_cancel(OWNER, ABSENT, None).await.map(drop) })
    }));
    sites.push((
        "claim_upstream_cancel_undated",
        Kind::Internal,
        |s| -> Out {
            Box::pin(async move {
                s.claim_upstream_cancel_undated(OWNER, ABSENT, None)
                    .await
                    .map(drop)
            })
        },
    ));
    sites.push(("record_cancel_attempt", Kind::Internal, |s| -> Out {
        Box::pin(async move { s.record_cancel_attempt(OWNER, ABSENT, None).await.map(drop) })
    }));
    sites.push(("transition (test-only)", Kind::Internal, |s| -> Out {
        Box::pin(async move {
            s.transition(OWNER, ABSENT, 1, TaskTransition::Cancel, at())
                .await
                .map(drop)
        })
    }));
    sites.push(("expire", Kind::Sweep, |s| -> Out {
        Box::pin(async move {
            let admission =
                std::sync::Arc::new(crate::idempotency::admission::ExecutionAdmission::new(
                    std::sync::Arc::new(|| 1_000),
                ));
            s.expire(ABSENT, 1, &admission, CancelHold::Off).await
        })
    }));
    sites
}

fn to_terminal(gate: &TaskGate) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    gate.pause(1, deadline, deadline + std::time::Duration::from_secs(30));
    gate.certify(1);
    gate.commit();
}

// G13: each store site asks for its class, then obeys the commit edge.
#[tokio::test(flavor = "current_thread")]
async fn every_store_site_asks_for_its_class_and_obeys_the_gate() {
    for (name, kind, call) in sites() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = TaskStore::open(&dir.path().join("tasks"), StoreLimits::default())
            .await
            .expect("a clean store opens");
        let gate = store.gate_for_test();
        let open = call(store.clone()).await;
        assert_eq!(
            gate.seams().take_admits(),
            vec![kind],
            "{name} asks for {kind:?}"
        );
        to_terminal(&gate);
        let terminal = call(store.clone()).await;
        match kind {
            Kind::External => {
                assert_eq!(
                    terminal,
                    Err(StoreError::Restarting),
                    "{name}: refused after commit"
                );
            }
            Kind::Internal => {
                assert_eq!(
                    terminal, open,
                    "{name}: admitted after commit, as when open"
                );
            }
            Kind::Sweep => {
                assert_eq!(
                    terminal,
                    Err(StoreError::Skipped),
                    "{name}: skipped after commit"
                );
            }
        }
    }
}
