// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7757: a task whose backend call outlasts the shutdown drain is
//! cancelled before the task store closes, on both shutdown paths.
//!
//! `Gateway::run` (HTTP) and the stdio EOF teardown both end tasks through
//! `task_runtime::shutdown`. The first row drives that helper directly; no
//! test drives `Gateway::run` itself, whose shutdown is an
//! OS signal. The second row drives the stdio EOF path end to end.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::super::task_runtime::{self, ShutdownBudget};
use super::owner2_stdio_tasks::{BACKEND, dispatch, fixture_on, held_backend, modern_call, reopen};
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL;
use crate::gateway::task_service::TaskService;
use crate::gateway::task_service::execution::CancelOutcome;
use crate::protocol::tasks::TaskStatus;

const BOUND: Duration = Duration::from_secs(10);

fn task_id(answer: &Value) -> String {
    answer
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a task handle: {answer}"))
        .to_owned()
}

fn store_config(store: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.tasks.store_dir = store.display().to_string();
    config
}

/// The record as the next process reads it: terminal, settled by startup
/// recovery as interrupted after dispatch, and never the backend's own
/// `done`. Then the held call is released, and the record must not move: no
/// worker of the previous process is left to commit into it.
async fn assert_recovered_and_left_alone(
    service: &TaskService,
    id: &str,
    release: &tokio::sync::watch::Sender<bool>,
) {
    let recovered = service
        .get(LOCAL_OPERATOR_PRINCIPAL, id)
        .expect("the local operator's task is in its store");
    let wire = serde_json::to_value(recovered.task.wire()).expect("the task serializes");
    assert_eq!(recovered.task.status(), TaskStatus::Completed, "{wire}");
    assert!(
        wire.to_string().contains("gateway_restart_after_dispatch")
            && !wire.to_string().contains("done"),
        "settled by recovery as interrupted, not by the old worker: {wire}"
    );
    release.send_modify(|open| *open = true);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let later = service
        .get(LOCAL_OPERATOR_PRINCIPAL, id)
        .expect("still readable");
    assert_eq!(
        later.revision, recovered.revision,
        "nothing wrote to the record after the old process shut down"
    );
}

/// DRAIN.1, DRAIN.2, DRAIN.3 through the helper both paths call.
#[tokio::test]
async fn a_drain_timeout_cancels_the_running_worker_before_the_store_closes() {
    let (url, mut arrived, release) = held_backend().await;
    let mut fixture = fixture_on((url, Arc::new(AtomicUsize::new(0))), None).await;
    let id = task_id(&dispatch(&fixture, modern_call(1, "held", "drain", true)).await);
    tokio::time::timeout(BOUND, arrived.wait_for(|seen| *seen >= 1))
        .await
        .expect("the held call reaches the backend")
        .expect("fixture alive");

    let expiry = fixture.expiry.take().expect("the fixture's expiry sweep");
    let cancelled = tokio::time::timeout(
        BOUND,
        task_runtime::shutdown(
            expiry,
            &fixture.tasks.executor,
            &fixture.tasks.service,
            ShutdownBudget::within(Duration::from_secs(10), Duration::from_secs(1)),
        ),
    )
    .await
    .expect("shutdown is bounded");

    assert_eq!(
        cancelled,
        Some(CancelOutcome {
            cancelled: 1,
            stopped: true,
        }),
        "the drain ran out, so the one running worker is cancelled and gone"
    );
    assert!(
        fixture
            .tasks
            .executor
            .drain(Duration::ZERO)
            .await
            .is_clean(),
        "no worker of the shut-down executor still holds its task"
    );

    let (service, _executor) = reopen(&store_config(fixture.store.path()))
        .await
        .expect("the lease is free once shutdown returned");
    assert_recovered_and_left_alone(&service, &id, &release).await;
}

/// DRAIN.4, the stdio EOF path end to end: EOF with a task whose backend
/// call outlasts the drain cancels it, says so in the log, and returns with
/// the store lease released.
#[test]
fn stdio_eof_cancels_a_task_that_outlasts_the_drain() {
    let records = crate::test_log_capture::records(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(eof_with_a_held_task());
    });
    let cancelled: Vec<_> = records
        .iter()
        .filter(|r| {
            r["fields"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("cancelled the remaining tasks"))
        })
        .collect();
    assert_eq!(cancelled.len(), 1, "one cancellation record: {records:#?}");
    assert_eq!(cancelled[0]["level"], "WARN", "{:#}", cancelled[0]);
    assert_eq!(cancelled[0]["fields"]["cancelled"], 1, "{:#}", cancelled[0]);
    assert_eq!(
        cancelled[0]["fields"]["all_stopped"], true,
        "{:#}",
        cancelled[0]
    );
}

async fn eof_with_a_held_task() {
    let (url, mut arrived, release) = held_backend().await;
    let store = tempfile::tempdir().expect("store root");
    let mut config = store_config(store.path());
    config.server.shutdown_timeout = Duration::from_secs(1);
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    let data = tempfile::tempdir().expect("data dir");
    let gateway = Gateway::new(config.clone())
        .await
        .expect("gateway boots")
        .with_data_dir(data.path().to_path_buf());
    let (mut stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut lines = BufReader::new(reader).lines();
    let handshake = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "drain", "version": "1"}}});
    for request in [handshake, modern_call(1, "held", "eof-drain", true)] {
        stdin
            .write_all(format!("{request}\n").as_bytes())
            .await
            .expect("write");
    }
    let mut id = None;
    while id.is_none() {
        let line = tokio::time::timeout(BOUND, lines.next_line())
            .await
            .expect("answered in time")
            .expect("read")
            .expect("a line");
        let answer: Value = serde_json::from_str(&line).expect("one frame");
        if answer.get("id") == Some(&json!(1)) {
            id = Some(task_id(&answer));
        }
    }
    let id = id.expect("the task answer");
    tokio::time::timeout(BOUND, arrived.wait_for(|seen| *seen >= 1))
        .await
        .expect("the held call reaches the backend")
        .expect("fixture alive");
    drop(stdin);

    tokio::time::timeout(Duration::from_secs(20), served)
        .await
        .expect("EOF returns inside its teardown window")
        .expect("no panic")
        .expect("run_stdio_on returns Ok");

    let (service, _executor) = reopen(&config)
        .await
        .expect("the lease is free once run_stdio_on returned");
    assert_recovered_and_left_alone(&service, &id, &release).await;
}

#[test]
fn the_stdio_budget_fits_inside_the_teardown_window() {
    let tight = ShutdownBudget::within(Duration::from_secs(10), Duration::from_secs(30));
    assert_eq!(
        tight,
        ShutdownBudget {
            drain: Duration::from_secs(8),
            cancel: Duration::from_secs(1),
            close: Duration::from_secs(1),
        },
        "a drain longer than the window leaves room to cancel and close"
    );
    let roomy = ShutdownBudget::within(Duration::from_secs(40), Duration::from_secs(1));
    assert_eq!(roomy.drain, Duration::from_secs(1), "a short drain is kept");
    let http = ShutdownBudget::within(Duration::from_secs(30), Duration::from_secs(30));
    assert_eq!(
        http,
        ShutdownBudget {
            drain: Duration::from_secs(24),
            cancel: Duration::from_secs(3),
            close: Duration::from_secs(3),
        },
        "HTTP: drain and cancel stay within nine tenths of one timeout"
    );
}
