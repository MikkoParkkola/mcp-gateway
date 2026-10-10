// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7839.CANCEL.3: an embedder that drops the `run_stdio_on` future before
//! EOF stops its task workers. None of them goes on to commit, and the store's
//! lease is free once the dropped future's last holder lets go.
//!
//! Observed from outside: the backend answers after the drop, and the store,
//! reopened, shows whether a worker was still there to commit that answer.

use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::owner2_stdio_tasks::{BACKEND, held_backend, modern_call, reopen};
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL;

/// T2 x dropped future (teardown family matrix): a task is mid-call when the
/// session future is dropped. The backend then answers, but no worker is left
/// to commit it: the task is never completed with the backend's result.
#[tokio::test]
async fn a_dropped_stdio_session_stops_its_task_workers() {
    let (url, mut arrived, release) = held_backend().await;
    let store = tempfile::tempdir().expect("store root");
    let mut config = Config::default();
    config.tasks.store_dir = store.path().display().to_string();
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
    let handshake = serde_json::json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "cancel3", "version": "1"}}});
    stdin
        .write_all(format!("{handshake}\n").as_bytes())
        .await
        .expect("write");
    tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("handshake answered in time")
        .expect("read");
    let created = modern_call(1, "held", "cancel3", true);
    stdin
        .write_all(format!("{created}\n").as_bytes())
        .await
        .expect("write");
    let answer = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("answered in time")
        .expect("read")
        .expect("a line");
    let answer: Value = serde_json::from_str(&answer).expect("one frame");
    let id = answer
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a task handle: {answer}"))
        .to_owned();
    tokio::time::timeout(Duration::from_secs(10), arrived.wait_for(|seen| *seen >= 1))
        .await
        .expect("the held call reaches the backend")
        .expect("fixture alive");

    // The embedder drops the session future before EOF.
    served.abort();
    assert!(
        served.await.is_err_and(|e| e.is_cancelled()),
        "the session future was dropped, not finished"
    );
    // The backend answers now. A worker still running would commit `done`.
    release.send_modify(|open| *open = true);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Custody is free once the dropped future's holders are gone: no worker
    // keeps the store. Polled for up to 5 s, so a slow runner only waits.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let (service, _executor) = loop {
        match reopen(&config).await {
            Ok(opened) => break opened,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("the dropped session still holds the store: {error:?}"),
        }
    };
    let task = service
        .get(LOCAL_OPERATOR_PRINCIPAL, &id)
        .expect("the task is in its store");
    let wire = serde_json::to_value(task.task.wire()).expect("the task serializes");
    let committed_answer = task.task.status() == crate::protocol::tasks::TaskStatus::Completed
        && wire.pointer("/result/content/0/text") == Some(&Value::from("done"));
    assert!(
        !committed_answer,
        "a worker outlived the dropped session and committed the backend's answer: {wire}"
    );
    drop(stdin);
}

/// The guard itself seals the executor. The row above cannot see the seal:
/// `stop_serving` alone already refuses the late commit, so a guard that only
/// stopped the store passed it (mutant m02 survived). Here the executor is
/// observed directly.
#[tokio::test]
async fn dropping_the_tasks_guard_seals_the_executor() {
    let store = tempfile::tempdir().expect("store root");
    let mut config = Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    let (service, executor) = reopen(&config).await.expect("the store opens");
    let guard = super::super::stdio_tasks::TasksDropGuard::new(&executor, &service);
    assert!(!executor.is_sealed(), "precondition: serving");
    drop(guard);
    assert!(
        executor.is_sealed(),
        "the dropped guard sealed the executor"
    );
}
