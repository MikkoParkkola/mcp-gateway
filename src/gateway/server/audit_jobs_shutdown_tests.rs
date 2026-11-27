// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D2.5 at the gateway: a `/mcp` request dropped at the listener's deadline
//! hands its invocation record off as it drops, and `run`'s shutdown waits
//! for that write before it returns.
//!
//! The request is parked at its commit (after its record was built, before
//! it is written), so only its drop can write the record. The handed-off
//! write is held at a gate the row opens only once a drain is waiting with
//! that job open: a drain that ran before the request was dropped (the
//! wrong order) sees no job, the gate stays shut, and no record lands.

use std::sync::atomic::Ordering;
use std::time::Duration;

/// A gateway whose stop is the smallest a listener grace fits in, so the
/// parked request is dropped at that grace's deadline, not by the row; its
/// audit log at `log`, its task store under `dir`.
fn gateway_config(dir: &std::path::Path, log: &std::path::Path) -> crate::config::Config {
    let mut built = crate::config::Config::default();
    built.server.shutdown_timeout = Duration::from_secs(14);
    built.server.port = 0;
    built.server.host = "127.0.0.1".to_string();
    built.security.transparency_log.enabled = Some(true);
    built.security.transparency_log.path = log.display().to_string();
    built.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
    built
}

/// A `gateway_invoke` of a backend no config names, in flight on its own
/// task: it is dispatched, fails, and its one invocation record is built and
/// held for the commit. The task ends when the gateway drops the request.
fn invoke_in_flight(port: u16) -> tokio::task::JoinHandle<()> {
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": "ghost", "tool": "t", "arguments": {}}}
    });
    tokio::spawn(async move {
        let _ = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}/mcp"))
            .header("accept", "application/json, text/event-stream")
            .json(&call)
            .send()
            .await;
    })
}

#[tokio::test]
async fn a_record_handed_off_at_the_listener_deadline_lands_before_shutdown_ends() {
    let minute = Duration::from_secs(60);
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = dir.path().join("audit.log");
    let mut gateway = super::super::Gateway::new(gateway_config(dir.path(), &log))
        .await
        .expect("gateway")
        .with_data_dir(dir.path().to_path_buf());
    let bound = gateway.bound_port_for_test();
    let jobs = gateway.audit_jobs_for_test();
    let trigger = gateway.shutdown_trigger_for_test();
    let mut server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let port = tokio::time::timeout(minute, bound)
        .await
        .expect("the gateway binds")
        .expect("the gateway reports its port");
    let jobs = jobs.await.expect("run hands over its audit jobs");
    jobs.seams.hold_commit.store(true, Ordering::SeqCst);
    jobs.seams.gate_jobs.store(true, Ordering::SeqCst);

    let client = invoke_in_flight(port);
    tokio::time::timeout(minute, jobs.seams.parked.notified())
        .await
        .expect("the request reaches its commit");
    trigger.send(()).expect("run still holds the trigger");

    let ended = loop {
        tokio::select! {
            () = jobs.seams.draining.notified() => {
                let open = jobs.seams.drains.lock().expect("drains").last().copied();
                if open.is_some_and(|open| open > 0) {
                    jobs.seams.job_gate.notify_one();
                }
            }
            ended = &mut server => break ended,
        }
    };
    let ended = ended.expect("run does not panic");
    assert!(ended.is_ok(), "a graceful shutdown returns Ok: {ended:?}");
    let drains = jobs.seams.drains.lock().expect("drains").clone();
    assert_eq!(
        drains,
        vec![1],
        "one drain, after the request dropped, with its handed-off job open"
    );
    let records: Vec<serde_json::Value> = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .filter(|entry: &serde_json::Value| entry.get("request_hash").is_some())
        .collect();
    assert!(
        records.iter().any(|record| record["server"] == "ghost"),
        "the handed-off record landed before run returned: {records:?}"
    );
    client.abort();
}
