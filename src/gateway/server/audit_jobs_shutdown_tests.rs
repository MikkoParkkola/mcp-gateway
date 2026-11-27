// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D2.5 at the gateway: `run`'s shutdown waits for every record write handed
//! off by a request that no longer awaits it, both one dropped at the
//! listener's deadline and one handed off by a request still finishing after
//! the listener returned.
//!
//! A `/mcp` request is parked at its commit (after its record was built,
//! before it is written), so only its drop at the deadline can write the
//! record (job A). The row also holds one in-flight permit, a request still
//! finishing; once the in-flight drain waits on it, the row hands off job B
//! and lets the permit go. Every handed-off write is held at a gate the row
//! opens only when a drain reports a job open. Drained in order, the one audit
//! drain sees both jobs; drained before the in-flight requests (the wrong
//! order), it sees only A and returns before B is handed off.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// The shared run-level config, with the smallest stop a listener grace fits
/// in (so the parked request is dropped at that grace's deadline, not by the
/// row) and its audit log at `log`.
fn config(dir: &std::path::Path, log: &std::path::Path) -> crate::config::Config {
    let mut config = super::super::http_test_config::http_test_config(dir);
    config.server.shutdown_timeout = Duration::from_secs(14);
    config.security.transparency_log.enabled = Some(true);
    config.security.transparency_log.path = log.display().to_string();
    config
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
    let mut gateway = super::super::Gateway::new(config(dir.path(), &log))
        .await
        .expect("gateway")
        .with_data_dir(dir.path().to_path_buf());
    let bound = gateway.bound_port_for_test();
    let jobs = gateway.audit_jobs_for_test();
    let inflight = gateway.inflight_for_test();
    let trigger = gateway.shutdown_trigger_for_test();
    let mut server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let port = tokio::time::timeout(minute, bound)
        .await
        .expect("the gateway binds")
        .expect("the gateway reports its port");
    let jobs = jobs.await.expect("run hands over its audit jobs");
    let inflight = inflight.await.expect("run hands over its in-flight gate");
    jobs.seams.hold_commit.store(true, Ordering::SeqCst);
    jobs.seams.gate_jobs.store(true, Ordering::SeqCst);

    let client = invoke_in_flight(port);
    tokio::time::timeout(minute, jobs.seams.parked.notified())
        .await
        .expect("the request reaches its commit");
    let mut finishing = Some(
        Arc::clone(&inflight)
            .acquire_owned()
            .await
            .expect("the gate is open before shutdown"),
    );
    let job_b = Arc::new(AtomicBool::new(false));
    trigger.send(()).expect("run still holds the trigger");

    let ended = loop {
        tokio::select! {
            () = jobs.seams.draining.notified() => {
                let open = jobs.seams.drains.lock().expect("drains").last().copied();
                if open.is_some_and(|open| open > 0) {
                    jobs.seams.open_gate();
                }
            }
            // The in-flight drain holds every permit but the row's: the
            // still-finishing request hands its write off, then ends. Polled,
            // as the drain gives no signal of its own.
            () = tokio::time::sleep(Duration::from_millis(5)), if finishing.is_some() => {
                if inflight.available_permits() == 0 {
                    let landed = Arc::clone(&job_b);
                    Arc::clone(&jobs).spawn(async move { landed.store(true, Ordering::SeqCst) });
                    finishing = None;
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
        vec![2],
        "one audit drain, after the in-flight one, with both handed-off jobs open"
    );
    assert!(
        job_b.load(Ordering::SeqCst),
        "the late hand-off landed before run returned"
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
