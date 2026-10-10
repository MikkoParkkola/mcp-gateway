// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D3-a slot machinery: the selection rule (T21), the unslotted fallback and
//! its test guard (T15, T16, T26), and the bounded slot-close write (T25).

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::grant_audit::{GrantNote, allow_unslotted_check_for_test, select_records};
use super::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, capability_backend, decisions, grant, grants, logger, stall_log,
};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::RequestId;
use crate::security::audit::AuditFailurePolicy;

const ALICE: (&str, &str) = ("api_key", "alice");

fn note(server: &str, tool: &str, trace: Option<&str>, allowed: bool) -> GrantNote {
    GrantNote {
        server: server.to_string(),
        tool: tool.to_string(),
        trace_id: trace.map(str::to_string),
        allowed,
        fields: serde_json::Map::new(),
        subject: None,
        repeat: None,
    }
}

fn invoke_args() -> Value {
    json!({ "server": CAPS, "tool": PERSONAL, "arguments": {} })
}

/// T21. The selection rule, one row per clause.
#[test]
fn selection_rule_table() {
    // (a) untraced then traced, same key: the traced one.
    let a = [
        note("s", "t", None, true),
        note("s", "t", Some("tr-1"), true),
    ];
    assert_eq!(select_records(&a), vec![&a[1]], "(a)");
    // (b) two untraced, same key, deny then allow: the last, which decided.
    let b = [note("s", "t", None, false), note("s", "t", None, true)];
    assert_eq!(select_records(&b), vec![&b[1]], "(b)");
    // (c) mixed keys: one selection per key, keyed on server and tool.
    let c = [
        note("s1", "t", None, false),
        note("s2", "t", None, true),
        note("s1", "u", None, true),
    ];
    let selected = select_records(&c);
    assert_eq!(selected.len(), 3, "(c) {selected:?}");
    for row in &c {
        assert!(
            selected.contains(&row),
            "(c) {row:?} missing from {selected:?}"
        );
    }
    // (d) two traced, same key: both.
    let d = [
        note("s", "t", Some("tr-1"), true),
        note("s", "t", Some("tr-2"), true),
    ];
    assert_eq!(select_records(&d), vec![&d[0], &d[1]], "(d)");
}

/// Wait, bounded, for the log to hold `count` decision records.
async fn wait_for_decisions(dir: &tempfile::TempDir, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = decisions(dir);
        if found.len() >= count || Instant::now() >= deadline {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// T15. A check outside every slot refuses with -32005 and still leaves
/// the decision's record, written on a spawned task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unslotted_check_refuses_and_still_records() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = Endpoint::start(false).await;
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::BestEffort);
    let who = api_key("alice");
    let _allowed = allow_unslotted_check_for_test();

    let refusal = meta
        .check_invocation_policy(&invoke_args(), Some("d3a-session"), &context(&who))
        .expect_err("an unslotted check fails closed, whatever the grant says");
    assert_eq!(refusal.to_rpc_code(), -32005, "{refusal}");
    let records = wait_for_decisions(&dir, 1).await;
    assert_eq!(records.len(), 1, "{records:#?}");
}

/// T15b. The same unslotted check on a stalled log: the refusal comes at
/// once and the spawned record write takes the bounded path, refused under
/// the stall rather than pinning a thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unslotted_check_on_stalled_log_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = Endpoint::start(false).await;
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::BestEffort);
    let log = meta
        .transparency_logger
        .clone()
        .expect("the gateway has a log");
    let release = stall_log(&log).await;
    let who = api_key("alice");
    let _allowed = allow_unslotted_check_for_test();

    let refusal = meta
        .check_invocation_policy(&invoke_args(), Some("d3a-session"), &context(&who))
        .expect_err("an unslotted check fails closed");
    assert_eq!(refusal.to_rpc_code(), -32005, "{refusal}");
    let deadline = Instant::now() + Duration::from_secs(2);
    while log.refused_under_stall_for_test() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    release();
    assert!(
        log.refused_under_stall_for_test() >= 1,
        "the spawned record write went through the bounded path"
    );
}

/// T16 (control of the guard). Without the opt-in, an unslotted check
/// panics under test, so a missed caller reds in CI.
#[tokio::test]
#[should_panic(expected = "slot")]
async fn unslotted_check_panics_under_test() {
    let dir = tempfile::tempdir().unwrap();
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_identity_grants(grants(vec![grant("g1", ALICE, ALICE)]));
    meta.enable_transparency_log(logger(&dir, AuditFailurePolicy::BestEffort));
    meta.set_capabilities(capability_backend(9, ALICE));
    let who = api_key("alice");

    let _ = meta.check_invocation_policy(&invoke_args(), Some("d3a-session"), &context(&who));
}

/// A writer the thread-local subscriber in T26 fills.
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// T26. Off every runtime, an unslotted check still refuses with -32005,
/// does not panic, and logs the lost record at `error!`.
#[tokio::test]
async fn off_runtime_unslotted_check_refuses_without_panic() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = Endpoint::start(false).await;
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = Arc::new(gateway(
        &endpoint,
        rows,
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    ));

    let worker = Arc::clone(&meta);
    let (code, log) = std::thread::spawn(move || {
        let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&buffer);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::ERROR)
            .with_writer(move || Captured(Arc::clone(&sink)))
            .finish();
        // A callsite another thread cached as off would miss this capture (MIK-8254).
        crate::test_log_capture::keep_interest_open();
        let code = tracing::subscriber::with_default(subscriber, || {
            let _allowed = allow_unslotted_check_for_test();
            let who = api_key("alice");
            worker
                .check_invocation_policy(&invoke_args(), Some("d3a-session"), &context(&who))
                .err()
                .map(|error| error.to_rpc_code())
        });
        let log =
            String::from_utf8(buffer.lock().expect("capture lock").clone()).unwrap_or_default();
        (code, log)
    })
    .join()
    .expect("the off-runtime check must not panic");
    assert_eq!(code, Some(-32005), "off-runtime unslotted check");
    assert!(log.contains("ERROR"), "the lost record is logged: {log:?}");
}

/// The append bound T25 arms the log with.
const APPEND_BOUND: Duration = Duration::from_millis(200);

/// T25. A two-step `gateway_execute` chain on the personal capability; the
/// log stalls after step 1's invocation append (so `log.admit` has long
/// passed) and before the slot closes. Step 2's own append stalls and fails,
/// which today the chain reports as -32603. The slot-close decision write
/// must find the stalled log and answer -32005 within the bound, never pin
/// a runtime thread on a synchronous append. The wait is bounded by a
/// watchdog on a separate `std::thread`, outside every runtime.
#[test]
fn stalled_log_bounds_the_decision_write() {
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the scenario runtime builds");
        let outcome = runtime.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let endpoint = Arc::new(Endpoint::start(true).await);
            let log = logger(&dir, AuditFailurePolicy::FailClosed);
            let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
                .with_identity_grants(grants(vec![grant("g1", ALICE, ALICE)]))
                .with_code_mode(true);
            meta.enable_transparency_log(Arc::clone(&log));
            meta.set_capabilities(capability_backend(endpoint.port, ALICE));
            let meta = Arc::new(meta);
            let step = json!({ "tool": format!("{CAPS}:{PERSONAL}"), "arguments": {} });
            let chain = json!({ "chain": [step.clone(), step] });
            let call = tokio::spawn({
                let meta = Arc::clone(&meta);
                async move {
                    let who = api_key("alice");
                    let response = Box::pin(meta.handle_tools_call(
                        RequestId::Number(1),
                        "gateway_execute",
                        chain,
                        Some("d3a-session"),
                        context(&who),
                    ))
                    .await;
                    serde_json::to_value(&response).expect("a response serialises")
                }
            });
            endpoint.wait_for_arrivals(1).await;
            endpoint.release_one();
            endpoint.wait_for_arrivals(2).await;
            let gate = log.stall_next_write_for_test(APPEND_BOUND);
            endpoint.release_one();
            // The gate opens only after the call answers, so a decision write
            // that waited on the stall never answers: the hang guard below
            // fails it, and `refused` names the bounded path (MIK-8222).
            let answer = call.await.expect("the call task completes");
            gate.release();
            (answer, log.refused_under_stall_for_test())
        });
        let _ = sent.send(outcome);
    });
    let (answer, refused) = received
        .recv_timeout(Duration::from_secs(10))
        .expect("the call must answer: a stalled decision write pinned the scenario");
    assert_eq!(
        answer.pointer("/error/code").and_then(Value::as_i64),
        Some(-32005),
        "{answer}"
    );
    assert!(
        refused >= 1,
        "the slot-close decision write took the bounded path and was refused under the stall"
    );
}

/// MIK-7663.GH2409.3. A failed decision write replaces an HTTP answer with
/// -32005 under the id the request recorded in its slot, so the replaced
/// answer is never read back, however large; with no id recorded the
/// refusal carries a null id, even when the answer names one.
#[tokio::test]
async fn http_refusal_carries_the_recorded_id_without_reading_the_answer() {
    const PAST_ANY_READ: usize = 16 * 1024 * 1024 + 1;
    for (recorded, padding, expected_id) in [
        (Some(RequestId::Number(7)), PAST_ANY_READ, json!(7)),
        (None, 16, Value::Null),
    ] {
        let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
        let log = logger(&dir, AuditFailurePolicy::FailClosed);
        let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
            .with_identity_grants(grants(vec![grant("g1", ALICE, ALICE)]));
        meta.enable_transparency_log(Arc::clone(&log));
        meta.set_capabilities(capability_backend(endpoint.port, ALICE));
        log.fail_next_append_of_kind_for_test(super::grant_audit_fixture::DECISION_KIND);
        let who = api_key("alice");
        let answer = json!({ "jsonrpc": "2.0", "id": 7, "result": { "pad": "x".repeat(padding) } });

        let response = super::grant_audit::slot_http(Some(Arc::clone(&log)), async {
            super::grant_audit::note_answer_id(recorded.as_ref());
            meta.check_invocation_policy(&invoke_args(), Some("d3a-session"), &context(&who))
                .expect("alice holds the grant");
            axum::Json(answer)
        })
        .await;

        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let refusal: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(refusal["error"]["code"], json!(-32005), "{refusal}");
        assert_eq!(
            refusal["id"], expected_id,
            "recorded {recorded:?}: {refusal}"
        );
    }
}
