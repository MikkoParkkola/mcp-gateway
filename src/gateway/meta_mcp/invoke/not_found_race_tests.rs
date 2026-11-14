// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call to a missing backend records `not_found` only when the backend is
//! missing both where the gate judged the name and where the dispatch
//! resolves it. A reload between the two moves the record with the call: a
//! backend lost after the gate saw it records the plain error, and one
//! registered after the gate missed it is dispatched and records its own
//! outcome. The window is the dispatch seam's (`before_dispatch_resolution`).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::dispatch_seam::before_dispatch_resolution;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, register_answering};
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;

const OK: &str = r#"{"content": [{"type": "text", "text": "ok"}], "isError": false}"#;

/// A gateway over `alpha` (counted) with a log in `dir`.
fn logged(dir: &tempfile::TempDir) -> (MetaMcp, Arc<std::sync::atomic::AtomicUsize>) {
    let (registry, calls) = counted_backend("alpha");
    let logger = crate::security::TransparencyLogger::open(Arc::new(
        crate::security::TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "nf".to_string(),
            ..crate::security::TransparencyLogConfig::default()
        },
    ))
    .expect("open log");
    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(Arc::new(logger));
    (meta, calls)
}

/// The invocation records in `dir`, oldest first.
fn records(dir: &tempfile::TempDir) -> Vec<Value> {
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e.get("tool").is_some())
        .filter(|e| e["event"] != "response_delivery_attempt")
        .collect()
}

/// `server`'s `read`, as one request (inside its own visibility memo).
async fn call(meta: &MetaMcp, server: &str) -> String {
    let args = json!({"server": server, "tool": "read", "arguments": {}});
    let answer = with_visibility_memo(meta.invoke_tool(&args, None, &ctx(&AllowAll))).await;
    format!("{answer:?}")
}

/// Control: the gate saw `alpha`, and a reload removed it before the
/// dispatch resolved. The call misses as before and records the plain error,
/// never `not_found`: the gate judged a backend that existed.
#[tokio::test]
async fn a_backend_lost_after_the_gate_saw_it_records_no_not_found() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, calls) = logged(&dir);
    let registry = Arc::clone(meta.backends.for_test());
    let _armed = before_dispatch_resolution(move || {
        assert!(registry.remove("alpha"), "premise: alpha was registered");
    });
    let answer = call(&meta, "alpha").await;
    assert!(
        answer.contains("Backend not found: alpha"),
        "premise: {answer}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "premise: nothing was sent");
    let all = records(&dir);
    let [record] = all.as_slice() else {
        panic!("one record: {all:?}");
    };
    assert_ne!(record["decision"]["kind"], "not_found", "{record}");
    assert_eq!(record["outcome"], json!("error"), "{record}");
}

/// Control: the gate found `beta` unregistered, and a reload registered it
/// before the dispatch resolved. The call is dispatched and records its own
/// outcome, never `not_found`.
#[tokio::test]
async fn a_backend_registered_after_the_gate_missed_it_records_no_not_found() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = logged(&dir);
    let registry = Arc::clone(meta.backends.for_test());
    let beta_calls = Arc::new(std::sync::Mutex::new(None));
    let seen = Arc::clone(&beta_calls);
    let _armed = before_dispatch_resolution(move || {
        let calls = register_answering(&registry, "beta", serde_json::from_str(OK).expect("ok"));
        *seen.lock().expect("lock") = Some(calls);
    });
    let answer = call(&meta, "beta").await;
    let calls = beta_calls
        .lock()
        .expect("lock")
        .clone()
        .expect("premise: the seam fired and registered beta");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "premise: the call was dispatched to beta: {answer}"
    );
    let all = records(&dir);
    let [record] = all.as_slice() else {
        panic!("one record: {all:?}");
    };
    assert_ne!(record["decision"]["kind"], "not_found", "{record}");
    assert_eq!(record["outcome"], json!("ok"), "{record}");
}

/// Control: two calls on the same pair in one request, the first missed at
/// the gate and dispatched after a reload registered it, the second seen
/// by the gate and lost before its dispatch. Neither records `not_found`:
/// a mark is the invocation's own.
#[tokio::test]
async fn a_mark_never_reaches_a_later_call_on_the_same_name() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = logged(&dir);
    let registry = Arc::clone(meta.backends.for_test());
    let args = json!({"server": "beta", "tool": "read", "arguments": {}});
    with_visibility_memo(async {
        let first = Arc::clone(&registry);
        let armed = before_dispatch_resolution(move || {
            let _ = register_answering(&first, "beta", serde_json::from_str(OK).expect("ok"));
        });
        let _ = meta.invoke_tool(&args, None, &ctx(&AllowAll)).await;
        drop(armed);
        let second = Arc::clone(&registry);
        let _armed = before_dispatch_resolution(move || {
            assert!(second.remove("beta"), "premise: beta was registered");
        });
        let _ = meta.invoke_tool(&args, None, &ctx(&AllowAll)).await;
    })
    .await;
    let all = records(&dir);
    assert_eq!(all.len(), 2, "one record per call: {all:?}");
    for record in &all {
        assert_ne!(record["decision"]["kind"], "not_found", "{record}");
    }
}

/// A miss, then a reload registers the backend, then a call on the same name
/// in the same request: the second call dispatches and records its own
/// outcome, never the first call's `not_found`.
#[tokio::test]
async fn a_miss_does_not_label_a_later_successful_call() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = logged(&dir);
    let registry = Arc::clone(meta.backends.for_test());
    let args = json!({"server": "beta", "tool": "read", "arguments": {}});
    with_visibility_memo(async {
        let _ = meta.invoke_tool(&args, None, &ctx(&AllowAll)).await;
        let _ = register_answering(&registry, "beta", serde_json::from_str(OK).expect("ok"));
        let _ = meta.invoke_tool(&args, None, &ctx(&AllowAll)).await;
    })
    .await;
    let all = records(&dir);
    let [missed, served] = all.as_slice() else {
        panic!("one record per call: {all:?}");
    };
    assert_eq!(missed["decision"]["kind"], "not_found", "premise: {missed}");
    assert_ne!(served["decision"]["kind"], "not_found", "{served}");
    assert_eq!(served["outcome"], json!("ok"), "{served}");
}
