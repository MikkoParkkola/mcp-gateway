// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision fixture table, HTTP rows: one concrete call per decider site
//! on the direct route (`/mcp/{backend}`) and the meta route's HTTP gate
//! (`/mcp`), each pinning its whole decision with `assert_row`.
//!
//! What every refusal row pins, read at 01aa22f2cc:
//! - `rule_id` absent: each site below notes its kind with `None`.
//! - `grant_id` absent: the decision constructor sets `grant_id: None`
//!   (`decision_record.rs:304`); flipped when a writer of the decision's
//!   grant id lands.
//! - findings `NotRun`: no production writer of `request_findings` yet;
//!   flipped when the request-findings writer lands.
//! - no effect: an effect is noted only after admission.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture_logged, post_direct, post_meta_invoke};
use crate::gateway::meta_mcp::grant_audit_fixture::{entries, logger};
use crate::security::audit::AuditFailurePolicy;
use crate::security::decision_fixture_table::{DecisionRow, Findings, RuleId, assert_row};

/// How a refused call is answered to its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// A `result` with `isError: true`.
    IsErrorResult,
    /// A JSON-RPC `error`.
    RpcError,
}

/// What a refusal row expects of the call's answer and record, each value
/// read from the source line its row cites.
#[derive(Debug, Clone, Copy)]
struct Refusal {
    status: StatusCode,
    form: Form,
    /// The record's `outcome`.
    outcome: &'static str,
    /// The record's `error_code`; `None` requires the key absent.
    code: Option<i64>,
}

/// A table gateway logging both routes to `dir`.
async fn table(dir: &Arc<tempfile::TempDir>) -> Fx {
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let meta_log = Arc::clone(&log);
    fixture_logged(Answer::Ok, log, |mut meta| {
        meta.enable_transparency_log(meta_log);
        meta
    })
    .await
}

/// The invocation records in `dir`'s log: entries naming a tool that are not
/// delivery attempts.
fn records(dir: &tempfile::TempDir) -> Vec<Value> {
    entries(dir)
        .into_iter()
        .filter(|e| e.get("tool").is_some() && e["event"] != "response_delivery_attempt")
        .collect()
}

/// Checks a refused call's `(status, body)` and its one new record against
/// `want`, and that the backend was sent nothing; returns the decision.
fn refused(
    fx: &Fx,
    dir: &tempfile::TempDir,
    (status, body): (StatusCode, Value),
    (before, sent): (usize, usize),
    want: Refusal,
) -> Value {
    assert_eq!(status, want.status, "the answer's status: {body}");
    let form = if body.get("error").is_some() {
        Form::RpcError
    } else {
        assert_eq!(body["result"]["isError"], true, "premise: refused: {body}");
        Form::IsErrorResult
    };
    assert_eq!(form, want.form, "the answer's form: {body}");
    assert_eq!(
        super::direct_continuation_tests::dispatched(fx),
        sent,
        "the backend was sent the call: {body}"
    );
    let mut all = records(dir);
    let new = all.split_off(before);
    let [record] = new.as_slice() else {
        panic!("premise: one new invocation record: {new:?}; answer {body}");
    };
    assert_eq!(record["outcome"], want.outcome, "{body}: {record}");
    assert_eq!(
        record.get("error_code").and_then(Value::as_i64),
        want.code,
        "{body}: {record}"
    );
    if want.code.is_none() {
        assert!(record.get("error_code").is_none(), "{body}: {record}");
    }
    record["decision"].clone()
}

/// A refusal row: `kind` at a kind-only site, nothing else recorded.
const fn refusal(name: &'static str, kind: &'static str, absent: &'static str) -> DecisionRow {
    DecisionRow {
        name,
        kind,
        rule_id: RuleId::Absent(absent),
        grant_id: None,
        findings: Findings::NotRun,
        effect: None,
        decided: "fresh",
    }
}

/// `backend_not_found` answers HTTP 404 with -32001 (`direct_caller.rs:419-425`);
/// a non-200 answer is classified by its status (`direct_audit.rs:92-93`), and
/// 404 reads as `invalid` with the body's code (`audit.rs:130`).
const NOT_FOUND: Refusal = Refusal {
    status: StatusCode::NOT_FOUND,
    form: Form::RpcError,
    outcome: "invalid",
    code: Some(-32001),
};

/// N4: a scoped key names a backend in its grant that is not registered; the
/// scoped view's absence notes `not_found` (`direct_caller.rs:345`, via
/// `note_absent`, `:257`).
#[tokio::test]
async fn n4_direct_not_found_in_a_scoped_view() {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let before = (
        records(&dir).len(),
        super::direct_continuation_tests::dispatched(&fx),
    );
    let answer = post_direct(&fx, "ghost", "k-alpha-ghost", "read", json!({}), None, None).await;
    let decision = refused(&fx, &dir, answer, before, NOT_FOUND);
    assert_row(
        &decision,
        &refusal(
            "n4_direct_not_found_in_a_scoped_view",
            "not_found",
            "the target matches nothing",
        ),
    );
}

/// N5: an unscoped key names a backend that matches nothing; `backend_for`
/// finds none (`direct_caller.rs:487`).
#[tokio::test]
async fn n5_direct_not_found_by_lookup() {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let before = (
        records(&dir).len(),
        super::direct_continuation_tests::dispatched(&fx),
    );
    let answer = post_direct(&fx, "nowhere", "k-std", "read", json!({}), None, None).await;
    let decision = refused(&fx, &dir, answer, before, NOT_FOUND);
    assert_row(
        &decision,
        &refusal(
            "n5_direct_not_found_by_lookup",
            "not_found",
            "the target matches nothing",
        ),
    );
}

/// N1: on the meta route's HTTP gate, a scoped key names a server in its
/// grant that is not registered: the gate answers the absent step
/// (`gate.rs:539` in `absent_answer`, from `gate_answer`, `gate.rs:584`). The
/// in-process `invoke_tool` skips this gate (it reaches N2's site instead).
#[tokio::test]
async fn n1_meta_not_found_at_the_gate() {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let before = (
        records(&dir).len(),
        super::direct_continuation_tests::dispatched(&fx),
    );
    let answer =
        post_meta_invoke(&fx, "k-alpha-ghost", "ghost", "read", json!({}), None, None).await;
    // The gate's absent answer is an `isError` result naming the tool as
    // unlisted (`gate.rs:544-545`), on a 200; a result reads as `tool_error`
    // with no code (`audit.rs:68-70`).
    let absent = Refusal {
        status: StatusCode::OK,
        form: Form::IsErrorResult,
        outcome: "tool_error",
        code: None,
    };
    let decision = refused(&fx, &dir, answer, before, absent);
    assert_row(
        &decision,
        &refusal(
            "n1_meta_not_found_at_the_gate",
            "not_found",
            "the target matches nothing",
        ),
    );
}
