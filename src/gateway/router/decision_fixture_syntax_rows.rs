// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Syntax rows on `/mcp` (part 3b-1 of the decision fixture table): the
//! authorizer's name check (`router/authorization.rs:379`) and the malformed
//! retry fields (`meta_refusal_audit.rs:128`).

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::super::direct_guards_fixture::{Fx, post_meta_invoke, send};
use super::{Form, Refusal, records, refusal, refused, table};
use crate::gateway::meta_mcp::grant_audit_fixture::entries;
use crate::security::decision_fixture_table::{DecisionRow, assert_row};

/// A syntax refusal row: each site below notes its kind with no rule id.
const fn syntax(name: &'static str) -> DecisionRow {
    refusal(name, "syntax", "kind-only site: noted with no rule id")
}

/// The backend sends so far.
fn sends(fx: &Fx) -> usize {
    super::super::direct_continuation_tests::dispatched(fx)
}

/// S3: `gateway_invoke` naming `read.v2` on `/mcp`. The gate asks the
/// caller's authorizer before any catalogue (`gate.rs:455`, through
/// `visibility.rs:140`), and `decide_tool_target` refuses the name's shape
/// (`authorization.rs:379`): `.` is outside `[A-Za-z0-9_-]`. The gate keeps
/// that refusal's code and pair (`gate.rs:459`) and answers the withheld
/// name as an absent one, an `isError` result on a 200; the record is
/// `denied` with the kept -32600 (`denial.rs:45-48`) and the kept pair
/// (`meta_mcp/invoke/audit.rs:604-615`). Reached on the meta route only: on the direct route
/// `backend_handlers.rs:140-142` (S6) refuses the name first.
#[tokio::test]
async fn s3_meta_invalid_tool_name_at_the_authorizer() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let fx = table(&dir).await;
    let base = (records(&dir).len(), sends(&fx));
    let answer = post_meta_invoke(&fx, "k-std", "alpha", "read.v2", json!({}), None, None).await;
    let withheld = Refusal {
        status: StatusCode::OK,
        form: Form::IsErrorResult,
        outcome: "denied",
        code: Some(-32600),
    };
    let decision = refused(&fx, &dir, answer, base, withheld);
    assert_row(
        &decision,
        &syntax("s3_meta_invalid_tool_name_at_the_authorizer"),
    );
}

/// Log entries carrying a decision, whether or not they name a tool.
fn decided(dir: &tempfile::TempDir) -> Vec<Value> {
    entries(dir)
        .into_iter()
        .filter(|e| e.get("decision").is_some())
        .collect()
}

/// S17: a `/mcp` `tools/call` whose `requestState` is not a string
/// (`mrtr.rs:274-279`) is refused before any target is resolved, by
/// `answer_malformed` (`dispatch_tools_call.rs:133-140`). No gate has noted a
/// kind yet, so the record takes the site's own `syntax`
/// (`meta_refusal_audit.rs:128`, applied at `:327-331`), `invalid` with
/// -32602, answered 400. The record names no server and no tool, so it is
/// found by its decision, not through `records`.
#[tokio::test]
async fn s17_meta_malformed_retry_fields() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let fx = table(&dir).await;
    let earlier = decided(&dir).len();
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
        "requestState": 5,
    });
    let (status, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the answer's status: {body}"
    );
    assert_eq!(body["error"]["code"], -32602, "the answer's code: {body}");
    assert_eq!(sends(&fx), 0, "the backend was sent the call: {body}");
    let new = decided(&dir).split_off(earlier);
    let [record] = new.as_slice() else {
        panic!("premise: one new record with a decision: {new:?}; answer {body}");
    };
    assert_eq!(record["outcome"], "invalid", "{body}: {record}");
    assert_eq!(record["error_code"], -32602, "{body}: {record}");
    // Refused before any target was resolved: the record names none, and no
    // tenant was attributed.
    assert_eq!(
        record["server"].as_str().unwrap_or_default(),
        "",
        "{record}"
    );
    assert!(record.get("tool").is_none_or(Value::is_null), "{record}");
    assert!(record.get("tenants").is_none(), "{record}");
    assert!(record.get("tenants_total").is_none(), "{record}");
    assert_row(
        &record["decision"],
        &syntax("s17_meta_malformed_retry_fields"),
    );
}
