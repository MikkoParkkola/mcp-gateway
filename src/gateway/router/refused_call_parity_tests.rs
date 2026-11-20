// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Direct route: a tools/call the caller is not allowed to see leaves the
//! same firewall state as a tools/call for a name that exists nowhere.
//!
//! Each row builds three fresh gateways. The withheld arm and the missing arm
//! each send one probe, then one call for a tool the caller can see. The
//! control sends only that visible call. On one gateway the probe and the
//! visible call present the same session id and the same caller key.
//!
//! The tenant guard is not in these rows: this fixture's firewall leaves it
//! off, and no builder turns it on. The anomaly detector can be armed, but
//! its transition tracker is a private field with no reader a router test can
//! call, so that row is not here either.

use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, Fx, fixture_firewalled_audited, fixture_firewalled_budget_built, post_direct,
};
use super::route_matrix_driver_tests::audit_events;

const BACKEND: &str = "alpha";
const SESSION: &str = "parity-session";
/// Denied to `k-deny` by name, and absent from the catalogue, so `k-std`
/// meets it as a name that exists nowhere. The two probes are the same name,
/// which is what makes the absent answers comparable.
const PROBE: &str = "gateway_invok";
/// Listed, and not on `k-deny`'s deny list, so both keys can see it.
const VISIBLE: &str = "note";
const WITHHELD_KEY: &str = "k-deny";
const OPEN_KEY: &str = "k-std";

fn absent_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{
                "type": "text",
                "text": "the backend does not list a tool named `gateway_invok`"
            }],
            "isError": true
        }
    })
}

fn allowed_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{ "type": "text", "text": "ok" }],
            "isError": false
        }
    })
}

fn budget_refusal_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32600,
            "message": "Firewall blocked: Call budget exceeded: 2 calls in the window (limit 1)"
        }
    })
}

fn assert_absent(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, &absent_body(), "{body}");
}

fn assert_allowed(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, &allowed_body(), "{body}");
}

fn assert_budget_refused(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body, &budget_refusal_body(), "{body}");
}

async fn fresh_budget(limit: usize) -> (Fx, std::sync::Arc<tempfile::TempDir>) {
    let dir = crate::test_dir_keep::kept_tempdir();
    let fx = fixture_firewalled_budget_built(
        Answer::WithNote,
        (dir.path().join("audit.jsonl"), limit),
        |meta| meta,
    )
    .await;
    (fx, dir)
}

async fn fresh_audited() -> (Fx, std::sync::Arc<tempfile::TempDir>) {
    let dir = crate::test_dir_keep::kept_tempdir();
    let fx = fixture_firewalled_audited(Answer::WithNote, dir.path().join("audit.jsonl")).await;
    (fx, dir)
}

async fn call(fx: &Fx, key: &str, tool: &str) -> (StatusCode, Value) {
    post_direct(fx, BACKEND, key, tool, json!({}), None, Some(SESSION)).await
}

/// One withheld call and one missing call each use up a budget of one, so the
/// visible call that follows is refused with the same budget answer. The
/// visible call alone is still inside the budget and is allowed.
#[tokio::test(flavor = "current_thread")]
async fn direct_withheld_and_missing_spend_one_call_budget() {
    let (withheld, _withheld_dir) = fresh_budget(1).await;
    let (probe, body) = call(&withheld, WITHHELD_KEY, PROBE).await;
    assert_absent(probe, &body);
    let (status, withheld_visible) = call(&withheld, WITHHELD_KEY, VISIBLE).await;
    assert_budget_refused(status, &withheld_visible);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 0);

    let (missing, _missing_dir) = fresh_budget(1).await;
    let (probe, body) = call(&missing, OPEN_KEY, PROBE).await;
    assert_absent(probe, &body);
    let (status, missing_visible) = call(&missing, OPEN_KEY, VISIBLE).await;
    assert_budget_refused(status, &missing_visible);
    assert_eq!(missing_visible, withheld_visible);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 0);

    let (control, _control_dir) = fresh_budget(1).await;
    let (status, body) = call(&control, OPEN_KEY, VISIBLE).await;
    assert_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

/// A budget of two is not used up by the probe. The visible call after a
/// withheld name and after a missing name is allowed, as is the visible call
/// alone. A check that always refuses the second call fails this row.
#[tokio::test(flavor = "current_thread")]
async fn direct_withheld_and_missing_do_not_spend_a_two_call_budget() {
    let (withheld, _withheld_dir) = fresh_budget(2).await;
    let (probe, body) = call(&withheld, WITHHELD_KEY, PROBE).await;
    assert_absent(probe, &body);
    let (status, withheld_visible) = call(&withheld, WITHHELD_KEY, VISIBLE).await;
    assert_allowed(status, &withheld_visible);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 1);

    let (missing, _missing_dir) = fresh_budget(2).await;
    let (probe, body) = call(&missing, OPEN_KEY, PROBE).await;
    assert_absent(probe, &body);
    let (status, missing_visible) = call(&missing, OPEN_KEY, VISIBLE).await;
    assert_allowed(status, &missing_visible);
    assert_eq!(missing_visible, withheld_visible);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 1);

    let (control, _control_dir) = fresh_budget(2).await;
    let (status, body) = call(&control, OPEN_KEY, VISIBLE).await;
    assert_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

/// The event names written for a withheld probe equal those written for a
/// missing probe, and both lists include the request row. The visible call
/// alone writes a request row of its own.
#[tokio::test(flavor = "current_thread")]
async fn direct_withheld_and_missing_write_the_same_probe_audit() {
    let (withheld, withheld_dir) = fresh_audited().await;
    let (probe, withheld_probe) = call(&withheld, WITHHELD_KEY, PROBE).await;
    assert_absent(probe, &withheld_probe);
    let withheld_events = audit_events(&withheld_dir.path().join("audit.jsonl"));
    let (status, body) = call(&withheld, WITHHELD_KEY, VISIBLE).await;
    assert_allowed(status, &body);

    let (missing, missing_dir) = fresh_audited().await;
    let (probe, missing_probe) = call(&missing, OPEN_KEY, PROBE).await;
    assert_absent(probe, &missing_probe);
    assert_eq!(missing_probe, withheld_probe);
    let missing_events = audit_events(&missing_dir.path().join("audit.jsonl"));
    assert_eq!(missing_events, withheld_events);
    assert!(
        withheld_events.contains(&"request".to_string()),
        "{withheld_events:?}"
    );

    let (control, control_dir) = fresh_audited().await;
    let (status, body) = call(&control, OPEN_KEY, VISIBLE).await;
    assert_allowed(status, &body);
    let control_events = audit_events(&control_dir.path().join("audit.jsonl"));
    assert!(
        control_events.contains(&"request".to_string()),
        "{control_events:?}"
    );
}
