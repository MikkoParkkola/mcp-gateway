// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A tools/call the caller is not allowed to see leaves the same firewall
//! state as a tools/call for a name that exists nowhere.
//!
//! The direct rows call the backend route. The meta rows call
//! `gateway_invoke` on `/mcp` with that name as the target. On both routes
//! the firewall scans the target, so a withheld probe and a missing probe
//! are charged alike.
//!
//! Each row builds three fresh gateways. The withheld arm and the missing arm
//! each send one probe, then one call for a tool the caller can see. The
//! control sends only that visible call. On one gateway the probe and the
//! visible call present the same session id and the same caller key.
//!
//! The tenant rows turn the tenant guard on. The anomaly row reads the
//! detector's tracker and compares the whole pair map before the probe with
//! the map after the visible call.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, Fx, fixture_firewalled_anomaly, fixture_firewalled_audited,
    fixture_firewalled_budget_built, fixture_firewalled_tenant, post_direct, post_meta_invoke,
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

fn tenant_refusal_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32600,
            "message": "Firewall blocked: Cross-tenant reach exceeded: principal touched 2 distinct tenants (limit 1)"
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

fn assert_tenant_refused(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body, &tenant_refusal_body(), "{body}");
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

async fn call_for(fx: &Fx, key: &str, tool: &str, tenant: &str) -> (StatusCode, Value) {
    post_direct(
        fx,
        BACKEND,
        key,
        tool,
        json!({ "tenant": tenant }),
        None,
        Some(SESSION),
    )
    .await
}

async fn fresh_tenant(max_tenants: usize) -> Fx {
    fixture_firewalled_tenant(Answer::WithNote, max_tenants).await
}

async fn fresh_anomaly() -> Fx {
    fixture_firewalled_anomaly(Answer::WithNote).await
}

fn learned_pairs(fx: &Fx) -> BTreeMap<(String, String), u64> {
    fx.state
        .firewall
        .as_ref()
        .expect("firewall")
        .anomaly_tracker_for_test()
        .expect("anomaly detector")
        .pair_counts_for_test()
}

/// Pairs whose count differs between the two snapshots, as `(from, to, delta)`.
fn pair_deltas(
    before: &BTreeMap<(String, String), u64>,
    after: &BTreeMap<(String, String), u64>,
) -> Vec<(String, String, i64)> {
    let mut keys: Vec<(String, String)> = before.keys().chain(after.keys()).cloned().collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter_map(|key| {
            let was = i64::try_from(before.get(&key).copied().unwrap_or(0)).expect("count");
            let now = i64::try_from(after.get(&key).copied().unwrap_or(0)).expect("count");
            (now != was).then(|| (key.0, key.1, now - was))
        })
        .collect()
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
    // One scan each way: the probe is charged as one request, and its absent
    // answer passes the response scan once.
    assert_eq!(withheld_events, ["request", "response"]);

    let (control, control_dir) = fresh_audited().await;
    let (status, body) = call(&control, OPEN_KEY, VISIBLE).await;
    assert_allowed(status, &body);
    let control_events = audit_events(&control_dir.path().join("audit.jsonl"));
    assert!(
        control_events.contains(&"request".to_string()),
        "{control_events:?}"
    );
}

/// A tenant limit of one is used up by the probe's tenant, so the visible
/// call that names a second tenant is refused with the same tenant answer.
/// The visible call alone names one tenant and is allowed.
#[tokio::test(flavor = "current_thread")]
async fn direct_withheld_and_missing_reach_a_second_tenant() {
    let withheld = fresh_tenant(1).await;
    let (probe, body) = call_for(&withheld, WITHHELD_KEY, PROBE, "t1").await;
    assert_absent(probe, &body);
    let (status, withheld_visible) = call_for(&withheld, WITHHELD_KEY, VISIBLE, "t2").await;
    assert_tenant_refused(status, &withheld_visible);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 0);

    let missing = fresh_tenant(1).await;
    let (probe, body) = call_for(&missing, OPEN_KEY, PROBE, "t1").await;
    assert_absent(probe, &body);
    let (status, missing_visible) = call_for(&missing, OPEN_KEY, VISIBLE, "t2").await;
    assert_tenant_refused(status, &missing_visible);
    assert_eq!(missing_visible, withheld_visible);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 0);

    let control = fresh_tenant(1).await;
    let (status, body) = call_for(&control, OPEN_KEY, VISIBLE, "t2").await;
    assert_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

/// A tenant limit of two still has room after the probe. The visible call
/// after a withheld name and after a missing name is allowed. A check that
/// always refuses the second tenant fails this row.
#[tokio::test(flavor = "current_thread")]
async fn direct_withheld_and_missing_stay_inside_a_two_tenant_limit() {
    let withheld = fresh_tenant(2).await;
    let (probe, body) = call_for(&withheld, WITHHELD_KEY, PROBE, "t1").await;
    assert_absent(probe, &body);
    let (status, withheld_visible) = call_for(&withheld, WITHHELD_KEY, VISIBLE, "t2").await;
    assert_allowed(status, &withheld_visible);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 1);

    let missing = fresh_tenant(2).await;
    let (probe, body) = call_for(&missing, OPEN_KEY, PROBE, "t1").await;
    assert_absent(probe, &body);
    let (status, missing_visible) = call_for(&missing, OPEN_KEY, VISIBLE, "t2").await;
    assert_allowed(status, &missing_visible);
    assert_eq!(missing_visible, withheld_visible);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 1);

    let control = fresh_tenant(2).await;
    let (status, body) = call_for(&control, OPEN_KEY, VISIBLE, "t2").await;
    assert_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

/// The only pair the tracker gains, for a withheld probe and for a missing
/// one, is `alpha:gateway_invok -> alpha:note`, by one. The visible call
/// alone changes no pair. The fixture has already seeded other pairs, so the
/// assertion is the difference between the two maps.
#[tokio::test(flavor = "current_thread")]
async fn direct_withheld_and_missing_record_one_anomaly_step() {
    let withheld = fresh_anomaly().await;
    let before = learned_pairs(&withheld);
    let (probe, body) = call(&withheld, WITHHELD_KEY, PROBE).await;
    assert_absent(probe, &body);
    let (status, body) = call(&withheld, WITHHELD_KEY, VISIBLE).await;
    assert_allowed(status, &body);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        pair_deltas(&before, &learned_pairs(&withheld)),
        vec![(
            "alpha:gateway_invok".to_string(),
            "alpha:note".to_string(),
            1
        )]
    );

    let missing = fresh_anomaly().await;
    let before = learned_pairs(&missing);
    let (probe, body) = call(&missing, OPEN_KEY, PROBE).await;
    assert_absent(probe, &body);
    let (status, body) = call(&missing, OPEN_KEY, VISIBLE).await;
    assert_allowed(status, &body);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        pair_deltas(&before, &learned_pairs(&missing)),
        vec![(
            "alpha:gateway_invok".to_string(),
            "alpha:note".to_string(),
            1
        )]
    );

    let control = fresh_anomaly().await;
    let before = learned_pairs(&control);
    let (status, body) = call(&control, OPEN_KEY, VISIBLE).await;
    assert_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    assert_eq!(learned_pairs(&control), before);
}

/// Text A for the probe, then the hint this route appends. The probe is one
/// edit from the listed `gateway_invoke`, and both keys can see that name.
const PROBE_SENTENCE: &str = concat!(
    "the backend does not list a tool named `gateway_invok`. ",
    "Did you mean: gateway_invoke?"
);

/// `gateway_invoke` delivers a tool result as pretty JSON in one text block.
/// `isError` on the outer result follows the payload's own flag.
fn wrapped(payload: &Value) -> Value {
    let text = serde_json::to_string_pretty(payload).expect("pretty");
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{ "type": "text", "text": text }],
            "isError": payload.get("isError") == Some(&Value::Bool(true))
        }
    })
}

fn meta_absent_body() -> Value {
    wrapped(&json!({
        "content": [{ "type": "text", "text": PROBE_SENTENCE }],
        "isError": true
    }))
}

/// The tool result a visible `note` call wraps. The dispatch then adds a
/// generated `_trace_id`, so the two arms of one row do not share one body.
fn visible_result() -> Value {
    json!({
        "content": [{ "type": "text", "text": "ok" }],
        "isError": false
    })
}

fn assert_meta_absent(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, &meta_absent_body(), "{body}");
}

/// 200, the wrapped tool result, and nothing else except the generated
/// `_trace_id` inside that text.
fn assert_meta_allowed(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(body["jsonrpc"], "2.0", "{body}");
    assert_eq!(body["id"], 1, "{body}");
    assert_eq!(body["result"]["isError"], false, "{body}");
    assert_eq!(
        body["result"]["content"].as_array().map(Vec::len),
        Some(1),
        "{body}"
    );
    let text = body["result"]["content"][0]["text"].as_str().unwrap_or("");
    let inner: Value = serde_json::from_str(text).unwrap_or_else(|err| panic!("{err}: {body}"));
    assert_eq!(
        text,
        serde_json::to_string_pretty(&inner).expect("pretty"),
        "{body}"
    );
    let mut bare = inner;
    let trace = bare.as_object_mut().and_then(|map| map.remove("_trace_id"));
    assert!(
        trace
            .as_ref()
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty()),
        "{body}"
    );
    assert_eq!(bare, visible_result(), "{body}");
}

/// The two allowed bodies, compared with the generated trace removed.
fn assert_same_allowed(left: &Value, right: &Value) {
    fn bare(body: &Value) -> Value {
        let mut body = body.clone();
        let text = body["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let mut inner: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if let Some(map) = inner.as_object_mut() {
            map.remove("_trace_id");
        }
        if let Some(slot) = body.pointer_mut("/result/content/0/text") {
            *slot = Value::String(serde_json::to_string_pretty(&inner).unwrap_or_default());
        }
        body
    }
    assert_eq!(bare(left), bare(right), "left {left} right {right}");
}

/// This route answers a firewall block with 400. The message is the shared
/// wording the direct route answers with 403.
fn assert_meta_budget_refused(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, &budget_refusal_body(), "{body}");
}

fn assert_meta_tenant_refused(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, &tenant_refusal_body(), "{body}");
}

async fn meta_call(fx: &Fx, key: &str, tool: &str) -> (StatusCode, Value) {
    post_meta_invoke(fx, key, BACKEND, tool, json!({}), None, Some(SESSION)).await
}

async fn meta_call_for(fx: &Fx, key: &str, tool: &str, tenant: &str) -> (StatusCode, Value) {
    post_meta_invoke(
        fx,
        key,
        BACKEND,
        tool,
        json!({ "tenant": tenant }),
        None,
        Some(SESSION),
    )
    .await
}

/// One withheld `gateway_invoke` and one missing one each use up a budget of
/// one, so the visible call that follows is refused with the same budget
/// answer. The visible call alone is still inside the budget and is allowed.
#[tokio::test(flavor = "current_thread")]
async fn meta_withheld_and_missing_spend_one_call_budget() {
    let (withheld, _withheld_dir) = fresh_budget(1).await;
    let (probe, body) = meta_call(&withheld, WITHHELD_KEY, PROBE).await;
    assert_meta_absent(probe, &body);
    let (status, withheld_visible) = meta_call(&withheld, WITHHELD_KEY, VISIBLE).await;
    assert_meta_budget_refused(status, &withheld_visible);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 0);

    let (missing, _missing_dir) = fresh_budget(1).await;
    let (probe, body) = meta_call(&missing, OPEN_KEY, PROBE).await;
    assert_meta_absent(probe, &body);
    let (status, missing_visible) = meta_call(&missing, OPEN_KEY, VISIBLE).await;
    assert_meta_budget_refused(status, &missing_visible);
    assert_eq!(missing_visible, withheld_visible);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 0);

    let (control, _control_dir) = fresh_budget(1).await;
    let (status, body) = meta_call(&control, OPEN_KEY, VISIBLE).await;
    assert_meta_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

/// A budget of two is not used up by the probe. The visible call after a
/// withheld name and after a missing name is allowed, as is the visible call
/// alone. A check that always refuses the second call fails this row.
#[tokio::test(flavor = "current_thread")]
async fn meta_withheld_and_missing_do_not_spend_a_two_call_budget() {
    let (withheld, _withheld_dir) = fresh_budget(2).await;
    let (probe, body) = meta_call(&withheld, WITHHELD_KEY, PROBE).await;
    assert_meta_absent(probe, &body);
    let (status, withheld_visible) = meta_call(&withheld, WITHHELD_KEY, VISIBLE).await;
    assert_meta_allowed(status, &withheld_visible);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 1);

    let (missing, _missing_dir) = fresh_budget(2).await;
    let (probe, body) = meta_call(&missing, OPEN_KEY, PROBE).await;
    assert_meta_absent(probe, &body);
    let (status, missing_visible) = meta_call(&missing, OPEN_KEY, VISIBLE).await;
    assert_meta_allowed(status, &missing_visible);
    assert_same_allowed(&missing_visible, &withheld_visible);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 1);

    let (control, _control_dir) = fresh_budget(2).await;
    let (status, body) = meta_call(&control, OPEN_KEY, VISIBLE).await;
    assert_meta_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

/// The event names written for a withheld probe equal those written for a
/// missing probe, and both lists include the request row. The visible call
/// alone writes a request row of its own.
#[tokio::test(flavor = "current_thread")]
async fn meta_withheld_and_missing_write_the_same_probe_audit() {
    let (withheld, withheld_dir) = fresh_audited().await;
    let (probe, withheld_probe) = meta_call(&withheld, WITHHELD_KEY, PROBE).await;
    assert_meta_absent(probe, &withheld_probe);
    let withheld_events = audit_events(&withheld_dir.path().join("audit.jsonl"));
    let (status, body) = meta_call(&withheld, WITHHELD_KEY, VISIBLE).await;
    assert_meta_allowed(status, &body);

    let (missing, missing_dir) = fresh_audited().await;
    let (probe, missing_probe) = meta_call(&missing, OPEN_KEY, PROBE).await;
    assert_meta_absent(probe, &missing_probe);
    assert_eq!(missing_probe, withheld_probe);
    let missing_events = audit_events(&missing_dir.path().join("audit.jsonl"));
    assert_eq!(missing_events, withheld_events);
    // One scan each way: the probe is charged as one request, and its absent
    // answer passes the response scan once.
    assert_eq!(withheld_events, ["request", "response"]);

    let (control, control_dir) = fresh_audited().await;
    let (status, body) = meta_call(&control, OPEN_KEY, VISIBLE).await;
    assert_meta_allowed(status, &body);
    let control_events = audit_events(&control_dir.path().join("audit.jsonl"));
    assert!(
        control_events.contains(&"request".to_string()),
        "{control_events:?}"
    );
}

/// A tenant limit of one is used up by the probe's tenant, so the visible
/// call that names a second tenant is refused with the same tenant answer.
/// The visible call alone names one tenant and is allowed.
#[tokio::test(flavor = "current_thread")]
async fn meta_withheld_and_missing_reach_a_second_tenant() {
    let withheld = fresh_tenant(1).await;
    let (probe, body) = meta_call_for(&withheld, WITHHELD_KEY, PROBE, "t1").await;
    assert_meta_absent(probe, &body);
    let (status, withheld_visible) = meta_call_for(&withheld, WITHHELD_KEY, VISIBLE, "t2").await;
    assert_meta_tenant_refused(status, &withheld_visible);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 0);

    let missing = fresh_tenant(1).await;
    let (probe, body) = meta_call_for(&missing, OPEN_KEY, PROBE, "t1").await;
    assert_meta_absent(probe, &body);
    let (status, missing_visible) = meta_call_for(&missing, OPEN_KEY, VISIBLE, "t2").await;
    assert_meta_tenant_refused(status, &missing_visible);
    assert_eq!(missing_visible, withheld_visible);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 0);

    let control = fresh_tenant(1).await;
    let (status, body) = meta_call_for(&control, OPEN_KEY, VISIBLE, "t2").await;
    assert_meta_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

/// A tenant limit of two still has room after the probe. The visible call
/// after a withheld name and after a missing name is allowed. A check that
/// always refuses the second tenant fails this row.
#[tokio::test(flavor = "current_thread")]
async fn meta_withheld_and_missing_stay_inside_a_two_tenant_limit() {
    let withheld = fresh_tenant(2).await;
    let (probe, body) = meta_call_for(&withheld, WITHHELD_KEY, PROBE, "t1").await;
    assert_meta_absent(probe, &body);
    let (status, withheld_visible) = meta_call_for(&withheld, WITHHELD_KEY, VISIBLE, "t2").await;
    assert_meta_allowed(status, &withheld_visible);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 1);

    let missing = fresh_tenant(2).await;
    let (probe, body) = meta_call_for(&missing, OPEN_KEY, PROBE, "t1").await;
    assert_meta_absent(probe, &body);
    let (status, missing_visible) = meta_call_for(&missing, OPEN_KEY, VISIBLE, "t2").await;
    assert_meta_allowed(status, &missing_visible);
    assert_same_allowed(&missing_visible, &withheld_visible);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 1);

    let control = fresh_tenant(2).await;
    let (status, body) = meta_call_for(&control, OPEN_KEY, VISIBLE, "t2").await;
    assert_meta_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

/// The only pair the tracker gains, for a withheld probe and for a missing
/// one, is `alpha:gateway_invok -> alpha:note`, by one. The visible call
/// alone changes no pair. The fixture has already seeded other pairs, so the
/// assertion is the difference between the two maps.
#[tokio::test(flavor = "current_thread")]
async fn meta_withheld_and_missing_record_one_anomaly_step() {
    let withheld = fresh_anomaly().await;
    let before = learned_pairs(&withheld);
    let (probe, body) = meta_call(&withheld, WITHHELD_KEY, PROBE).await;
    assert_meta_absent(probe, &body);
    let (status, body) = meta_call(&withheld, WITHHELD_KEY, VISIBLE).await;
    assert_meta_allowed(status, &body);
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        pair_deltas(&before, &learned_pairs(&withheld)),
        vec![(
            "alpha:gateway_invok".to_string(),
            "alpha:note".to_string(),
            1
        )]
    );

    let missing = fresh_anomaly().await;
    let before = learned_pairs(&missing);
    let (probe, body) = meta_call(&missing, OPEN_KEY, PROBE).await;
    assert_meta_absent(probe, &body);
    let (status, body) = meta_call(&missing, OPEN_KEY, VISIBLE).await;
    assert_meta_allowed(status, &body);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        pair_deltas(&before, &learned_pairs(&missing)),
        vec![(
            "alpha:gateway_invok".to_string(),
            "alpha:note".to_string(),
            1
        )]
    );

    let control = fresh_anomaly().await;
    let before = learned_pairs(&control);
    let (status, body) = meta_call(&control, OPEN_KEY, VISIBLE).await;
    assert_meta_allowed(status, &body);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    assert_eq!(learned_pairs(&control), before);
}

/// The same rows for a withheld name the backend lists.
#[path = "refused_call_listed_parity_tests.rs"]
mod listed;
