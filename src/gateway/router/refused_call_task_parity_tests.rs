// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A task-augmented `tools/call` on `/mcp` for a name the caller is not
//! allowed to see leaves the request firewall uncharged, as does the same
//! call for a name that is not surfaced.
//!
//! Both are refused before the firewall has a target, so neither spends a
//! call budget, names a tenant, nor teaches the anomaly detector a pair.
//! The call that follows, for a surfaced tool the same caller can see,
//! is still the first call the firewall scores. On this path that call is
//! answered with the confirmation challenge, which is a result, not a
//! refusal.
//!
//! Each row builds three fresh gateways. The withheld arm surfaces the
//! probe name and the visible name, and the caller is denied the probe.
//! The missing arm surfaces only the visible name, so the probe matches
//! nothing. The control sends no probe. On one gateway the probe and the
//! visible call present the same caller key and no session.
//!
//! Audit rows for this path are already pinned. A withheld surfaced task
//! call and a missing name write no `request` row, and a visible task call
//! writes one. See `mcp_withheld_surfaced_task_leaves_what_a_missing_name_leaves`,
//! `assert_visible_control`, and `assert_refused_as_missing` in
//! `src/gateway/route_check_matrix_p3_tests.rs`. This file does not repeat them.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, Fx, TaskFirewall, fixture_task_firewalled, send_with_headers, with_transport,
};
use crate::config::SurfacedToolConfig;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

const PROBE: &str = "other";
const VISIBLE: &str = "read";
/// Denied `other`, and not denied `read`, so the withheld probe and the
/// visible call can share one caller key.
const WITHHELD_KEY: &str = "k-deny-x";
const OPEN_KEY: &str = "k-std";
/// The confirmation prompt's stable sentence. The challenge is a successful
/// result (`resultType` `input_required`), and this sentence is in both the
/// destructive prompt and the unclassified one.
const CHALLENGE_PROMPT: &str = "It runs as a task once accepted";

/// Code `-32601`, HTTP 404, and the absent-name message. The message names
/// the probe: the visible tool stays `read` on the same gateway.
fn absent_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32601,
            "message": "JSON-RPC error -32601: Unknown tool: other"
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
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body, &absent_body(), "{body}");
}

/// A permitted visible task call. The challenge is not a refusal: HTTP 200,
/// no error, and the confirmation result.
fn assert_challenge(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(body["result"]["resultType"], "input_required", "{body}");
    assert!(
        body.to_string().contains(CHALLENGE_PROMPT),
        "a permitted task call was not the confirmation challenge: {body}"
    );
}

/// Every string in an answer that carries the challenge sentence: the text
/// the caller is asked, without the sealed state and ids beside it, which
/// differ from call to call. A withheld probe and a missing one must leave
/// the challenge that follows them worded the same.
fn challenge_texts(body: &Value) -> Vec<String> {
    fn walk(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(text) if text.contains(CHALLENGE_PROMPT) => out.push(text.clone()),
            Value::Array(items) => items.iter().for_each(|item| walk(item, out)),
            Value::Object(fields) => fields.values().for_each(|field| walk(field, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(body, &mut out);
    out
}

fn assert_budget_refused(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, &budget_refusal_body(), "{body}");
}

fn assert_tenant_refused(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, &tenant_refusal_body(), "{body}");
}

/// Whether the gateway surfaces the probe name beside `read`.
enum Surface {
    /// `read` only, so the probe name matches no tool.
    Read,
    /// `read` and the probe name, so a key denied the probe is withheld it.
    Both,
}

fn surface_read(meta: MetaMcp) -> MetaMcp {
    meta.with_surfaced_tools(vec![surfaced(VISIBLE)])
}

fn surface_both(meta: MetaMcp) -> MetaMcp {
    meta.with_surfaced_tools(vec![surfaced(VISIBLE), surfaced(PROBE)])
}

fn surfaced(tool: &str) -> SurfacedToolConfig {
    SurfacedToolConfig {
        server: "alpha".to_string(),
        tool: tool.to_string(),
    }
}

/// Lists `read` as destructive, so a visible task call is challenged, and
/// lists the probe name, so withholding it is the caller's policy and not
/// an empty catalogue. Counts every send that is not `tools/list`.
struct Listed {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Listed {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({"tools": [
                {
                    "name": "read",
                    "inputSchema": {"type": "object"},
                    "annotations": {"destructiveHint": true, "readOnlyHint": false}
                },
                {
                    "name": "other",
                    "inputSchema": {"type": "object"},
                    "annotations": {"destructiveHint": false, "readOnlyHint": true}
                }
            ]})
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            body,
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

async fn open(
    arm: TaskFirewall,
    surface: Surface,
) -> (Fx, Arc<AtomicUsize>, Arc<tempfile::TempDir>) {
    let dir = crate::test_dir_keep::kept_tempdir();
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(Listed {
        calls: Arc::clone(&calls),
    });
    let audit = dir.path().join("audit.jsonl");
    let fx = match surface {
        Surface::Read => {
            with_transport(
                transport,
                Box::pin(fixture_task_firewalled(
                    Answer::Ok,
                    audit,
                    arm,
                    surface_read,
                )),
            )
            .await
        }
        Surface::Both => {
            with_transport(
                transport,
                Box::pin(fixture_task_firewalled(
                    Answer::Ok,
                    audit,
                    arm,
                    surface_both,
                )),
            )
            .await
        }
    };
    (fx, calls, dir)
}

fn headers(name: &'static str) -> [(&'static str, &'static str); 3] {
    [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", name),
    ]
}

fn task_params(name: &str, arguments: Value, idempotency: &str) -> Value {
    let mut params = json!({
        "name": name,
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "elicitation": {"form": {}},
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            }
        }
    });
    params["arguments"] = arguments;
    params["_meta"][IDEMPOTENCY_KEY_META] = json!(idempotency);
    params
}

/// A plain modern `tools/call`: no `task`, so the confirmation gate has
/// nothing to ask. The capabilities object is required once the modern
/// header is set; without it the request is malformed and refused before
/// the firewall, and the control would record no pair.
fn plain_params(name: &str) -> Value {
    json!({
        "name": name,
        "arguments": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}
        }
    })
}

async fn task_call(
    fx: &Fx,
    key: &str,
    tool: &'static str,
    arguments: Value,
    idempotency: &str,
) -> (StatusCode, Value) {
    let headers = headers(tool);
    send_with_headers(
        fx,
        "/mcp",
        key,
        "tools/call",
        task_params(tool, arguments, idempotency),
        None,
        &headers,
    )
    .await
}

async fn plain_call(fx: &Fx, key: &str, tool: &'static str) -> (StatusCode, Value) {
    let headers = headers(tool);
    send_with_headers(
        fx,
        "/mcp",
        key,
        "tools/call",
        plain_params(tool),
        None,
        &headers,
    )
    .await
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

/// A withheld probe and a missing probe each leave a budget of one unused,
/// so the visible task call that follows is still permitted and is
/// challenged. Two visible task calls with no probe spend the budget: the
/// second is the budget refusal, which is how the row shows the guard is on.
#[tokio::test(flavor = "current_thread")]
async fn task_withheld_and_missing_do_not_spend_one_call_budget() {
    let (withheld, withheld_calls, _withheld_dir) =
        open(TaskFirewall::Budget(1), Surface::Both).await;
    let (status, body) =
        task_call(&withheld, WITHHELD_KEY, PROBE, json!({}), "budget-w-probe").await;
    assert_absent(status, &body);
    let (status, withheld_visible) = task_call(
        &withheld,
        WITHHELD_KEY,
        VISIBLE,
        json!({}),
        "budget-w-visible",
    )
    .await;
    assert_challenge(status, &withheld_visible);
    assert_eq!(withheld_calls.load(Ordering::SeqCst), 0);

    let (missing, missing_calls, _missing_dir) = open(TaskFirewall::Budget(1), Surface::Read).await;
    let (status, body) = task_call(&missing, OPEN_KEY, PROBE, json!({}), "budget-m-probe").await;
    assert_absent(status, &body);
    let (status, missing_visible) =
        task_call(&missing, OPEN_KEY, VISIBLE, json!({}), "budget-m-visible").await;
    assert_challenge(status, &missing_visible);
    assert_eq!(
        challenge_texts(&missing_visible),
        challenge_texts(&withheld_visible)
    );
    assert_eq!(missing_calls.load(Ordering::SeqCst), 0);

    let (control, control_calls, _control_dir) = open(TaskFirewall::Budget(1), Surface::Read).await;
    let (status, body) = task_call(&control, OPEN_KEY, VISIBLE, json!({}), "budget-c-1").await;
    assert_challenge(status, &body);
    let (status, body) = task_call(&control, OPEN_KEY, VISIBLE, json!({}), "budget-c-2").await;
    assert_budget_refused(status, &body);
    assert_eq!(control_calls.load(Ordering::SeqCst), 0);
}

/// A withheld probe and a missing probe name a tenant the firewall never
/// sees, so the visible call that names a second tenant is still the
/// caller's first tenant and is challenged. Two visible calls naming `t1`
/// then `t2` spend the reach of one: the second is the tenant refusal.
#[tokio::test(flavor = "current_thread")]
async fn task_withheld_and_missing_do_not_reach_a_second_tenant() {
    let (withheld, withheld_calls, _withheld_dir) =
        open(TaskFirewall::Tenant(1), Surface::Both).await;
    let (status, body) = task_call(
        &withheld,
        WITHHELD_KEY,
        PROBE,
        json!({"tenant": "t1"}),
        "tenant-w-probe",
    )
    .await;
    assert_absent(status, &body);
    let (status, withheld_visible) = task_call(
        &withheld,
        WITHHELD_KEY,
        VISIBLE,
        json!({"tenant": "t2"}),
        "tenant-w-visible",
    )
    .await;
    assert_challenge(status, &withheld_visible);
    assert_eq!(withheld_calls.load(Ordering::SeqCst), 0);

    let (missing, missing_calls, _missing_dir) = open(TaskFirewall::Tenant(1), Surface::Read).await;
    let (status, body) = task_call(
        &missing,
        OPEN_KEY,
        PROBE,
        json!({"tenant": "t1"}),
        "tenant-m-probe",
    )
    .await;
    assert_absent(status, &body);
    let (status, missing_visible) = task_call(
        &missing,
        OPEN_KEY,
        VISIBLE,
        json!({"tenant": "t2"}),
        "tenant-m-visible",
    )
    .await;
    assert_challenge(status, &missing_visible);
    assert_eq!(
        challenge_texts(&missing_visible),
        challenge_texts(&withheld_visible)
    );
    assert_eq!(missing_calls.load(Ordering::SeqCst), 0);

    let (control, control_calls, _control_dir) = open(TaskFirewall::Tenant(1), Surface::Read).await;
    let (status, body) = task_call(
        &control,
        OPEN_KEY,
        VISIBLE,
        json!({"tenant": "t1"}),
        "tenant-c-1",
    )
    .await;
    assert_challenge(status, &body);
    let (status, body) = task_call(
        &control,
        OPEN_KEY,
        VISIBLE,
        json!({"tenant": "t2"}),
        "tenant-c-2",
    )
    .await;
    assert_tenant_refused(status, &body);
    assert_eq!(control_calls.load(Ordering::SeqCst), 0);
}

/// A withheld probe and a missing probe add no pair. The visible task call
/// after either is this caller's first scanned call, so it adds none either:
/// a probe that had been scanned would have left a predecessor, and this
/// call would record one. The control's visible call then a second visible
/// tool records exactly the seeded successor, one pair.
#[tokio::test(flavor = "current_thread")]
async fn task_withheld_and_missing_record_no_anomaly_pair() {
    let (withheld, withheld_calls, _withheld_dir) =
        open(TaskFirewall::Anomaly, Surface::Both).await;
    let before = learned_pairs(&withheld);
    let (status, body) =
        task_call(&withheld, WITHHELD_KEY, PROBE, json!({}), "anomaly-w-probe").await;
    assert_absent(status, &body);
    assert!(
        pair_deltas(&before, &learned_pairs(&withheld)).is_empty(),
        "the withheld probe changed the pair map"
    );
    let before_visible = learned_pairs(&withheld);
    let (status, withheld_visible) = task_call(
        &withheld,
        WITHHELD_KEY,
        VISIBLE,
        json!({}),
        "anomaly-w-visible",
    )
    .await;
    assert_challenge(status, &withheld_visible);
    assert!(
        pair_deltas(&before_visible, &learned_pairs(&withheld)).is_empty(),
        "the visible call recorded a pair, so the probe had left it a predecessor"
    );
    assert_eq!(withheld_calls.load(Ordering::SeqCst), 0);

    let (missing, missing_calls, _missing_dir) = open(TaskFirewall::Anomaly, Surface::Read).await;
    let before = learned_pairs(&missing);
    let (status, body) = task_call(&missing, OPEN_KEY, PROBE, json!({}), "anomaly-m-probe").await;
    assert_absent(status, &body);
    assert!(
        pair_deltas(&before, &learned_pairs(&missing)).is_empty(),
        "the missing probe changed the pair map"
    );
    let before_visible = learned_pairs(&missing);
    let (status, missing_visible) =
        task_call(&missing, OPEN_KEY, VISIBLE, json!({}), "anomaly-m-visible").await;
    assert_challenge(status, &missing_visible);
    assert_eq!(
        challenge_texts(&missing_visible),
        challenge_texts(&withheld_visible)
    );
    assert!(
        pair_deltas(&before_visible, &learned_pairs(&missing)).is_empty(),
        "the visible call recorded a pair, so the probe had left it a predecessor"
    );
    assert_eq!(missing_calls.load(Ordering::SeqCst), 0);

    let (control, control_calls, _control_dir) = open(TaskFirewall::Anomaly, Surface::Both).await;
    let before = learned_pairs(&control);
    let (status, body) =
        task_call(&control, OPEN_KEY, VISIBLE, json!({}), "anomaly-c-visible").await;
    assert_challenge(status, &body);
    assert!(
        pair_deltas(&before, &learned_pairs(&control)).is_empty(),
        "the first visible call recorded a pair"
    );
    let (status, body) = plain_call(&control, OPEN_KEY, PROBE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(
        pair_deltas(&before, &learned_pairs(&control)),
        vec![("alpha:read".to_string(), "alpha:other".to_string(), 1)],
        "the admitted successor did not add exactly one pair"
    );
    assert_eq!(control_calls.load(Ordering::SeqCst), 1, "{body}");
}
