// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! More count rows: the meta route's streamed answers, a delivery refusal
//! that replaces a folded answer, deliveries in sequence, and the counter's
//! help text.

use super::super::direct_guards_fixture::{Fx, replace_backend};
use super::*;

/// `gateway_invoke read` on `alpha` accepting a streamed answer, with a
/// progress token so the route opens its notification-first stream. The
/// whole body as text.
async fn invoke_streamed(fx: &Fx) -> String {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
        "_meta": {"progressToken": "p1"}
    });
    post_streamed(fx, params).await
}

/// Playbook `p` accepting a streamed answer, as [`invoke_streamed`].
async fn run_p_streamed(fx: &Fx) -> String {
    let params = json!({
        "name": "gateway_run_playbook",
        "arguments": {"name": "p", "arguments": {}},
        "_meta": {"progressToken": "p1"}
    });
    post_streamed(fx, params).await
}

async fn post_streamed(fx: &Fx, params: Value) -> String {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&body).into_owned()
}

/// The answer a streamed body ends on, asserting the premise that it is an
/// SSE stream whose terminal event is the answer to request 1.
fn terminal_answer(body: &str) -> Value {
    let events: Vec<Value> = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str(data.trim()).ok())
        .collect();
    let answer = events
        .last()
        .unwrap_or_else(|| panic!("premise: an SSE stream: {body}"))
        .clone();
    assert_eq!(
        answer["id"], 1,
        "premise: the answer is the terminal event: {body}"
    );
    answer
}

/// N3, streamed: a backend's in-band error folded on the meta route counts
/// once as `backend`.
#[test]
fn a_streamed_meta_backend_error_counts_as_backend() {
    let (body, text) = counted(async {
        let fx = fixture(Answer::RpcError(-32001), |_| {}).await;
        invoke_streamed(&fx).await
    });
    folded_text(&terminal_answer(&body));
    assert_eq!(all(&text), BACKEND, "{body}\n{text}");
}

/// N4, streamed: a backend timeout folded on the meta route counts once as
/// `backend`.
#[test]
fn a_streamed_meta_backend_timeout_counts_as_backend() {
    let (body, text) = counted(async {
        let fx = fixture(Answer::FailsWith(backend_timeout), |_| {}).await;
        invoke_streamed(&fx).await
    });
    folded_text(&terminal_answer(&body));
    assert_eq!(all(&text), BACKEND, "{body}\n{text}");
}

/// N7, streamed: a plan aborting on a backend's in-band error counts once as
/// `backend`.
#[test]
fn a_streamed_plan_ending_on_a_backends_error_counts_as_backend() {
    let (body, text) = counted(async {
        let fx = serving(Answer::RpcError(-32001), one_step("abort")).await;
        run_p_streamed(&fx).await
    });
    let answer = terminal_answer(&body);
    assert!(
        answer.get("error").is_some(),
        "premise: the plan ended in error: {answer}"
    );
    assert_eq!(all(&text), BACKEND, "{body}\n{text}");
}

/// N19 and R1, a control: the firewall refuses a folded backend error that
/// carries a credential, replacing the folded answer with its delivery
/// refusal. The refusal is what is counted, as the gateway's `request`, not
/// the backend failure it replaced. Mutant m19 (the count reads a frame's
/// fold before its own error, and every frame is stamped) turns it red.
#[cfg(feature = "firewall")]
#[test]
fn a_delivery_refusal_replacing_a_folded_answer_counts_as_the_refusal() {
    use super::super::direct_guards_fixture::{CREDENTIAL_KEY, fixture_firewalled};
    let ((_, answer), text) = counted(async {
        let fx = fixture_firewalled(Answer::RpcErrorText(CREDENTIAL_KEY)).await;
        invoke(&fx).await
    });
    assert_eq!(
        answer["error"]["code"], -32600,
        "premise: the delivery refusal replaced the answer: {answer}"
    );
    assert_eq!(all(&text), [0, 1, 0, 0], "{answer}\n{text}");
}

/// N19 and R1, streamed.
#[cfg(feature = "firewall")]
#[test]
fn a_streamed_delivery_refusal_replacing_a_folded_answer_counts_as_the_refusal() {
    use super::super::direct_guards_fixture::{CREDENTIAL_KEY, fixture_firewalled};
    let (body, text) = counted(async {
        let fx = fixture_firewalled(Answer::RpcErrorText(CREDENTIAL_KEY)).await;
        invoke_streamed(&fx).await
    });
    let answer = terminal_answer(&body);
    assert_eq!(
        answer["error"]["code"], -32600,
        "premise: the delivery refusal replaced the answer: {answer}"
    );
    assert_eq!(all(&text), [0, 1, 0, 0], "{body}\n{text}");
}

/// N20, a control: a folded backend failure, then the same caller's next
/// request served: the second delivery counts nothing. Mutant m20 (a
/// delivery starts from the previous delivery's fold) turns it red.
#[test]
fn a_served_request_after_a_folded_one_counts_nothing() {
    let ((first, second), text) = counted(async {
        let fx = fixture(Answer::RpcError(-32001), |_| {}).await;
        let first = invoke(&fx).await;
        let _ = replace_backend(&fx, "alpha");
        let second = invoke(&fx).await;
        (first, second)
    });
    folded_text(&first.1);
    assert!(
        second.1["result"]["isError"] != true && second.1.get("error").is_none(),
        "premise: the second request was served: {}",
        second.1
    );
    assert_eq!(all(&text), BACKEND, "only the first counts: {text}");
}

/// H1: the counter's help says which `isError` results it counts.
#[test]
fn the_error_counters_help_names_the_counted_tool_results() {
    let ((), text) = counted(async {});
    let help = text
        .lines()
        .find(|l| l.starts_with("# HELP mcp_gateway_errors_total "))
        .unwrap_or_else(|| panic!("no help line in:\n{text}"));
    assert!(
        help.contains(
            "A tool's own isError: true result is not an error here; a failure the gateway \
             answers as an isError result (a meta-route dispatch failure, a refusal, a playbook \
             or chain ending on a failed step) counts once, by whose failure it is."
        ),
        "{help}"
    );
}
