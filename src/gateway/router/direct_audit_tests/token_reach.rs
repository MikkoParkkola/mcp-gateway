// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every call made with an exchanged key-server token records that token,
//! its id and its issuance row in the call's decision.

use super::*;

use super::backend_oracle::tasks::{send, tasks_meta};
use crate::gateway::router::tests::task_execution_adapter::input_round as round;

async fn token_fixture() -> (Fixture, String, String) {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        key_server: true,
        ..Setup::default()
    })
    .await;
    let ks = fx.state.key_server.as_ref().expect("fixture key server");
    let (bearer, jti) = crate::key_server::issuance_row_tests::mint_for(ks, &["alpha"]).await;
    (fx, bearer, jti)
}

fn issuance_row_of(fx: &Fixture, jti: &str) -> Value {
    std::fs::read_to_string(&fx.path)
        .expect("issuance log reads")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .find(|row| row["event"] == "token.issued" && row["token_jti"] == jti)
        .expect("the minted token has an issuance row")
}

fn assert_carries(record: &Value, fx: &Fixture, jti: &str) {
    let issued = issuance_row_of(fx, jti);
    assert_eq!(record["decision"]["token"]["jti"], jti, "{record}");
    assert_eq!(
        record["decision"]["token"]["issuance_row"]["counter"], issued["counter"],
        "{record}"
    );
    assert_eq!(
        record["decision"]["token"]["issuance_row"]["entry_hash"], issued["entry_hash"],
        "{record}"
    );
    assert!(
        record["decision"].get("token_unavailable").is_none(),
        "{record}"
    );
}

async fn post_bearer(
    fx: &Fixture,
    uri: &str,
    body: &str,
    bearer: &str,
    stream: bool,
) -> (StatusCode, String) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"));
    if stream {
        request = request.header("accept", "application/json, text/event-stream");
    }
    let request = request
        .body(axum::body::Body::from(body.to_owned()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post_modern_bearer(fx: &Fixture, body: &str, bearer: &str) -> (StatusCode, String) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("authorization", format!("Bearer {bearer}"))
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body.to_owned()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn invoke(server: &str) -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
           "params": {"name": "gateway_invoke",
                      "arguments": {"server": server, "tool": "t", "arguments": {"q": 1}}}})
    .to_string()
}

/// A meta call answered as JSON carries the minted token and its issuance row.
#[tokio::test]
async fn a_meta_call_answered_as_json_records_its_token() {
    let (fx, bearer, jti) = token_fixture().await;
    let (status, body) = post_bearer(&fx, "/mcp", &invoke("alpha"), &bearer, false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_carries(&only_invocation(&fx), &fx, &jti);
}

/// A meta call answered as a stream carries the minted token and its issuance row.
#[tokio::test]
async fn a_meta_call_answered_as_a_stream_records_its_token() {
    let (fx, bearer, jti) = token_fixture().await;
    let (status, body) = post_bearer(&fx, "/mcp", &invoke("alpha"), &bearer, true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_carries(&only_invocation(&fx), &fx, &jti);
}

/// A direct backend call carries the minted token and its issuance row.
#[tokio::test]
async fn a_direct_backend_call_records_its_token() {
    let (fx, bearer, jti) = token_fixture().await;
    let (status, body) = post_bearer(&fx, "/mcp/alpha", &tools_call("t"), &bearer, false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_carries(&only_invocation(&fx), &fx, &jti);
}

/// A backend scope refusal still records the presented token and its issuance row.
#[tokio::test]
async fn a_call_refused_by_the_router_records_its_token() {
    let (fx, bearer, jti) = token_fixture().await;
    post_bearer(&fx, "/mcp", &invoke("beta"), &bearer, false).await;
    let record = only_invocation(&fx);
    assert_eq!(record["outcome"], "denied", "{record}");
    assert_carries(&record, &fx, &jti);
}

/// A replay records the token without calling the backend a second time.
#[tokio::test]
async fn a_replayed_call_records_its_token() {
    let (fx, bearer, jti) = token_fixture().await;
    let (status, first) =
        post_modern_bearer(&fx, &super::meta_replay::keyed_invoke(1).0, &bearer).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) =
        post_modern_bearer(&fx, &super::meta_replay::keyed_invoke(2).0, &bearer).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "{second}");
    let records = invocations(&fx);
    assert_eq!(records.len(), 2, "{records:?}");
    assert_carries(&records[1], &fx, &jti);
}

/// A keyed task call of `alpha:t` as `bearer`, from a client that can answer
/// questions; the id of the task it made.
async fn start_task(fx: &Fixture, bearer: &str) -> String {
    let mut meta = tasks_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("reach-task");
    meta["io.modelcontextprotocol/clientCapabilities"]["elicitation"] = json!({});
    let params = json!({"name": "gateway_invoke", "task": {}, "_meta": meta,
                        "arguments": {"server": "alpha", "tool": "t", "arguments": {}}});
    let (_, made) = send(fx, bearer, "tools/call", "gateway_invoke", params).await;
    made.pointer("/result/taskId")
        .or_else(|| made.pointer("/result/task/taskId"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned()
}

/// Wait, at most 30 s, until task `id` is no longer working and the backend
/// has been called `sent` times; the status it rests in.
async fn rests(fx: &Fixture, id: &str, sent: usize) -> crate::protocol::tasks::TaskStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let now = fx.state.task_executor.service.store.status_for_test(id);
        let settled = now.filter(|s| *s != crate::protocol::tasks::TaskStatus::Working);
        if let Some(status) = settled
            && fx.calls.load(Ordering::SeqCst) == sent
        {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "premise: task {id} never rested after {sent} call(s): {now:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The token id a record's decision names, if any.
fn named_jti(record: &Value) -> Option<&str> {
    record["decision"]["token"]["jti"].as_str()
}

/// The task worker's step carries the token its task was started with.
#[tokio::test]
async fn a_task_step_records_its_token() {
    let (fx, bearer, jti) = token_fixture().await;
    let id = start_task(&fx, &bearer).await;
    rests(&fx, &id, 1).await;
    let records = invocations(&fx);
    assert!(!records.is_empty(), "premise: the step was recorded");
    for record in &records {
        assert_carries(record, &fx, &jti);
    }
}

/// A task resumed with a second exchanged token records the second token for
/// the resumed step, and never the token that started it.
#[tokio::test]
async fn a_resumed_task_step_records_the_resuming_token() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        key_server: true,
        reply: Some(round::ask("confirm", "reach-round")),
        ..Setup::default()
    })
    .await;
    let ks = fx.state.key_server.as_ref().expect("fixture key server");
    let mint = crate::key_server::issuance_row_tests::mint_for;
    let (starter, starter_jti) = mint(ks, &["alpha"]).await;
    let (resumer, resumer_jti) = mint(ks, &["alpha"]).await;
    assert_ne!(starter_jti, resumer_jti, "premise: two tokens");
    let id = start_task(&fx, &starter).await;
    assert_eq!(
        rests(&fx, &id, 1).await,
        crate::protocol::tasks::TaskStatus::InputRequired,
        "premise: the task waits for its answer"
    );
    let earlier = invocations(&fx).len();
    let mut meta = tasks_meta();
    meta["io.modelcontextprotocol/clientCapabilities"]["elicitation"] = json!({});
    let resume = json!({"taskId": id, "_meta": meta,
                        "inputResponses": {"confirm": round::answer()}});
    send(&fx, &resumer, "tasks/update", &id, resume).await;
    rests(&fx, &id, 2).await;
    let later = invocations(&fx);
    let resumed = &later[earlier..];
    assert!(
        !resumed.is_empty(),
        "premise: the resumed step was recorded"
    );
    for record in resumed {
        assert_ne!(named_jti(record), Some(starter_jti.as_str()), "{record}");
    }
    let step = resumed
        .iter()
        .rev()
        .find(|record| named_jti(record) == Some(resumer_jti.as_str()))
        .unwrap_or_else(|| panic!("no resumed record names the second token: {resumed:?}"));
    assert_carries(step, &fx, &resumer_jti);
}

/// A Web UI tool call made with an admin exchanged token carries that token.
#[tokio::test]
async fn a_web_ui_tool_call_records_its_token() {
    let (fx, _, _) = token_fixture().await;
    // Admin for mint_for's issuer and group, and a token reaching every
    // backend: the two things the UI route asks of an exchanged token.
    let admin: crate::control_plane::ControlPlaneRoleRule = serde_json::from_value(
        json!({"issuer": "https://issuer.invalid", "group": "g", "role": "admin"}),
    )
    .expect("an admin mapping rule");
    fx.state
        .live_config
        .edit(|c| c.control_plane.role_mapping.rules = vec![admin]);
    let ks = fx.state.key_server.as_ref().expect("fixture key server");
    let (bearer, jti) = crate::key_server::issuance_row_tests::mint_for(ks, &["*"]).await;
    let ask = json!({"server": "alpha", "tool": "t", "arguments": {"q": 1}, "confirm_write": true});
    let route = crate::gateway::routes::UI_TOOLS_CALL;
    let (status, answer) = post_bearer(&fx, route, &ask.to_string(), &bearer, false).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "{answer}");
    assert_carries(&only_invocation(&fx), &fx, &jti);
}
