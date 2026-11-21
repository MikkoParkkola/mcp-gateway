// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every call made with an exchanged key-server token records that token,
//! its id and its issuance row in the call's decision.

use super::*;

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
