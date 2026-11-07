// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Over HTTP a result's relay receipts record when the server takes the
//! response body's first chunk, under the generation current then, on the
//! meta route and the direct route alike. Each row gets its response back
//! with the body unread (the handler and `emit_http` have run), changes the
//! published collusion action, then reads the body, or drops it unread.

use super::live_recording::live_fixture;
use super::*;

/// Publish `action` on the live config the router and the Meta-MCP share.
fn publish(fx: &Fixture, action: CollusionAction) {
    let mut config = (*fx.state.live_config.get()).clone();
    config.security.firewall.collusion.action = action;
    fx.state.live_config.set(config);
}

/// What a client that takes either framing accepts.
const EITHER: &str = "application/json, text/event-stream";

/// POST `body` to `uri` as bearer `who`, accepting `accept`; the response
/// with its body unread.
async fn unread(
    fx: &Fixture,
    (uri, accept): (&str, &str),
    who: &str,
    body: &Value,
) -> axum::response::Response {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", accept)
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header(
            "mcp-name",
            body["params"]["name"].as_str().unwrap_or_default(),
        )
        .header("authorization", format!("Bearer {who}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    create_router(Arc::clone(&fx.state))
        .oneshot(request)
        .await
        .unwrap()
}

/// A meta `gateway_invoke` of `alpha:read` accepting `accept`, its body
/// unread.
async fn meta_read_accepting(fx: &Fixture, who: &str, accept: &str) -> axum::response::Response {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "gateway_invoke", "arguments": invoke("read", &json!({})),
                                 "_meta": meta_of(&json!({}))}});
    unread(fx, ("/mcp", accept), who, &body).await
}

/// [`meta_read_accepting`] either framing.
async fn meta_read_unread(fx: &Fixture, who: &str) -> axum::response::Response {
    meta_read_accepting(fx, who, EITHER).await
}

/// A direct `/mcp/alpha` call of `read`, its body unread.
async fn direct_read_unread(fx: &Fixture, who: &str) -> axum::response::Response {
    unread(
        fx,
        ("/mcp/alpha", EITHER),
        who,
        &call("read", &json!({}), None, None),
    )
    .await
}

/// Read the body as the server would; it must deliver the orchard text.
async fn take_body(response: axum::response::Response) -> String {
    assert_eq!(
        response.status().as_u16(),
        200,
        "base: the read is answered"
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    assert!(
        body.contains("orchard ledger"),
        "base: the read is delivered: {body}"
    );
    body
}

/// h1: a meta answer built under `off` and read after `block` is published
/// is recorded, so another caller's relay of it is refused.
/// Mutants killed: m2 (the generation read when the answer is built), m3
/// (the commit run when the body is wrapped, not at its first chunk).
#[tokio::test]
async fn h1_a_meta_answer_records_at_its_body_poll() {
    let fx = live_fixture(CollusionAction::Off).await;
    let response = meta_read_unread(&fx, "a").await;
    publish(&fx, CollusionAction::Block);
    take_body(response).await;
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), PROSE).await, 0);
}

/// h2: a meta answer whose body is dropped unread records nothing.
/// Mutant killed: m3 (the commit run when the body is wrapped).
#[tokio::test]
async fn h2_a_meta_body_dropped_unread_records_nothing() {
    let fx = live_fixture(CollusionAction::Block).await;
    let response = meta_read_unread(&fx, "a").await;
    drop(response);
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
}

/// h3: a JSON answer (the client accepts only JSON) that carries receipts
/// keeps its exact length and JSON content type, so it does not turn into
/// a chunked stream.
/// Mutant killed: m4 (the length dropped).
#[tokio::test]
async fn h3_an_answer_with_receipts_keeps_its_length_and_type() {
    let fx = live_fixture(CollusionAction::Block).await;
    let response = meta_read_accepting(&fx, "a", "application/json").await;
    let length = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = take_body(response).await;
    assert_eq!(length, Some(body.len()), "the length is the body's");
    assert_eq!(content_type.as_deref(), Some("application/json"));
}

/// h7: a direct-route answer built under `off` and read after `block` is
/// published is recorded.
/// Mutant killed: m13 (the direct route's immediate commit).
#[tokio::test]
async fn h7_a_direct_answer_records_at_its_body_poll() {
    let fx = live_fixture(CollusionAction::Off).await;
    let response = direct_read_unread(&fx, "a").await;
    publish(&fx, CollusionAction::Block);
    take_body(response).await;
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 0);
}

/// h7b: a direct-route body dropped unread records nothing.
/// Mutant killed: m13.
#[tokio::test]
async fn h7b_a_direct_body_dropped_unread_records_nothing() {
    let fx = live_fixture(CollusionAction::Block).await;
    let response = direct_read_unread(&fx, "a").await;
    drop(response);
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// h7c: a direct-route answer built under `block` and read after `off` is
/// published records nothing: the read decides.
/// Mutant killed: m13.
#[tokio::test]
async fn h7c_a_direct_block_to_off_flip_before_the_read_records_nothing() {
    let fx = live_fixture(CollusionAction::Block).await;
    let response = direct_read_unread(&fx, "a").await;
    publish(&fx, CollusionAction::Off);
    take_body(response).await;
    publish(&fx, CollusionAction::Block);
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
}
