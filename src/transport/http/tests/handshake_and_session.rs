// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7324.COV.3: the legacy SSE handshake, session capture on a response,
//! and the OAuth token on the wire, each against a loopback peer.

use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;

use super::{default_session, make_transport, make_transport_sse, transport_with_oauth};
use crate::Error;
use crate::transport::Transport as _;

/// Every request's headers, in arrival order.
type Seen = Arc<Mutex<Vec<HeaderMap>>>;

/// A peer on loopback that records each request's headers and answers each
/// request with `answer(method)`. Returns its `http://addr` base.
async fn peer(
    answer: impl Fn(&Method) -> Response + Clone + Send + Sync + 'static,
) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |method: Method, headers: HeaderMap| {
        let record = Arc::clone(&record);
        let answer = answer.clone();
        async move {
            record.lock().unwrap().push(headers);
            answer(&method)
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{addr}"), seen)
}

fn reply(status: StatusCode, content_type: &str, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(body.into())
        .unwrap()
}

const RESULT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

fn json_result(_: &Method) -> Response {
    reply(StatusCode::OK, "application/json", RESULT.to_string())
}

/// A JSON result that also mints a session with these raw header bytes.
fn json_result_with_session(session: &'static [u8]) -> impl Fn(&Method) -> Response + Clone {
    move |method| {
        let mut response = json_result(method);
        response
            .headers_mut()
            .insert("mcp-session-id", HeaderValue::from_bytes(session).unwrap());
        response
    }
}

/// The handshake against a peer whose SSE stream is `body` (or `status`).
async fn handshake(status: StatusCode, body: String) -> crate::Result<String> {
    let (base, _) = peer(move |_| reply(status, "text/event-stream", body.clone())).await;
    make_transport_sse(&format!("{base}/sse"))
        .establish_sse_connection()
        .await
}

// =========================================================================
// SSE handshake
// =========================================================================

#[tokio::test]
async fn a_failing_sse_status_is_a_transport_error_naming_it() {
    let err = handshake(StatusCode::INTERNAL_SERVER_ERROR, String::new())
        .await
        .expect_err("a 500 opens no stream");
    assert!(
        matches!(&err, Error::Transport(m) if m.contains("500")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_handshake_past_64_kib_without_a_newline_is_refused() {
    let err = handshake(StatusCode::OK, "x".repeat(64 * 1024 + 1))
        .await
        .expect_err("an unbounded line is cut off");
    assert!(
        matches!(&err, Error::Transport(m) if m.contains("65536-byte buffer")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn exactly_64_kib_without_a_newline_is_still_read() {
    // The bound is `>`, not `>=`: at the limit the stream is read to its end.
    let err = handshake(StatusCode::OK, "x".repeat(64 * 1024))
        .await
        .expect_err("no endpoint either way");
    assert!(
        matches!(&err, Error::Transport(m) if m.contains("ended without endpoint")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn the_endpoint_event_is_found_past_other_events_and_its_session_kept() {
    // A ping's data is not an endpoint, and a blank line resets the event
    // type, so a `data:` line after it is not one either.
    let body = "event: ping\ndata: /not-this\n\nevent: endpoint\n\ndata: /also-not\n\
                event: endpoint\ndata: /messages?session_id=abc\n\n"
        .to_string();
    let (base, _) = peer(move |_| reply(StatusCode::OK, "text/event-stream", body.clone())).await;
    let t = make_transport_sse(&format!("{base}/sse"));

    let endpoint = t.establish_sse_connection().await.unwrap();

    assert_eq!(endpoint, "/messages?session_id=abc");
    assert_eq!(default_session(&t).as_deref(), Some("abc"));
}

#[tokio::test]
async fn a_stream_that_ends_without_an_endpoint_is_an_error() {
    let err = handshake(StatusCode::OK, "event: ping\ndata: {}\n\n".to_string())
        .await
        .expect_err("no endpoint event arrived");
    assert!(
        matches!(&err, Error::Transport(m) if m.contains("ended without endpoint")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn an_endpoint_that_does_not_parse_is_returned_without_a_session() {
    // Neither as a URL nor appended to `http://localhost`: the port is not a
    // number. Resolution is the caller's step; here nothing is extracted.
    let body = "event: endpoint\ndata: :x?session_id=abc\n\n".to_string();
    let (base, _) = peer(move |_| reply(StatusCode::OK, "text/event-stream", body.clone())).await;
    let t = make_transport_sse(&format!("{base}/sse"));

    assert_eq!(
        t.establish_sse_connection().await.unwrap(),
        ":x?session_id=abc"
    );
    assert_eq!(default_session(&t), None);
}

// =========================================================================
// Session capture on a response
// =========================================================================

async fn one_request(
    answer: impl Fn(&Method) -> Response + Clone + Send + Sync + 'static,
    single: bool,
) -> (
    std::sync::Arc<super::HttpTransport>,
    crate::Result<crate::protocol::JsonRpcResponse>,
) {
    let (base, _) = peer(answer).await;
    let t = make_transport(&format!("{base}/mcp"));
    if single {
        t.mark_single_tenant();
    }
    let result = t.request("tools/call", None).await;
    (t, result)
}

#[tokio::test]
async fn a_single_tenant_transport_stores_the_minted_session() {
    let (t, result) = one_request(json_result_with_session(b"sess-1"), true).await;
    result.unwrap();
    assert_eq!(default_session(&t).as_deref(), Some("sess-1"));
}

#[tokio::test]
async fn a_session_id_that_is_not_visible_ascii_is_not_stored() {
    let (t, result) = one_request(json_result_with_session(b"sess-\xe9"), false).await;
    result.unwrap();
    assert_eq!(default_session(&t), None);
}

#[tokio::test]
async fn a_response_without_a_session_id_stores_nothing() {
    let (t, result) = one_request(json_result, false).await;
    result.unwrap();
    assert!(t.sessions.read().is_empty());
}

#[tokio::test]
async fn an_event_stream_reply_to_a_post_is_decoded() {
    let answer = |_: &Method| {
        reply(
            StatusCode::OK,
            "text/event-stream",
            format!("event: message\ndata: {RESULT}\n\n"),
        )
    };
    let (_, result) = one_request(answer, false).await;
    assert_eq!(
        result.unwrap().result,
        Some(serde_json::json!({"ok": true}))
    );
}

// The multi-entry guard: a per-user slot's transport that would come to hold
// a second caller's session trips the debug assertion rather than mixing them.
#[cfg(debug_assertions)]
#[tokio::test]
#[should_panic(expected = "must never accumulate more than one caller identity's session")]
async fn a_single_tenant_transport_never_holds_a_second_callers_session() {
    let (base, _) = peer(json_result_with_session(b"sess-2")).await;
    let t = make_transport(&format!("{base}/mcp"));
    t.mark_single_tenant();
    t.sessions
        .write()
        .insert("other-caller".to_string(), "sess-1".to_string());
    let _ = t.request("tools/call", None).await;
}

// =========================================================================
// OAuth token on the wire
// =========================================================================

#[tokio::test]
async fn a_live_oauth_token_is_sent_as_a_bearer_on_requests_and_the_sse_stream() {
    let token = format!("{}-{}", "live", "token");
    // GET opens the SSE stream; POST carries a request.
    let (base, seen) = peer(|method| {
        if method == Method::GET {
            reply(
                StatusCode::OK,
                "text/event-stream",
                "event: endpoint\ndata: /messages\n\n".to_string(),
            )
        } else {
            json_result(method)
        }
    })
    .await;
    let t = transport_with_oauth(&format!("{base}/mcp")).unwrap();
    t.oauth_client
        .as_ref()
        .unwrap()
        .lock()
        .await
        .install_live_token_for_test(&token);

    t.request("tools/call", None).await.unwrap();
    t.establish_sse_connection().await.unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    for headers in seen.iter() {
        assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {token}"));
    }
}

#[tokio::test]
async fn an_unparseable_message_target_gets_no_oauth_token() {
    let t = transport_with_oauth("http://127.0.0.1:1/mcp").unwrap();
    *t.message_url.write() = Some("not a url".to_string());

    let err = t.get_oauth_token().await.expect_err("no target, no token");

    assert!(
        matches!(&err, Error::TransportPermanent(m) if m.contains("unparseable target")),
        "got {err:?}"
    );
}
