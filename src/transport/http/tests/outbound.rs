// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The outbound half over HTTP, and status-carried JSON-RPC errors.

use super::*;

// =============================================================================
// MIK-7272.SUB.2b — the outbound half over HTTP.
//
// Plan rows: docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md
// :58 (S-02, "over stdio and over HTTP") and :59 (S-03, per-request isolation).
// The correlation here is the framing, not a token: every frame on a response
// stream belongs to the request that opened it.
// =============================================================================

fn sse_body(notifications: &[&str], id: u64) -> String {
    use std::fmt::Write as _;
    let mut body = String::new();
    for note in notifications {
        body.push_str("data: ");
        body.push_str(note);
        body.push_str("\n\n");
    }
    let _ = write!(
        body,
        "data: {{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"ok\":true}}}}\n\n"
    );
    body
}

const PROGRESS: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"tok-a","progress":1}}"#;
const MESSAGE: &str = r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"working"}}"#;

/// S-02 over HTTP, both methods. The token-less `notifications/message` is the
/// half stdio cannot carry: here the stream itself names the owner.
#[tokio::test]
async fn http_forwards_both_notification_methods_to_the_callers_sink() {
    let body = sse_body(&[PROGRESS, MESSAGE], 1);

    let (response, notifications) = crate::transport::notification_sink::collect(None, async {
        // ADR-014 §4: a relayed `notifications/message` reaches the caller
        // only if the caller declared a level, so the request this row is
        // about declares one. What the row asserts is unchanged.
        crate::transport::notification_sink::set_request_log_level(Some("debug"));
        sse_decoder::decode_sse_exchange(sse_stream(body)).await
    })
    .await;

    assert!(response.is_ok(), "the caller still gets its result");
    assert_eq!(notifications.len(), 2);
    assert_eq!(notifications[0].method, "notifications/progress");
    assert_eq!(
        notifications[1].method, "notifications/message",
        "a token-less notification is attributable over HTTP, and only here"
    );
}

/// S-03 over HTTP, the negative control. Two calls in flight; a notification on
/// one response stream must not cross into the other's sink. The isolation is
/// structural -- two calls are two tasks, so two sinks -- and the identical
/// progress token in both bodies is there to prove the token is not what does
/// the routing on this transport.
#[tokio::test]
async fn http_never_crosses_a_notification_between_two_calls_in_flight() {
    let mine = sse_body(&[PROGRESS], 1);
    let theirs = sse_body(
        &[
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"not yours"}}"#,
        ],
        2,
    );

    let left = tokio::spawn(crate::transport::notification_sink::collect(
        None,
        async move {
            // ADR-014 §4: a relayed `notifications/message` reaches the caller
            // only if the caller declared a level, so the request this row is
            // about declares one. What the row asserts is unchanged.
            crate::transport::notification_sink::set_request_log_level(Some("debug"));
            tokio::task::yield_now().await;
            sse_decoder::decode_sse_exchange(sse_stream(mine))
                .await
                .map(|_| ())
        },
    ));
    let right = tokio::spawn(crate::transport::notification_sink::collect(
        None,
        async move {
            // ADR-014 §4: a relayed `notifications/message` reaches the caller
            // only if the caller declared a level, so the request this row is
            // about declares one. What the row asserts is unchanged.
            crate::transport::notification_sink::set_request_log_level(Some("debug"));
            sse_decoder::decode_sse_exchange(sse_stream(theirs))
                .await
                .map(|_| ())
        },
    ));

    let (_, l) = left.await.unwrap();
    let (_, r) = right.await.unwrap();

    assert_eq!(l.len(), 1);
    assert_eq!(l[0].method, "notifications/progress");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].method, "notifications/message");
}

/// A backend that raises nothing still answers, and the sink stays empty --
/// the `Accept`-negotiated stream is a conforming answer either way.
#[tokio::test]
async fn http_leaves_the_sink_empty_when_the_backend_raises_nothing() {
    let (response, notifications) = crate::transport::notification_sink::collect(
        None,
        sse_decoder::decode_sse_exchange(sse_stream(sse_body(&[], 1))),
    )
    .await;

    assert!(response.is_ok());
    assert!(notifications.is_empty());
}

/// Row 16 - a non-probe caller receiving a status-carried JSON-RPC error sees
/// the peer's own refusal, and is not retried. The assertions read the variant
/// and the ask count, never the rendered string. What this row separates is a
/// classification, and the error type has a rendering collision by design:
/// `Error::TransportConnect`'s `Display` is byte-identical to
/// `Error::Transport`'s (`src/error.rs:158-167`), so a string assertion cannot
/// say which transport variant it caught, and the message this row does read -
/// the peer's own text - would survive a wrong variant intact.
///
/// The status is 405 and not 404 deliberately. A 404 is the one status already
/// entangled with session recovery - `is_session_expired_error`
/// (`src/transport/http/mod.rs:164`) matches on a message starting `http 404` -
/// so a 404 here would make this row and row 16d the same response shape,
/// distinguished only by the error code and whether a session was set. Nothing
/// this row pins needs 404; leaving it to row 16d keeps the two verdicts
/// independent. 400 and 426 are likewise avoided: they are the version-mismatch
/// statuses the branch above already claims (`mod.rs:1289`).
#[tokio::test]
async fn row_16_a_status_carried_json_rpc_error_reaches_the_caller_as_json_rpc() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32601,"message":"Method not found: tools/list"}}"#,
    )
    .await;

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

    let err = request_through_retry(&transport, "tools/list")
        .await
        .expect_err("a refused call must not report success");

    match &err {
        Error::JsonRpc { code, message, .. } => {
            assert_eq!(
                *code,
                crate::protocol::era::METHOD_NOT_FOUND_CODE,
                "the peer's own code must survive the status carriage"
            );
            assert!(
                message.contains("Method not found"),
                "the peer's message must replace the rendered status, got: {message}"
            );
        }
        other => panic!(
            "a status-carried JSON-RPC error must reach the caller as Error::JsonRpc, got: {other:?}"
        ),
    }
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "a refusal is terminal: retrying it asks a peer that already answered"
    );

    server.abort();
}

/// Row 16e - the referee for section 3's ruling 2b, which rows 16 and 16d
/// cannot settle between them: 16 uses a 405 and 16d a session-shaped 404, so
/// neither forces a 404 *refusal* to become `Error::JsonRpc`. A design that
/// exempted 404 from body parsing to protect session recovery would keep both
/// green while making the status-carried arm unreachable on the real HTTP path,
/// because 404 is the refusal carriage `STATELESS.5b` names.
///
/// The stale session is planted deliberately. Without it the 404 branch of
/// `is_session_expired_error` (`src/transport/http/mod.rs:164`) has nothing to
/// recover and the row would pass for the wrong reason; with it, one hit proves
/// the refusal neither re-initialized nor retried.
#[tokio::test]
async fn row_16e_a_404_carrying_a_refusal_is_terminal_and_does_not_reinitialize() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::NOT_FOUND,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32601,"message":"Method not found: tools/list"}}"#,
    )
    .await;

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    transport
        .sessions
        .write()
        .insert(String::new(), "stale-session".to_string());

    let err = request_through_retry(&transport, "tools/list")
        .await
        .expect_err("a refused call must not report success");

    match &err {
        Error::JsonRpc { code, .. } => assert_eq!(
            *code,
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
            "a 404 is the spec's refusal carriage; the peer's code must survive it"
        ),
        other => panic!(
            "a 404 carrying a refusal must reach the caller as Error::JsonRpc, got: {other:?}"
        ),
    }
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "a refusal is terminal even under 404: no retry and no re-initialize"
    );

    server.abort();
}

/// Row 16b - the other half of the same branch, and it passes today: a non-2xx
/// whose body carries no JSON-RPC error is still an opaque fault, and is still
/// retried. Split from row 16 so neither verdict masks the other.
#[tokio::test]
async fn row_16b_a_non_2xx_without_a_json_rpc_error_body_is_still_retried() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::BAD_GATEWAY,
        "<html><body>502 Bad Gateway</body></html>",
    )
    .await;

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

    let err = request_through_retry(&transport, "tools/list")
        .await
        .expect_err("a 502 must not report success");

    assert!(
        matches!(err, Error::Transport(_)),
        "an opaque gateway fault is not the peer speaking, got: {err:?}"
    );
    assert_eq!(
        hits.load(Ordering::Relaxed),
        3,
        "an opaque fault stays retryable; narrowing that is a silent availability loss"
    );

    server.abort();
}

/// Row 16g - the half row 16f alone cannot pin, and the one the health probe
/// depends on. `row_6b` asserts that a status-carried `-32603` is scored as an
/// unserved answer rather than a transport fault, but it asserts it against a
/// mock that fabricates `Error::JsonRpc` directly. Nothing in that row reaches
/// the HTTP path, so a change that stopped producing a code-bearing error for a
/// 5xx would leave `row_6b` green while the probe tore down every backend that
/// declined over HTTP with a 500. This row is that missing leg: the real
/// transport, a real 500, and the code still reaching the caller.
#[tokio::test]
async fn row_16g_a_5xx_carrying_a_json_rpc_error_keeps_the_peers_code() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32603,"message":"internal error"}}"#,
    )
    .await;

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

    let err = request_through_retry(&transport, "tools/list")
        .await
        .expect_err("a 500 must not report success");

    match &err {
        Error::JsonRpcRetryable { code, status, .. } => {
            assert_eq!(
                *code,
                crate::error::rpc_codes::INTERNAL_ERROR,
                "the probe scores the peer's code; flattening it restarts a backend that is up"
            );
            assert_eq!(*status, 500, "the carriage is what kept the retry");
        }
        other => panic!("a 5xx-carried refusal must keep the peer's code, got: {other:?}"),
    }
    assert_eq!(
        hits.load(Ordering::Relaxed),
        3,
        "a 5xx still invites a retry; carrying a code must not make it terminal"
    );

    server.abort();
}

/// Row 12 - the four body shapes the new parsing branch must NOT claim. Each
/// stays an opaque transport fault, which is what keeps the health probe
/// restarting a dead backend rather than filing a proxy's error page as a
/// considered refusal. Passes today and must keep passing: it exists to catch
/// the branch widening past what it was scoped to.
#[tokio::test]
async fn row_12_a_non_2xx_body_that_is_not_the_peers_refusal_stays_a_transport_fault() {
    const SHAPES: [(&str, &str); 4] = [
        ("absent", ""),
        ("not JSON", "<html><body>502 Bad Gateway</body></html>"),
        (
            "JSON with no error member",
            r#"{"jsonrpc":"2.0","id":{id},"result":{}}"#,
        ),
        (
            "an error under a foreign id",
            r#"{"jsonrpc":"2.0","id":"not-the-callers-id","error":{"code":-32601,"message":"Method not found"}}"#,
        ),
    ];

    for (label, body) in SHAPES {
        let (addr, _hits, server) =
            spawn_fixed_response_server(axum::http::StatusCode::BAD_GATEWAY, body).await;

        let transport = make_transport(&format!("http://{addr}/mcp"));
        *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

        let err = transport
            .request("tools/list", None)
            .await
            .expect_err("a 502 must not report success");

        assert!(
            matches!(err, Error::Transport(_)),
            "a body that is {label} is not the peer refusing, got: {err:?}"
        );

        server.abort();
    }
}

/// Row 16d - a 404 whose body carries the session-expiry refusal as a JSON-RPC
/// error must still drive session recovery.
///
/// `is_session_expired_error` (`src/transport/http/mod.rs:164`) only inspects
/// `Error::Transport` text, and only matches a message starting `http 404`. The
/// new parsing branch turns exactly this response into `Error::JsonRpc`, at
/// which point the classifier stops firing and a remote that invalidates its
/// session on token refresh is never re-initialized. The existing 404 recovery
/// test answers with a bare text body, so it cannot see this: it keeps passing
/// through the same regression.
#[tokio::test]
async fn row_16d_a_404_carrying_a_session_error_body_still_reinitializes() {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;

    const FRESH_SESSION: &str = "fresh-session-after-json-404";

    async fn mcp_handler(
        State(hits): State<Arc<std::sync::atomic::AtomicU32>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        hits.fetch_add(1, Ordering::Relaxed);
        let session = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();

        if body["method"] == "initialize" {
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("mcp-session-id", FRESH_SESSION.parse().unwrap());
            return (
                StatusCode::OK,
                resp_headers,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "serverInfo": {"name": "mock", "version": "0"}
                    }
                })),
            )
                .into_response();
        }

        if session == FRESH_SESSION {
            return (
                StatusCode::OK,
                Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {"ok": true}})),
            )
                .into_response();
        }

        // The stale session, refused as a well-formed JSON-RPC error under a
        // 404 rather than as opaque text.
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32015, "message": "Session not found"}
            })),
        )
            .into_response()
    }

    let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(Arc::clone(&hits));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    set_default_session(&transport, "stale-session-killed-on-refresh");

    let response = transport
        .request("tools/list", None)
        .await
        .expect("session recovery must carry the request through");

    assert!(
        response.error.is_none(),
        "the retried request after re-initialize must succeed"
    );
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH_SESSION),
        "the stale session must be replaced, not kept"
    );

    server.abort();
}
