// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Session expiry, re-initialise and retry (MIK-5982), and per-call headers.

use super::*;

// =========================================================================
// Session expiry → re-initialize → retry (MIK-5982)
// =========================================================================

/// When the backend daemon restarts, the stored session ID is dead and the
/// backend answers `-32015 Session not found`. The transport must drop the
/// session, re-run the initialize handshake, and retry the original request
/// once. Regression test for the 2026-06-11 incident (hebb unreachable 6.5h
/// behind a permanently re-opening circuit breaker).
#[tokio::test]
async fn request_reinitializes_session_and_retries_on_session_not_found() {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;

    const FRESH_SESSION: &str = "fresh-session-after-restart";

    async fn mcp_handler(
        State(hits): State<Arc<std::sync::atomic::AtomicU32>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        hits.fetch_add(1, Ordering::Relaxed);
        let session = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let method = body["method"].as_str().unwrap_or("");

        // Notifications (no id) are acknowledged unconditionally.
        if body.get("id").is_none() {
            return StatusCode::ACCEPTED.into_response();
        }

        if method == "initialize" {
            // Restarted daemon: hands out a fresh session on initialize.
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
            // Post-restart session: requests succeed.
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"ok": true}
                })),
            )
                .into_response()
        } else {
            // Stale (pre-restart) session: the rust-mcp-sdk signature.
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "code": -32015,
                    "data": null,
                    "message": "Bad Request: Session not found"
                })),
            )
                .into_response()
        }
    }

    // GIVEN: a mock backend that rejects the stale session
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
    set_default_session(&transport, "stale-session-from-before-restart");

    // WHEN: a request rides the dead session
    let response = transport.request("tools/list", None).await.unwrap();

    // THEN: the transport re-initialized and the retry succeeded
    assert!(response.error.is_none(), "retried request must succeed");
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH_SESSION),
        "fresh session ID must replace the stale one"
    );

    server.abort();
}

/// robn's case (#247): a remote that invalidates the session on OAuth token
/// refresh answers a live request with a bare HTTP 404. Per the MCP 2025-11-25
/// transport spec (2.5.4), the client must open a new session with a fresh
/// `InitializeRequest` (no session id) and retry. The transport must drop the
/// dead session, re-run the initialize handshake, and retry the original
/// request once. This is the 404 sibling of the `-32015` regression above;
/// #248 added the `http 404` clause to the expiry classifier, and this test
/// pins the end-to-end behaviour for the exact shape reported in #247.
#[tokio::test]
async fn request_reinitializes_session_and_retries_on_http_404() {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;

    const FRESH_SESSION: &str = "fresh-session-after-404";

    async fn mcp_handler(
        State(hits): State<Arc<std::sync::atomic::AtomicU32>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        hits.fetch_add(1, Ordering::Relaxed);
        let session = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let method = body["method"].as_str().unwrap_or("");

        // Notifications (no id) are acknowledged unconditionally.
        if body.get("id").is_none() {
            return StatusCode::ACCEPTED.into_response();
        }

        if method == "initialize" {
            // Remote hands out a fresh session on re-initialize (the refreshed
            // OAuth token is already on the request at this point).
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
            // Post-reinit session: requests succeed.
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"ok": true}
                })),
            )
                .into_response()
        } else {
            // Stale session invalidated on token refresh: bare HTTP 404, the
            // exact shape robn reported in #247.
            (StatusCode::NOT_FOUND, "session terminated".to_string()).into_response()
        }
    }

    // GIVEN: a streamable backend that 404s the session the remote just killed
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
    set_default_session(&transport, "stale-session-pre-refresh");

    // WHEN: a request rides the session the remote just invalidated
    let response = transport.request("tools/list", None).await.unwrap();

    // THEN: the 404 read as session-expiry; transport re-initialized and retried
    assert!(
        response.error.is_none(),
        "retried request must succeed after the 404 triggers a re-initialize"
    );
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH_SESSION),
        "fresh session ID must replace the one invalidated on token refresh"
    );

    server.abort();
}

/// MIK-6040 (#247): a remote that invalidates the MCP session on OAuth token
/// refresh may answer a live request with HTTP **200** and the expiry encoded as
/// a JSON-RPC `error` member (code `-32600`/`-32015`, message "Session not
/// found") rather than a non-2xx status. The transport sees this as
/// `Ok(JsonRpcResponse)` with `error: Some(..)`, so the `Err`-string classifier
/// never fires. The `is_session_expired_response` path must catch it and run the
/// same drop-session / re-initialize / retry-once recovery as the 404 and
/// `-32015` cases above.
#[tokio::test]
async fn request_reinitializes_on_jsonrpc_session_error_response() {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;

    const FRESH_SESSION: &str = "fresh-session-after-jsonrpc-session-err";

    async fn mcp_handler(
        State(hits): State<Arc<std::sync::atomic::AtomicU32>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        hits.fetch_add(1, Ordering::Relaxed);
        let session = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let method = body["method"].as_str().unwrap_or("");

        if body.get("id").is_none() {
            return StatusCode::ACCEPTED.into_response();
        }

        if method == "initialize" {
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
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"ok": true}
                })),
            )
                .into_response()
        } else {
            // Stale session: HTTP 200 + JSON-RPC error (the MIK-6040 shape).
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32600, "message": "Session not found"}
                })),
            )
                .into_response()
        }
    }

    // GIVEN: a backend that signals stale-session via 200 + jsonrpc error
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
    set_default_session(&transport, "stale-session-before-refresh");

    // WHEN: a request rides the dead session and the remote answers 200 + error
    let response = transport.request("tools/list", None).await.unwrap();

    // THEN: recovery re-initialized (no stale session) and the retry succeeded
    assert!(
        response.error.is_none(),
        "retried request after jsonrpc session error must succeed"
    );
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH_SESSION),
        "fresh session ID must replace the stale one"
    );

    server.abort();
}

/// A request without any session that fails with a non-session error must NOT
/// trigger the re-initialize path (no retry storm on genuinely broken backends).
#[tokio::test]
async fn request_does_not_reinitialize_without_a_session() {
    use axum::{Json, Router, http::StatusCode, routing::post};
    use serde_json::json;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Bad Request: Session not found"})),
            )
        }),
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    // No session_id set: the expiry signature without a prior session must
    // surface as a plain error (nothing to re-initialize).

    let err = transport.request("tools/list", None).await.unwrap_err();
    // The marker, not the backend's own wording: the body is redacted at the
    // boundary now, so "Session not found" never reaches an error string.
    assert!(err.to_string().contains("session expired"), "{err}");
    assert!(
        !err.to_string().contains("-32015"),
        "the untrusted body must not survive into the error: {err}"
    );

    server.abort();
}

#[test]
fn session_expired_detection_matches_known_signatures() {
    // The raw body no longer reaches the classifier: `safe_http_status_error`
    // converts it at the HTTP boundary, because the body is backend-controlled
    // and may echo our own credentials. So the contract under test is the PAIR
    // — the conversion, then the match. Testing either half alone is how this
    // broke: the redaction landed without the classifier change and session
    // recovery stopped, silently, with every other test still green (MIK-7221).
    let raw_rust_mcp_sdk =
        "{\"code\":-32015,\"data\":null,\"message\":\"Bad Request: Session not found\"}";
    let converted = safe_http_status_error(reqwest::StatusCode::BAD_REQUEST, raw_rust_mcp_sdk);
    assert!(
        !converted.to_string().contains("-32015"),
        "the untrusted body must not survive into the error: {converted}"
    );
    assert!(
        is_session_expired_error(&converted),
        "expiry must still be recognised after redaction: {converted}"
    );

    // The lowercase-only shape, which is the other half of the boundary check.
    let converted_lower =
        safe_http_status_error(reqwest::StatusCode::BAD_REQUEST, "session not found, sorry");
    assert!(is_session_expired_error(&converted_lower));

    // MCP spec: 404 = session terminated/expired. Reaches the classifier directly.
    assert!(is_session_expired_error(&Error::Transport(
        "HTTP 404 Not Found: ".to_string()
    )));

    // A non-expiry body converts to a bare status and must NOT match. Without
    // this, a conversion that returned the marker unconditionally would pass.
    let other = safe_http_status_error(reqwest::StatusCode::BAD_REQUEST, "malformed json");
    assert!(!is_session_expired_error(&other), "{other}");

    // Plain transport failure must not match
    assert!(!is_session_expired_error(&Error::Transport(
        "Request failed: connection refused".to_string()
    )));
    // Non-transport errors must not match
    assert!(!is_session_expired_error(&Error::Protocol(
        "session expired".to_string()
    )));

    // The status-carried carriage: a peer that words its expiry rather than
    // coding it used to match as `HTTP 404`, and now arrives parsed. Both arms
    // read the same marker set, or a peer loses session recovery by the
    // accident of having sent a body that parses.
    assert!(is_session_expired_error(&Error::JsonRpc {
        code: -32001,
        message: "Session expired".to_string(),
        data: None,
    }));
    // ...and the narrowness holds: an ordinary refusal is not an expiry.
    assert!(!is_session_expired_error(&Error::JsonRpc {
        code: crate::protocol::era::METHOD_NOT_FOUND_CODE,
        message: "Method not found: tools/list".to_string(),
        data: None,
    }));

    // The retryable carriage: a 429/503 whose body words the same expiry now
    // parses into `JsonRpcRetryable`. Reading only the terminal variant here
    // would keep a stale `MCP-Session-Id` and retry against a dead session.
    assert!(is_session_expired_error(&Error::JsonRpcRetryable {
        code: -32001,
        message: "Session expired".to_string(),
        status: 503,
        data: None,
    }));
    assert!(!is_session_expired_error(&Error::JsonRpcRetryable {
        code: crate::protocol::era::METHOD_NOT_FOUND_CODE,
        message: "Method not found: tools/list".to_string(),
        status: 429,
        data: None,
    }));
}

#[test]
fn session_expired_response_detection_matches_known_signatures() {
    let make = |code: i32, message: &str| JsonRpcResponse::error(None, code, message);

    // MIK-6040: 200 + JSON-RPC error shapes a remote may use for session expiry.
    assert!(is_session_expired_response(&make(
        -32600,
        "Session not found"
    )));
    assert!(is_session_expired_response(&make(
        -32015,
        "Bad Request: Session not found"
    )));
    // Match on message alone, even with an unexpected code.
    assert!(is_session_expired_response(&make(
        -32000,
        "session not found"
    )));
    // Unrelated JSON-RPC errors must not match.
    assert!(!is_session_expired_response(&make(
        -32601,
        "Method not found"
    )));
    // A successful response (no error) must not match.
    assert!(!is_session_expired_response(&JsonRpcResponse {
        result: Some(serde_json::json!({"ok": true})),
        error: None,
        ..JsonRpcResponse::error(None, 0, "")
    }));
}

// MIK-6734 slice 2b-i — request_with_headers injects per-request headers on the
// wire (the spine for identity-credential propagation), and a per-request header
// overrides a static header of the same name for that call only.
#[tokio::test]
async fn request_with_headers_injects_and_overrides_on_the_wire() {
    use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
    use tokio::sync::{Mutex, oneshot};

    async fn capture(
        State(sender): State<Arc<Mutex<Option<oneshot::Sender<HeaderMap>>>>>,
        headers: HeaderMap,
        _body: axum::body::Bytes,
    ) -> Json<serde_json::Value> {
        if let Some(s) = sender.lock().await.take() {
            let _ = s.send(headers);
        }
        Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}}))
    }

    let (tx, rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(Some(tx)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/messages", post(capture))
        .with_state(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Static header "Authorization: static" on the transport.
    let mut custom = HashMap::new();
    custom.insert("Authorization".to_string(), "static".to_string());
    let transport = make_transport_with_headers(&format!("http://{addr}/mcp"), custom);
    *transport.message_url.write() = Some(format!("http://{addr}/messages"));

    // Per-request headers: override Authorization + add a fresh header.
    let extra = vec![
        (
            "Authorization".to_string(),
            "Bearer per-user-assertion".to_string(),
        ),
        ("X-Idp-Audience".to_string(), "https://mem".to_string()),
    ];
    let _ = transport
        .request_with_headers(
            "tools/call",
            None,
            &extra,
            None,
            ResendPermission::Permitted,
        )
        .await;

    let headers = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .unwrap()
        .unwrap();
    // Per-request value wins over the static one.
    assert_eq!(headers["authorization"], "Bearer per-user-assertion");
    assert_eq!(headers["x-idp-audience"], "https://mem");
    server.abort();
}

// The default trait method ignores extra headers: plain request() behaves the
// same as request_with_headers(&[]) — no accidental leakage into a call that
// passes none.
#[tokio::test]
async fn request_without_extra_headers_uses_static_only() {
    use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
    use tokio::sync::{Mutex, oneshot};

    async fn capture(
        State(sender): State<Arc<Mutex<Option<oneshot::Sender<HeaderMap>>>>>,
        headers: HeaderMap,
        _body: axum::body::Bytes,
    ) -> Json<serde_json::Value> {
        if let Some(s) = sender.lock().await.take() {
            let _ = s.send(headers);
        }
        Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}}))
    }

    let (tx, rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(Some(tx)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/messages", post(capture))
        .with_state(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mut custom = HashMap::new();
    custom.insert("Authorization".to_string(), "static".to_string());
    let transport = make_transport_with_headers(&format!("http://{addr}/mcp"), custom);
    *transport.message_url.write() = Some(format!("http://{addr}/messages"));

    let _ = transport.request("tools/call", None).await;

    let headers = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(headers["authorization"], "static");
    assert!(!headers.contains_key("x-idp-audience"));
    server.abort();
}

// F3 reload sink-completeness (MIK-6746): close() must abort the OAuth
// token-refresh background task, or a stopped/hot-reloaded backend leaves an
// orphaned task that keeps the OAuth client Arc alive and can still refresh +
// persist a gateway-held backend token via TokenStorage::save.
#[tokio::test]
async fn close_aborts_oauth_refresh_task() {
    let t = make_transport("http://127.0.0.1:1/mcp");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    // A long-lived task standing in for the refresh loop: it only sends if it
    // is NOT aborted.
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let _ = tx.send(());
    });
    *t.refresh_task.write() = Some(handle);

    // No session_id was ever set, so close() skips the network DELETE.
    t.close().await.unwrap();

    assert!(
        t.refresh_task.read().is_none(),
        "close() must take the refresh task handle"
    );
    // Aborted task drops its sender without sending -> receiver resolves to Err.
    assert!(
        rx.await.is_err(),
        "close() must abort the refresh task (sender dropped without sending)"
    );
}

// F3 / MIK-6746 reconnect regression: initialize() is re-entered on
// session-expiry (request() -> initialize()), so storing a new refresh task
// must abort the prior one. Dropping a JoinHandle does NOT cancel the task, so
// a plain overwrite would orphan the old refresh loop, keeping the OAuth client
// Arc alive and still persisting a gateway-held token. store_refresh_task() is
// the idempotent slot used by initialize().
#[tokio::test]
async fn store_refresh_task_aborts_previous() {
    let t = make_transport("http://127.0.0.1:1/mcp");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    // First task standing in for the pre-reconnect refresh loop: only sends if
    // it is NOT aborted.
    let first = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let _ = tx.send(());
    });
    t.store_refresh_task(first);

    // Simulate reconnect storing a fresh refresh task.
    let second = tokio::spawn(async { tokio::time::sleep(Duration::from_secs(3600)).await });
    t.store_refresh_task(second);

    assert!(
        t.refresh_task.read().is_some(),
        "the reconnect refresh task must be stored"
    );
    // The first task was aborted -> its sender dropped without sending.
    assert!(
        rx.await.is_err(),
        "storing a new refresh task must abort the previous one (no orphan)"
    );
}
