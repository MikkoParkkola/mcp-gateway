// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An HTTP backend's answer is counted while it is read, and one
//! over the cap is refused as `Error::ResponseTooLarge`, never held whole.

use super::*;

const CAP: usize = 64 * 1024;

/// A body template that is exactly `len` bytes once the shared server swaps
/// `{id}` for a one-digit request id (each row sends fewer than ten requests).
fn sized_template(len: usize) -> &'static str {
    let head = r#"{"jsonrpc":"2.0","id":{id},"result":{"content":[{"type":"text","text":""#;
    let tail = r#""}]}}"#;
    let pad = len + "{id}".len() - 1 - head.len() - tail.len();
    Box::leak(format!("{head}{}{tail}", "a".repeat(pad)).into_boxed_str())
}

async fn sized_server(
    status: axum::http::StatusCode,
    len: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let (addr, _hits, server) = spawn_fixed_response_server(status, sized_template(len)).await;
    (addr, server)
}

fn capped_transport(addr: std::net::SocketAddr) -> Arc<HttpTransport> {
    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    transport.set_max_response_bytes(CAP);
    transport
}

/// CAP.1/CAP.2: a 2xx JSON answer one byte over the cap is refused, typed,
/// and asked once: the retry policy reads the same answer as final.
#[tokio::test]
async fn a_json_answer_over_the_cap_is_refused_as_too_large() {
    let (addr, hits, server) =
        spawn_fixed_response_server(axum::http::StatusCode::OK, sized_template(CAP + 1)).await;
    let err = request_through_retry(&capped_transport(addr), "tools/call")
        .await
        .expect_err("an answer over the cap must be refused");
    assert!(
        matches!(err, Error::ResponseTooLarge { limit: CAP }),
        "expected ResponseTooLarge {{ limit: {CAP} }}, got: {err:?}"
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), 1);
    server.abort();
}

/// The boundary: an answer of exactly the cap is read whole.
#[tokio::test]
async fn a_json_answer_of_exactly_the_cap_is_read() {
    let (addr, server) = sized_server(axum::http::StatusCode::OK, CAP).await;
    let answer = capped_transport(addr)
        .request("tools/call", None)
        .await
        .expect("an answer of exactly the cap must be read");
    assert!(answer.result.is_some(), "{answer:?}");
    server.abort();
}

/// CAP.1: a non-2xx body is counted the same way.
#[tokio::test]
async fn an_error_body_over_the_cap_is_refused_as_too_large() {
    let (addr, server) = sized_server(axum::http::StatusCode::INTERNAL_SERVER_ERROR, CAP + 1).await;
    let err = capped_transport(addr)
        .request("tools/call", None)
        .await
        .expect_err("an error body over the cap must be refused");
    assert!(
        matches!(err, Error::ResponseTooLarge { limit: CAP }),
        "expected ResponseTooLarge {{ limit: {CAP} }}, got: {err:?}"
    );
    server.abort();
}

/// Not sticky: after one over-cap answer, the next answer under the cap on the
/// same transport is read (a per-transport budget would refuse it forever).
#[tokio::test]
async fn one_over_cap_answer_does_not_refuse_the_next_call() {
    let (big, big_server) = sized_server(axum::http::StatusCode::OK, CAP + 1).await;
    let transport = capped_transport(big);
    assert!(transport.request("tools/call", None).await.is_err());
    big_server.abort();
    let (small, small_server) = sized_server(axum::http::StatusCode::OK, 200).await;
    *transport.message_url.write() = Some(format!("http://{small}/mcp"));
    let answer = transport
        .request("tools/call", None)
        .await
        .expect("the next small answer must be read");
    assert!(answer.result.is_some(), "{answer:?}");
    small_server.abort();
}

/// Without a configured cap, the stdio default bounds an HTTP answer too.
#[test]
fn the_default_cap_is_the_stdio_frame_default() {
    let transport = make_transport("http://127.0.0.1:1/mcp");
    assert_eq!(
        transport.max_response_bytes(),
        crate::transport::DEFAULT_MAX_FRAME_BYTES
    );
}

/// A chunked answer (no Content-Length) that never ends: only counting while
/// reading can stop it.
async fn endless() -> axum::response::Response {
    use futures::StreamExt as _;
    let opening = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":""#;
    let chunks = futures::stream::iter([bytes::Bytes::from_static(opening)])
        .chain(futures::stream::repeat_with(|| {
            bytes::Bytes::from(vec![b'a'; 16 * 1024])
        }))
        .map(Ok::<_, std::io::Error>);
    axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from_stream(chunks))
        .unwrap()
}

/// CAP.1 (review r1): an endless chunked answer is refused once it crosses
/// the cap, long before any end of stream, and the next call is served.
#[tokio::test]
async fn an_endless_chunked_answer_is_refused_at_the_cap() {
    let (addr, task) = crate::test_fixture_host::serve_http(
        axum::Router::new().route("/mcp", axum::routing::post(endless)),
    )
    .await;
    let transport = capped_transport(addr);
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        transport.request("tools/call", None),
    )
    .await
    .expect("the read must stop at the cap, not wait for an end that never comes")
    .expect_err("an endless answer must be refused");
    assert!(
        matches!(err, Error::ResponseTooLarge { limit: CAP }),
        "{err:?}"
    );
    task.abort();
    let (small, small_server) = sized_server(axum::http::StatusCode::OK, 200).await;
    *transport.message_url.write() = Some(format!("http://{small}/mcp"));
    assert!(transport.request("tools/call", None).await.is_ok());
    small_server.abort();
}

// Through a Backend: the cap reaches both HTTP construction paths (R9) and an
// over-cap answer is no breaker failure (R5). Kept here, beside the cap's
// other rows, since they test the same limit end to end.

/// A peer: `/padded` pads its `initialize` answer to 70 000 bytes; a
/// `tools/call` of `big` is answered with CAP + 1 bytes, anything else small.
async fn backend_peer(uri: axum::http::Uri, body: String) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let request: Value = serde_json::from_str(&body).unwrap_or_default();
    let Some(id) = request.get("id").cloned() else {
        return axum::http::StatusCode::ACCEPTED.into_response();
    };
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let tool = request.pointer("/params/name").and_then(Value::as_str);
    let result = match (method, tool) {
        ("initialize", _) => {
            let pad = if uri.path() == "/padded" { 70_000 } else { 0 };
            serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "peer", "version": "1", "pad": "x".repeat(pad)}})
        }
        ("tools/list", _) => serde_json::json!({"tools": []}),
        ("tools/call", Some("big")) => {
            let id = id.to_string();
            let text = sized_template(CAP + 1).replace("{id}", &id);
            return (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                text,
            )
                .into_response();
        }
        _ => serde_json::json!({"content": [{"type": "text", "text": "ok"}]}),
    };
    axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

async fn peer() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new()
        .route("/padded", axum::routing::post(backend_peer))
        .route("/plain", axum::routing::post(backend_peer));
    crate::test_fixture_host::serve_http(app).await
}

fn http_backend(url: &str, limit: Option<usize>) -> Arc<crate::backend::Backend> {
    let config = crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: url.to_owned(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        max_frame_bytes: limit,
        timeout: Duration::from_secs(10),
        ..crate::config::BackendConfig::default()
    };
    Arc::new(crate::backend::Backend::new(
        "capped",
        config,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// R9: a slot's start handshake is read under the backend's own limit.
#[tokio::test]
async fn the_backend_limit_bounds_its_start_handshake() {
    let (addr, task) = peer().await;
    let url = format!("http://{addr}/padded");
    for (limit, starts) in [(None, true), (Some(128 * 1024), true), (Some(CAP), false)] {
        let started =
            tokio::time::timeout(Duration::from_secs(20), http_backend(&url, limit).start())
                .await
                .expect("each start ends within 20 s");
        assert_eq!(started.is_ok(), starts, "limit {limit:?}: {started:?}");
    }
    task.abort();
}

/// R9: a per-user listener's own transport carries the same limit.
#[test]
fn a_listener_transport_carries_the_backend_limit() {
    let url = "http://127.0.0.1:1/plain";
    let raised = http_backend(url, Some(128 * 1024))
        .listener_transport()
        .unwrap();
    assert_eq!(raised.max_response_bytes(), 128 * 1024);
    let unset = http_backend(url, None).listener_transport().unwrap();
    assert_eq!(
        unset.max_response_bytes(),
        crate::transport::DEFAULT_MAX_FRAME_BYTES
    );
}

/// R5: over-cap answers past the breaker's threshold leave it closed, and
/// the next ordinary call is served.
#[tokio::test]
async fn over_cap_answers_do_not_open_the_breaker() {
    let (addr, task) = peer().await;
    let backend = http_backend(&format!("http://{addr}/plain"), Some(CAP));
    backend.start().await.expect("the plain peer starts");
    let big = serde_json::json!({"name": "big", "arguments": {}});
    for _ in 0..6 {
        let err = backend
            .request("tools/call", Some(big.clone()))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ResponseTooLarge { .. }), "{err:?}");
    }
    assert_eq!(
        backend.circuit_breaker_stats().state,
        crate::failsafe::CircuitState::Closed,
        "an answer over the limit is the backend answering, not failing"
    );
    let small = serde_json::json!({"name": "small", "arguments": {}});
    assert!(backend.request("tools/call", Some(small)).await.is_ok());
    task.abort();
}

// Code review r1: the other two body paths, read directly.

/// The JSON-RPC id of a posted frame, as the template's `{id}` wants it.
fn posted_id(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|frame| frame.get("id").cloned())
        .map_or_else(|| "null".to_owned(), |id| id.to_string())
}

/// A POST answered as an event stream: one event carrying CAP + 1 bytes.
async fn streamed_answer(body: String) -> axum::response::Response {
    let data = sized_template(CAP + 1).replace("{id}", &posted_id(&body));
    axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .body(axum::body::Body::from(format!(
            "event: message\ndata: {data}\n\n"
        )))
        .unwrap()
}

/// CAP.1 (review r1): a POST answered as an event stream is held to the same
/// limit as a JSON body, not only to the decoder's own per-event bound.
#[tokio::test]
async fn an_event_stream_answer_over_the_cap_is_refused() {
    let app = axum::Router::new().route("/mcp", axum::routing::post(streamed_answer));
    let (addr, task) = crate::test_fixture_host::serve_http(app).await;
    let err = capped_transport(addr)
        .request("tools/call", None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::ResponseTooLarge { limit: CAP }),
        "{err:?}"
    );
    task.abort();
}

/// A legacy SSE peer: GET opens a session stream naming `/messages`; every
/// POST is answered with a JSON body, CAP + 1 bytes for `big`, CAP for `exact`.
async fn legacy_peer() -> (String, tokio::task::JoinHandle<()>) {
    async fn session() -> axum::response::Response {
        let opening = futures::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from_static(
            b"event: endpoint\ndata: /messages\n\n",
        ))]);
        let held = futures::StreamExt::chain(opening, futures::stream::pending());
        axum::response::Response::builder()
            .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
            .body(axum::body::Body::from_stream(held))
            .unwrap()
    }
    async fn message(body: String) -> axum::response::Response {
        use axum::response::IntoResponse as _;
        let frame: Value = serde_json::from_str(&body).unwrap_or_default();
        if frame.get("method").and_then(Value::as_str) == Some("initialize") {
            let id = frame.get("id").cloned().unwrap_or_default();
            let result = serde_json::json!({"protocolVersion": "2024-11-05", "capabilities": {},
                "serverInfo": {"name": "legacy", "version": "1"}});
            let answer = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
            return axum::Json(answer).into_response();
        }
        let len = match frame.pointer("/params/name").and_then(Value::as_str) {
            Some("big") => CAP + 1,
            Some("exact") => CAP,
            _ => 200,
        };
        let text = sized_template(len).replace("{id}", &posted_id(&body));
        axum::response::Response::builder()
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(text))
            .unwrap()
    }
    let app = axum::Router::new()
        .route("/sse", axum::routing::get(session))
        .route("/messages", axum::routing::post(message));
    let (addr, task) = crate::test_fixture_host::serve_http(app).await;
    (format!("http://{addr}/sse"), task)
}

/// CAP.1 (review r1): the SSE-mode JSON body is read under the cap: one byte
/// over is refused, exactly the cap is read.
#[tokio::test]
async fn an_sse_mode_json_body_is_held_to_the_cap() {
    let (url, task) = legacy_peer().await;
    let transport = make_transport_sse(&url);
    transport.set_max_response_bytes(CAP);
    transport.initialize().await.expect("the legacy handshake");
    let call = |name: &str| Some(serde_json::json!({"name": name, "arguments": {}}));
    let err = transport
        .request("tools/call", call("big"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::ResponseTooLarge { limit: CAP }),
        "{err:?}"
    );
    let exact = transport.request("tools/call", call("exact")).await;
    assert!(exact.is_ok_and(|answer| answer.result.is_some()));
    task.abort();
}

/// Review r1: on a live transport an error body that cannot be read is an
/// empty body, so the caller still gets the status; only a body over the
/// limit (row above) or under the preview's budget is reported as the read's.
#[tokio::test]
async fn an_unreadable_error_body_still_reports_the_status() {
    // A 500 that promises 100 body bytes, sends 7, and closes.
    let (addr, task) = crate::test_fixture_host::serve_cut_body(
        "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 100\r\n\r\n",
        b"partial",
    )
    .await;
    let err = capped_transport(addr)
        .request("tools/call", None)
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("500"),
        "the status, not the read failure: {err:?}"
    );
    assert!(!matches!(err, Error::ResponseTooLarge { .. }), "{err:?}");
    task.abort();
}

/// A POST answered as an event stream of twenty 8 KiB progress notes, then a
/// small result: 160 KiB in all, each event far under the cap.
async fn chatty_answer(body: String) -> axum::response::Response {
    let note = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/progress",
        "params": {"progressToken": "t", "progress": 1, "message": "p".repeat(8 * 1024)}});
    let mut stream = format!("event: message\ndata: {note}\n\n").repeat(20);
    let id = posted_id(&body);
    stream.push_str(&format!(
        "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"content\":[]}}}}\n\n"
    ));
    axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .body(axum::body::Body::from(stream))
        .unwrap()
}

/// Design delta (review r1): an event stream holds only the event being
/// assembled (notifications are published as they complete), so the limit
/// bounds one event, never the exchange's total: many small events summing
/// past the cap are served.
#[tokio::test]
async fn many_small_events_past_the_cap_in_total_are_served() {
    let app = axum::Router::new().route("/mcp", axum::routing::post(chatty_answer));
    let (addr, task) = crate::test_fixture_host::serve_http(app).await;
    let answer = capped_transport(addr).request("tools/call", None).await;
    assert!(
        answer.is_ok_and(|a| a.result.is_some()),
        "each event is under the cap"
    );
    task.abort();
}
