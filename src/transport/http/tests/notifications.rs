// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request-scoped notifications and pre-dispatch connect failures (MIK-7272).

use super::*;

// =========================================================================
// MIK-7272.SUB.2b — request-scoped notifications MUST flow on the response
// stream of their own request. The inbound half: the transport stops
// discarding a notification it saw on a request's stream and returns it
// alongside the response, in stream order, from one call.
//
// Governing plan: the cluster B connection-invariance test plan, S-02
// (forwarding) and S-03 (per-request isolation).
// Design: the sub2b request scoped notifications design.
// =========================================================================

/// A notification seen ahead of the response is CAPTURED, not dropped.
///
/// A conforming server may interleave `notifications/progress` on the response
/// stream of the call in flight. It belongs to that call, and reaches the
/// caller's sink rather than being discarded on the way to the result.
#[tokio::test]
async fn sse_decode_captures_the_notification_seen_before_the_response() {
    // GIVEN: a progress notification ahead of the answer, on one stream
    let body = concat!(
        "event: message\n",
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"t-1\",\"progress\":1}}\n",
        "\n",
        "event: message\n",
        "data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"tools\":[]}}\n",
    );

    // WHEN: the transport decodes it inside the caller's sink scope
    let (response, notifications) = crate::transport::notify_ingress::test_support::collect(
        None,
        sse_decoder::decode_sse_exchange(sse_stream(body)),
    )
    .await;

    // THEN: the response still reaches the caller ...
    assert!(
        response
            .expect("the response after a notification must decode")
            .result
            .is_some(),
        "the response frame must still be returned"
    );
    // ... AND the notification is no longer lost.
    assert_eq!(
        notifications
            .iter()
            .map(|n| n.method.as_str())
            .collect::<Vec<_>>(),
        vec!["notifications/progress"],
        "the notification seen on this request's stream must reach its sink"
    );
}

/// Stream order is preserved: two notifications reach the sink in the order the
/// server sent them, ahead of the response that ended the scan.
///
/// Order is a property of publishing each frame as it decodes: a driver that
/// buffered and replayed could not promise it.
#[tokio::test]
async fn sse_decode_preserves_the_order_two_notifications_arrived_in() {
    // GIVEN: message then progress, in that order, before the answer
    let body = concat!(
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}\n",
        "\n",
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":2}}\n",
        "\n",
        "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n",
    );

    // WHEN: the transport decodes it
    let (_, notifications) = crate::transport::notify_ingress::test_support::collect(None, async {
        // ADR-014 §4: a relayed `notifications/message` reaches the caller
        // only if the caller declared a level, so the request this row is
        // about declares one. What the row asserts is unchanged.
        crate::transport::notification_sink::set_request_log_level(Some("debug"));
        sse_decoder::decode_sse_exchange(sse_stream(body)).await
    })
    .await;

    // THEN: both are delivered, in arrival order
    assert_eq!(
        notifications
            .iter()
            .map(|n| n.method.as_str())
            .collect::<Vec<_>>(),
        vec!["notifications/message", "notifications/progress"],
        "stream order must survive the capture"
    );
}

/// A body with no notifications leaves the sink empty, never a phantom entry.
///
/// The negative case an empty world would also satisfy is guarded by equality
/// against a literal count, not by `is_empty()` alone on an untouched channel.
#[tokio::test]
async fn sse_decode_delivers_no_notifications_when_the_server_sent_none() {
    let body = "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ok\":true}}\n";
    let (response, notifications) = crate::transport::notify_ingress::test_support::collect(
        None,
        sse_decoder::decode_sse_exchange(sse_stream(body)),
    )
    .await;
    assert!(
        response
            .expect("valid response must decode")
            .result
            .is_some()
    );
    assert_eq!(
        notifications.len(),
        0,
        "a clean stream must not manufacture a notification"
    );
}

/// The SSE stream of a call carrying `frame` ahead of its answer.
fn sse_with(frame: &serde_json::Value) -> String {
    format!(
        "event: message\ndata: {frame}\n\nevent: message\ndata: {}\n",
        serde_json::json!({"jsonrpc": "2.0", "id": 5, "result": {"content": []}})
    )
}

/// HTTP in-call: a backend's progress frame reaches the
/// caller without the gateway-only and scoped members it planted.
#[tokio::test]
async fn sse_decode_strips_what_a_backend_planted_on_a_progress_frame() {
    use crate::protocol::reserved_members::test_support::{
        assert_progress_stripped, planted_progress,
    };
    let body = sse_with(&planted_progress("t-1"));
    let (_, notifications) = crate::transport::notify_ingress::test_support::collect(
        None,
        sse_decoder::decode_sse_exchange(sse_stream(body)),
    )
    .await;
    assert_eq!(notifications.len(), 1, "the progress frame must arrive");
    let params = notifications[0].params.as_ref().expect("params");
    assert_progress_stripped("http in-call", "t-1", params);
}

/// A backend's `notifications/tasks` is the gateway's own
/// to raise; one a backend sends during a call never reaches the caller.
#[tokio::test]
async fn sse_decode_withholds_a_backend_tasks_notification() {
    let frame = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/tasks",
        "params": {"taskId": "FORGED-TASK", "status": "completed"},
    });
    let (_, notifications) = crate::transport::notify_ingress::test_support::collect(
        None,
        sse_decoder::decode_sse_exchange(sse_stream(sse_with(&frame))),
    )
    .await;
    assert!(
        notifications.is_empty(),
        "a backend notifications/tasks reached the caller: {notifications:?}"
    );
}

// =========================================================================
// MIK-7272.SUB.4 -- a connect failure is pre-dispatch only without a redirect
// =========================================================================

/// Reads one HTTP/1.1 request (head, then `content-length` body bytes) so the
/// fake server answers only after the client finished sending.
async fn drain_request(stream: &mut tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let length = String::from_utf8_lossy(&buf[..head_end])
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < head_end + length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The falsifier for the pre-dispatch signal, at the only level where a
/// redirect can actually be followed.
///
/// `safe_request_error_for` is told whether the transport's redirect counter
/// moved across the send. That claim is worth nothing unless the policy
/// closure really increments on a followed hop, and the classifier's own unit
/// rows cannot show it -- they pass the bit in by hand. This row builds the
/// real client, makes it follow a real 307 into a closed port, and asserts
/// both halves: the counter moved, and the resulting connect failure was NOT
/// released as pre-dispatch. A 307 re-submits the body, so the origin that
/// redirected may already have executed the call.
#[tokio::test]
async fn a_connect_failure_after_a_followed_redirect_is_not_pre_dispatch() {
    use tokio::io::AsyncWriteExt;

    // From the reserved range: once the listener closes below, no parallel
    // port-0 bind can take this port before the hop (MIK-8211).
    let port = crate::test_ports::reserved_port();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    // Same host AND port as the base URL (`evaluate_redirect` refuses a
    // cross-origin hop); `localhost`, a name, clears the loopback SSRF guard.
    let target = format!("http://localhost:{port}/moved");
    let server = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Close the port BEFORE answering, so the hop the client is about to
            // take is deterministically refused rather than racing this task.
            drop(listener);
            // Read the whole request first: answering and closing with request
            // bytes unread resets the connection (tokio 1.54), and the reset can
            // overtake the 307, so the FIRST request fails and no hop is taken.
            drain_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {target}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    let base = format!("http://localhost:{port}/mcp");
    let transport =
        HttpTransport::new(&base, HashMap::new(), Duration::from_secs(5), true).unwrap();
    *transport.message_url.write() = Some(base);

    let err = transport.request("tools/call", None).await.unwrap_err();
    // What the sanitized error hides: the send's real error chain, so a rare
    // sighting under load names its mechanism (MIK-8359).
    let why = format!(
        "{err}; hops followed: {}; send error: {}",
        transport.redirects_followed.load(Ordering::SeqCst),
        transport
            .last_send_error
            .lock()
            .clone()
            .unwrap_or_else(|| "none recorded".to_owned())
    );
    assert_eq!(
        transport.redirects_followed.load(Ordering::SeqCst),
        1,
        "precondition: the policy must have followed exactly one hop, or this \
         row proves nothing about the redirect case: {why}"
    );
    assert!(
        err.to_string().contains("connection failed"),
        "precondition: the hop must have been REFUSED. A timeout or a rejected \
         redirect would satisfy every other assertion here while testing \
         nothing about the redirect case: {why}"
    );
    assert!(
        !err.is_pre_dispatch(),
        "the 307 re-submitted the body, so the redirecting origin may already \
         have executed the call; releasing the idempotency key here would \
         admit a second execution: {why}"
    );
    assert!(matches!(err, Error::Transport(_)), "{why}");

    server.abort();
}

/// The positive control beside it: no redirect, connect refused, key released.
/// Without this row the counter could be wired to a constant `false` and the
/// falsifier above would still be green.
#[tokio::test]
async fn an_unredirected_connect_failure_is_pre_dispatch_end_to_end() {
    // The client end of a live loopback connection owns this port without
    // listening, for the whole test: the connect is refused on every platform,
    // and no other process can bind the port and answer it, the way it could
    // a dropped listener's port (#1754). The client is bound explicitly,
    // without address reuse, so no later connect can be handed its port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(false).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let client = socket
        .connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    // Declared after `client`, so dropped first: the server end's port, not
    // the explicitly bound one, takes the TIME_WAIT.
    let _server = listener.accept().await.unwrap().0;
    let addr = client.local_addr().unwrap();

    let base = format!("http://{addr}/mcp");
    let transport =
        HttpTransport::new(&base, HashMap::new(), Duration::from_secs(5), true).unwrap();
    *transport.message_url.write() = Some(base);

    let err = transport.request("tools/call", None).await.unwrap_err();
    assert_eq!(transport.redirects_followed.load(Ordering::SeqCst), 0);
    assert!(
        err.to_string().contains("connection failed"),
        "precondition: the port must have refused, not timed out: {err}"
    );
    assert!(
        err.is_pre_dispatch(),
        "a refused connection wrote no bytes, so the key must be released: {err}"
    );
}
