// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WIRE.18: exercise the production SSE response body, including its drop.
//! Full authenticated HTTP request/reply routing remains WIRE.8 coverage.

use super::*;
use axum::response::IntoResponse;
use futures::StreamExt;
use futures::stream::BoxStream;

type Body = BoxStream<'static, Result<axum::body::Bytes, axum::Error>>;

fn body(mux: &Arc<NotificationMultiplexer>, session: &str) -> Body {
    crate::gateway::streaming::create_sse_response(
        Arc::clone(mux),
        session.to_string(),
        None,
        Duration::from_secs(60),
    )
    .expect("the session exists")
    .into_response()
    .into_body()
    .into_data_stream()
    .boxed()
}

async fn event(body: &mut Body, expected: &str) -> Value {
    let bytes = tokio::time::timeout(LIMIT, body.next())
        .await
        .expect("a complete SSE body frame must be yielded")
        .expect("the body remains open")
        .expect("the body has no I/O error");
    let frame = std::str::from_utf8(&bytes).expect("UTF-8 SSE");
    assert!(frame.ends_with("\n\n"), "complete SSE frame: {frame:?}");
    assert!(
        frame
            .lines()
            .any(|line| line == format!("event: {expected}")),
        "expected {expected}, got {frame:?}"
    );
    let data = frame
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .collect::<Vec<_>>()
        .join("\n");
    let value: Value = serde_json::from_str(&data).expect("JSON SSE data");
    assert_eq!(
        frame,
        format!("event: {expected}\ndata: {value}\n\n"),
        "the body must contain exactly one event line, one canonical JSON data line and one terminating blank line"
    );
    value
}

async fn no_frame(body: &mut Body) {
    assert!(
        tokio::time::timeout(Duration::from_millis(20), body.next())
            .await
            .is_err(),
        "no frame or closure may arrive while queued producers can run"
    );
}

async fn pending_ids<T>(
    proxy: &ProxyManager,
    expected: usize,
    wait: &tokio::task::JoinHandle<T>,
) -> Vec<String> {
    // The raw channel registers and synchronously try_sends before its first
    // await. A pending map observed after yielding therefore witnesses an
    // enqueued exchange; failed enqueue removes it before yielding.
    let started = std::time::Instant::now();
    loop {
        let ids: Vec<_> = proxy.pending_sampling.read().keys().cloned().collect();
        assert!(ids.len() <= expected, "unexpected extra pending exchange");
        if ids.len() == expected {
            return ids;
        }
        assert!(
            !wait.is_finished(),
            "the exchange ended before a writer accepted it"
        );
        // A yielding runnable task prevents Tokio's paused clock from auto-
        // advancing. Use a real bound for this staging loop, not paused time.
        assert!(
            started.elapsed() < LIMIT,
            "the production body must have a live selected request writer"
        );
        tokio::task::yield_now().await;
    }
}

fn answer(proxy: &ProxyManager, session: &str, id: &str) -> Value {
    let reply = json!({"jsonrpc":"2.0", "id":id, "result":{"roots":[]}});
    assert!(proxy.resolve_pending(id, session, reply.clone()));
    reply
}

async fn bridge_result(
    wait: tokio::task::JoinHandle<Result<Value, BridgeError>>,
) -> Result<Value, BridgeError> {
    tokio::time::timeout(LIMIT, wait)
        .await
        .expect("the bridge finishes within the test bound")
        .expect("the bridge task does not panic")
}

async fn bridge_result_without_time_advance(
    wait: tokio::task::JoinHandle<Result<Value, BridgeError>>,
) -> Result<Value, BridgeError> {
    let clock = tokio::time::Instant::now();
    let watchdog = std::time::Instant::now();
    std::future::poll_fn(|cx| {
        if wait.is_finished() {
            return std::task::Poll::Ready(());
        }
        assert!(
            watchdog.elapsed() < LIMIT,
            "dropping the selected body must finish its exchange without any prompt timeout"
        );
        // Keep the runtime runnable so paused Tokio time cannot advance to
        // the bridge's prompt deadline and manufacture the same NoSession.
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    })
    .await;
    assert_eq!(tokio::time::Instant::now(), clock);
    wait.await.expect("the bridge task does not panic")
}

fn refused(result: Result<Value, BridgeError>, retries: &RetryLog, proxy: &ProxyManager) {
    assert!(
        matches!(
            result,
            Err(BridgeError::Delivery {
                error: DeliveryError::NoSession,
                ..
            })
        ),
        "non-delivery must fail closed: {result:?}"
    );
    assert!(retries.0.lock().expect("retry log").is_empty());
    assert!(proxy.pending_sampling.read().is_empty());
}

#[tokio::test]
async fn mik_7212_sse_two_bodies_receive_one_raw_request() {
    let (mux, proxy, session) = fixture();
    let mut first = body(&mux, &session);
    let mut second = body(&mux, &session);
    event(&mut first, "connected").await;
    event(&mut second, "connected").await;
    let id = "sse-one-recipient";
    let wait = start(&proxy, &session, id, "roots/list", None);
    pending_ids(&proxy, 1, &wait).await;
    assert_eq!(
        event(&mut first, "message").await,
        json!({"jsonrpc":"2.0","id":id,"method":"roots/list"})
    );
    no_frame(&mut second).await;
    let reply = answer(&proxy, &session, id);
    assert_eq!(finish(wait).await, Ok(reply));
    assert!(proxy.pending_sampling.read().is_empty());
    no_frame(&mut first).await;
    no_frame(&mut second).await;
}

#[tokio::test]
async fn mik_7212_sse_raw_frame_preserves_params_and_id() {
    let (mux, proxy, session) = fixture();
    let mut first = body(&mux, &session);
    event(&mut first, "connected").await;
    let id = "sse-exact-frame";
    let params = json!({"messages":[], "maxTokens":23, "unknown":{"keep":[true,7]}});
    let wait = start(
        &proxy,
        &session,
        id,
        "sampling/createMessage",
        Some(params.clone()),
    );
    pending_ids(&proxy, 1, &wait).await;
    assert_eq!(
        event(&mut first, "message").await,
        json!({"jsonrpc":"2.0","id":id,"method":"sampling/createMessage","params":params})
    );
    let reply = json!({"jsonrpc":"2.0","id":id,"result":{
        "role":"assistant", "model":"client", "content":{"type":"text","text":"answer"}
    }});
    assert!(proxy.resolve_pending(id, &session, reply.clone()));
    assert_eq!(finish(wait).await, Ok(reply));
    assert!(proxy.pending_sampling.read().is_empty());
    no_frame(&mut first).await;
}

#[tokio::test(start_paused = true)]
async fn mik_7212_sse_selected_unpolled_body_drop_refuses_without_replay() {
    let (mux, proxy, session) = fixture();
    let first = body(&mux, &session);
    let mut second = body(&mux, &session);
    let retries = Arc::new(RetryLog::default());
    let wait = start_bridge(&proxy, &session, &retries);
    let ids = pending_ids(&proxy, 1, &wait).await;
    drop(first);
    refused(
        bridge_result_without_time_advance(wait).await,
        &retries,
        &proxy,
    );
    event(&mut second, "connected").await;
    no_frame(&mut second).await;
    let mut late = body(&mux, &session);
    event(&mut late, "connected").await;
    no_frame(&mut late).await;
    assert!(!proxy.resolve_pending(
        &ids[0],
        &session,
        json!({"jsonrpc":"2.0","id":ids[0],"result":{"roots":[]}})
    ));
}

#[tokio::test]
async fn mik_7212_sse_selected_body_drop_after_handoff_refuses_without_replay() {
    let (mux, proxy, session) = fixture();
    let mut first = body(&mux, &session);
    let mut second = body(&mux, &session);
    event(&mut first, "connected").await;
    let retries = Arc::new(RetryLog::default());
    let wait = start_bridge(&proxy, &session, &retries);
    let request = event(&mut first, "message").await;
    assert_eq!(request["method"], "roots/list");
    assert!(pending(&proxy, request["id"].as_str().expect("request ID")));
    drop(first);
    refused(bridge_result(wait).await, &retries, &proxy);
    event(&mut second, "connected").await;
    no_frame(&mut second).await;
}

#[tokio::test(start_paused = true)]
async fn mik_7212_sse_unpolled_body_expiry_never_retries_or_yields_question() {
    let (mux, proxy, session) = fixture();
    let mut first = body(&mux, &session);
    let retries = Arc::new(RetryLog::default());
    let wait = start_bridge(&proxy, &session, &retries);
    pending_ids(&proxy, 1, &wait).await;
    tokio::time::advance(BRIDGE_PROMPT_TIMEOUT + Duration::from_millis(1)).await;
    refused(bridge_result(wait).await, &retries, &proxy);
    event(&mut first, "connected").await;
    no_frame(&mut first).await;
}

#[tokio::test(start_paused = true)]
async fn mik_7212_sse_yielded_frame_timeout_retries_with_missing_answer() {
    let (mux, proxy, session) = fixture();
    let mut first = body(&mux, &session);
    event(&mut first, "connected").await;
    let retries = Arc::new(RetryLog::default());
    let wait = start_bridge(&proxy, &session, &retries);
    let request = event(&mut first, "message").await;
    assert_eq!(request["method"], "roots/list");
    assert!(pending(&proxy, request["id"].as_str().expect("request ID")));
    tokio::time::advance(BRIDGE_PROMPT_TIMEOUT + Duration::from_millis(1)).await;
    assert_eq!(
        bridge_result(wait).await,
        Ok(json!({"content":[{"type":"text","text":"done"}]}))
    );
    {
        let calls = retries.0.lock().expect("retry log");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].get("inputResponses").is_none());
        assert_eq!(calls[0]["requestState"], "backend-opaque-state");
    }
    assert!(proxy.pending_sampling.read().is_empty());
    no_frame(&mut first).await;
}

#[tokio::test]
async fn mik_7212_sse_queued_abort_preserves_the_other_exchange() {
    let (mux, proxy, session) = fixture();
    let mut first = body(&mux, &session);
    let aborted = start(&proxy, &session, "sse-abort-a", "roots/list", None);
    pending_ids(&proxy, 1, &aborted).await;
    let kept = start(&proxy, &session, "sse-keep-b", "roots/list", None);
    pending_ids(&proxy, 2, &kept).await;
    aborted.abort();
    assert!(
        tokio::time::timeout(LIMIT, aborted)
            .await
            .expect("abort join bound")
            .expect_err("task was cancelled")
            .is_cancelled()
    );
    assert!(!pending(&proxy, "sse-abort-a"));
    assert!(pending(&proxy, "sse-keep-b"));
    event(&mut first, "connected").await;
    assert_eq!(
        event(&mut first, "message").await,
        json!({"jsonrpc":"2.0","id":"sse-keep-b","method":"roots/list"})
    );
    let reply = answer(&proxy, &session, "sse-keep-b");
    assert_eq!(finish(kept).await, Ok(reply));
    no_frame(&mut first).await;
    assert!(proxy.pending_sampling.read().is_empty());
}

#[tokio::test]
async fn mik_7212_sse_reply_before_body_poll_suppresses_a_late_question() {
    let (mux, proxy, session) = fixture();
    let mut first = body(&mux, &session);
    let id = "sse-early-reply";
    let wait = start(&proxy, &session, id, "roots/list", None);
    pending_ids(&proxy, 1, &wait).await;
    let reply = answer(&proxy, &session, id);
    assert_eq!(finish(wait).await, Ok(reply));
    event(&mut first, "connected").await;
    no_frame(&mut first).await;
}

#[tokio::test]
async fn mik_7212_sse_owner_removal_closes_a_handed_off_exchange() {
    let (mux, proxy, session) = fixture();
    let mut first = body(&mux, &session);
    event(&mut first, "connected").await;
    let retries = Arc::new(RetryLog::default());
    let wait = start_bridge(&proxy, &session, &retries);
    let request = event(&mut first, "message").await;
    let id = request["id"].as_str().expect("request ID");
    assert!(pending(&proxy, id));
    assert!(!mux.remove_session_for(&session, "foreign"));
    assert!(
        pending(&proxy, id),
        "foreign removal must preserve the exchange"
    );
    assert!(mux.remove_session_for(&session, "anonymous"));
    refused(bridge_result(wait).await, &retries, &proxy);
    assert!(!proxy.resolve_pending(
        id,
        &session,
        json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}})
    ));
}

#[tokio::test]
async fn mik_7212_sse_notifications_still_reach_both_bodies() {
    let (mux, _proxy, session) = fixture();
    let mut first = body(&mux, &session);
    let mut second = body(&mux, &session);
    event(&mut first, "connected").await;
    event(&mut second, "connected").await;
    let notification = json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"});
    assert!(mux.send_to_session(
        &session,
        TaggedNotification {
            source: "backend".to_string(),
            event_type: "message".to_string(),
            data: notification.clone(),
            event_id: None,
        }
    ));
    assert_eq!(event(&mut first, "message").await, notification);
    assert_eq!(event(&mut second, "message").await, notification);
}
