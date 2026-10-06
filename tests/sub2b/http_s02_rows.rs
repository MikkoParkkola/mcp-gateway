// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// `S-02` over HTTP.

// ── S-02 over HTTP ──────────────────────────────────────────────────────────

/// Read one notification off a still-open call, then release it and read the
/// result — the liveness assertion of ADR-014 row 4, over HTTP.
///
/// Returns the notification frame and the result frame, in the order the
/// client actually saw them. The release is a second POST because the first
/// connection is parked and cannot carry anything.
///
/// Each step has its own bound and PROBE label, so a timeout names the step
/// that stalled. Only PROBE-B is the buffered arm: there the call is parked
/// and nothing has released it. A stall at any other step is a slow POST, a
/// release that was not serviced, or a result that never came.
async fn notification_then_result(
    session: &HttpSession,
    received: &Received,
    arguments: Value,
    request_meta: Value,
) -> (Value, Value) {
    let (status, content_type, mut reader) = timeout(
        READ_TIMEOUT,
        SseReader::post(
            &session.client,
            &session.url,
            &session.session,
            invoke(2, SLOW_TOOL, &arguments, &request_meta),
        ),
    )
    .await
    .expect("PROBE-A: the slow call's POST never answered");
    assert!(
        status == 200,
        "the slow call was refused before it streamed: status={status} body={}",
        reader.drain().await
    );
    assert!(
        content_type.contains("text/event-stream"),
        "the gateway answered {content_type}, so it never committed to a \
         stream and the notification below cannot arrive before the result"
    );

    // The first frame must arrive while the call is still parked at the
    // fixture. Nothing has released it, so a buffered consumer would deadlock
    // here and this read is what proves the gateway does not.
    let mut notification = timeout(READ_TIMEOUT, reader.next_frame())
        .await
        .expect("PROBE-B: no frame while the call is parked, the buffered arm")
        .expect("the body ended before any frame");
    while is_gateway_own(&notification) {
        notification = timeout(READ_TIMEOUT, reader.next_frame())
            .await
            .expect("PROBE-B: no frame after the gateway's own audit line")
            .expect("the body ended after the gateway's own audit line");
    }
    assert!(
        parked_slow_calls(received, 1).await,
        "the frame arrived but the call is not parked, so it proves no \
         liveness: {notification}"
    );

    let (release_status, _, release_body) = timeout(
        READ_TIMEOUT,
        post_sse(
            &session.client,
            &session.url,
            &session.session,
            invoke(3, RELEASE_TOOL, &json!({}), &json!({})),
        ),
    )
    .await
    .expect("PROBE-C: the release call never returned");
    assert_eq!(
        release_status, 200,
        "the release call failed, so the result below cannot arrive: \
         {release_body}"
    );

    let mut result = timeout(READ_TIMEOUT, reader.next_frame())
        .await
        .expect("PROBE-D: no frame followed the release");
    while result.as_ref().is_some_and(|frame| !has_id(frame, 2)) {
        result = timeout(READ_TIMEOUT, reader.next_frame())
            .await
            .expect("PROBE-E: the stream stalled before the result frame");
    }
    let result = result.expect("the body ended before the result frame");
    (notification, result)
}

/// `S-02`, progress half, HTTP: a backend's `notifications/progress` reaches
/// the client that provoked it *before* that call's result.
///
/// GIVEN a call to the slow tool, which emits one progress notification and
/// then withholds its result until a second call releases it,
/// WHEN the client reads the response body incrementally,
/// THEN it reads the notification while the call is still parked, and the
/// result only after it releases it.
///
/// The order is the assertion and the parking is what gives it force: a
/// gateway that buffers cannot pass this row, because the result it would be
/// buffering does not exist until the client has acted on the notification.
/// ADR-014 Acceptance row 4.
#[tokio::test]
async fn s02_progress_http_reaches_its_own_call_before_the_result() {
    // GIVEN
    let (backend_url, received, _gate) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let (notification, result) = timeout(
        READ_TIMEOUT * 10,
        notification_then_result(
            &session,
            &received,
            json!({}),
            json!({"progressToken": "client-token"}),
        ),
    )
    .await
    .expect("the row ran past its overall bound; each step answered in its own");

    // THEN
    assert!(
        is_method(&notification, "notifications/progress"),
        "the first frame was not a progress notification: {notification}"
    );
    assert_eq!(
        progress_token_of(&notification),
        Some(&json!("client-token")),
        "the client must see its own token back, not the minted one: \
         {notification}"
    );
    assert!(
        has_id(&result, 2),
        "the last frame is not this call's result: {result}"
    );
    session.shutdown().await;
}

/// `S-02`, message half, HTTP: a backend's `notifications/message` reaches the
/// client that provoked it before that call's result.
///
/// GIVEN a call to the slow tool declaring `logLevel`, so the fixture emits a
/// logging notification and then withholds its result,
/// WHEN the client reads the response body incrementally,
/// THEN it reads the notification while the call is still parked, and the
/// result only after it releases it.
///
/// The separate row matters because a logging notification carries no request
/// linkage: the only thing tying it to this call is the stream it arrived on,
/// so the progress row above cannot stand in for it. ADR-014 Acceptance row 4.
#[tokio::test]
async fn s02_message_http_reaches_its_own_call_before_the_result() {
    // GIVEN
    let (backend_url, received, _gate) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let marker = "sub2b-http-message-solo";
    let (notification, result) = timeout(
        READ_TIMEOUT * 10,
        notification_then_result(
            &session,
            &received,
            json!({"message_marker": marker}),
            json!({"io.modelcontextprotocol/logLevel": "info"}),
        ),
    )
    .await
    .expect("the row ran past its overall bound; each step answered in its own");

    // THEN
    assert!(
        is_method(&notification, "notifications/message"),
        "the first frame was not a logging notification: {notification}"
    );
    assert_eq!(
        notification.pointer("/params/data"),
        Some(&json!(marker)),
        "the logging notification is not the one this call provoked: \
         {notification}"
    );
    assert!(
        has_id(&result, 2),
        "the last frame is not this call's result: {result}"
    );
    session.shutdown().await;
}

/// Release every parked call; the two-gate body counts one release per call.
async fn release(session: &HttpSession, id: i64) {
    let (status, _, body) = post_sse(
        &session.client,
        &session.url,
        &session.session,
        invoke(id, RELEASE_TOOL, &json!({}), &json!({})),
    )
    .await;
    assert_eq!(status, 200, "the release call failed: {body}");
}
