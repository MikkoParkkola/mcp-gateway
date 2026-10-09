// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// `S-03` over HTTP: both halves.

// ── S-03 over HTTP: both halves ─────────────────────────────────────────────

/// Two slow calls held open at once on one session, released by a third, and
/// the body each was answered with.
///
/// Both isolation rows need the same three POSTs — two calls that park in the
/// fixture so their streams are provably open at the same time, and a third
/// that releases them — and differ only in the discriminator they then look
/// for. So only the discriminator lives in the rows.
///
/// `call_a` and `call_b` are each that call's `arguments` and its
/// request-scoped `_meta` declaration. Call A is id 2, call B is id 3, and the
/// release is id 4.
async fn concurrent_slow_bodies(
    session: &HttpSession,
    received: &Received,
    call_a: (Value, Value),
    call_b: (Value, Value),
) -> (String, String) {
    let post = |id: i64, (arguments, request_meta): (Value, Value)| {
        let (client, url, mcp_session) = (
            session.client.clone(),
            session.url.clone(),
            session.session.clone(),
        );
        tokio::spawn(async move {
            post_sse(
                &client,
                &url,
                &mcp_session,
                invoke(id, SLOW_TOOL, &arguments, &request_meta),
            )
            .await
        })
    };
    let answering_a = post(2, call_a);
    let answering_b = post(3, call_b);

    let both_parked = parked_slow_calls(received, 2).await;
    if !both_parked {
        // Release whatever did park, so the two bodies below are answers and
        // not a second timeout, and report them: a row that fails here fails
        // because of what the gateway said, and the message must carry it.
        let reached_fixture: Vec<String> = received
            .lock()
            .expect("fixture sink poisoned")
            .iter()
            .map(|request| {
                tool_name(request).unwrap_or_else(|| {
                    request
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or("?")
                        .to_owned()
                })
            })
            .collect();
        let _ = post_sse(
            &session.client,
            &session.url,
            &session.session,
            invoke(4, RELEASE_TOOL, &json!({}), &json!({})),
        )
        .await;
        let answered_a = timeout(READ_TIMEOUT, answering_a).await;
        let answered_b = timeout(READ_TIMEOUT, answering_b).await;
        let log = std::fs::read_to_string(&session.log).unwrap_or_default();
        let skip = log.chars().count().saturating_sub(12_000);
        let tail: String = log.chars().skip(skip).collect();
        panic!(
            "both calls must be in flight at once for this row to observe \
             isolation. The fixture saw {reached_fixture:?}; call A answered \
             {answered_a:?}; call B answered {answered_b:?}\ngateway log tail:\n{tail}"
        );
    }
    assert!(
        !answering_a.is_finished() && !answering_b.is_finished(),
        "a slow call answered before it was released"
    );

    let (release_status, _, release_body) = post_sse(
        &session.client,
        &session.url,
        &session.session,
        invoke(4, RELEASE_TOOL, &json!({}), &json!({})),
    )
    .await;
    assert_eq!(
        release_status, 200,
        "the release call failed, so nothing below can run: {release_body}"
    );

    let answered_a = timeout(READ_TIMEOUT, answering_a).await;
    let answered_b = timeout(READ_TIMEOUT, answering_b).await;
    let (status_a, content_type_a, body_a) =
        answered_a.expect("call A never returned").expect("call A");
    let (status_b, content_type_b, body_b) =
        answered_b.expect("call B never returned").expect("call B");
    for (label, status, content_type, body) in [
        ("A", status_a, &content_type_a, &body_a),
        ("B", status_b, &content_type_b, &body_b),
    ] {
        assert_eq!(status, 200, "call {label} was refused: {body}");
        assert!(
            content_type.contains("text/event-stream"),
            "call {label} answered {content_type}, not a stream: {body}"
        );
    }
    assert!(
        sse_frames(&body_a).iter().any(|frame| has_id(frame, 2)),
        "call A's body carries no result of its own: {body_a}"
    );
    assert!(
        sse_frames(&body_b).iter().any(|frame| has_id(frame, 3)),
        "call B's body carries no result of its own: {body_b}"
    );
    (body_a, body_b)
}

/// Every notification of one method carried by one response body, in order.
fn notified(body: &str, method: &str, field: &str) -> Vec<Value> {
    sse_frames(body)
        .into_iter()
        .filter(|frame| is_method(frame, method) && !is_gateway_own(frame))
        .filter_map(|frame| frame.pointer(field).cloned())
        .collect()
}

/// The trace ids of the gateway's own audit lines carried by one response
/// body. Exactly the frames `notified` steps over, so that the rows below can
/// assert the audit line is stream-isolated too, and emitted once — the two
/// `set_request_log_level` call sites make double emission a live risk that
/// the single-sink unit tests cannot see.
fn gateway_own_trace_ids(body: &str) -> Vec<Value> {
    sse_frames(body)
        .into_iter()
        .filter(is_gateway_own)
        .filter_map(|frame| frame.pointer("/params/data/trace_id").cloned())
        .collect()
}

/// `S-03`, message half, HTTP: two `tools/call` POSTs in flight at once each
/// receive their own backend `notifications/message` and no other's.
///
/// GIVEN two concurrent calls to the slow tool, each declaring `logLevel` and
/// each carrying a marker only its own backend leg echoes,
/// WHEN both have reached the fixture and parked there — so both response
/// streams are open at the same time — and a third call releases them,
/// THEN each response body carries its own result id and exactly its own
/// marker.
///
/// This is the row stdio cannot have (see "why there is no stdio row here"
/// above): a logging notification carries no request linkage, so the only
/// discriminator is *which stream it was written to*, and over HTTP the
/// response body is that stream. ADR-014 row 14.
///
/// The release differs from the stdio rows: it is a third POST rather than a
/// second message on one connection, because two parked calls hold two
/// connections and neither can be used to send anything.
#[tokio::test]
async fn s03_message_http_isolates_by_stream() {
    // GIVEN
    let (backend_url, received, _gate) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let marker_a = "sub2b-http-message-A";
    let marker_b = "sub2b-http-message-B";
    let (body_a, body_b) = concurrent_slow_bodies(
        &session,
        &received,
        (
            json!({"message_marker": marker_a}),
            json!({"io.modelcontextprotocol/logLevel": "info"}),
        ),
        (
            json!({"message_marker": marker_b}),
            json!({"io.modelcontextprotocol/logLevel": "info"}),
        ),
    )
    .await;

    // THEN
    assert_eq!(
        notified(&body_a, "notifications/message", "/params/data"),
        vec![json!(marker_a)],
        "call A's stream must carry its own message and only its own: {body_a}"
    );
    assert_eq!(
        notified(&body_b, "notifications/message", "/params/data"),
        vec![json!(marker_b)],
        "call B's stream must carry its own message and only its own: {body_b}"
    );
    let (audit_a, audit_b) = (
        gateway_own_trace_ids(&body_a),
        gateway_own_trace_ids(&body_b),
    );
    assert_eq!(
        audit_a.len(),
        1,
        "call A's own audit line must appear exactly once on its stream: {body_a}"
    );
    assert_eq!(
        audit_b.len(),
        1,
        "call B's own audit line must appear exactly once on its stream: {body_b}"
    );
    assert_ne!(
        audit_a, audit_b,
        "each call's audit line must carry its own trace id, not the other call's"
    );
    session.shutdown().await;
}

/// `S-03`, progress half, HTTP: two `tools/call` POSTs in flight at once each
/// receive their own `notifications/progress`, carrying their own caller's
/// token.
///
/// GIVEN two concurrent calls to the slow tool, each declaring its own
/// `progressToken`,
/// WHEN both have parked in the fixture and a third call releases them,
/// THEN each response body carries exactly its own caller's token — not the
/// other call's, and not the gateway's minted one, which ADR-014 §2 requires
/// be translated back on the way out.
///
/// The stdio instance of this row
/// (`s03_progress_stdio_each_call_sees_only_its_own_token`) can only count
/// tokens on one shared stdout. Here the two streams are separate objects, so
/// *the token is on the wrong stream* is a distinguishable failure rather than
/// an inference. ADR-014 row 14.
#[tokio::test]
async fn s03_progress_http_isolates_by_stream() {
    s03_round(Handling::Concurrent).await;
}

/// MIK-8199 AC3: a backend that takes call B only once call A is answered
/// fails this row before any token is judged, and the failure carries the
/// fixture's view and the gateway's log.
#[tokio::test]
#[should_panic(expected = "both calls must be in flight")]
async fn s03_fails_when_the_backend_serialises_the_calls() {
    s03_round(Handling::Serialised).await;
}

async fn s03_round(handling: Handling) {
    // GIVEN
    let (backend_url, received, _gate) = spawn_fixture_backend_handling(handling).await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let (body_a, body_b) = concurrent_slow_bodies(
        &session,
        &received,
        // The `call` argument is inert — the fixture reads only
        // `message_marker` — and exists so the two calls are not byte-identical
        // below `_meta`. Two requests that differ only inside `_meta` are the
        // shape an in-flight dedupe would collapse into one, and a collapsed
        // pair fails this row for a reason that has nothing to do with
        // isolation.
        (json!({"call": "A"}), json!({"progressToken": "token-A"})),
        (json!({"call": "B"}), json!({"progressToken": "token-B"})),
    )
    .await;

    // THEN
    assert_eq!(
        notified(&body_a, "notifications/progress", "/params/progressToken"),
        vec![json!("token-A")],
        "call A's stream must carry its own token and only its own: {body_a}"
    );
    assert_eq!(
        notified(&body_b, "notifications/progress", "/params/progressToken"),
        vec![json!("token-B")],
        "call B's stream must carry its own token and only its own: {body_b}"
    );
    session.shutdown().await;
}
