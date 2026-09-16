// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Plumbing for `notifications.rs`: the bounded SSE reader, the listen-stream
//! opener, and the two shaped assertions its rows share.
//!
//! A child of `notifications`, declared there with `#[path]`, so the parent
//! module promotes ONE new declaration. Nothing here asserts a criterion; every
//! oracle lives in the rows.
use super::super::super::*;
use super::super::support::*;

use futures::StreamExt as _;

/// The method the tail emits (design §6, §10.2 — no trailing segment;
/// `notifications/tasks/` is the reserved prefix).
pub(super) const TASK_NOTIFICATION: &str = "notifications/tasks";

/// Where a notification says which subscription asked for it.
pub(super) const SUBSCRIPTION_ID_META: &str = "io.modelcontextprotocol/subscriptionId";

/// Bounds the WHOLE read of an event that must arrive, not one chunk, so a
/// stream dribbling keep-alives cannot extend it.
pub(super) const ARRIVES_WITHIN: Duration = Duration::from_secs(5);

/// How long a stream that must stay quiet is observed. Honest only because a
/// positive event of the same generation has already been read.
pub(super) const SILENT_FOR: Duration = Duration::from_secs(2);

/// A [`GateHandle`] that releases every held dispatch when it is dropped, so a
/// panicking or timing-out row never parks a worker on the gate semaphore.
pub(super) struct ReleasedOnDrop(pub(super) GateHandle);

impl Drop for ReleasedOnDrop {
    fn drop(&mut self) {
        self.0.release_all();
    }
}

/// What a bounded read found. Three answers, not two: "nothing arrived on an
/// open stream" and "the stream ended" are different facts, and an absence row
/// that cannot tell them apart is satisfied by the transport failing.
pub(super) enum StreamEvent {
    Message(Value),
    Silent,
    Closed,
}

/// An open SSE body, read frame by frame.
///
/// `to_bytes` cannot be used: this response has no end, and a row written that
/// way hangs instead of failing. Chunk boundaries are not frame boundaries, so
/// bytes accumulate until a complete `\n\n`-terminated block is available.
pub(super) struct EventStream {
    body: axum::body::BodyDataStream,
    buffer: Vec<u8>,
    ended: bool,
}

impl EventStream {
    /// The next JSON payload, bounded by `within`.
    pub(super) async fn next(&mut self, within: Duration) -> StreamEvent {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if let Some(message) = self.take_frame() {
                return StreamEvent::Message(message);
            }
            if self.ended {
                return StreamEvent::Closed;
            }
            match tokio::time::timeout_at(deadline, self.body.next()).await {
                Err(_) => return StreamEvent::Silent,
                Ok(None) => self.ended = true,
                Ok(Some(Ok(chunk))) => self.buffer.extend_from_slice(&chunk),
                // A failed body is a transport fault, never an absent
                // notification, and no row may read it as one.
                Ok(Some(Err(error))) => {
                    panic!("the subscription body failed mid-stream: {error}")
                }
            }
        }
    }

    /// One complete SSE block from the buffer, skipping keep-alive comments.
    fn take_frame(&mut self) -> Option<Value> {
        loop {
            let end = self.buffer.windows(2).position(|pair| pair == b"\n\n")?;
            let block: Vec<u8> = self.buffer.drain(..end + 2).collect();
            let text = String::from_utf8(block)
                .unwrap_or_else(|error| panic!("a subscription frame must be UTF-8: {error}"));
            let data: Vec<&str> = text
                .lines()
                .filter_map(|l| l.strip_prefix("data: "))
                .collect();
            if data.is_empty() {
                // A keep-alive comment or a bare `event:` line carries no
                // payload; its timing is not what these rows are about.
                continue;
            }
            let payload = data.join("\n");
            return Some(serde_json::from_str(&payload).unwrap_or_else(|error| {
                panic!("a subscription frame must be JSON ({error}): {payload}")
            }));
        }
    }
}

/// The HTTP request the modern route requires, as `principal`.
///
/// `support::http_request`'s construction, minus the `Mcp-Name` mirror that
/// `subscriptions/listen` does not carry, copied because that function is
/// private to `support`. It cannot be skipped: `task_intent_for_call`
/// (`handlers/tasks.rs:121`) refuses `-32600` without a `VerifiedIdentity` and
/// `route_task_owner` (`:59`) derives the owner from `stable_actor_id()`, so a
/// create and a listen built differently would compare two different owners and
/// the narrowing under test would fire for a fixture reason. No new identity:
/// `key-a`/`alice` and `key-b`/`bob` are the suite's own pairs.
fn listen_request(principal: &str, body: &Value) -> axum::http::Request<axum::body::Body> {
    let method = body["method"].as_str().unwrap_or_default().to_string();
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", &method)
        .header("authorization", format!("Bearer {principal}"))
        .body(axum::body::Body::from(
            serde_json::to_vec(body).expect("a fixture body serialises"),
        ))
        .expect("a fixture request builds");
    let subject = match principal {
        "key-a" => "alice",
        "key-b" => "bob",
        "key-admin" => "root",
        other => panic!("no verified subject belongs to '{other}'"),
    };
    request
        .extensions_mut()
        .insert(crate::key_server::oidc::VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@adapter.test"),
            name: None,
            groups: Vec::new(),
            issuer: "https://idp.adapter.test".to_string(),
        });
    request
}

/// Open a listen stream as `principal` and consume its acknowledgement.
///
/// The ack is read here so that a later "nothing arrived" is about
/// notifications, and so every stream — the silent ones included — is proved
/// admitted and live before it is used as evidence.
pub(super) async fn open_listen(
    state: &Arc<AppState>,
    principal: &str,
    id: i64,
    params: Value,
) -> EventStream {
    let body = task_method(id, "subscriptions/listen", params);
    let response = create_router(Arc::clone(state))
        .oneshot(listen_request(principal, &body))
        .await
        .expect("the router must answer");
    let status = response.status();
    if status != StatusCode::OK {
        // A refusal is an ordinary body that ends, so it can be shown.
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a refusal body ends");
        panic!(
            "the listen stream for {principal} must be admitted before anything \
             can be observed on it, got {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    let mut stream = EventStream {
        body: response.into_body().into_data_stream(),
        buffer: Vec::new(),
        ended: false,
    };
    let ack = expect_message(&mut stream, "the acknowledgement that opens the stream").await;
    std::assert_eq!(
        ack["result"]["_meta"][SUBSCRIPTION_ID_META],
        json!(id),
        "the subscription id is the listen request's own id: {ack}"
    );
    stream
}

/// The next message, or a failure naming which of the other two answers came.
pub(super) async fn expect_message(stream: &mut EventStream, what: &str) -> Value {
    match stream.next(ARRIVES_WITHIN).await {
        StreamEvent::Message(message) => message,
        StreamEvent::Silent => panic!("{what} never arrived within {ARRIVES_WITHIN:?}"),
        StreamEvent::Closed => panic!("the stream ended before {what} arrived"),
    }
}

/// Assert the first notification on `stream` is this caller's own task and
/// that nothing follows it. The first message is decisive: a foreign task
/// arriving ahead of the owner's fails here, which is the per-listener
/// `delivers` filter observed rather than assumed.
pub(super) async fn assert_only_its_own_task(
    stream: &mut EventStream,
    own: &str,
    subscription: i64,
    who: &str,
) {
    let event = expect_message(stream, &format!("{who}'s own task notification")).await;
    std::assert_eq!(
        event["method"],
        json!(TASK_NOTIFICATION),
        "the method a task transition publishes is `{TASK_NOTIFICATION}`; \
         {who}'s stream carried {event}"
    );
    std::assert_eq!(
        event["params"]["taskId"],
        json!(own),
        "{who}'s stream must carry {own} and no other task: {event}"
    );
    std::assert_eq!(
        event["params"]["_meta"][SUBSCRIPTION_ID_META],
        json!(subscription),
        "a notification is tagged with the subscription that asked for it: {event}"
    );

    match stream.next(SILENT_FOR).await {
        StreamEvent::Silent => {}
        StreamEvent::Message(extra) => panic!(
            "{who}'s stream carried a second notification after its own; the \
             other principal's transition is published into this same broadcast \
             generation and must be dropped by this listener's filter: {extra}"
        ),
        StreamEvent::Closed => panic!("{who}'s stream ended instead of staying quiet"),
    }
}

/// Assert a stream that must receive nothing receives nothing — and is still
/// open while it does.
pub(super) async fn assert_receives_nothing(stream: &mut EventStream, why: &str) {
    match stream.next(SILENT_FOR).await {
        StreamEvent::Silent => {}
        StreamEvent::Message(event) => panic!("{why}, yet it carried {event}"),
        StreamEvent::Closed => panic!(
            "{why} — but the stream ENDED, so nothing was observed. An absence \
             read off a closed channel is not an absence"
        ),
    }
}

/// A task notification as design §6 defines it, for the parser controls only.
pub(super) fn task_notification(task_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": TASK_NOTIFICATION,
        "params": { "taskId": task_id }
    })
}
