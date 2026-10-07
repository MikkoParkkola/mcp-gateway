// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The SSE response builders: the session stream, the subscription and
//! request-scoped streams, and the first-event-wins race.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::Stream;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tracing::warn;

use super::{NotificationMultiplexer, STREAMING_TARGET};
use crate::gateway::auth::live::{Delivery, delivery};
use crate::gateway::outbound::{OutboundFrame, StreamJudge, sse_data, sse_message};

/// Create SSE response for GET /mcp
///
/// Takes owned data to satisfy Rust 2024 lifetime capture rules for `impl Stream`.
#[allow(clippy::needless_pass_by_value)] // owned values required for stream lifetime
pub fn create_sse_response(
    multiplexer: Arc<NotificationMultiplexer>,
    session_id: String,
    last_event_id: Option<String>,
    keep_alive_interval: Duration,
) -> Option<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    // Access session data
    let sessions = multiplexer.sessions.read();
    let session = sessions.get(session_id.as_str())?;

    // Update last event ID if provided (for resumability)
    if let Some(ref id) = last_event_id {
        *session.last_event_id.write() = Some(id.clone());
    }

    let mut rx = session.subscribe();
    // Held for its credential slot, which a resume may replace: each copy is
    // judged against the credential the session holds when it is written.
    let session = Arc::clone(session);
    let session_id_owned = session_id;
    drop(sessions);

    // Create the stream with owned data
    let stream = stream! {
        // Send initial connection event
        yield Ok(Event::default()
            .event("connected")
            .data(json!({ "session_id": session_id_owned }).to_string()));

        loop {
            match rx.recv().await {
                Ok(item) => {
                    // G6: judged again as it is written, not only as it was
                    // queued, so a credential that died in between is written
                    // nothing.
                    match credential_at_write(&multiplexer, &session, &item).await {
                        Delivery::Deliver => {}
                        Delivery::OutOfScope => {
                            withhold(&item);
                            continue;
                        }
                        Delivery::Dead => {
                            withhold(&item);
                            settle_stranded(&mut rx);
                            warn!(target: STREAMING_TARGET, "session stream's credential no longer authenticates; closing");
                            break;
                        }
                    }
                    // MIN.2: recorded and committed as it is written; an item
                    // whose record fails closed is withheld.
                    if let Some(mark) = &item.mark
                        && !mark.written(multiplexer.reads.get()).await
                    {
                        if let Some(watch) = &item.watch {
                            watch.report(false);
                        }
                        continue;
                    }
                    if let Some(watch) = &item.watch {
                        watch.report(true);
                    }
                    let notification = &item.note;
                    // MCP-standard events (event_type == "message") send raw
                    // JSON-RPC as data so compliant clients (e.g. Claude Code)
                    // can parse them as server-to-client requests.
                    let event = if notification.event_type == "message" {
                        Event::default()
                            .event("message")
                            .data(crate::protocol::cacheable::message_event_data(&notification.data))
                    } else {
                        Event::default()
                            .event(&notification.event_type)
                            .data(serde_json::to_string(notification).unwrap_or_default())
                    };

                    // Add event ID if present
                    let event = if let Some(ref id) = notification.event_id {
                        event.id(id.clone())
                    } else {
                        event
                    };

                    yield Ok(event);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Client fell behind, notify them
                    yield Ok(Event::default()
                        .event("lagged")
                        .data(json!({ "missed": n }).to_string()));
                }
            }
        }
    };

    Some(Sse::new(stream).keep_alive(KeepAlive::new().interval(keep_alive_interval).text("ping")))
}

/// What writing `item` to `session`'s stream should do now. Without an
/// installed authorizer nothing scoped was queued (fan-out refuses), and the
/// router installs one before any stream opens, so the copy is written.
async fn credential_at_write(
    multiplexer: &NotificationMultiplexer,
    session: &super::ClientSession,
    item: &super::SessionFrame,
) -> Delivery {
    let authorizer = multiplexer.authorizer.read().clone();
    let Some(authorizer) = authorizer else {
        return Delivery::Deliver;
    };
    let credential = session.credential.read().clone();
    delivery(
        &authorizer,
        credential.as_ref(),
        item.audience.as_audience(),
    )
    .await
}

/// Report `item` withheld, so a request's waiter does not wait for it.
fn withhold(item: &super::SessionFrame) {
    if let Some(watch) = &item.watch {
        watch.report(false);
    }
}

/// H2: a stream ending on a dead credential reports every copy still queued
/// withheld, so no waiter runs to its timeout for a copy that will never be
/// written. Nothing is marked read and no receipt commits.
fn settle_stranded(rx: &mut broadcast::Receiver<super::SessionFrame>) {
    loop {
        match rx.try_recv() {
            Ok(stranded) => withhold(&stranded),
            Err(broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(_) => break,
        }
    }
}

/// Builds the frame a listener receives for a `notifications/tasks`
/// notification: the full task state, re-authorized for that reader.
///
/// `None` withholds the frame. `reader` is the listener's credential
/// re-resolved just now, so a role revoked since the stream opened is not
/// honoured from a stale snapshot.
#[async_trait::async_trait]
pub trait TaskFrames: Send + Sync {
    /// The frame to send, built but not yet on record as delivered.
    async fn frame(
        &self,
        notification: &Value,
        subscription: &crate::protocol::subscriptions::SubscriptionId,
        reader: &crate::gateway::auth::AuthenticatedClient,
    ) -> Option<TaskFrame>;
}

/// A task frame built for one reader.
pub struct TaskFrame {
    /// The tagged frame.
    pub frame: Value,
    /// It carries a stored task's output, which is a read of stored data.
    pub restored_output: bool,
    /// Records the delivery once the stream's own gates have passed.
    pub delivery: Box<dyn TaskFrameDelivery>,
}

/// The bookkeeping of a task frame that is about to be written.
#[async_trait::async_trait]
pub trait TaskFrameDelivery: Send {
    /// Record `sent` as delivered; `false` withholds it.
    async fn delivered(self: Box<Self>, sent: &Value) -> bool;
}

fn is_task_notification(notification: &Value) -> bool {
    notification.get("method").and_then(Value::as_str) == Some("notifications/tasks")
}

/// The response body of a `subscriptions/listen` request.
///
/// An SSE stream that stays open, per the transport specification: the
/// acknowledgement is its first event, and each notification the client
/// subscribed to follows on the same stream.
///
/// No resumability and no event ids — MCP 2026-07-28 removed both, so there is
/// nothing for a client to resume from and nothing to number.
// Eight inputs: each is a distinct stream concern (credential, filter, id, first
// event, keep-alive, the delivery judge, the request params for the judge, the
// per-reader task frames); bundling them would only rename the list.
#[allow(clippy::too_many_arguments)]
pub(crate) fn subscription_stream(
    mut listener: crate::gateway::subscription_registry::Listener,
    filter: crate::protocol::subscriptions::ListenRequest,
    subscription: crate::protocol::subscriptions::SubscriptionId,
    acknowledgement: Value,
    keep_alive_interval: Duration,
    judge: StreamJudge,
    request_params: Option<Value>,
    task_frames: Option<std::sync::Arc<dyn TaskFrames>>,
) -> axum::response::Response {
    use crate::gateway::subscription_registry::delivers;

    let stream = stream! {
        // The acknowledgement rides the stream it opens, so a client has one
        // thing to read rather than a body and then a stream.
        // Annotated because this function erases the stream into a
        // `Response`, so nothing else pins the error type.
        // MIN.2: the acknowledgement is a document the stream writes like any
        // other, so it is judged and recorded first; one withheld, or one its
        // record replaced, ends the stream before it opens.
        let Some(frame) = judge.judge_acknowledgement(acknowledgement, request_params.as_ref()) else {
            return;
        };
        let Some(ack) = sse_data(&judge.record(frame).await) else {
            return;
        };
        yield Ok::<_, Infallible>(Event::default().event("message").data(ack));

        let mut graceful = true;
        loop {
            match listener.recv().await {
                Ok(published) => {
                    // Filtered per listener, never at the publisher: one
                    // client's filter must not decide what another receives.
                    if !delivers(&filter, &published.notification) {
                        continue;
                    }
                    // Re-validated at delivery, only for wanted items: a token
                    // revoked or expired after the stream opened is not told.
                    match listener.delivery(&published).await {
                        Delivery::Deliver => {}
                        Delivery::OutOfScope => continue,
                        Delivery::Dead => {
                            // Skipping would hold one of the listener slots for
                            // a stream that can never receive again. Not
                            // graceful: a dead credential receives no further
                            // frame of any kind, and learns of the refusal when
                            // it re-subscribes.
                            warn!(target: STREAMING_TARGET, "subscription listener's credential no longer authenticates; closing");
                            graceful = false;
                            break;
                        }
                    }
                    // A task notification is built for THIS reader at delivery
                    // (full state, re-authorized); every other kind is the
                    // published value, tagged.
                    let (tagged, task) = match &task_frames {
                        Some(frames) if is_task_notification(&published.notification) => {
                            // Resolved again for this frame: a credential that
                            // stopped authenticating since `delivery()` passed
                            // ends the stream, as `Delivery::Dead` does.
                            let Some(reader) = listener.current_client().await else {
                                warn!(target: STREAMING_TARGET, "subscription listener's credential no longer authenticates; closing");
                                graceful = false;
                                break;
                            };
                            let Some(built) = frames
                                .frame(&published.notification, &subscription, &reader)
                                .await
                            else {
                                // A grant decision on the way could not be
                                // written. Closing makes the gap visible;
                                // re-subscribing recovers, as for a lag.
                                warn!(target: STREAMING_TARGET, "task notification withheld; closing so the client re-subscribes");
                                graceful = false;
                                break;
                            };
                            (built.frame.clone(), Some(built))
                        }
                        _ => (subscription.tag(published.notification), None),
                    };
                    // MIN.2 (H8): judged for the listener's caller, recorded,
                    // and committed as it is written; withheld when blocked.
                    // Stored task output is judged as a read of stored data.
                    let sent = task.as_ref().map(|_| tagged.clone());
                    let judged = if task.as_ref().is_some_and(|task| task.restored_output) {
                        judge.judge_restored_document(tagged)
                    } else {
                        judge.judge_document(tagged)
                    };
                    let Some(frame) = judged else {
                        continue;
                    };
                    let recorded = judge.record(frame).await;
                    if recorded.is_withheld() {
                        continue;
                    }
                    // Only a frame that is about to go out is on the delivery
                    // record, and its relay receipts count only then. The
                    // read-history commit (`sse_data`) comes after this gate,
                    // so a frame withheld here consumes no allowance.
                    if let (Some(task), Some(sent)) = (task, sent)
                        && !task.delivery.delivered(&sent).await
                    {
                        warn!(target: STREAMING_TARGET, "task notification could not be recorded; closing so the client re-subscribes");
                        graceful = false;
                        break;
                    }
                    let Some(data) = sse_data(&recorded) else {
                        continue;
                    };
                    yield Ok(Event::default().event("message").data(data));
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    // Delivering the remainder would leave this client holding
                    // stale state with no way to learn it. Closing makes the
                    // gap visible, and re-subscribing is the recovery the
                    // revision leaves available now that resumability is gone.
                    warn!(target: STREAMING_TARGET,
                        missed,
                        "subscription stream fell behind; closing so the client re-subscribes"
                    );
                    // Not graceful: updates were lost, and a success response
                    // would tell the client its state is complete.
                    graceful = false;
                    break;
                }
            }
        }
        // The server ended the subscription (a client that hangs up drops the
        // stream and never gets here). A lagged stream just closes: the
        // abrupt end is the specification's non-graceful signal. The graceful
        // end is a frame like any other, so it goes only to a credential that
        // still authenticates.
        if graceful
            && listener.current_client().await.is_some()
            && let Some(frame) = judge.judge_document(subscription.graceful_end())
            && let Some(end) = sse_data(&judge.record(frame).await)
        {
            yield Ok(Event::default().event("message").data(end));
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(keep_alive_interval).text("ping"))
        .into_response()
}

/// Re-frame an already-built JSON-RPC response as an event stream carrying the
/// notifications the backend raised during that same call, ahead of the result.
///
/// Deliberately NOT one of the two existing pipes: `subscription_stream` is
/// forbidden request-scoped traffic (SUB.2a) and `create_sse_response` is the
/// session-scoped standalone stream. This is the response body of ONE request.
///
/// The result frame is the bytes the JSON path already produced, so an SSE
/// client and a JSON client see byte-identical results -- there is no second
/// producer of the decorated result to drift from the first. `MIK-7272.SUB.2b`.
pub(crate) async fn request_scoped_event_stream(
    response: axum::response::Response,
    notifications: Vec<OutboundFrame>,
    judge: Arc<StreamJudge>,
) -> axum::response::Response {
    use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
    use futures::StreamExt as _;

    // `subscriptions/listen` already answered with a stream of its own, and a
    // refusal that never reached the dispatch has no result to frame.
    let is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !is_json {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    // Lazy, frame by frame: each notification is committed, and the answer's
    // body read (which commits its reservation, MIK-7116.MIN.2 F3), only as
    // the client reads this stream, never while it is being built.
    let sse = stream! {
        for frame in notifications {
            if let Some(event) = sse_message(&judge.record(frame).await) {
                yield Ok::<_, Infallible>(axum::body::Bytes::from(event));
            }
        }
        yield Ok(axum::body::Bytes::from_static(b"event: message\ndata: "));
        let mut result = body.into_data_stream();
        while let Some(Ok(chunk)) = result.next().await {
            yield Ok(chunk);
        }
        yield Ok(axum::body::Bytes::from_static(b"\n\n"));
    };

    parts.headers.insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/event-stream"),
    );
    parts.headers.insert(
        CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    // The re-framed body is a different length; a stale one truncates it.
    parts.headers.remove(CONTENT_LENGTH);

    (parts, axum::body::Body::from_stream(sse)).into_response()
}

/// One SSE frame carrying `data`, in the `event: message` shape both arms use.
fn message_frame(data: &str) -> String {
    format!("event: message\ndata: {data}\n\n")
}

/// The terminal frame emitted when we have committed to SSE and dispatch then
/// resolved to something we cannot frame. Ending the stream silently would
/// leave the client with neither a result nor an error -- a worse failure than
/// the one being guarded against.
const UNFRAMEABLE_FRAME: &str = concat!(
    "event: message\ndata: ",
    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"response not frameable over event stream"}}"#,
    "\n\n"
);

/// Frame a finished dispatch as the stream's last event.
///
/// Framing requires JSON and 200, or 503 (a -32005 audit refusal decided after dispatch). Else is
/// unreachable -- every non-200 is decided in validation and routing, which
/// precede the only block that can publish -- but those are properties of the
/// call graph, not invariants the compiler holds, so a future publisher gets
/// the error frame rather than a truncated body.
async fn terminal_frame(response: axum::response::Response) -> String {
    use axum::http::header::CONTENT_TYPE;

    let is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !is_json || !matches!(response.status().as_u16(), 200 | 503) {
        return UNFRAMEABLE_FRAME.to_string();
    }
    match axum::body::to_bytes(response.into_body(), usize::MAX).await {
        Ok(bytes) => message_frame(&String::from_utf8_lossy(&bytes)),
        Err(_) => UNFRAMEABLE_FRAME.to_string(),
    }
}

/// Race `dispatch` against the first notification it publishes, and let
/// whichever arrives first decide the response body's shape.
///
/// **Dispatch first** -- nothing was published, so this falls through to
/// [`request_scoped_event_stream`] and every request that publishes nothing
/// stays byte-identical to the buffered arm, non-JSON pass-through included.
///
/// **Notification first** -- commit to SSE headers before dispatch finishes,
/// write that frame immediately, keep forwarding, and frame the result last.
/// Committing early also fixes the status at 200; that is sound because a
/// request that ends non-200 never reaches the block that can publish, so it
/// always takes the buffered arm. `MIK-7272.SUB.2b`.
pub(crate) async fn first_event_wins_stream<F>(
    dispatch: F,
    mut rx: tokio::sync::mpsc::Receiver<OutboundFrame>,
    judge: Arc<StreamJudge>,
) -> axum::response::Response
where
    F: Future<Output = axum::response::Response> + Send + 'static,
{
    use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};

    let mut dispatch = Box::pin(dispatch);
    let first = tokio::select! {
        biased;
        Some(notification) = rx.recv() => notification,
        response = &mut dispatch => {
            let response = judge.emit(response).await;
            // Nothing was published; the sender is gone, so try_recv only
            // confirms that. Hand the finished response to the buffered arm.
            let mut drained = Vec::new();
            while let Ok(notification) = rx.try_recv() {
                drained.push(notification);
            }
            return request_scoped_event_stream(response, drained, judge).await;
        }
    };

    let body = stream! {
        if let Some(event) = sse_message(&judge.record(first).await) {
            yield Ok::<_, Infallible>(event);
        }
        loop {
            tokio::select! {
                biased;
                Some(notification) = rx.recv() => {
                    if let Some(event) = sse_message(&judge.record(notification).await) {
                        yield Ok(event);
                    }
                }
                response = &mut dispatch => {
                    // Drain what the sink still holds before the result frame,
                    // so a notification published as dispatch resolved is not
                    // overtaken by the result it preceded.
                    while let Ok(notification) = rx.try_recv() {
                        if let Some(event) = sse_message(&judge.record(notification).await) {
                            yield Ok(event);
                        }
                    }
                    yield Ok(terminal_frame(judge.emit(response).await).await);
                    break;
                }
            }
        }
    };

    let mut response = axum::body::Body::from_stream(body).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}

#[cfg(test)]
mod terminal_frame_tests {
    use axum::http::{StatusCode, header::CONTENT_TYPE};
    use axum::response::IntoResponse;

    /// MIK-7663.GH2409.2. A -32005 audit refusal decided after dispatch is a
    /// 503 JSON body; on a committed event stream it is framed as the stream's
    /// last message, keeping its code and request id, never replaced by the
    /// unframeable error.
    #[tokio::test]
    async fn post_dispatch_audit_refusal_keeps_code_and_id() {
        let body =
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32005,"message":"audit unavailable"}}"#;
        let response = (
            StatusCode::SERVICE_UNAVAILABLE,
            [(CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response();
        let frame = super::terminal_frame(response).await;
        assert_eq!(frame, super::message_frame(body));
        assert_ne!(frame, super::UNFRAMEABLE_FRAME);
    }

    /// Control: a 503 that is not JSON cannot be framed and gets the error frame.
    #[tokio::test]
    async fn non_json_503_is_unframeable() {
        let response = (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
        assert_eq!(
            super::terminal_frame(response).await,
            super::UNFRAMEABLE_FRAME
        );
    }
}
