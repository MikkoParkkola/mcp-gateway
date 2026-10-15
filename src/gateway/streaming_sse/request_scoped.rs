// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The request-scoped SSE stream.

use super::{Arc, Infallible, IntoResponse, OutboundFrame, StreamJudge, sse_message};
use async_stream::stream;

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
/// Marks a gateway-authored refusal that must reach the client exactly as the
/// auth layer's would, whatever `Accept` offered: it is not framed as an event.
#[derive(Clone, Copy)]
pub(crate) struct Unframed;

pub(crate) async fn request_scoped_event_stream(
    response: axum::response::Response,
    notifications: Vec<OutboundFrame>,
    judge: Arc<StreamJudge>,
) -> axum::response::Response {
    use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
    use futures::StreamExt as _;

    // `subscriptions/listen` already answered with a stream of its own, and a
    // refusal that never reached the dispatch has no result to frame.
    if response.extensions().get::<Unframed>().is_some() {
        return response;
    }
    let is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !is_json {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    // MIK-8176: the answer's holds move into the stream and are handed off
    // only as its event is yielded; a stream dropped first gives them back.
    let carried = parts
        .extensions
        .remove::<crate::gateway::meta_mcp::sealed_hold::CarriedHolds>();
    // Lazy, frame by frame: each notification is committed, and the answer's
    // body read (which commits its reservation, MIK-7116.MIN.2 F3), only as
    // the client reads this stream, never while it is being built.
    let sse = stream! {
        for frame in notifications {
            if let Some(event) = sse_message(&judge.record(frame).await) {
                yield Ok::<_, Infallible>(axum::body::Bytes::from(event));
            }
        }
        if let Some(carried) = &carried {
            crate::gateway::meta_mcp::sealed_hold::hand_off(carried);
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
