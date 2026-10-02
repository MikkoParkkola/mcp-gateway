// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The HTTP answer sink (H1, H2, H4). The fast path is the plain `Json`
//! answer it always was. A frame holding a reservation is serialized up
//! front and committed only when the body is polled: an answer held unread
//! by backpressure stays pending, and one dropped unread commits nothing
//! (F3).

use axum::http::{HeaderValue, StatusCode, header::CONTENT_TYPE};
use axum::response::IntoResponse;

use super::{OutboundFrame, Payload};
use crate::protocol::JsonRpcResponse;

impl OutboundFrame {
    /// The answer this frame carries, read-only, for the status line and the
    /// client accounting that precede the write.
    pub(crate) const fn response(&self) -> Option<&JsonRpcResponse> {
        match &self.payload {
            Payload::Response(response) => Some(response),
            _ => None,
        }
    }

    /// Whether this frame answers a request (a refusal can replace it).
    pub(crate) const fn is_answer(&self) -> bool {
        matches!(self.payload, Payload::Response(_) | Payload::Answer(_))
    }
}

/// Write an answer frame as the HTTP response, with the session header when
/// `session_id` is not empty.
pub(crate) fn to_http(
    frame: OutboundFrame,
    status: StatusCode,
    session_id: &str,
) -> axum::response::Response {
    let mut response = match frame.ticket {
        None => match frame.payload {
            Payload::Response(answer) => axum::Json(answer).into_response(),
            Payload::Answer(answer) => axum::Json(answer).into_response(),
            // Only answers reach the HTTP sink; anything else writes nothing.
            _ => axum::body::Body::empty().into_response(),
        },
        Some(_) => held_body(frame),
    };
    *response.status_mut() = status;
    crate::gateway::router::helpers::attach_session_header(response.headers_mut(), session_id);
    response
}

/// The configured path with a reservation: bytes now, commit at first poll.
fn held_body(frame: OutboundFrame) -> axum::response::Response {
    let bytes = match &frame.payload {
        Payload::Response(answer) => serde_json::to_vec(answer),
        Payload::Answer(answer) => serde_json::to_vec(answer),
        _ => return axum::body::Body::empty().into_response(),
    };
    let Ok(bytes) = bytes else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let body = futures::stream::once(async move {
        frame.written();
        Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(bytes))
    });
    let mut response = axum::body::Body::from_stream(body).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
