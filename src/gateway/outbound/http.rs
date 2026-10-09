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

    /// The answer as it will be written, for a record that hashes it: the
    /// direct route's rendered value, or a refusal that replaced it.
    pub(crate) fn answer_document(&self) -> Option<serde_json::Result<serde_json::Value>> {
        match &self.payload {
            Payload::Answer(answer) => Some(Ok(answer.clone())),
            Payload::Response(response) => Some(serde_json::to_value(response)),
            _ => None,
        }
    }
}

/// The `tenant_read` record an answer still owes: written by [`emit_http`]
/// once every late replacer ran, so it describes the frame actually sent
/// (design §4.6).
#[derive(Debug, Clone)]
struct PendingRecord(serde_json::Map<String, serde_json::Value>);

/// Write `response`'s pending `tenant_read` record, after the late replacers
/// (`slot_http`). Under `FailClosed` a failed write replaces the answer with
/// the audit-unavailable refusal; its body is dropped unread, so its
/// reservation commits nothing.
pub(crate) async fn emit_http(
    response: axum::response::Response,
    log: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
) -> axum::response::Response {
    emit_http_checked(response, log).await.0
}

/// [`emit_http`], also saying whether the answer went out as built (`true`)
/// or a failed read-record write replaced it (`false`): what a relay receipt
/// may follow.
pub(crate) async fn emit_http_checked(
    mut response: axum::response::Response,
    log: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
) -> (axum::response::Response, bool) {
    let receipts = response
        .extensions_mut()
        .remove::<crate::gateway::meta_mcp::invoke::relay::DeferredReceipts>();
    let (response, written) = emit_pending(response, log).await;
    // The answer went out as built, or a failed read record replaced it.
    if let Some(receipts) = receipts {
        receipts.commit(written);
    }
    (response, written)
}

async fn emit_pending(
    mut response: axum::response::Response,
    log: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
) -> (axum::response::Response, bool) {
    let Some(PendingRecord(fields)) = response.extensions_mut().remove::<PendingRecord>() else {
        return (response, true);
    };
    if super::audit::record_fields(fields, log).await {
        return (response, true);
    }
    let id = response
        .extensions()
        .get::<HeldAnswerId>()
        .and_then(|held| held.0.clone());
    let refusal = id.map_or_else(
        || {
            let error = crate::Error::AuditUnavailable;
            JsonRpcResponse::error(None, error.to_rpc_code(), error.to_string())
        },
        |id| {
            crate::gateway::meta_mcp::error_response_preserving_status(
                id,
                &crate::Error::AuditUnavailable,
            )
        },
    );
    let mut refused = (StatusCode::SERVICE_UNAVAILABLE, axum::Json(refusal)).into_response();
    // The refusal keeps the answer's session header, so a legacy client keeps
    // its session across it.
    if let Some(session) = response.headers().get("mcp-session-id") {
        refused
            .headers_mut()
            .insert("mcp-session-id", session.clone());
    }
    (refused, false)
}

/// A late replacer swapping `from` for `to`: the original's pending read
/// record moves to the replacement, so [`emit_http`] still records the
/// original assessment (design §4.6), and `from`'s body is dropped unread.
pub(crate) fn carry_record(from: &mut axum::response::Response, to: &mut axum::response::Response) {
    if let Some(record) = from.extensions_mut().remove::<PendingRecord>() {
        to.extensions_mut().insert(record);
    }
    if let Some(id) = from.extensions_mut().remove::<HeldAnswerId>() {
        to.extensions_mut().insert(id);
    }
}

/// Write an answer frame as the HTTP response, with the session header when
/// `session_id` is not empty. Its `tenant_read` record is left pending for
/// [`emit_http`].
pub(crate) fn to_http(
    frame: OutboundFrame,
    status: StatusCode,
    session_id: &str,
) -> axum::response::Response {
    let pending = frame
        .assessment()
        .filter(|_| !frame.record_taken)
        .map(|a| a.record_fields(frame.key.as_deref()))
        .filter(|fields| !fields.is_empty());
    let held_id = pending.as_ref().map(|_| frame.answer_id());
    // MIK-8176: the holds this answer carries ride on the response until its
    // reply hands them off; a replacer's new response leaves them behind.
    let carried = match &frame.payload {
        Payload::Response(answer) => answer
            .result
            .as_ref()
            .map(crate::gateway::meta_mcp::sealed_hold::carried),
        Payload::Answer(answer) => Some(crate::gateway::meta_mcp::sealed_hold::carried(answer)),
        _ => None,
    };
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
    if let Some(carried) = carried {
        response.extensions_mut().insert(carried);
    }
    if let Some(fields) = pending {
        response.extensions_mut().insert(PendingRecord(fields));
        if let Some(id) = held_id {
            response.extensions_mut().insert(HeldAnswerId(id));
        }
    }
    response
}

/// The request id of an answer whose body holds a reservation, so a late
/// replacer (`slot_http`) can refuse it without reading, and so committing,
/// the body it drops.
#[derive(Debug, Clone)]
pub(crate) struct HeldAnswerId(pub(crate) Option<crate::protocol::RequestId>);

/// The configured path with a reservation: bytes now, commit at first poll.
fn held_body(frame: OutboundFrame) -> axum::response::Response {
    let id = frame.answer_id();
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
    response.extensions_mut().insert(HeldAnswerId(id));
    response
}
