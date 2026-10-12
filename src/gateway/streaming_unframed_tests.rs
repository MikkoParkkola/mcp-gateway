// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: a refusal marked `Unframed` reaches the client as the auth
//! layer's would, whatever was queued beside it: no event wraps it.

use super::*;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse as _;

fn judge() -> Arc<StreamJudge> {
    Arc::new(StreamJudge::new(
        None,
        Arc::new(crate::gateway::outbound::RejectionAudit::new(None, 1)),
        None,
    ))
}

const REFUSAL: &str = "{\"error\":{\"code\":-32000,\"message\":\"Invalid token\"}}";

fn refusal() -> axum::response::Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        [(CONTENT_TYPE, "application/json")],
        REFUSAL.to_string(),
    )
        .into_response()
}

async fn passed_through(response: axum::response::Response) -> (u16, String) {
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a bounded body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf-8"))
}

#[tokio::test]
async fn an_unframed_refusal_is_passed_through_as_built() {
    let mut marked = refusal();
    marked.extensions_mut().insert(Unframed);
    let note = OutboundFrame::unjudged(crate::gateway::outbound::Payload::Notification(
        crate::protocol::JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: "notifications/progress".to_string(),
            params: None,
        },
    ));
    let response = request_scoped_event_stream(marked, vec![note], judge()).await;
    assert_eq!(passed_through(response).await, (401, REFUSAL.to_string()));
}

/// The control: the same refusal without the marker is framed as an event, so
/// the row above is held by the marker and nothing else.
#[tokio::test]
async fn the_same_refusal_without_the_marker_is_framed() {
    let response = request_scoped_event_stream(refusal(), Vec::new(), judge()).await;
    let (status, body) = passed_through(response).await;
    assert_eq!(status, 401);
    assert!(body.starts_with("event: message\ndata: "), "{body}");
}
