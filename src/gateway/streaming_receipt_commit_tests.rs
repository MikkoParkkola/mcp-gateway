// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! h4/h4b: a request-scoped SSE answer's relay receipts commit when the
//! client reads the result's frame, in both arms of
//! [`first_event_wins_stream`]: the dispatch first (the buffered arm, which
//! streams the emitted body lazily) and a notification first (the stream
//! arm, which reads the emitted body inside the poll that yields the result
//! frame). Commits are counted at the commit funnel.

use super::*;
use crate::gateway::meta_mcp::invoke::relay::{
    DeferredReceipts, StagedReceipts, commit_capture_hook,
};

/// A JSON answer carrying receipts, as the meta route's collector leaves it.
fn answer_with_receipts() -> axum::response::Response {
    let mut response = (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_string(),
    )
        .into_response();
    let live = Arc::new(crate::config_reload::LiveConfig::new(
        crate::config::Config::default(),
    ));
    response.extensions_mut().insert(DeferredReceipts::new(
        StagedReceipts::none(),
        true,
        Some(live),
    ));
    response
}

fn judge() -> Arc<StreamJudge> {
    Arc::new(StreamJudge::new(
        None,
        Arc::new(crate::gateway::outbound::RejectionAudit::new(None, 1)),
        None,
    ))
}

fn progress() -> OutboundFrame {
    OutboundFrame::unjudged(crate::gateway::outbound::Payload::Notification(
        crate::protocol::JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: "notifications/progress".to_string(),
            params: None,
        },
    ))
}

/// The SSE answer of one call. `notify_first`: a notification is published
/// before the dispatch resolves (the stream arm); else the dispatch
/// resolves first (the buffered arm).
async fn sse_answer(notify_first: bool) -> axum::response::Response {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let dispatch_gate = Arc::clone(&gate);
    if notify_first {
        tx.send(progress()).await.unwrap();
    } else {
        gate.add_permits(1);
        drop(tx);
    }
    let response = first_event_wins_stream(
        async move {
            let _permit = dispatch_gate.acquire().await.unwrap();
            answer_with_receipts()
        },
        rx,
        judge(),
    )
    .await;
    if notify_first {
        gate.add_permits(1);
    }
    response
}

/// h4: in both arms nothing commits until the client reads the stream, and
/// reading it commits once.
/// Mutant killed: m3 (the commit run when the body is wrapped).
#[tokio::test(flavor = "current_thread")]
async fn h4_a_request_scoped_sse_answer_records_when_the_client_reads_it() {
    for notify_first in [false, true] {
        let before = commit_capture_hook::reached();
        let response = sse_answer(notify_first).await;
        assert_eq!(
            commit_capture_hook::reached(),
            before,
            "nothing commits before the client reads (notify first: {notify_first})"
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&bytes).contains(r#""result""#),
            "base: the result frame was read"
        );
        assert_eq!(
            commit_capture_hook::reached(),
            before + 1,
            "reading the result commits once (notify first: {notify_first})"
        );
    }
}

/// h4b: in both arms a stream dropped unread commits nothing.
/// Mutant killed: m3.
#[tokio::test(flavor = "current_thread")]
async fn h4b_a_request_scoped_sse_stream_dropped_unread_records_nothing() {
    for notify_first in [false, true] {
        let before = commit_capture_hook::reached();
        drop(sse_answer(notify_first).await);
        assert_eq!(
            commit_capture_hook::reached(),
            before,
            "a stream dropped unread commits nothing (notify first: {notify_first})"
        );
    }
}
