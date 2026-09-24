// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use axum::http::header::CONTENT_TYPE;

fn json_response(body: &str) -> axum::response::Response {
    (
        axum::http::StatusCode::OK,
        [(CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn note(method: &str) -> crate::protocol::JsonRpcNotification {
    crate::protocol::JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: None,
    }
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// S-02's ordering clause: the notifications reach the stream **before the
/// result**. That is a claim about frame order in the body, which is what
/// an SSE client reads.
#[tokio::test]
async fn notifications_are_framed_ahead_of_the_result() {
    let response = request_scoped_event_stream(
        json_response(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
        vec![
            note("notifications/progress"),
            note("notifications/message"),
        ],
    )
    .await;

    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "text/event-stream"
    );
    let body = body_text(response).await;
    let progress = body.find("notifications/progress").expect("progress frame");
    let message = body.find("notifications/message").expect("message frame");
    let result = body.find(r#""result""#).expect("result frame");
    assert!(progress < message, "capture order is preserved");
    assert!(message < result, "every notification precedes the result");
}

/// S-01: `Accept` alone decides the shape, so a call that raised nothing
/// still answers on a stream -- one frame, and it is the result.
#[tokio::test]
async fn a_stream_with_no_notifications_still_carries_the_result() {
    let response = request_scoped_event_stream(
        json_response(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
        Vec::new(),
    )
    .await;

    let body = body_text(response).await;
    assert_eq!(body.matches("data: ").count(), 1);
    assert!(body.contains(r#""result""#));
}

/// An answer that is already a stream (`subscriptions/listen`) is left
/// alone: re-framing it would wrap one stream inside another.
#[tokio::test]
async fn an_answer_that_is_already_a_stream_is_passed_through() {
    let already = (
        axum::http::StatusCode::OK,
        [(CONTENT_TYPE, "text/event-stream")],
        "data: {\"already\":true}\n\n".to_string(),
    )
        .into_response();

    let response = request_scoped_event_stream(already, vec![note("notifications/progress")]).await;
    let body = body_text(response).await;
    assert!(
        !body.contains("notifications/progress"),
        "a subscription stream must not absorb request-scoped traffic (SUB.2a)"
    );
}

/// One frame at a time, so a test can act between them -- `body_text`
/// buffers, which cannot tell "framed on arrival" from "framed at the end".
async fn next_frame<S>(body: &mut S) -> String
where
    S: futures::Stream<Item = std::result::Result<axum::body::Bytes, axum::Error>> + Unpin,
{
    use futures::StreamExt;
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), body.next())
        .await
        .expect("no frame arrived: a notification was held behind the result")
        .expect("the stream ended early")
        .unwrap();
    String::from_utf8(chunk.to_vec()).unwrap()
}

/// The mid-stream arm of [`first_event_wins_stream`]: a notification
/// raised *after* the stream has already committed to SSE is framed when
/// it arrives, not held behind the result.
///
/// The HTTP acceptance rows read one notification and then release the
/// call, so the loop's `rx.recv()` arm -- every notification after the
/// first -- is unreachable from them. `MIK-7272.SUB.2b`.
#[tokio::test]
async fn a_notification_raised_after_the_first_frame_is_framed_before_the_result() {
    // GIVEN a dispatch parked on a gate, one notification already published
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let dispatch_gate = Arc::clone(&gate);
    tx.send(note("notifications/progress")).await.unwrap();
    let response = first_event_wins_stream(
        async move {
            let _permit = dispatch_gate.acquire().await.unwrap();
            json_response(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#)
        },
        rx,
    )
    .await;
    let mut body = response.into_body().into_data_stream();

    // WHEN the second notification is raised only after the first is read
    let first = next_frame(&mut body).await;
    tx.send(note("notifications/message")).await.unwrap();
    let second = next_frame(&mut body).await;
    gate.add_permits(1);
    let last = next_frame(&mut body).await;

    // THEN each is framed as it arrives, and this call's result is last
    assert!(first.contains("notifications/progress"), "{first}");
    assert!(second.contains("notifications/message"), "{second}");
    assert!(last.contains(r#""result""#), "{last}");
}
