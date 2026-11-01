// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Control identifiers over WebSocket (DELTA-5, T1.23): a progress
//! token and a subscription tag equal to an injected value still route, and
//! the copy the caller gets is scrubbed.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use super::{ProgressRegistration, WebSocketTransport};
use crate::security::needles::NeedleSet;
use crate::transport::upstream_tap::{KindSet, Requested, UpstreamNote};

const NEEDLE: &str = "control-id-secret-5b1e";

/// A transport whose needle set holds [`NEEDLE`].
fn with_needle() -> Arc<WebSocketTransport> {
    let t = WebSocketTransport::new(
        "ws://localhost:9999",
        HashMap::new(),
        std::time::Duration::from_secs(30),
        None,
    );
    let needles = NeedleSet::with_grace(std::time::Duration::from_secs(3_600));
    needles.insert("b", NEEDLE);
    let _ = t.inner.needles.set(Arc::new(needles));
    t
}

#[tokio::test]
async fn a_progress_token_equal_to_a_secret_routes_and_arrives_scrubbed() {
    let t = with_needle();
    let frame = json!({"jsonrpc": "2.0", "method": "notifications/progress",
        "params": {"progressToken": NEEDLE, "progress": 1}})
    .to_string();
    let (call, mut rx) = crate::transport::notify_ingress::test_support::scope(None, async {
        let _registration = ProgressRegistration::register(
            &t.inner.progress_destinations,
            Some(&json!({"_meta": {"progressToken": NEEDLE}})),
        );
        WebSocketTransport::dispatch_inbound(&t.inner, &frame).unwrap();
    });
    call.await;
    let got = rx
        .try_recv()
        .expect("the frame routes by the token the backend sent");
    let text = serde_json::to_string(&got.params).unwrap();
    assert!(
        !text.contains(NEEDLE),
        "the caller's copy holds the secret: {text}"
    );
}

#[tokio::test]
async fn a_subscription_tag_equal_to_a_secret_still_routes() {
    let t = with_needle();
    let requested = Requested {
        kinds: KindSet {
            resources_changed: true,
            ..KindSet::default()
        },
        uris: Vec::new(),
    };
    let mut rx = t.inner.taps.listen(&json!(NEEDLE), requested);
    let frame = json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
        "params": {"notifications": {"resourcesListChanged": true},
                   "_meta": {"io.modelcontextprotocol/subscriptionId": NEEDLE}}})
    .to_string();
    WebSocketTransport::dispatch_inbound(&t.inner, &frame).unwrap();
    assert!(
        matches!(rx.try_recv(), Ok(UpstreamNote::Ack { .. })),
        "the acknowledgement did not reach its listen"
    );
}

/// T1.21: an answer for no pending request is logged by the length of its
/// id, never the id.
#[test]
fn an_unmatched_id_is_logged_without_its_value() {
    let t = with_needle();
    let frame = json!({"jsonrpc": "2.0", "id": NEEDLE, "result": {}}).to_string();
    let logged = crate::test_log_capture::records(|| {
        WebSocketTransport::dispatch_inbound(&t.inner, &frame).unwrap();
    });
    let text = serde_json::to_string(&logged).unwrap();
    assert!(
        text.contains("response for"),
        "premise: the warning: {text}"
    );
    assert!(!text.contains(NEEDLE), "the log names the id: {text}");
}

/// T1.21: a frame this transport does not read is refused with an error
/// that quotes none of it (the read loop logs that error).
#[test]
fn a_refused_frame_quotes_none_of_itself() {
    for frame in [
        json!({"jsonrpc": NEEDLE, "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "mystery": NEEDLE}),
        json!({"jsonrpc": "2.0", "id": 1, "result": {}, "error": NEEDLE}),
    ] {
        let error = super::McpFrame::from_text(&frame.to_string()).unwrap_err();
        assert!(!error.to_string().contains(NEEDLE), "{frame}: {error}");
    }
}

/// T1.21: a close frame is logged by its code and the length of its reason.
#[test]
fn a_close_reason_is_logged_by_length() {
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    let frame = CloseFrame {
        code: CloseCode::Normal,
        reason: NEEDLE.into(),
    };
    let logged = crate::test_log_capture::records(|| super::log_close(Some(&frame)));
    let text = serde_json::to_string(&logged).unwrap();
    assert!(text.contains("close frame"), "premise: the record: {text}");
    assert!(!text.contains(NEEDLE), "the log names the reason: {text}");
}

/// Lead ruling G9 (WebSocket): the watch filter compares the scrubbed note.
/// A watcher of the redacted URI gets the update; one guessing the raw URI
/// does not.
#[test]
fn the_watch_filter_compares_the_redacted_uri() {
    use crate::transport::upstream_tap::Watched;
    let frame = json!({"jsonrpc": "2.0", "method": "notifications/resources/updated",
        "params": {"uri": format!("file:///x?k={NEEDLE}")}})
    .to_string();
    let redacted = with_needle();
    let mut rx = redacted
        .inner
        .taps
        .unsolicited(Watched::by(|uri| uri == "file:///x?k=[redacted]"));
    WebSocketTransport::dispatch_inbound(&redacted.inner, &frame).unwrap();
    let Ok(UpstreamNote::Notice { uri: Some(uri), .. }) = rx.try_recv() else {
        panic!("the watcher of the redacted URI got nothing");
    };
    assert_eq!(uri, "file:///x?k=[redacted]");
    let raw = with_needle();
    let mut rx = raw
        .inner
        .taps
        .unsolicited(Watched::by(|uri| uri.contains(NEEDLE)));
    WebSocketTransport::dispatch_inbound(&raw.inner, &frame).unwrap();
    assert!(
        rx.try_recv().is_err(),
        "a watcher guessing the raw URI got it"
    );
}

/// What a call's delivery record says about its answer, for a backend that
/// answers with `reply` (the members after the id) while `secret` is an
/// injected value. The reader routes the answer as sent; the call scrubs it
/// on its own task, so the effect lands in this call's cell.
async fn recorded_effect(reply: serde_json::Value, secret: &str) -> (serde_json::Value, String) {
    let url = super::tests::mock_backend(move |request| {
        let mut answer = reply.clone();
        answer["jsonrpc"] = json!("2.0");
        answer["id"] = request["id"].clone();
        vec![answer]
    })
    .await;
    let t = super::tests::connected(&url).await;
    let needles = NeedleSet::with_grace(std::time::Duration::from_secs(3_600));
    needles.insert("b", secret);
    let _ = t.inner.needles.set(Arc::new(needles));
    let mut fields = serde_json::Map::new();
    let answer = crate::gateway::delivery_facts::scope(async {
        let answer = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::transport::Transport::request(t.as_ref(), "tools/call", None),
        )
        .await
        .expect("answered");
        crate::gateway::delivery_facts::record_fields(
            crate::gateway::delivery_facts::snapshot().as_ref(),
            false,
            &mut fields,
        );
        answer
    })
    .await;
    (
        fields.get("response_effect").cloned().unwrap_or_default(),
        format!("{answer:?}"),
    )
}

/// Over WebSocket too: a redacted answer is recorded as rewritten.
#[tokio::test]
async fn a_redacted_answer_is_recorded_as_rewritten() {
    let reply =
        json!({"result": {"content": [{"type": "text", "text": format!("echo {NEEDLE}")}]}});
    let (effect, answer) = recorded_effect(reply, NEEDLE).await;
    assert!(!answer.contains(NEEDLE), "premise: scrubbed: {answer}");
    assert_eq!(effect, json!("rewritten"), "{answer}");
}

/// An answer replaced by the fixed refusal is recorded as refused.
#[tokio::test]
async fn a_replaced_answer_is_recorded_as_refused() {
    let reply = json!({"error": {"code": 7_391_540, "message": "nope"}});
    let (effect, answer) = recorded_effect(reply, "7391540").await;
    assert!(answer.contains("Err"), "premise: refused: {answer}");
    assert_eq!(effect, json!("refused"), "{answer}");
}

/// Control: an answer the scrub left alone is recorded as delivered.
#[tokio::test]
async fn a_clean_answer_is_recorded_as_delivered() {
    let reply = json!({"result": {"content": [{"type": "text", "text": "nothing to hide"}]}});
    let (effect, answer) = recorded_effect(reply, NEEDLE).await;
    assert!(
        answer.contains("nothing to hide"),
        "premise: answered: {answer}"
    );
    assert_eq!(effect, json!("delivered"), "{answer}");
}
