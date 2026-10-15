// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 C0b: a held GET stream closes when a clock rollback moves
//! its held adapter issuance into the future beyond skew.
use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use futures::StreamExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::tests::{
    http_backend_at, scoped_auth_config, test_router_app_state_with_auth, view_judge_for,
};
use super::{AppState, create_router};
use crate::gateway::openwebui_adapter::AdapterAssertion;
use crate::gateway::streaming::TaggedNotification;
use crate::protocol::Tool;

const WITHIN: Duration = Duration::from_secs(5);

enum Frame {
    Message(Value),
    Eof,
}

struct BodyFrames {
    body: axum::body::BodyDataStream,
    buffer: Vec<u8>,
    ended: bool,
}

impl BodyFrames {
    fn from_response(response: axum::response::Response) -> Self {
        Self {
            body: response.into_body().into_data_stream(),
            buffer: Vec::new(),
            ended: false,
        }
    }

    fn take_frame(&mut self) -> Option<Value> {
        loop {
            let end = self.buffer.windows(2).position(|pair| pair == b"\n\n")?;
            let block: Vec<u8> = self.buffer.drain(..end + 2).collect();
            let text = String::from_utf8(block)
                .unwrap_or_else(|error| panic!("VOID: GET frame must be UTF-8: {error}"));
            let data: Vec<&str> = text
                .lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .collect();
            if data.is_empty() {
                continue;
            }
            let payload = data.join("\n");
            return Some(serde_json::from_str(&payload).unwrap_or_else(|error| {
                panic!("VOID: GET frame must be JSON ({error}): {payload}")
            }));
        }
    }

    async fn next(&mut self) -> Frame {
        let deadline = tokio::time::Instant::now() + WITHIN;
        loop {
            if let Some(message) = self.take_frame() {
                return Frame::Message(message);
            }
            if self.ended {
                std::assert!(
                    self.buffer.is_empty(),
                    "VOID: GET EOF carried an unterminated partial frame"
                );
                return Frame::Eof;
            }
            match tokio::time::timeout_at(deadline, self.body.next()).await {
                Err(elapsed) => panic!("VOID: GET stream timed out after {WITHIN:?}: {elapsed}"),
                Ok(None) => self.ended = true,
                Ok(Some(Ok(chunk))) => self.buffer.extend_from_slice(&chunk),
                Ok(Some(Err(error))) => panic!("VOID: GET body failed: {error}"),
            }
        }
    }
}

fn tool(description: &str) -> Tool {
    serde_json::from_value(json!({
        "name": "allowed_tool",
        "description": description,
        "inputSchema": {"type": "object", "properties": {}}
    }))
    .unwrap_or_else(|error| panic!("VOID: allowed_tool fixture must parse: {error}"))
}

fn genuine_receipt(t0: u64) -> AdapterAssertion {
    let iat = i64::try_from(t0).expect("test clock fits i64");
    AdapterAssertion::verified_for_test(iat, iat + 120, 30)
        .unwrap_or_else(|| panic!("VOID: genuine signed capture refused at issuance"))
}

fn fresh_verifies(t0: u64) -> bool {
    let iat = i64::try_from(t0).expect("test clock fits i64");
    AdapterAssertion::verified_for_test(iat, iat + 120, 30).is_some()
}

async fn open_get(state: &Arc<AppState>, receipt: AdapterAssertion) -> (BodyFrames, String) {
    let mut request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream")
        .header("authorization", "Bearer scoped-key")
        .body(axum::body::Body::empty())
        .expect("a fixture request builds");
    request
        .extensions_mut()
        .insert(crate::key_server::oidc::VerifiedIdentity {
            subject: "alice".to_string(),
            email: "alice@adapter.test".to_string(),
            name: None,
            groups: Vec::new(),
            issuer: "https://idp.adapter.test".to_string(),
        });
    request.extensions_mut().insert(receipt);
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer");
    let status = response.status();
    if status != StatusCode::OK {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a refusal body ends");
        panic!(
            "VOID: GET stream must be admitted, got {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    let mut frames = BodyFrames::from_response(response);
    let session = match frames.next().await {
        Frame::Message(connected) => connected["session_id"]
            .as_str()
            .unwrap_or_else(|| panic!("VOID: connected frame names no session: {connected}"))
            .to_string(),
        Frame::Eof => panic!("VOID: GET stream ended before connected"),
    };
    std::assert!(!session.is_empty(), "VOID: empty session id");
    (frames, session)
}

fn hint() -> TaggedNotification {
    TaggedNotification {
        source: "demo".to_string(),
        event_type: "message".to_string(),
        data: json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
        event_id: None,
    }
}

async fn judged_broadcast(state: &Arc<AppState>) -> usize {
    let judge = view_judge_for(state);
    state
        .multiplexer
        .broadcast_to_backend_judged(&hint(), "demo", &*judge)
        .await
}

async fn expect_hint(frames: &mut BodyFrames, what: &str) {
    match frames.next().await {
        Frame::Message(frame) => std::assert_eq!(
            frame["method"],
            json!("notifications/tools/list_changed"),
            "VOID: {what} must be the judged hint: {frame}"
        ),
        Frame::Eof => panic!("VOID: stream ended before {what}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_get_stream_closes_when_its_held_adapter_issuance_moves_into_the_future() {
    let (state, _store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    let backend = http_backend_at("demo", "http://127.0.0.1:9/mcp");
    backend.store_shared_tools_for_test(vec![tool("before")]);
    std::assert!(
        state.backends.register(Arc::clone(&backend)),
        "VOID: demo backend must register"
    );
    let t0 = crate::clock::unix_secs().expect("clock after 1970");
    let capture = crate::clock::test_clock::at_secs(t0);
    let receipt = genuine_receipt(t0);
    let (mut held, _held_session) = open_get(&state, receipt).await;
    drop(capture);
    let live = crate::clock::test_clock::at_secs(t0 - 30);
    std::assert!(fresh_verifies(t0), "VOID: fresh verify at t0-30");
    backend.store_shared_tools_for_test(vec![tool("healthy-change")]);
    let reached = judged_broadcast(&state).await;
    std::assert!(reached > 0, "VOID: healthy judged broadcast reached none");
    expect_hint(&mut held, "healthy hint").await;
    drop(live);
    let rolled = crate::clock::test_clock::at_secs(t0 - 31);
    std::assert!(!fresh_verifies(t0), "VOID: fresh refusal at t0-31");
    let fresh_iat = i64::try_from(t0 - 31).expect("test clock fits i64");
    let control_receipt = AdapterAssertion::verified_for_test(fresh_iat, fresh_iat + 120, 30)
        .unwrap_or_else(|| panic!("VOID: control capture under rollback clock refused"));
    let (mut control, _control_session) = open_get(&state, control_receipt).await;
    backend.store_shared_tools_for_test(vec![tool("rollback-change")]);
    let reached = judged_broadcast(&state).await;
    std::assert!(reached > 0, "VOID: rollback judged broadcast reached none");
    expect_hint(&mut control, "live control hint").await;
    let leaked: Option<Value> = match held.next().await {
        Frame::Eof => None,
        Frame::Message(frame) => Some(frame),
    };
    drop(rolled);
    std::assert!(
        leaked.is_none(),
        "a GET stream must close when its held adapter issuance moves into \
         the future, yet it carried a further frame: {leaked:?}"
    );
}

fn resource_update(marker: &str) -> TaggedNotification {
    TaggedNotification {
        source: "demo".to_string(),
        event_type: "message".to_string(),
        data: json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": {"uri": marker}
        }),
        event_id: None,
    }
}

async fn expect_update(frames: &mut BodyFrames, marker: &str) {
    match frames.next().await {
        Frame::Message(frame) => std::assert_eq!(
            frame["params"]["uri"],
            json!(marker),
            "VOID: the {marker} update must arrive: {frame}"
        ),
        Frame::Eof => panic!("VOID: stream ended before the {marker} update"),
    }
}

/// MIK-8350 (seat HIGH on 8264fcb00): a frame that is not a judged hint (a
/// `resources/updated`, sent with no judged backend) is held to the stream's
/// own subject as it is written, as a listener's is. Once the held adapter
/// receipt has expired, the GET stream writes it nothing and closes. A
/// control stream opened with a receipt minted at the same instant receives
/// the same frame, so the broadcast itself is proven.
/// Red before the fix: only the bearer is rechecked, so the expired receipt's
/// stream is written the update. Mutant: the non-hint subject check removed.
#[tokio::test(flavor = "current_thread")]
async fn a_get_stream_writes_no_unjudged_frame_once_its_adapter_receipt_expires() {
    let (state, _store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    let backend = http_backend_at("demo", "http://127.0.0.1:9/mcp");
    backend.store_shared_tools_for_test(vec![tool("before")]);
    std::assert!(
        state.backends.register(Arc::clone(&backend)),
        "VOID: demo backend must register"
    );
    let t0 = crate::clock::unix_secs().expect("clock after 1970");
    let capture = crate::clock::test_clock::at_secs(t0);
    let (mut held, _held_session) = open_get(&state, genuine_receipt(t0)).await;
    let reached = state
        .multiplexer
        .broadcast_to_backend(&resource_update("healthy"), "demo")
        .await;
    std::assert!(reached > 0, "VOID: healthy update reached none");
    expect_update(&mut held, "healthy").await;
    drop(capture);

    let later = t0 + 300;
    let expired = crate::clock::test_clock::at_secs(later);
    std::assert!(!fresh_verifies(t0), "VOID: the held receipt has expired");
    let (mut control, _control_session) = open_get(&state, genuine_receipt(later)).await;
    let reached = state
        .multiplexer
        .broadcast_to_backend(&resource_update("after-expiry"), "demo")
        .await;
    std::assert!(reached > 0, "VOID: post-expiry update reached none");
    expect_update(&mut control, "after-expiry").await;
    let leaked: Option<Value> = match held.next().await {
        Frame::Eof => None,
        Frame::Message(frame) => Some(frame),
    };
    drop(expired);
    std::assert!(
        leaked.is_none(),
        "an unjudged frame was written to a GET stream whose adapter receipt \
         has expired: {leaked:?}"
    );
}

/// Queue `count` updates that no stream reads yet, so a queue smaller than
/// `count` overflows.
async fn overflow(state: &Arc<AppState>, count: usize) {
    for index in 0..count {
        let reached = state
            .multiplexer
            .broadcast_to_backend(&resource_update(&format!("flood-{index}")), "demo")
            .await;
        std::assert!(reached > 0, "VOID: flood update {index} reached none");
    }
}

/// MIK-8350 (final-delta seat MEDIUM): the `lagged` notice a stream writes when
/// its queue overflowed is a frame like any other, so it too is held to the
/// stream's own subject. Once the held adapter receipt has expired, an
/// overflowed GET stream writes no `lagged` notice and closes. A control stream
/// with a fresh receipt, overflowed the same way, receives the notice, so the
/// overflow itself is proven.
/// Red before the fix: only the bearer is rechecked for the notice, so the
/// expired receipt's stream is written `{"missed": n}`. Mutant: the notice's
/// subject check removed.
#[tokio::test(flavor = "current_thread")]
async fn an_overflowed_get_stream_writes_no_lag_notice_once_its_adapter_receipt_expires() {
    let (state, _store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    let backend = http_backend_at("demo", "http://127.0.0.1:9/mcp");
    backend.store_shared_tools_for_test(vec![tool("before")]);
    std::assert!(
        state.backends.register(Arc::clone(&backend)),
        "VOID: demo backend must register"
    );
    let t0 = crate::clock::unix_secs().expect("clock after 1970");
    let capture = crate::clock::test_clock::at_secs(t0);
    let (mut held, _held_session) = open_get(&state, genuine_receipt(t0)).await;
    drop(capture);

    let later = t0 + 300;
    let expired = crate::clock::test_clock::at_secs(later);
    std::assert!(!fresh_verifies(t0), "VOID: the held receipt has expired");
    let (mut control, _control_session) = open_get(&state, genuine_receipt(later)).await;
    // One more than the stream queue holds (the default buffer is 100).
    overflow(&state, 105).await;
    match control.next().await {
        Frame::Message(frame) => std::assert!(
            frame.get("missed").is_some(),
            "VOID: the overflowed control stream must report its lag first: {frame}"
        ),
        Frame::Eof => panic!("VOID: the control stream ended instead of reporting its lag"),
    }
    let leaked: Option<Value> = match held.next().await {
        Frame::Eof => None,
        Frame::Message(frame) => Some(frame),
    };
    drop(expired);
    std::assert!(
        leaked.is_none(),
        "a lag notice was written to a GET stream whose adapter receipt has \
         expired: {leaked:?}"
    );
}
