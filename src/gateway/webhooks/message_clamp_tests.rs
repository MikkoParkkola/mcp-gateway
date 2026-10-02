// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6 test 8 (#2471): a webhook `message` payload, delivered
//! through the real webhook handler to a subscribed legacy SSE stream, never
//! reaches the client claiming a `public` scope.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use futures::StreamExt;
use serde_json::{Value, json};

use super::{held, make_definition, make_handler_state, make_multiplexer};
use crate::capability::{WebhookDefinition, WebhookTransform};
use crate::gateway::streaming::create_sse_response;
use crate::gateway::webhooks::webhook_handler;

/// `event_type: message` and no data mapping: the whole payload is delivered.
fn message_definition() -> WebhookDefinition {
    WebhookDefinition {
        transform: WebhookTransform {
            event_type: Some("message".to_string()),
            ..WebhookTransform::default()
        },
        ..make_definition(true)
    }
}

/// The `data` line of the first `message` event in `seen`, once it is complete.
fn message_data(seen: &str) -> Option<String> {
    let rest = &seen[seen.find("event: message")?..];
    if !rest.contains("\n\n") {
        return None;
    }
    let line = rest.lines().find(|line| line.starts_with("data:"))?;
    Some(line.trim_start_matches("data:").trim().to_owned())
}

/// POST `payload` to the webhook handler with a legacy SSE stream subscribed,
/// and return the `data` of the `message` frame that stream carries.
async fn delivered(payload: &Value) -> String {
    let multiplexer = make_multiplexer();
    multiplexer.set_authorizer(super::authorizer(None));
    let owner = crate::gateway::session_id::SessionOwner::Credential("in".to_string());
    let (session, _receiver) =
        multiplexer.get_or_create_session_scoped(Some("in"), &owner, held("key-in-scope"));
    let sse = create_sse_response(
        Arc::clone(&multiplexer),
        session,
        None,
        Duration::from_secs(3600),
    )
    .expect("the session exists");
    let mut stream = sse.into_response().into_body().into_data_stream();

    let response = webhook_handler(
        State(make_handler_state(multiplexer, message_definition())),
        HeaderMap::new(),
        axum::body::Bytes::from(payload.to_string()),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);

    let mut seen = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            seen.push_str(&String::from_utf8_lossy(&chunk.expect("a body chunk")));
            if let Some(data) = message_data(&seen) {
                return Some(data);
            }
        }
        None
    })
    .await;
    read.ok()
        .flatten()
        .unwrap_or_else(|| panic!("no message frame reached the stream: {seen}"))
}

#[tokio::test]
async fn a_webhook_response_payload_reaches_the_stream_private() {
    let payload = json!({"jsonrpc": "2.0", "id": 1, "result": {"cacheScope": "public"}});
    assert!(
        payload.to_string().contains("\"public\""),
        "fixture is public"
    );

    let data = delivered(&payload).await;

    let frame: Value = serde_json::from_str(&data).expect("the frame is JSON");
    assert_eq!(frame["result"]["cacheScope"], "private", "{data}");
    assert_eq!(frame["id"], 1, "{data}");
}

#[tokio::test]
async fn a_webhook_notification_payload_reaches_the_stream_unchanged() {
    let payload = json!({"jsonrpc": "2.0", "method": "notifications/x",
        "params": {"cacheScope": "public"}});

    let data = delivered(&payload).await;

    assert_eq!(data, payload.to_string());
}
