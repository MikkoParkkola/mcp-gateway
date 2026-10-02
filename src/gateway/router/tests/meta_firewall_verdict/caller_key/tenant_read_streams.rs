// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7116.MIN.2 red tests on the GET session stream (H7): 2i and the
//! webhook half of 2x. A child of `tenant_reads`, sharing its fixture.
//!
//! Each stream is a real GET `/mcp` under the one API key. A subscriber that
//! is not polled holds its copy of a broadcast frame unwritten in its buffer,
//! which is what "stalled" means here.

use std::time::Duration;

use futures::StreamExt as _;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::gateway::streaming::TaggedNotification;

/// An open GET `/mcp` body under the fixture key, read event by event.
struct Stream {
    body: axum::body::BodyDataStream,
    buffer: String,
}

impl Stream {
    async fn open(router: &axum::Router) -> Self {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("accept", "text/event-stream")
            .header("authorization", "Bearer key-one")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "GET /mcp opens"
        );
        Self {
            body: response.into_body().into_data_stream(),
            buffer: String::new(),
        }
    }

    /// Every `data:` payload that arrives within `within`, skipping the
    /// `connected` event and keep-alives.
    async fn drain(&mut self, within: Duration) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + within;
        while let Ok(Some(Ok(chunk))) = tokio::time::timeout_at(deadline, self.body.next()).await {
            self.buffer.push_str(&String::from_utf8_lossy(&chunk));
        }
        let mut out = Vec::new();
        while let Some(end) = self.buffer.find("\n\n") {
            let block: String = self.buffer.drain(..end + 2).collect();
            if block.contains("event: connected") {
                continue;
            }
            out.extend(
                block
                    .lines()
                    .filter_map(|l| l.strip_prefix("data: "))
                    .map(str::to_string),
            );
        }
        out
    }
}

fn names(tenant: &str) -> TaggedNotification {
    TaggedNotification {
        source: "demo".to_string(),
        event_type: "message".to_string(),
        data: json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": { "uri": "rows://latest", "customer_id": tenant },
        }),
        event_id: None,
    }
}

fn mentions(events: &[String], tenant: &str) -> bool {
    events.iter().any(|e| e.contains(tenant))
}

const QUIET: Duration = Duration::from_millis(300);

/// Row 2i: two subscribers under one key, one fast and one stalled. A is
/// written to the fast one, the window passes, and B is judged while the
/// stalled copy of A is still pending: B is withheld. The stalled write of A
/// refreshes last-seen, so a B right after it is still withheld; once a full
/// window passes with nothing pending, B is delivered.
#[tokio::test]
async fn delayed_subscriber_copy_fails_closed() {
    for mode in [CrossTenantReads::Off, CrossTenantReads::Block] {
        let (state, _store) = split_state(mode, 1).await;
        let router = create_router(Arc::clone(&state));
        let mut fast = Stream::open(&router).await;
        let mut stalled = Stream::open(&router).await;
        let _ = fast.drain(QUIET).await;
        let _ = stalled.drain(QUIET).await;

        state.multiplexer.broadcast(names(A));
        assert!(
            mentions(&fast.drain(QUIET).await, A),
            "{mode:?}: A reaches the fast subscriber"
        );
        tokio::time::sleep(Duration::from_millis(1_200)).await;

        state.multiplexer.broadcast(names(B));
        let got = fast.drain(QUIET).await;
        if mode == CrossTenantReads::Off {
            assert!(mentions(&got, B), "control: off delivers B: {got:?}");
            continue;
        }
        assert!(
            !mentions(&got, B),
            "B was delivered while a copy of A was still unwritten: {got:?}"
        );

        let late = stalled.drain(QUIET).await;
        assert!(
            mentions(&late, A),
            "the stalled copy of A is written late: {late:?}"
        );
        assert!(
            !mentions(&late, B),
            "nor does B reach the stalled one: {late:?}"
        );
        state.multiplexer.broadcast(names(B));
        let got = fast.drain(QUIET).await;
        assert!(
            !mentions(&got, B),
            "last-seen is the late write of A, not its enqueue: {got:?}"
        );

        tokio::time::sleep(Duration::from_millis(1_200)).await;
        state.multiplexer.broadcast(names(B));
        let got = fast.drain(QUIET).await;
        assert!(
            mentions(&got, B),
            "after a quiet window B is ordinary: {got:?}"
        );
    }
}

/// A webhook route on the `demo` backend: the body's `customer_id` is mapped
/// away, so only the raw inbound payload names the tenant.
fn webhook_routes(state: &AppState) -> axum::Router {
    let capability = crate::capability::parse_capability(
        r#"
name: hooks
description: Rows changed upstream
webhooks:
  rows:
    path: /rows
    method: POST
    notify: true
    transform:
      event_type: "rows.changed"
      data:
        kind: "{{kind}}"
providers:
  primary:
    service: rest
    config:
      base_url: http://localhost:9
      path: /unused
      method: GET
"#,
    )
    .unwrap();
    let mut registry =
        crate::gateway::webhooks::WebhookRegistry::new(crate::config::WebhookConfig {
            enabled: true,
            base_path: "/webhooks".to_string(),
            require_signature: false,
            ..crate::config::WebhookConfig::default()
        })
        .with_backend("demo");
    registry.register_capability(&capability);
    registry.create_routes(Arc::clone(&state.multiplexer))
}

async fn post_webhook(routes: &axum::Router, body: &Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/webhooks/rows")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = routes.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "the webhook is received"
    );
}

/// Row 2x, webhook half: a POST read of A, then a webhook whose raw body
/// names B but whose transform drops it. Block: not delivered.
#[tokio::test]
async fn webhook_and_event_scan_root() {
    let who = caller();
    for mode in [CrossTenantReads::Off, CrossTenantReads::Block] {
        let (state, _store) = split_state(mode, 3600).await;
        let router = create_router(Arc::clone(&state));
        let hooks = webhook_routes(&state);
        let mut stream = Stream::open(&router).await;
        let _ = stream.drain(QUIET).await;

        let (a, _, body) = send(&router, call_with(&who, true, None, 0, &reading(A))).await;
        assert_eq!(a, Delivered, "{body}");
        post_webhook(&hooks, &json!({ "kind": "row-77", "customer_id": B })).await;
        let got = stream.drain(QUIET).await;
        if mode == CrossTenantReads::Off {
            assert!(
                mentions(&got, "row-77"),
                "control: off delivers the webhook: {got:?}"
            );
        } else {
            assert!(
                !mentions(&got, "row-77"),
                "a webhook naming B in its raw body reached an A reader: {got:?}"
            );
        }
    }
}
