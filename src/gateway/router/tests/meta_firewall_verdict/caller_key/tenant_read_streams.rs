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
use crate::test_wait::HANG_BOUND;

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
    /// `connected` event and keep-alives. For a check that something does NOT
    /// arrive: a positive assert on this result races the window (MIK-8295),
    /// so use [`Self::drain_until`] for that.
    async fn drain_for_absence(&mut self, within: Duration) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + within;
        while let Ok(Some(Ok(chunk))) = tokio::time::timeout_at(deadline, self.body.next()).await {
            self.buffer.push_str(&String::from_utf8_lossy(&chunk));
        }
        self.take_events()
    }

    /// Payloads until `enough` holds for them, or `HANG_BOUND` passes (the
    /// caller's assert then says what was missing), and then any more within
    /// `QUIET`, where an extra that must not arrive would show.
    async fn drain_until(&mut self, enough: impl Fn(&[String]) -> bool) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + HANG_BOUND;
        let mut out = self.take_events();
        while !enough(&out) {
            match tokio::time::timeout_at(deadline, self.body.next()).await {
                Ok(Some(Ok(chunk))) => {
                    self.buffer.push_str(&String::from_utf8_lossy(&chunk));
                    out.extend(self.take_events());
                }
                _ => return out,
            }
        }
        // timing: absence
        out.extend(self.drain_for_absence(QUIET).await);
        out
    }

    /// The whole events buffered so far, as `data:` payloads.
    fn take_events(&mut self) -> Vec<String> {
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

/// What a row expects of an event, so its collector waits for a delivery
/// and only watches a window for a withholding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arrival {
    Delivered,
    Withheld,
}

impl Arrival {
    fn when(delivered: bool) -> Self {
        if delivered { Self::Delivered } else { Self::Withheld }
    }
}

/// The events naming `needle`, waited for when they must arrive and watched
/// for over `QUIET` when they must not.
async fn expect(stream: &mut Stream, needle: &str, arrival: Arrival) -> Vec<String> {
    match arrival {
        Arrival::Delivered => stream.drain_until(|e| mentions(e, needle)).await,
        // timing: absence
        Arrival::Withheld => stream.drain_for_absence(QUIET).await,
    }
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
        let _ = fast.drain_for_absence(QUIET).await;
        let _ = stalled.drain_for_absence(QUIET).await;

        state.multiplexer.broadcast(names(A));
        assert!(
            mentions(&fast.drain_until(|e| mentions(e, A)).await, A),
            "{mode:?}: A reaches the fast subscriber"
        );
        // The product's quiet window must pass; longer under load is fine.
        // timing: lower-bound
        tokio::time::sleep(Duration::from_millis(1_200)).await;

        state.multiplexer.broadcast(names(B));
        let got = expect(&mut fast, B, Arrival::when(mode == CrossTenantReads::Off)).await;
        if mode == CrossTenantReads::Off {
            assert!(mentions(&got, B), "control: off delivers B: {got:?}");
            continue;
        }
        assert!(
            !mentions(&got, B),
            "B was delivered while a copy of A was still unwritten: {got:?}"
        );

        let late = stalled.drain_until(|e| mentions(e, A)).await;
        assert!(
            mentions(&late, A),
            "the stalled copy of A is written late: {late:?}"
        );
        assert!(
            !mentions(&late, B),
            "nor does B reach the stalled one: {late:?}"
        );
        state.multiplexer.broadcast(names(B));
        let got = expect(&mut fast, B, Arrival::Withheld).await;
        assert!(
            !mentions(&got, B),
            "last-seen is the late write of A, not its enqueue: {got:?}"
        );

        // timing: lower-bound
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        state.multiplexer.broadcast(names(B));
        let got = fast.drain_until(|e| mentions(e, B)).await;
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
        let _ = stream.drain_for_absence(QUIET).await;

        let (a, _, body) = send(&router, call_with(&who, true, None, 0, &reading(A))).await;
        assert_eq!(a, Delivered, "{body}");
        post_webhook(&hooks, &json!({ "kind": "row-77", "customer_id": B })).await;
        let arrival = Arrival::when(mode == CrossTenantReads::Off);
        let got = expect(&mut stream, "row-77", arrival).await;
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

/// A `message` webhook route on the `demo` backend: the event's document is
/// the body, or its `data` mapping (`transform` lines), written with its
/// top-level `id` and no wrapper to scan (MIK-7822).
fn message_routes(state: &AppState, transform: &str) -> axum::Router {
    let capability = crate::capability::parse_capability(&format!(
        r#"
name: hooks
description: Rows changed upstream
webhooks:
  rows:
    path: /rows
    method: POST
    notify: true
    transform:
      event_type: "message"
{transform}
providers:
  primary:
    service: rest
    config:
      base_url: http://localhost:9
      path: /unused
      method: GET
"#
    ))
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

/// After a read of A on `arg_keys`, POST `body` to a `message` route with
/// `transform`: the events the A reader's stream receives.
async fn message_events(
    mode: CrossTenantReads,
    arg_keys: &[&str],
    transform: &str,
    body: &Value,
    arrival: Arrival,
) -> Vec<String> {
    let (state, _store) = keyed_state(mode, 3600, arg_keys).await;
    let router = create_router(Arc::clone(&state));
    let hooks = message_routes(&state, transform);
    let mut stream = Stream::open(&router).await;
    let _ = stream.drain_for_absence(QUIET).await;
    let (a, _, answer) = send(&router, call_with(&caller(), true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{answer}");
    post_webhook(&hooks, body).await;
    expect(&mut stream, "row-78", arrival).await
}

async fn message_delivered(
    mode: CrossTenantReads,
    arg_keys: &[&str],
    transform: &str,
    body: &Value,
    arrival: Arrival,
) -> bool {
    mentions(
        &message_events(mode, arg_keys, transform, body, arrival).await,
        "row-78",
    )
}

/// MIK-7822: a `message` webhook whose only mention of B is its top-level
/// `id` (an object, then a JSON string) is withheld from an A reader under
/// Block; the same body naming A is delivered.
#[tokio::test]
async fn message_webhook_top_level_id_is_judged() {
    let keys = ["customer_id"];
    for tenant in [A, B] {
        let named = json!({ "customer_id": tenant });
        for id in [named.clone(), json!(named.to_string())] {
            let body = json!({ "id": id, "kind": "row-78" });
            assert!(
                message_delivered(CrossTenantReads::Off, &keys, "", &body, Arrival::Delivered).await,
                "control: off delivers {body}"
            );
            let arrival = Arrival::when(tenant == A);
            let got = message_delivered(CrossTenantReads::Block, &keys, "", &body, arrival).await;
            assert_eq!(
                got,
                tenant == A,
                "block, top-level id naming {tenant}: {body}"
            );
        }
    }
}

/// MIK-7822, mapped: with `id` itself a tenant key, a mapping that writes a
/// body field (raw key not a tenant key) into the top-level `id` names B only
/// in the written document.
#[tokio::test]
async fn message_webhook_mapped_top_level_id_is_judged() {
    let keys = ["customer_id", "id"];
    let transform = "      data:\n        id: \"{ref}\"\n        kind: \"{kind}\"";
    for tenant in [A, B] {
        let body = json!({ "ref": tenant, "kind": "row-78" });
        let off = message_events(
            CrossTenantReads::Off,
            &keys,
            transform,
            &body,
            Arrival::Delivered,
        )
        .await;
        assert!(
            mentions(&off, &format!(r#""id":"{tenant}""#)),
            "control: off delivers the mapped id: {off:?}"
        );
        let arrival = Arrival::when(tenant == A);
        let got = message_delivered(CrossTenantReads::Block, &keys, transform, &body, arrival).await;
        assert_eq!(got, tenant == A, "block, mapped id naming {tenant}: {body}");
    }
    // A mapped `id` does not replace the raw scan: B named only in a field the
    // mapping drops is still judged.
    let body = json!({ "ref": "evt-1", "kind": "row-78", "customer_id": B });
    let got = message_delivered(
        CrossTenantReads::Block,
        &["customer_id"],
        transform,
        &body,
        Arrival::Withheld,
    )
    .await;
    assert!(!got, "block, B only in the dropped raw field: {body}");
}

/// A modern `subscriptions/listen` stream under the fixture key, past its
/// acknowledgement.
async fn open_listen(router: &axum::Router) -> Stream {
    open_listen_naming(router, None).await
}

/// [`open_listen`] whose request params also name `tenant`.
async fn open_listen_naming(router: &axum::Router, tenant: Option<&str>) -> Stream {
    let mut body = json!({
        "jsonrpc": "2.0", "id": 9, "method": "subscriptions/listen",
        "params": {
            "notifications": { "toolsListChanged": true },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    if let Some(tenant) = tenant {
        body["params"]["customer_id"] = json!(tenant);
    }
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer key-one")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "subscriptions/listen")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "listen opens"
    );
    let mut stream = Stream {
        body: response.into_body().into_data_stream(),
        buffer: String::new(),
    };
    let ack = stream
        .drain_until(|e| e.iter().any(|e| e.contains("subscriptionId")))
        .await;
    assert!(
        ack.iter().any(|e| e.contains("subscriptionId")),
        "the acknowledgement opens the stream: {ack:?}"
    );
    stream
}

/// Rows 2k and 11 (H8): a `subscriptions/listen` event naming B, after a
/// POST read of A under the same key, is withheld in block mode.
#[tokio::test]
async fn listen_keyed_on_caller_key() {
    let who = caller();
    for mode in [CrossTenantReads::Off, CrossTenantReads::Block] {
        let (state, _store) = split_state(mode, 3600).await;
        let router = create_router(Arc::clone(&state));
        let mut listen = open_listen(&router).await;
        let (a, _, body) = send(&router, call_with(&who, true, None, 0, &reading(A))).await;
        assert_eq!(a, Delivered, "{body}");
        state.subscriptions.publish(json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": { "customer_id": B },
        }));
        let arrival = Arrival::when(mode == CrossTenantReads::Off);
        let got = expect(&mut listen, B, arrival).await;
        if mode == CrossTenantReads::Off {
            assert!(
                mentions(&got, B),
                "control: off delivers the event: {got:?}"
            );
        } else {
            assert!(
                !mentions(&got, B),
                "a listen event naming B reached an A reader: {got:?}"
            );
        }
    }
}

/// Review (H8): a listen request whose own params name A reads A, so a B
/// event on that stream is withheld in block mode, with no other read.
#[tokio::test]
async fn listen_request_params_are_a_read() {
    for mode in [CrossTenantReads::Off, CrossTenantReads::Block] {
        let (state, _store) = split_state(mode, 3600).await;
        let router = create_router(Arc::clone(&state));
        let mut listen = open_listen_naming(&router, Some(A)).await;
        state.subscriptions.publish(json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": { "customer_id": B },
        }));
        let arrival = Arrival::when(mode == CrossTenantReads::Off);
        let got = expect(&mut listen, B, arrival).await;
        if mode == CrossTenantReads::Off {
            assert!(
                mentions(&got, B),
                "control: off delivers the event: {got:?}"
            );
        } else {
            assert!(
                !mentions(&got, B),
                "a B event reached a listener whose request named A: {got:?}"
            );
        }
    }
}
