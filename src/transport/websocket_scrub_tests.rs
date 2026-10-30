// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Control identifiers over WebSocket (MIK-9035 DELTA-5, T1.23): a progress
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
    let (call, mut rx) = crate::transport::notification_sink::scope(None, async {
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
