// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio reader's tap step (MIK-7630 I5 design §4): a listen's frames
//! and its terminal response go to the listen, never to a pending request,
//! and progress keeps its existing route.

use std::collections::HashMap;

use serde_json::json;

use super::StdioTransport;
use crate::transport::upstream_tap::{Requested, UpstreamNote};

fn transport() -> std::sync::Arc<StdioTransport> {
    StdioTransport::new(
        "echo",
        HashMap::new(),
        None,
        std::time::Duration::from_secs(30),
        None,
    )
}

#[test]
fn a_listen_response_ends_the_listen_and_skips_pending() {
    let t = transport();
    let mut rx = t.taps.listen(&json!(41), Requested::default());
    let (tx, mut pending) = tokio::sync::oneshot::channel();
    t.pending.insert("41".to_string(), tx);
    t.handle_response(r#"{"jsonrpc":"2.0","id":41,"result":{"resultType":"complete"}}"#)
        .unwrap();
    assert_eq!(rx.try_recv(), Ok(UpstreamNote::End));
    assert!(
        pending.try_recv().is_err(),
        "the listen id is not answered as a request"
    );
}

#[test]
fn a_tagged_notification_reaches_the_listen() {
    let t = transport();
    let mut rx = t.taps.listen(&json!(5), Requested::default());
    let line = json!({"jsonrpc": "2.0", "method": "notifications/resources/list_changed",
        "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": 5}}});
    t.handle_response(&line.to_string()).unwrap();
    assert!(matches!(rx.try_recv(), Ok(UpstreamNote::Notice { .. })));
}

#[test]
fn progress_is_not_taken_by_an_open_legacy_tap() {
    let t = transport();
    let mut legacy = t.taps.unsolicited();
    let line = json!({"jsonrpc": "2.0", "method": "notifications/progress",
        "params": {"progressToken": "p", "progress": 1}});
    t.handle_response(&line.to_string()).unwrap();
    assert!(legacy.try_recv().is_err());
}

/// MIK-7899 CLASS.1: a `-32601` answer to a stdio listen says the peer has
/// no listen; it is not the listen's graceful end.
#[test]
fn a_method_not_found_answer_is_not_a_graceful_end() {
    let t = transport();
    let mut rx = t.taps.listen(&json!(42), Requested::default());
    t.handle_response(
        r#"{"jsonrpc":"2.0","id":42,"error":{"code":-32601,"message":"Method not found"}}"#,
    )
    .unwrap();
    assert_eq!(rx.try_recv(), Ok(UpstreamNote::Unsupported));
}
