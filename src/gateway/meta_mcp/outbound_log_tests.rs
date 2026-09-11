// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's own `notifications/message`, on the stream of the request
//! that asked for it (ADR-014 §3 and §4, `MIK-7272.SUB.2b` Acceptance rows 1
//! and 2).
//!
//! These run the real dispatch under a real sink. The only double is the
//! backend transport at the network boundary, borrowed from `authz_tests`
//! rather than rebuilt -- a second fixture assembling the caller context its
//! own way would prove the fixture works, not that the emitter is reached.
//!
//! What they cannot prove is the seam: `set_request_log_level` is called here
//! directly, where production calls it from the two `classify_and_observe`
//! sites. The end-to-end evidence for that is
//! `tests/mik_7272_sub2b_acs.rs`, which declares the level in `_meta` and
//! reads the frames off a real transport.

use std::sync::atomic::Ordering;

use serde_json::Value;

use crate::gateway::authz::AllowAll;
use crate::protocol::JsonRpcNotification;
use crate::transport::notification_sink;

use super::MetaMcp;
use super::authz_tests::{counted_backend, ctx, invoke_args};

/// Every `notifications/message` a scoped invocation put on the caller's sink.
async fn messages_from_invoke(declared: Option<&str>) -> Vec<JsonRpcNotification> {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let (result, notifications) = notification_sink::collect(async {
        notification_sink::set_request_log_level(declared);
        Box::pin(meta.invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll), None)).await
    })
    .await;

    assert!(result.is_ok(), "the invocation must succeed: {result:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the call must actually reach the backend, or an empty sink proves nothing"
    );
    notifications
        .into_iter()
        .filter(|notification| notification.method == "notifications/message")
        .collect()
}

fn field<'a>(notification: &'a JsonRpcNotification, pointer: &str) -> &'a Value {
    notification
        .params
        .as_ref()
        .and_then(|params| params.pointer(pointer))
        .unwrap_or_else(|| panic!("notification carries no {pointer}: {notification:?}"))
}

/// Row 1: a request that declared `info` is told about its own invocation on
/// its own response stream, not only through the operator's process log.
#[tokio::test]
async fn row1_a_declared_level_puts_the_audit_line_on_the_requests_own_stream() {
    let messages = messages_from_invoke(Some("info")).await;

    assert_eq!(
        messages.len(),
        1,
        "the invocation's audit line must reach the caller exactly once"
    );
    assert_eq!(field(&messages[0], "/level"), "info");
    assert_eq!(field(&messages[0], "/logger"), "gateway.invoke");
    assert_eq!(field(&messages[0], "/data/message"), "tool invoked");
    assert_eq!(field(&messages[0], "/data/tool"), "read");
    assert_eq!(field(&messages[0], "/data/server"), "alpha");
}

/// Row 2: absence means silence. A request that declared no level gets no
/// `notifications/message` at all -- there is no default, and no fall back to
/// whatever the session set with `logging/setLevel`.
#[tokio::test]
async fn row2_no_declared_level_yields_no_messages_at_all() {
    assert!(
        messages_from_invoke(None).await.is_empty(),
        "an undeclared request must receive silence, not a default level"
    );
}

/// A level the gateway does not know is treated as undeclared, not as a
/// protocol error: the field is optional, so a typo silences this request's
/// messages rather than failing a tool call that has nothing to do with
/// logging.
#[tokio::test]
async fn an_unparseable_declared_level_is_silence_not_a_refusal() {
    assert!(
        messages_from_invoke(Some("chatty")).await.is_empty(),
        "an unknown level must be read as absent"
    );
}

/// The comparison is `raised >= declared`, so a caller that asked for `error`
/// does not receive the `info` audit line.
#[tokio::test]
async fn a_level_above_the_emitted_one_filters_the_audit_line_out() {
    assert!(
        messages_from_invoke(Some("error")).await.is_empty(),
        "`info` is below `error` and must not be delivered"
    );
}
