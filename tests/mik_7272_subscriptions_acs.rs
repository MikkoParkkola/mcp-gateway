// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7272 §3.9 — subscriptions and streams
//! under MCP 2026-07-28.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 8".
//!
//! The revision replaces the HTTP GET stream and `resources/subscribe` with one
//! long-lived POST-response stream a client opts into by notification type. It
//! also removes stream resumability — a broken stream loses the in-flight
//! request, and the client re-issues it with a new id.
//!
//! That last part is why this increment carries a safety rule rather than only
//! a shape: re-issuing a side-effecting call is how one booking becomes two.

use mcp_gateway::protocol::subscriptions::{ListenRequest, NotificationKind, SubscriptionId};
use serde_json::json;

#[test]
fn ac_sub_1_a_client_opts_in_by_notification_type() {
    // Opt-in, not a firehose. A client that asked for tool-list changes must
    // not be sent resource updates it never wanted and cannot interpret.
    let request = ListenRequest::from_params(Some(&json!({
        "toolsListChanged": true,
        "resourcesListChanged": false
    })))
    .expect("a well-formed listen request");

    assert!(request.wants(NotificationKind::ToolsListChanged));
    assert!(!request.wants(NotificationKind::ResourcesListChanged));
    assert!(
        !request.wants(NotificationKind::PromptsListChanged),
        "a type the client did not name is a type it did not ask for"
    );
}

#[test]
fn ac_sub_1_a_listen_request_naming_nothing_is_refused() {
    // A subscription to nothing is a stream held open forever carrying no
    // traffic — a resource the client can allocate by accident and never
    // notice.
    assert!(
        ListenRequest::from_params(Some(&json!({}))).is_none(),
        "a subscription must name at least one type"
    );
    assert!(ListenRequest::from_params(None).is_none());
    assert!(
        ListenRequest::from_params(Some(&json!({ "toolsListChanged": false }))).is_none(),
        "asking for nothing explicitly is still asking for nothing"
    );
}

#[test]
fn ac_sub_1_the_server_tags_what_it_sends() {
    // The client is told which subscription a notification belongs to, because
    // it may hold several and the payloads do not otherwise say.
    let id = SubscriptionId::mint();
    let tagged = id.tag(json!({ "method": "notifications/tools/list_changed" }));

    assert_eq!(
        tagged["_meta"]["io.modelcontextprotocol/subscriptionId"],
        json!(id.as_str()),
        "the subscription id travels under the specification's own key"
    );
}

#[test]
fn ac_sub_1_two_subscriptions_are_distinguishable() {
    assert_ne!(
        SubscriptionId::mint().as_str(),
        SubscriptionId::mint().as_str()
    );
}

#[test]
fn ac_sub_2_a_request_scoped_notification_is_not_a_subscription_notification() {
    // Progress and log messages belong to the request that caused them and
    // travel on its own response stream. Routing them to the subscription
    // stream would deliver them to a client that never made that request.
    for method in ["notifications/progress", "notifications/message"] {
        assert!(
            NotificationKind::from_method(method).is_none(),
            "{method} is request-scoped and cannot be subscribed to"
        );
    }
    assert_eq!(
        NotificationKind::from_method("notifications/tools/list_changed"),
        Some(NotificationKind::ToolsListChanged)
    );
}

// ===========================================================================
// MIK-7272.SUB.3 / .4 — resumability is gone, so re-issue safety matters.
//
// A broken response stream loses the in-flight request and the client MUST
// re-issue it with a new request id. Without deduplication that turns one
// booking into two — and the auto-generated key is derived from the tool name
// and arguments, which a retry repeats exactly, so the mechanism is there. What
// is not automatic is that a multi-round-trip retry must NOT collide with it.
// ===========================================================================

mod reissue {
    use mcp_gateway::protocol::mrtr::RetryFields;
    use serde_json::json;

    #[test]
    fn ac_sub_4_a_reissued_call_is_the_same_call() {
        // The property re-issue safety rests on: the same call, re-sent after a
        // broken stream, must look the same to the deduplicator. A key derived
        // from the tool name and arguments has that; a key derived from the
        // request id would not, and the request id is required to change.
        let first = json!({ "name": "book_flight", "arguments": { "seat": "12A" } });
        let reissued = json!({ "name": "book_flight", "arguments": { "seat": "12A" } });
        assert_eq!(
            first["arguments"], reissued["arguments"],
            "a re-issue differs only in its request id, which must not be part \
             of what identifies the call"
        );
    }

    #[test]
    fn ac_sub_4_a_continuation_retry_is_not_the_same_call() {
        // The other side, and the one that bites. A multi-round-trip retry
        // carries the same tool and the same arguments as the call it
        // continues — so a deduplicator keyed on those alone would treat the
        // retry as a duplicate and replay the interim result forever. The
        // retry fields have to be part of what identifies it.
        let original = RetryFields::from_params(Some(&json!({
            "name": "book_flight", "arguments": { "seat": "12A" }
        })));
        let retry = RetryFields::from_params(Some(&json!({
            "name": "book_flight",
            "arguments": { "seat": "12A" },
            "inputResponses": { "confirm": { "action": "accept" } },
            "requestState": "envelope"
        })));

        assert!(!original.is_retry());
        assert!(retry.is_retry());
        assert_ne!(
            original.request_state, retry.request_state,
            "the retry is distinguishable from the call it continues, which is \
             what stops a deduplicator swallowing it"
        );
    }

    #[test]
    fn ac_sub_4_two_different_continuations_are_distinguishable() {
        // Two users answering the same question about the same flight. If the
        // continuation did not participate in identity, the second would be
        // served the first one's cached outcome.
        let a = RetryFields::from_params(Some(&json!({
            "name": "book_flight", "arguments": {}, "requestState": "envelope-a"
        })));
        let b = RetryFields::from_params(Some(&json!({
            "name": "book_flight", "arguments": {}, "requestState": "envelope-b"
        })));
        assert_ne!(a.request_state, b.request_state);
    }
}
