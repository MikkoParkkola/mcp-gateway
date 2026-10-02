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

use mcp_gateway::protocol::RequestId;
use mcp_gateway::protocol::subscriptions::{ListenRequest, NotificationKind, SubscriptionId};
use serde_json::json;

// The filter shape below is the specification's own example, verbatim from
// /specification/2026-07-28/basic/patterns/subscriptions:
//
//   "params": {
//     "notifications": {
//       "toolsListChanged": true,
//       "resourceSubscriptions": ["file:///project/config.json"]
//     }
//   }
//
// The first version of these rows was written from the changelog and the index
// rather than this page, and encoded three wire errors that all agreed with the
// implementation. Quoting the page is what makes them tests rather than a
// second copy of the same assumption.

#[test]
fn ac_sub_1_a_client_opts_in_by_notification_type() {
    // Opt-in, not a firehose. A client that asked for tool-list changes must
    // not be sent resource updates it never wanted and cannot interpret.
    let request = ListenRequest::from_params(Some(&json!({
        "notifications": {
            "toolsListChanged": true,
            "resourcesListChanged": false
        }
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
fn ac_sub_1_the_filter_is_nested_under_notifications() {
    // Read at the params root, every conforming request looked empty and was
    // refused — the opt-ins were never where they were looked for.
    assert!(
        ListenRequest::from_params(Some(&json!({ "toolsListChanged": true }))).is_none(),
        "opt-ins at the params root are not a filter"
    );
    assert!(
        ListenRequest::from_params(Some(&json!({
            "notifications": { "toolsListChanged": true }
        })))
        .is_some_and(|r| r.wants(NotificationKind::ToolsListChanged))
    );
}

#[test]
fn ac_sub_1_resource_subscriptions_names_uris_not_a_boolean() {
    // The one field in the filter table that is not a boolean. Read as one, a
    // client's resource list was silently dropped and it received nothing for
    // the resources it named.
    let request = ListenRequest::from_params(Some(&json!({
        "notifications": {
            "toolsListChanged": true,
            "resourceSubscriptions": ["file:///project/config.json"]
        }
    })))
    .expect("the specification's own example must parse");

    assert!(request.wants(NotificationKind::ResourceSubscriptions));
    assert_eq!(
        request.resource_uris(),
        ["file:///project/config.json"],
        "the subscribed resource URIs must survive parsing"
    );
}

#[test]
fn ac_sub_1_a_request_without_a_filter_is_invalid_but_an_empty_filter_is_not() {
    // Two different answers. No filter at all is invalid params. An empty
    // filter is a client asking for nothing, which the specification permits
    // and which is acknowledged rather than refused.
    assert!(ListenRequest::from_params(None).is_none());
    assert!(
        ListenRequest::from_params(Some(&json!({}))).is_none(),
        "a listen request must carry a notifications filter"
    );

    let empty = ListenRequest::from_params(Some(&json!({ "notifications": {} })))
        .expect("an empty filter is a valid request");
    assert!(
        empty.is_empty(),
        "it asked for nothing, and that is allowed"
    );
}

#[test]
fn ac_sub_1_an_unrecognised_notification_type_is_ignored_not_refused() {
    // A server is expected to handle unsupported types gracefully; refusing
    // them would make every future notification type a breaking change.
    let request = ListenRequest::from_params(Some(&json!({
        "notifications": { "toolsListChanged": true, "somethingFuture": true }
    })))
    .expect("an unknown key must not sink the request");

    assert!(request.wants(NotificationKind::ToolsListChanged));
}

/// MIK-7766: the stream opens with the acknowledgement NOTIFICATION, tagged
/// and naming only what the gateway delivers; task ids go under
/// `notifications.taskIds`, as the tasks extension names them.
#[test]
fn ac_sub_1_the_acknowledgement_names_what_is_delivered() {
    let request = ListenRequest::from_params(Some(&json!({
        "notifications": {
            "toolsListChanged": true,
            "promptsListChanged": true,
            "resourceSubscriptions": ["file:///a"],
        },
        "taskIds": ["t-1"],
    })))
    .expect("a valid filter");
    let ack = request.acknowledgement(&SubscriptionId::of_request(RequestId::Number(7)));
    assert_eq!(
        ack,
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/subscriptions/acknowledged",
            "params": {
                "_meta": { "io.modelcontextprotocol/subscriptionId": 7 },
                "notifications": { "toolsListChanged": true, "taskIds": ["t-1"] },
            },
        })
    );

    let quiet = ListenRequest::from_params(Some(&json!({ "notifications": {} })))
        .expect("an empty filter is valid");
    let ack = quiet.acknowledgement(&SubscriptionId::of_request(RequestId::Number(8)));
    assert_eq!(ack["params"]["notifications"], json!({}), "{ack}");
}

/// MIK-7778: the tasks extension's own placement, `notifications.taskIds`,
/// opts in and is named back in the acknowledgement, like the root form.
#[test]
fn ac_sub_1_a_nested_task_filter_opts_in_and_is_acknowledged() {
    let request = ListenRequest::from_params(Some(&json!({
        "notifications": { "taskIds": ["t-1", 5, "t-2"] },
    })))
    .expect("a valid filter");
    assert!(request.wants(NotificationKind::Tasks));
    assert_eq!(request.task_ids(), ["t-1", "t-2"]);
    let ack = request.acknowledgement(&SubscriptionId::of_request(RequestId::Number(9)));
    assert_eq!(
        ack["params"]["notifications"],
        json!({ "taskIds": ["t-1", "t-2"] }),
        "{ack}"
    );

    // Both placements are one filter: merged in request order (root first),
    // each id once.
    let both = ListenRequest::from_params(Some(&json!({
        "taskIds": ["t-2", "t-1"],
        "notifications": { "taskIds": ["t-1", "t-3", "t-2"] },
    })))
    .expect("a valid filter");
    assert_eq!(both.task_ids(), ["t-2", "t-1", "t-3"]);
}

/// MIK-7766: a server-ended subscription closes with the listen request's
/// own response, a complete result carrying only the subscription id.
#[test]
fn ac_sub_1_a_graceful_end_is_the_listen_response() {
    for id in [RequestId::Number(4), RequestId::String("sub-b".into())] {
        let subscription = SubscriptionId::of_request(id);
        let wire = subscription.as_value();
        assert_eq!(
            subscription.graceful_end(),
            json!({
                "jsonrpc": "2.0",
                "id": wire,
                "result": {
                    "resultType": "complete",
                    "_meta": { "io.modelcontextprotocol/subscriptionId": wire },
                },
            })
        );
    }
}

#[test]
fn ac_sub_1_the_subscription_id_is_the_requests_own_id() {
    // "The value is the JSON-RPC ID of the subscriptions/listen request."
    // A minted id looks authoritative and leaves the client unable to correlate
    // a notification with the subscription that asked for it.
    let numeric = SubscriptionId::of_request(RequestId::Number(1));
    assert_eq!(numeric.as_value(), json!(1), "a numeric id stays numeric");

    let textual = SubscriptionId::of_request(RequestId::String("sub-a".into()));
    assert_eq!(textual.as_value(), json!("sub-a"));
}

#[test]
fn ac_sub_1_the_server_tags_what_it_sends_under_params_meta() {
    // The specification's own notification example puts the tag in
    // `params._meta`. At the notification root it is well-formed, present, and
    // in a place no conforming client looks.
    let id = SubscriptionId::of_request(RequestId::Number(1));
    let tagged = id.tag(json!({
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": { "uri": "file:///project/config.json" }
    }));

    assert_eq!(
        tagged["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        json!(1),
        "the tag belongs under params._meta, as a number when the id was one"
    );
    assert_eq!(
        tagged["params"]["uri"], "file:///project/config.json",
        "tagging must not disturb the notification's own params"
    );
    assert!(
        tagged.get("_meta").is_none(),
        "nothing should be left at the notification root"
    );
}

#[test]
fn ac_sub_1_two_subscriptions_are_distinguishable() {
    assert_ne!(
        SubscriptionId::of_request(RequestId::Number(1)),
        SubscriptionId::of_request(RequestId::Number(2))
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

// ===========================================================================
// Through the transport. The rows above prove the model; these prove the
// gateway serves it — which is the difference between a type and a feature.
// ===========================================================================

#[path = "mik_7272_subscriptions_acs/http.rs"]
mod http;
