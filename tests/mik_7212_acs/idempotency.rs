// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::idempotency::derive_key;
use mcp_gateway::protocol::cacheable::result_type_of;
use serde_json::json;

#[test]
fn ac_mrtr_10_a_retry_does_not_collide_with_the_call_it_continues() {
    // Same tool, same arguments, different continuation. A key derived from
    // the tool and arguments alone would call the retry a duplicate and
    // replay the interim result forever — the call could never finish.
    let original = derive_key("book_flight", &json!({ "seat": "12A" }));
    let retry = derive_key(
        "book_flight",
        &json!({
            "seat": "12A",
            "inputResponses": { "confirm": { "action": "accept" } },
            "requestState": "envelope"
        }),
    );
    assert_ne!(
        original, retry,
        "the continuation must participate in what identifies the call"
    );
}

#[test]
fn ac_mrtr_10_two_callers_continuations_do_not_collide() {
    // Two users answering the same question about the same flight. Without
    // the continuation in the key, the second is served the first's result.
    let a = derive_key("book_flight", &json!({ "requestState": "envelope-a" }));
    let b = derive_key("book_flight", &json!({ "requestState": "envelope-b" }));
    assert_ne!(a, b);
}

#[test]
fn ac_mrtr_10_a_reissued_identical_call_still_deduplicates() {
    // The property re-issue safety needs, unharmed: a stream broke, the
    // client re-sent the same call with a new request id, and the key is
    // the same because the request id was never part of it.
    assert_eq!(
        derive_key("book_flight", &json!({ "seat": "12A" })),
        derive_key("book_flight", &json!({ "seat": "12A" }))
    );
}

#[test]
fn ac_mrtr_10_an_interim_result_is_not_a_completed_call() {
    // The other half. Caching an `input_required` as a completion would
    // make the tool answer "still waiting" to every later caller, forever,
    // without ever asking anyone anything.
    assert_eq!(
        result_type_of(&json!({
            "resultType": "input_required",
            "requestState": "envelope"
        })),
        "input_required",
        "an interim result is distinguishable from a completed one, which is \
         what lets the cache refuse to store it"
    );
    assert_ne!(
        result_type_of(&json!({ "resultType": "input_required" })),
        "complete"
    );
}
