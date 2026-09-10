// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7216 / MRTR.10 — a non-final result must not be cached as if it were final.
//!
//! MCP 2026 lets a tool call return `resultType: "input_required"`, meaning the
//! call has not finished: it is waiting for the caller to supply something. The
//! gateway caches completed calls for idempotency. Storing an `input_required`
//! result makes every later retry of that call replay the *request for input*
//! instead of running the call, so the exchange can never complete.

use mcp_gateway::cache::ResponseCache;
use mcp_gateway::idempotency::{CheckOutcome, IdempotencyCache};
use serde_json::json;
use std::time::Duration;

const TTL: Duration = Duration::from_secs(60);

fn completed_value(cache: &IdempotencyCache, key: &str) -> Option<serde_json::Value> {
    match cache.check(key) {
        CheckOutcome::Completed(v) => Some(v),
        _ => None,
    }
}

#[test]
fn an_input_required_result_is_not_served_from_the_idempotency_cache() {
    let cache = IdempotencyCache::new();
    cache.mark_in_flight("k");
    cache.mark_completed("k", json!({"resultType": "input_required"}));

    assert!(
        matches!(cache.check("k"), CheckOutcome::Proceed),
        "an input_required result was cached as final; every retry now replays \
         the request for input instead of running the call"
    );
}

#[test]
fn a_complete_result_is_still_cached() {
    let cache = IdempotencyCache::new();
    cache.mark_in_flight("k");
    cache.mark_completed("k", json!({"resultType": "complete", "v": 1}));

    assert_eq!(
        completed_value(&cache, "k").and_then(|v| v.get("v").cloned()),
        Some(json!(1)),
        "guarding non-final results must not stop final ones being cached"
    );
}

#[test]
fn a_result_omitting_result_type_is_cached_as_complete() {
    // Every pre-2026 backend omits the field, and the specification requires
    // clients to read the absence as "complete". Refusing to cache these would
    // disable idempotency for every legacy backend.
    let cache = IdempotencyCache::new();
    cache.mark_in_flight("k");
    cache.mark_completed("k", json!({"v": 2}));

    assert_eq!(
        completed_value(&cache, "k").and_then(|v| v.get("v").cloned()),
        Some(json!(2)),
        "a legacy backend's result omits resultType and must still be cached"
    );
}

// The idempotency cache is only half of MRTR.10. `gateway_invoke` also stores
// every result in the response cache and serves later calls from it, so a
// non-final result held there re-serves the request for input on its own.

#[test]
fn an_input_required_result_is_not_stored_in_the_response_cache() {
    let cache = ResponseCache::new();
    let key = ResponseCache::build_key("srv", "tool", &json!({"a": 1}));
    cache.set(&key, json!({"resultType": "input_required"}), TTL);

    assert_eq!(
        cache.get(&key),
        None,
        "an input_required result was stored in the response cache; every later \
         call replays the request for input instead of running the tool"
    );
}

#[test]
fn the_response_cache_still_stores_final_and_legacy_results() {
    let cache = ResponseCache::new();
    let final_key = ResponseCache::build_key("srv", "tool", &json!({"a": 1}));
    let legacy_key = ResponseCache::build_key("srv", "tool", &json!({"a": 2}));

    cache.set(&final_key, json!({"resultType": "complete", "v": 1}), TTL);
    cache.set(&legacy_key, json!({"v": 2}), TTL);

    assert_eq!(
        cache.get(&final_key).and_then(|v| v.get("v").cloned()),
        Some(json!(1)),
        "guarding non-final results must not stop final ones being cached"
    );
    assert_eq!(
        cache.get(&legacy_key).and_then(|v| v.get("v").cloned()),
        Some(json!(2)),
        "a legacy backend's result omits resultType and must still be cached"
    );
}

// The guard must be "complete, or the field is absent" — not "anything except
// input_required". A guard written the second way passes every case above,
// because no case above presents a third value. These supply them: a type the
// gateway has never heard of, and a field that is present but malformed. The
// spec's default reading covers an *omitted* field; a present non-string is a
// broken result, and treating it as complete would let a backend skip the
// finality check by sending the field wrong.

fn not_final() -> Vec<serde_json::Value> {
    vec![
        json!({"resultType": "some_future_type"}),
        json!({"resultType": null}),
        json!({"resultType": 42}),
        json!({"resultType": {"kind": "complete"}}),
    ]
}

#[test]
fn neither_cache_stores_an_unrecognised_or_malformed_result_type() {
    for value in not_final() {
        let idem = IdempotencyCache::new();
        idem.mark_in_flight("k");
        assert!(
            !idem.mark_completed("k", value.clone()),
            "idempotency cache reported storing {value}, which is not a complete result"
        );
        assert!(
            matches!(idem.check("k"), CheckOutcome::Proceed),
            "{value} was served from the idempotency cache as if it were final"
        );

        let responses = ResponseCache::new();
        let key = ResponseCache::build_key("srv", "tool", &value);
        assert!(
            !responses.set(&key, value.clone(), TTL),
            "response cache reported storing {value}, which is not a complete result"
        );
        assert_eq!(
            responses.get(&key),
            None,
            "{value} was served from the response cache as if it were final"
        );
    }
}

#[test]
fn both_caches_report_the_writes_they_actually_make() {
    // The invoke path logs "Cached result" from these return values, so a
    // refusal that reported success would produce a log saying the opposite of
    // what the cache did.
    let idem = IdempotencyCache::new();
    idem.mark_in_flight("k");
    assert!(idem.mark_completed("k", json!({"resultType": "complete"})));

    let responses = ResponseCache::new();
    let key = ResponseCache::build_key("srv", "tool", &json!({"a": 1}));
    assert!(responses.set(&key, json!({"v": 1}), TTL));
}
