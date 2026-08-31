//! MIK-7216 / MRTR.10 — a non-final result must not be cached as if it were final.
//!
//! MCP 2026 lets a tool call return `resultType: "input_required"`, meaning the
//! call has not finished: it is waiting for the caller to supply something. The
//! gateway caches completed calls for idempotency. Storing an `input_required`
//! result makes every later retry of that call replay the *request for input*
//! instead of running the call, so the exchange can never complete.

use mcp_gateway::idempotency::{CheckOutcome, IdempotencyCache};
use serde_json::json;

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
