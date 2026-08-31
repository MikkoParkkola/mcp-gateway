// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.RESULT.2 — a backend reply omitting `resultType` reads as complete.
//!
//! The unit-level default already has tests (`tests/mik_7213_acs.rs`). What was
//! unproven is that the *consumers* of a real backend reply route through it.
//! `gateway_invoke` hands its dispatch result to the response cache
//! (`ResponseCache::set`) and to the idempotency reservation
//! (`IdempotencyReservation::complete` -> `IdempotencyCache::mark_completed`),
//! and both refuse a non-final result through `is_final`
//! (`src/cache.rs:166`, `src/idempotency.rs:283`). A default that read a missing
//! `resultType` as anything but `"complete"` would make every pre-2026 backend's
//! answer uncacheable and every idempotent call permanently retryable, silently.
//!
//! Each case pairs the legacy reply with an `input_required` reply through the
//! same entry point, so a guard that accepted everything would fail the second
//! half rather than pass both.

use std::time::Duration;

use mcp_gateway::cache::ResponseCache;
use mcp_gateway::idempotency::{CheckOutcome, IdempotencyCache};
use serde_json::{Value, json};

/// What a pre-2026 backend returns from `tools/call`: no `resultType` at all.
fn legacy_backend_reply() -> Value {
    json!({"content": [{"type": "text", "text": "42"}], "isError": false})
}

/// What a 2026 backend returns when it still needs something from the caller.
fn interim_backend_reply() -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {"confirm": {"method": "elicitation/create", "params": {}}},
        "requestState": "opaque"
    })
}

#[test]
fn ac_result_2_response_cache_stores_a_reply_without_a_result_type() {
    let cache = ResponseCache::new();
    let ttl = Duration::from_secs(60);

    assert!(
        cache.set("legacy", legacy_backend_reply(), ttl),
        "a backend reply omitting resultType must be treated as complete and cached"
    );
    assert_eq!(
        cache.get("legacy"),
        Some(legacy_backend_reply()),
        "the cached legacy reply must be servable"
    );

    assert!(
        !cache.set("interim", interim_backend_reply(), ttl),
        "an input_required reply must still be refused"
    );
    assert_eq!(cache.get("interim"), None);
}

#[test]
fn ac_result_2_idempotency_completes_a_reply_without_a_result_type() {
    let cache = IdempotencyCache::new();

    cache.mark_in_flight("legacy");
    assert!(
        cache.mark_completed("legacy", legacy_backend_reply()),
        "a backend reply omitting resultType must complete the idempotency entry"
    );
    match cache.check("legacy") {
        CheckOutcome::Completed(value) => assert_eq!(value, legacy_backend_reply()),
        other => panic!("expected a completed entry, got {other:?}"),
    }

    cache.mark_in_flight("interim");
    assert!(
        !cache.mark_completed("interim", interim_backend_reply()),
        "an input_required reply must still be refused"
    );
    assert!(
        matches!(cache.check("interim"), CheckOutcome::Proceed),
        "a refused non-final result must leave the key retryable"
    );
}
