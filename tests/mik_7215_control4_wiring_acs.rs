// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T4 and T5 of the `MIK-7215.CONTROL.4` test plan
//! (`docs/design/2026-09-08-control4-session-lifecycle-test-plan.md:55`).

use std::sync::Arc;

use mcp_gateway::gateway::session_lifecycle::{
    IDLE_TTL, SessionLifecycle, now_unix, wire_session_lifecycle,
};
use mcp_gateway::security::firewall::{Firewall, FirewallConfig};
use mcp_gateway::transition::TransitionTracker;
use serde_json::json;

/// A firewall whose anomaly detector is live AND whose tracker knows one
/// transition: `srv:tool-a` is followed by `srv:tool-b`, at confidence 1.0.
///
/// That trained edge is what makes the detector's per-identity state
/// OBSERVABLE through the public verdict. Without it every call scores the
/// neutral 0.5 — the cold-start value — and T4's assertion would hold whether
/// or not the sweep ever fired.
fn trained_firewall() -> Arc<Firewall> {
    let tracker = Arc::new(TransitionTracker::new());
    tracker.record_transition("trainer", "srv:tool-a");
    tracker.record_transition("trainer", "srv:tool-b");

    let cfg = FirewallConfig {
        enabled: true,
        anomaly_detection: true,
        ..FirewallConfig::default()
    };
    Arc::new(Firewall::from_config(cfg, Some(tracker)))
}

/// Score `srv:tool` for `identity`, leaving it as that identity's predecessor.
fn score(firewall: &Firewall, identity: &str, tool: &str) -> Option<f64> {
    firewall
        .check_request("", "srv", tool, &json!({}), "", identity)
        .anomaly_score
}

/// The value a call scores when the identity has no predecessor on record —
/// `anomaly.rs:156`, the vacant-slot branch.
const NO_PREDECESSOR: f64 = 0.5;
/// The value `srv:tool-b` scores when `srv:tool-a` IS on record, given the
/// trained edge — `1.0 - confidence`, and the fixture trains confidence 1.0.
const AFTER_TRAINED_PREDECESSOR: f64 = 0.0;

/// T4 — THE criterion. After a sweep reclaims an identity, the predecessor
/// state the anomaly detector held for it is gone, and the identity's next
/// call is scored as a first call.
///
/// Observed through the public verdict rather than the detector's map: the
/// requirement is that the identity is TREATED as new, and a storage accessor
/// added for a test would assert the weaker of the two.
///
/// Registration comes from the PRODUCTION function, never from this test: a
/// fixture that registers its own handler proves only that the test can
/// register one.
#[test]
fn a_sweep_reclaims_the_anomaly_detectors_state_for_that_identity() {
    let lifecycle = Arc::new(SessionLifecycle::new());
    let firewall = trained_firewall();
    wire_session_lifecycle(&lifecycle, &firewall);

    // CONTROL — an identity nobody sweeps, run through the same two calls.
    // Its second call MUST score against the predecessor, or the fixture is
    // inert and the swept identity's assertion below proves nothing.
    let kept = "identity-kept";
    assert_eq!(score(&firewall, kept, "tool-a"), Some(NO_PREDECESSOR));
    assert_eq!(
        score(&firewall, kept, "tool-b"),
        Some(AFTER_TRAINED_PREDECESSOR),
        "the fixture is inert: with no reap in between, tool-b must score \
         against the tool-a predecessor, so the trained edge did not take and \
         the swept-identity assertion below would pass over a cold detector"
    );

    // GIVEN the same first call for an identity whose deadline has passed
    let swept = "identity-under-sweep";
    assert_eq!(score(&firewall, swept, "tool-a"), Some(NO_PREDECESSOR));
    lifecycle.track(swept, now_unix().saturating_sub(1));

    // WHEN the sweep runs
    let reclaimed = lifecycle.reap(now_unix());

    // THEN the reclaimed identity's next call has no predecessor to score
    // against — the same call that scored 0.0 for the kept identity.
    assert_eq!(reclaimed, 1, "the sweep must report the key it removed");
    assert_eq!(
        score(&firewall, swept, "tool-b"),
        Some(NO_PREDECESSOR),
        "the sweep reported a reclaim but the detector still scored against a \
         predecessor — the handler never fired, or its Weak capture was dead"
    );
}

/// T5 — the constant the stated reclaim latency rests on. A wrong-by-10x value
/// passes every other row in the plan, because no other row reads it.
#[test]
fn idle_ttl_is_the_value_the_latency_bound_is_stated_against() {
    assert_eq!(
        IDLE_TTL.as_secs(),
        300,
        "D6 fixes IDLE_TTL at 300s; the documented reclaim latency of \
         IDLE_TTL + 1s + session_reaper_interval is stated against it"
    );
}
